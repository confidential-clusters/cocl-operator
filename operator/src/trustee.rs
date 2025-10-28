// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
// SPDX-FileCopyrightText: Dehan Meng <demeng@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, TimeDelta, Utc};
use clevis_pin_trustee_lib::Key as ClevisKey;
use json_patch::{AddOperation, PatchOperation, TestOperation};
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{
    ConfigMap, ConfigMapVolumeSource, Container, ContainerPort, EmptyDirVolumeSource, PodSpec,
    PodTemplateSpec, Secret, SecretVolumeSource, Service, ServicePort, ServiceSpec, Volume,
    VolumeMount,
};
use k8s_openapi::apimachinery::pkg::{
    apis::meta::v1::{LabelSelector, OwnerReference},
    util::intstr::IntOrString,
};
use kube::api::{ObjectMeta, Patch};
use kube::{Api, Client, Resource, ResourceExt};
use log::info;
use operator::{RvContextData, create_or_info_if_exists, create_or_update};
use rv_store::*;
use serde::{Serialize, Serializer};
use serde_json::Value::String as JsonString;
use std::collections::BTreeMap;

const TRUSTEE_DATA_DIR: &str = "/opt/trustee";
const TRUSTEE_SECRETS_PATH: &str = "/opt/trustee/kbs-repository/default";
const KBS_CONFIG_FILE: &str = "kbs-config.toml";
const REFERENCE_VALUES_FILE: &str = "reference-values.json";

const TRUSTEE_DATA_MAP: &str = "trustee-data";
const ATT_POLICY_MAP: &str = "attestation-policy";
const DEPLOYMENT_NAME: &str = "trustee-deployment";
const INTERNAL_KBS_PORT: i32 = 8080;

fn primitive_date_time_to_str<S>(d: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// Sync with Trustee
/// reference_value_provider_service::reference_value::ReferenceValue
/// (cannot import directly because its expiration doesn't serialize
/// right)
#[derive(Serialize)]
struct ReferenceValue {
    pub version: String,
    pub name: String,
    #[serde(serialize_with = "primitive_date_time_to_str")]
    pub expiration: DateTime<Utc>,
    pub value: serde_json::Value,
}

pub fn get_image_pcrs(image_pcrs_map: ConfigMap) -> Result<ImagePcrs> {
    let err = "Image PCRs map existed, but had no data";
    let image_pcrs_data = image_pcrs_map.data.context(err)?;
    let err = "Image PCRs data existed, but had no file";
    let image_pcrs_str = image_pcrs_data.get(PCR_CONFIG_FILE).context(err)?;
    serde_json::from_str(image_pcrs_str).map_err(Into::into)
}

fn recompute_reference_values(image_pcrs: ImagePcrs) -> Vec<ReferenceValue> {
    // TODO many grub+shim:many OS image recompute once supported
    let mut reference_values_in =
        BTreeMap::from([("svn".to_string(), vec![JsonString("1".to_string())])]);
    for pcr in image_pcrs.0.values().flat_map(|v| &v.pcrs) {
        reference_values_in
            .entry(format!("pcr{}", pcr.id))
            .or_default()
            .push(JsonString(pcr.value.clone()));
    }
    reference_values_in
        .iter()
        .map(|(name, values)| ReferenceValue {
            version: "0.1.0".to_string(),
            name: format!("tpm_{name}"),
            expiration: Utc::now() + TimeDelta::days(365),
            value: serde_json::Value::Array(values.to_vec()),
        })
        .collect()
}

pub async fn update_reference_values(ctx: RvContextData) -> Result<()> {
    let config_maps: Api<ConfigMap> = Api::default_namespaced(ctx.client);
    let image_pcrs_map = config_maps.get(PCR_CONFIG_MAP).await?;
    let reference_values = recompute_reference_values(get_image_pcrs(image_pcrs_map)?);

    let existing_data = config_maps.get(TRUSTEE_DATA_MAP).await?;
    let err = format!("ConfigMap {TRUSTEE_DATA_MAP} existed, but had no data");
    let existing_data_map = existing_data.data.context(err)?;
    let err = format!("ConfigMap {TRUSTEE_DATA_MAP} existed, but had no reference values");
    let existing_rvs = existing_data_map.get(REFERENCE_VALUES_FILE).context(err)?;

    let path = jsonptr::PointerBuf::parse(format!("/data/{REFERENCE_VALUES_FILE}"))?;
    let test_patch = PatchOperation::Test(TestOperation {
        path: path.clone(),
        value: JsonString(existing_rvs.clone()),
    });
    let add_patch = PatchOperation::Add(AddOperation {
        path,
        value: JsonString(serde_json::to_string(&reference_values)?),
    });
    let patch: Patch<ConfigMap> = Patch::Json(json_patch::Patch(vec![test_patch, add_patch]));
    let params = &Default::default();
    config_maps.patch(TRUSTEE_DATA_MAP, params, &patch).await?;
    info!("Recomputed reference values");
    Ok(())
}

fn generate_luks_key() -> Result<Vec<u8>> {
    // Constraint: 32 bytes b64-encoded, thus 24
    let mut pass = [0; 24];
    openssl::rand::rand_bytes(&mut pass)?;
    let key = general_purpose::STANDARD.encode(pass);
    let jwk = ClevisKey {
        key_type: "oct".to_string(),
        key,
    };
    serde_json::to_vec(&jwk).map_err(Into::into)
}

fn generate_secret_volume(id: &str) -> (Volume, VolumeMount) {
    (
        Volume {
            name: id.to_string(),
            secret: Some(SecretVolumeSource {
                secret_name: Some(id.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        },
        VolumeMount {
            name: id.to_string(),
            mount_path: format!("{TRUSTEE_SECRETS_PATH}/{id}"),
            ..Default::default()
        },
    )
}

pub async fn mount_secret(client: Client, id: &str) -> Result<()> {
    let deployments: Api<Deployment> = Api::default_namespaced(client);
    let mut deployment = deployments.get(DEPLOYMENT_NAME).await?;
    let err = format!("Deployment {DEPLOYMENT_NAME} existed, but had no spec");
    let depl_spec = deployment.spec.as_mut().context(err)?;
    let err = format!("Deployment {DEPLOYMENT_NAME} existed, but had no pod spec");
    let pod_spec = depl_spec.template.spec.as_mut().context(err)?;

    let (volume, volume_mount) = generate_secret_volume(id);
    pod_spec.volumes.get_or_insert_default().push(volume);
    let err = format!("Deployment {DEPLOYMENT_NAME} existed, but had no containers");
    let container = pod_spec.containers.get_mut(0).context(err)?;
    let vol_mounts = container.volume_mounts.get_or_insert_default();
    vol_mounts.push(volume_mount);

    deployments
        .replace(DEPLOYMENT_NAME, &Default::default(), &deployment)
        .await?;
    info!("Mounted secret {id} to {DEPLOYMENT_NAME}");
    Ok(())
}

pub async fn generate_secret(client: Client, id: &str) -> Result<()> {
    let secret_data = k8s_openapi::ByteString(generate_luks_key()?);
    let data = BTreeMap::from([("root".to_string(), secret_data)]);

    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(id.to_string()),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    };
    create_or_info_if_exists!(client, Secret, secret);
    Ok(())
}

pub async fn generate_attestation_policy(
    client: Client,
    owner_reference: OwnerReference,
) -> Result<()> {
    let policy_rego = include_str!("tpm.rego");
    let data = BTreeMap::from([
        ("default_cpu.rego".to_string(), policy_rego.to_string()),
        // Must create GPU policy or Trustee will attempt to write one to the read-only mount
        ("default_gpu.rego".to_string(), String::new()),
    ]);

    let config_map = ConfigMap {
        metadata: ObjectMeta {
            name: Some(ATT_POLICY_MAP.to_string()),
            owner_references: Some(vec![owner_reference]),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    };
    create_or_info_if_exists!(client, ConfigMap, config_map);
    Ok(())
}

pub async fn generate_trustee_data(client: Client, owner_reference: OwnerReference) -> Result<()> {
    let kbs_config = include_str!("kbs-config.toml");
    let policy_rego = include_str!("resource.rego");

    let data = BTreeMap::from([
        ("kbs-config.toml".to_string(), kbs_config.to_string()),
        ("policy.rego".to_string(), policy_rego.to_string()),
        (REFERENCE_VALUES_FILE.to_string(), "[]".to_string()),
    ]);

    let config_map = ConfigMap {
        metadata: ObjectMeta {
            name: Some(TRUSTEE_DATA_MAP.to_string()),
            owner_references: Some(vec![owner_reference]),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    };
    create_or_info_if_exists!(client, ConfigMap, config_map);
    Ok(())
}

pub async fn generate_kbs_service(
    client: Client,
    owner_reference: OwnerReference,
    kbs_port: Option<i32>,
) -> Result<()> {
    let svc_name = "kbs-service";
    let selector = Some(BTreeMap::from([("app".to_string(), "kbs".to_string())]));

    let mut service = Service {
        metadata: ObjectMeta {
            name: Some(svc_name.to_string()),
            owner_references: Some(vec![owner_reference.clone()]),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            selector: selector.clone(),
            ports: Some(vec![ServicePort {
                name: Some("kbs-port".to_string()),
                port: kbs_port.unwrap_or(INTERNAL_KBS_PORT),
                target_port: Some(IntOrString::Int(INTERNAL_KBS_PORT)),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    };
    create_or_update!(client, Service, service);
    Ok(())
}

fn generate_kbs_volume_templates() -> [(&'static str, &'static str, Volume); 3] {
    [
        (
            ATT_POLICY_MAP,
            "/opt/trustee/policies/opa",
            Volume {
                config_map: Some(ConfigMapVolumeSource {
                    name: ATT_POLICY_MAP.to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
        (
            TRUSTEE_DATA_MAP,
            TRUSTEE_DATA_DIR,
            Volume {
                config_map: Some(ConfigMapVolumeSource {
                    name: TRUSTEE_DATA_MAP.to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
        (
            "resource-dir",
            TRUSTEE_SECRETS_PATH,
            Volume {
                empty_dir: Some(EmptyDirVolumeSource {
                    medium: Some("Memory".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
    ]
}

fn generate_kbs_pod_spec(image: &str) -> PodSpec {
    let volumes = generate_kbs_volume_templates();
    PodSpec {
        containers: vec![Container {
            command: Some(vec![
                "/usr/local/bin/kbs".to_string(),
                "--config-file".to_string(),
                format!("{TRUSTEE_DATA_DIR}/{KBS_CONFIG_FILE}"),
            ]),
            image: Some(image.to_string()),
            name: "kbs".to_string(),
            ports: Some(vec![ContainerPort {
                container_port: INTERNAL_KBS_PORT,
                ..Default::default()
            }]),
            volume_mounts: Some(
                volumes
                    .iter()
                    .map(|(name, mount_path, _)| VolumeMount {
                        name: name.to_string(),
                        mount_path: mount_path.to_string(),
                        ..Default::default()
                    })
                    .collect(),
            ),
            ..Default::default()
        }],
        volumes: Some(
            volumes
                .iter()
                .map(|(name, _, volume)| {
                    let mut volume = volume.clone();
                    volume.name = name.to_string();
                    volume.clone()
                })
                .collect(),
        ),
        ..Default::default()
    }
}

pub async fn generate_kbs_deployment(
    client: Client,
    owner_reference: OwnerReference,
    image: &str,
) -> Result<()> {
    let selector = Some(BTreeMap::from([("app".to_string(), "kbs".to_string())]));
    let pod_spec = generate_kbs_pod_spec(image);

    // Inspired by trustee-operator
    let mut deployment = Deployment {
        metadata: ObjectMeta {
            name: Some(DEPLOYMENT_NAME.to_string()),
            owner_references: Some(vec![owner_reference]),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(1),
            selector: LabelSelector {
                match_labels: selector.clone(),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: selector,
                    ..Default::default()
                }),
                spec: Some(pod_spec),
            },
            ..Default::default()
        }),
        ..Default::default()
    };
    create_or_update!(client, Deployment, deployment);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_client::*;
    use compute_pcrs_lib::Pcr;
    use http::{Method, Request, StatusCode};
    use serde::Deserialize;

    fn dummy_pcrs() -> ImagePcrs {
        ImagePcrs(BTreeMap::from([(
            "cos".to_string(),
            ImagePcr {
                first_seen: Utc::now(),
                pcrs: vec![
                    Pcr {
                        id: 0,
                        value: "pcr0_val".to_string(),
                        parts: vec![],
                    },
                    Pcr {
                        id: 1,
                        value: "pcr1_val".to_string(),
                        parts: vec![],
                    },
                ],
            },
        )]))
    }

    fn dummy_pcrs_map() -> ConfigMap {
        let data = BTreeMap::from([(
            PCR_CONFIG_FILE.to_string(),
            serde_json::to_string(&dummy_pcrs()).unwrap(),
        )]);
        ConfigMap {
            data: Some(data),
            ..Default::default()
        }
    }

    #[test]
    fn test_get_image_pcrs_success() {
        let config_map = dummy_pcrs_map();
        let image_pcrs = get_image_pcrs(config_map).unwrap();
        assert_eq!(image_pcrs.0["cos"].pcrs.len(), 2);
        assert_eq!(image_pcrs.0["cos"].pcrs[0].value, "pcr0_val");
    }

    #[test]
    fn test_get_image_pcrs_no_data() {
        let config_map = ConfigMap::default();
        let err = get_image_pcrs(config_map).err().unwrap();
        assert!(err.to_string().contains("but had no data"));
    }

    #[test]
    fn test_get_image_pcrs_no_file() {
        let config_map = ConfigMap {
            data: Some(BTreeMap::new()),
            ..Default::default()
        };
        let err = get_image_pcrs(config_map).err().unwrap();
        assert!(err.to_string().contains("but had no file"));
    }

    #[test]
    fn test_get_image_pcrs_invalid_json() {
        let data = BTreeMap::from([(PCR_CONFIG_FILE.to_string(), "not json".to_string())]);
        let config_map = ConfigMap {
            data: Some(data),
            ..Default::default()
        };
        assert!(get_image_pcrs(config_map).is_err());
    }

    #[test]
    fn test_recompute_reference_values() {
        let result = recompute_reference_values(dummy_pcrs());
        assert_eq!(result.len(), 3);
        let rv = result.iter().find(|rv| rv.name == "tpm_pcr0").unwrap();
        let val_arr = rv.value.as_array().unwrap();
        let vals: Vec<_> = val_arr.iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(vals, vec!["pcr0_val".to_string()]);
    }

    fn generate_rv_ctx(client: Client) -> RvContextData {
        RvContextData {
            client,
            owner_reference: Default::default(),
            pcrs_compute_image: String::new(),
        }
    }

    #[tokio::test]
    async fn test_update_rvs_success() {
        let clos = |req: &Option<Request<_>>| match req {
            Some(r) if r.uri().path().contains(PCR_CONFIG_MAP) => Ok(dummy_pcrs_map()),
            _ => Ok(ConfigMap {
                data: Some(BTreeMap::from([(
                    REFERENCE_VALUES_FILE.to_string(),
                    "[]".to_string(),
                )])),
                ..Default::default()
            }),
        };
        let ctx = generate_rv_ctx(MockClient::new(clos, "test".to_string()).into_client());
        assert!(update_reference_values(ctx).await.is_ok());
    }

    #[tokio::test]
    async fn test_update_rvs_no_pcr_map() {
        let clos = |req: &Option<Request<_>>| match req {
            Some(r) if r.uri().path().contains(PCR_CONFIG_MAP) && r.method() == Method::GET => {
                Err::<ConfigMap, _>(StatusCode::NOT_FOUND)
            }
            None => Ok(ConfigMap::default()),
            _ => panic!("unexpected API interaction: {req:?}"),
        };
        let ctx = generate_rv_ctx(MockClient::new(clos, "test".to_string()).into_client());
        assert!(update_reference_values(ctx).await.is_err())
    }

    #[tokio::test]
    async fn test_update_rvs_no_trustee_map() {
        let clos = |req: &Option<Request<_>>| match req {
            Some(r) if r.uri().path().contains(PCR_CONFIG_MAP) => Ok(dummy_pcrs_map()),
            Some(r) if r.uri().path().contains(TRUSTEE_DATA_MAP) && r.method() == Method::GET => {
                Err::<ConfigMap, _>(StatusCode::NOT_FOUND)
            }
            None => Ok(ConfigMap::default()),
            _ => panic!("unexpected API interaction: {req:?}"),
        };
        let ctx = generate_rv_ctx(MockClient::new(clos, "test".to_string()).into_client());
        assert!(update_reference_values(ctx).await.is_err())
    }

    #[tokio::test]
    async fn test_update_rvs_no_trustee_data() {
        let clos = |req: &Option<Request<_>>| match req {
            Some(r) if r.uri().path().contains(PCR_CONFIG_MAP) => Ok(dummy_pcrs_map()),
            _ => Ok(ConfigMap::default()),
        };
        let ctx = generate_rv_ctx(MockClient::new(clos, "test".to_string()).into_client());
        let err = update_reference_values(ctx).await.err().unwrap();
        assert!(err.to_string().contains("but had no data"));
    }

    #[tokio::test]
    async fn test_update_rvs_no_file() {
        let clos = |req: &Option<Request<_>>| match req {
            Some(r) if r.uri().path().contains(PCR_CONFIG_MAP) => Ok(dummy_pcrs_map()),
            _ => Ok(ConfigMap {
                data: Some(BTreeMap::new()),
                ..Default::default()
            }),
        };
        let ctx = generate_rv_ctx(MockClient::new(clos, "test".to_string()).into_client());
        let err = update_reference_values(ctx).await.err().unwrap();
        assert!(err.to_string().contains("but had no reference values"));
    }

    #[test]
    fn test_generate_luks_key_returns_correct_size() {
        let jwk: ClevisKey = serde_json::from_slice(&generate_luks_key().unwrap()).unwrap();
        assert_eq!(jwk.key.len(), 32);
    }

    fn dummy_deployment() -> Deployment {
        Deployment {
            spec: Some(DeploymentSpec {
                replicas: Some(1),
                template: PodTemplateSpec {
                    spec: Some(PodSpec {
                        containers: vec![Container::default()],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_mount_secret_success() {
        let clos = |_: &_| Ok(dummy_deployment());
        let client = MockClient::new(clos, "test".to_string()).into_client();
        assert!(mount_secret(client, "id").await.is_ok());
    }

    #[tokio::test]
    async fn test_mount_secret_no_depl() {
        let clos = |req: &Option<Request<_>>| match req {
            Some(r) if r.uri().path().contains(DEPLOYMENT_NAME) && r.method() == Method::GET => {
                Err::<Deployment, _>(StatusCode::NOT_FOUND)
            }
            None => Ok(Deployment::default()),
            _ => panic!("unexpected API interaction: {req:?}"),
        };
        let client = MockClient::new(clos, "test".to_string()).into_client();
        assert!(mount_secret(client, "id").await.is_err());
    }

    #[tokio::test]
    async fn test_mount_secret_no_spec() {
        let mut depl = dummy_deployment();
        depl.spec = None;
        let client = MockClient::new(move |_| Ok(depl.clone()), "test".to_string()).into_client();
        let err = mount_secret(client, "id").await.err().unwrap();
        assert!(err.to_string().contains("but had no spec"));
    }

    #[tokio::test]
    async fn test_mount_secret_no_pod_spec() {
        let mut depl = dummy_deployment();
        let spec = depl.spec.as_mut().unwrap();
        spec.template.spec = None;
        let client = MockClient::new(move |_| Ok(depl.clone()), "test".to_string()).into_client();
        let err = mount_secret(client, "id").await.err().unwrap();
        assert!(err.to_string().contains("but had no pod spec"));
    }

    #[tokio::test]
    async fn test_mount_secret_no_containers() {
        let mut depl = dummy_deployment();
        let spec = depl.spec.as_mut().unwrap();
        let pod_spec = spec.template.spec.as_mut().unwrap();
        pod_spec.containers = vec![];
        let client = MockClient::new(move |_| Ok(depl.clone()), "test".to_string()).into_client();
        let err = mount_secret(client, "id").await.err().unwrap();
        assert!(err.to_string().contains("but had no containers"));
    }

    async fn test_create_success<
        F: Fn(Client) -> S,
        S: Future<Output = Result<()>>,
        T: Clone + Default + Send + Serialize + for<'de> Deserialize<'de> + 'static,
    >(
        create: F,
    ) {
        let clos = |_: &_| Ok(T::default());
        let client = MockClient::new(clos, "test".to_string()).into_client();
        assert!(create(client).await.is_ok());
    }

    async fn test_create_already_exists<
        F: Fn(Client) -> S,
        S: Future<Output = Result<()>>,
        T: Clone + Default + Send + Serialize + for<'de> Deserialize<'de> + 'static,
    >(
        create: F,
    ) {
        let clos = |req: &Option<Request<_>>| match req {
            Some(r) if r.method() == Method::POST => Err::<T, _>(StatusCode::CONFLICT),
            None => Ok(T::default()),
            _ => panic!("unexpected API interaction: {req:?}"),
        };
        let client = MockClient::new(clos, "test".to_string()).into_client();
        assert!(create(client).await.is_ok());
    }

    async fn test_replace<
        F: Fn(Client) -> S,
        S: Future<Output = Result<()>>,
        T: Clone + Default + Send + Serialize + for<'de> Deserialize<'de> + 'static,
    >(
        create: F,
    ) {
        let clos = |req: &Option<Request<_>>| match req {
            Some(r) if r.method() == Method::POST => Err::<T, _>(StatusCode::CONFLICT),
            Some(r) if [Method::GET, Method::PUT].contains(r.method()) => Ok(T::default()),
            None => Ok(T::default()),
            _ => panic!("unexpected API interaction: {req:?}"),
        };
        let client = MockClient::new(clos, "test".to_string()).into_client();
        assert!(create(client).await.is_ok());
    }

    async fn test_create_error<
        F: Fn(Client) -> S,
        S: Future<Output = Result<()>>,
        T: Clone + Default + Send + Serialize + for<'de> Deserialize<'de> + 'static,
    >(
        create: F,
    ) {
        let clos = |req: &Option<Request<_>>| match req {
            Some(r) if r.method() == Method::POST => Err::<T, _>(StatusCode::INTERNAL_SERVER_ERROR),
            None => Ok(T::default()),
            _ => panic!("unexpected API interaction: {req:?}"),
        };
        let client = MockClient::new(clos, "test".to_string()).into_client();
        let err = create(client).await.unwrap_err();
        let msg = "internal server error";
        assert_kube_api_error!(err, 500, "ServerTimeout", msg, "Failure");
    }

    #[tokio::test]
    async fn test_generate_att_policy_success() {
        let clos = |client| generate_attestation_policy(client, Default::default());
        test_create_success::<_, _, ConfigMap>(clos).await;
    }

    #[tokio::test]
    async fn test_generate_att_policy_already_exists() {
        let clos = |client| generate_attestation_policy(client, Default::default());
        test_create_already_exists::<_, _, ConfigMap>(clos).await;
    }

    #[tokio::test]
    async fn test_generate_att_policy_error() {
        let clos = |client| generate_attestation_policy(client, Default::default());
        test_create_error::<_, _, ConfigMap>(clos).await;
    }

    #[tokio::test]
    async fn test_generate_secret_success() {
        let clos = |client| generate_secret(client, "id");
        test_create_success::<_, _, Secret>(clos).await;
    }

    #[tokio::test]
    async fn test_generate_secret_already_exists() {
        let clos = |client| generate_secret(client, "id");
        test_create_already_exists::<_, _, Secret>(clos).await;
    }

    #[tokio::test]
    async fn test_generate_secret_error() {
        let clos = |client| generate_secret(client, "id");
        test_create_error::<_, _, Secret>(clos).await;
    }

    #[tokio::test]
    async fn test_generate_trustee_data_success() {
        let clos = |client| generate_trustee_data(client, Default::default());
        test_create_success::<_, _, ConfigMap>(clos).await;
    }

    #[tokio::test]
    async fn test_generate_trustee_data_already_exists() {
        let clos = |client| generate_trustee_data(client, Default::default());
        test_create_already_exists::<_, _, ConfigMap>(clos).await;
    }

    #[tokio::test]
    async fn test_generate_trustee_data_error() {
        let clos = |client| generate_trustee_data(client, Default::default());
        test_create_error::<_, _, ConfigMap>(clos).await;
    }

    #[tokio::test]
    async fn test_generate_kbs_service_success() {
        let clos = |client| generate_kbs_service(client, Default::default(), None);
        test_create_success::<_, _, Service>(clos).await;
    }

    #[tokio::test]
    async fn test_generate_kbs_service_replace() {
        let clos = |client| generate_kbs_service(client, Default::default(), None);
        test_replace::<_, _, Service>(clos).await;
    }

    #[tokio::test]
    async fn test_generate_kbs_service_error() {
        let clos = |client| generate_kbs_service(client, Default::default(), None);
        test_create_error::<_, _, Service>(clos).await;
    }

    #[tokio::test]
    async fn test_generate_kbs_depl_success() {
        let clos = |client| generate_kbs_deployment(client, Default::default(), "image");
        test_create_success::<_, _, Deployment>(clos).await;
    }

    #[tokio::test]
    async fn test_generate_kbs_depl_replace() {
        let clos = |client| generate_kbs_deployment(client, Default::default(), "image");
        test_replace::<_, _, Deployment>(clos).await;
    }

    #[tokio::test]
    async fn test_generate_kbs_depl_error() {
        let clos = |client| generate_kbs_deployment(client, Default::default(), "image");
        test_create_error::<_, _, Deployment>(clos).await;
    }
}
