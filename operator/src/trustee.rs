// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::Context;
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, TimeDelta, Utc};
use json_patch::{AddOperation, PatchOperation, TestOperation};
use k8s_openapi::api::core::v1::{ConfigMap, Secret};
use kube::api::{ObjectMeta, Patch, PatchParams, PostParams};
use kube::{Api, Client};
use log::info;
use openssl::pkey::PKey;
use serde::{Serialize, Serializer};
use std::{collections::BTreeMap, fs};

use crds::{KbsConfig, KbsConfigSpec, Trustee};
use rv_store::*;

const HTTPS_KEY: &str = "kbs-https-key";
const HTTPS_CERT: &str = "kbs-https-certificate";
const REFERENCE_VALUES_FILE: &str = "reference-values.json";

#[derive(Clone)]
pub struct RvContextData {
    pub client: Client,
    pub operator_namespace: String,
    pub trustee_namespace: String,
    pub pcrs_compute_image: String,
    pub rv_map: String,
}

/// Sync with clevis-pin-trustee::Key
#[derive(Serialize)]
struct ClevisKey {
    key_type: String,
    key: String,
}

macro_rules! info_if_exists {
    ($result:ident, $resource_type:literal, $resource_name:expr) => {
        match $result {
            Ok(_) => info!("Create {} {}", $resource_type, $resource_name),
            Err(kube::Error::Api(ae)) if ae.code == 409 => {
                info!("{} {} already exists", $resource_type, $resource_name)
            }
            Err(e) => return Err(e.into()),
        }
    };
}
pub(crate) use info_if_exists;

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

pub fn get_image_pcrs(image_pcrs_map: ConfigMap) -> anyhow::Result<ImagePcrs> {
    let image_pcrs_data = image_pcrs_map
        .data
        .context("Image PCRs map existed, but had no data")?;
    let image_pcrs_str = image_pcrs_data
        .get(PCR_CONFIG_FILE)
        .context("Image PCRs data existed, but had no file")?;
    serde_json::from_str(image_pcrs_str).map_err(Into::into)
}

pub async fn generate_kbs_auth_public_key(
    client: Client,
    namespace: &str,
    secret_name: &str,
) -> anyhow::Result<()> {
    let keypair = PKey::generate_ed25519()?;

    let private_pem = keypair.private_key_to_pem_pkcs8()?;
    fs::write("privateKey", &private_pem)?;

    let public_key = keypair.public_key_to_pem()?;
    fs::write("publicKey", &public_key)?;

    let public_key_b64 = general_purpose::STANDARD.encode(&public_key);

    let mut data = BTreeMap::new();
    data.insert(
        "publicKey".to_string(),
        k8s_openapi::ByteString(public_key_b64.into()),
    );

    let secret = Secret {
        metadata: kube::api::ObjectMeta {
            name: Some(secret_name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    };

    let secrets: Api<Secret> = Api::namespaced(client, namespace);
    let create = secrets.create(&PostParams::default(), &secret).await;
    info_if_exists!(create, "Secret", secret_name);

    Ok(())
}

pub async fn generate_kbs_https_certificate(client: Client, namespace: &str) -> anyhow::Result<()> {
    let secrets: Api<Secret> = Api::namespaced(client, namespace);
    for (name, key) in [(HTTPS_KEY, "https.key"), (HTTPS_CERT, "https.crt")] {
        // Dummy secret, TODO actual authentication (#2)
        let map = BTreeMap::from([(
            key.to_string(),
            k8s_openapi::ByteString("Zm9vYmFyCg==".into()),
        )]);
        let secret = Secret {
            metadata: kube::api::ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            data: Some(map),
            ..Default::default()
        };
        let create = secrets.create(&PostParams::default(), &secret).await;
        info_if_exists!(create, "Secret", name);
    }

    Ok(())
}

pub async fn generate_kbs_configurations(
    client: Client,
    namespace: &str,
    trustee: &Trustee,
) -> anyhow::Result<()> {
    let config_maps: Api<ConfigMap> = Api::namespaced(client, namespace);

    let kbs_config = include_str!("kbs-config.toml");
    let data = BTreeMap::from([("kbs-config.toml".to_string(), kbs_config.to_string())]);
    let config_map = ConfigMap {
        metadata: kube::api::ObjectMeta {
            name: Some(trustee.kbs_configuration.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    };

    let create = config_maps
        .create(&PostParams::default(), &config_map)
        .await;
    info_if_exists!(create, "ConfigMap", &trustee.kbs_configuration);

    Ok(())
}

pub async fn recompute_reference_values(ctx: RvContextData) -> anyhow::Result<()> {
    let operator_config_maps: Api<ConfigMap> =
        Api::namespaced(ctx.client.clone(), &ctx.operator_namespace);
    let image_pcrs_map = operator_config_maps.get(PCR_CONFIG_MAP).await?;
    let image_pcrs = get_image_pcrs(image_pcrs_map)?;
    // TODO many grub+shim:many OS image recompute once supported
    let mut reference_values_in = BTreeMap::from([(
        "svn".to_string(),
        vec![serde_json::Value::String("1".to_string())],
    )]);
    for pcr in image_pcrs.0.values().flat_map(|v| &v.pcrs) {
        reference_values_in
            .entry(format!("pcr{}", pcr.id))
            .or_default()
            .push(serde_json::Value::String(pcr.value.clone()));
    }
    let reference_values: Vec<_> = reference_values_in
        .iter()
        .map(|(name, values)| ReferenceValue {
            version: "0.1.0".to_string(),
            name: format!("tpm_{name}"),
            expiration: Utc::now() + TimeDelta::days(365),
            value: serde_json::Value::Array(values.to_vec()),
        })
        .collect();
    let reference_values_json = serde_json::to_string(&reference_values)?;
    let data = BTreeMap::from([(
        REFERENCE_VALUES_FILE.to_string(),
        reference_values_json.to_string(),
    )]);

    let trustee_config_maps: Api<ConfigMap> = Api::namespaced(ctx.client, &ctx.trustee_namespace);
    let mut rvs = trustee_config_maps.get(&ctx.rv_map).await?;
    rvs.data = Some(data);
    trustee_config_maps
        .replace(&ctx.rv_map, &PostParams::default(), &rvs)
        .await?;
    Ok(())
}

pub async fn create_reference_value_config_map(
    client: Client,
    namespace: &str,
    name: &str,
) -> anyhow::Result<()> {
    let empty_data = BTreeMap::from([(REFERENCE_VALUES_FILE.to_string(), "{}".to_string())]);
    let config_maps: Api<ConfigMap> = Api::namespaced(client, namespace);
    let config_map = ConfigMap {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        data: Some(empty_data),
        ..Default::default()
    };
    let create = config_maps
        .create(&PostParams::default(), &config_map)
        .await;
    info_if_exists!(create, "ConfigMap", name);

    Ok(())
}

fn generate_luks_key() -> anyhow::Result<Vec<u8>> {
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

pub async fn generate_secret(
    client: Client,
    namespace: &str,
    kbs_config_name: &str,
    id: &str,
) -> anyhow::Result<()> {
    let key = generate_luks_key()?;
    let secret_data = k8s_openapi::ByteString(key);
    let data = BTreeMap::from([("root".to_string(), secret_data)]);

    let secret = Secret {
        metadata: kube::api::ObjectMeta {
            name: Some(id.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    };

    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let create = secrets.create(&PostParams::default(), &secret).await;
    info_if_exists!(create, "Secret", id);

    let kbs_configs: Api<KbsConfig> = Api::namespaced(client, namespace);

    let existing_secrets = kbs_configs
        .get(kbs_config_name)
        .await?
        .spec
        .kbs_secret_resources;
    if existing_secrets.iter().any(|s| s == id) {
        info!("Secret with ID {id} already present");
        return Ok(());
    }

    let path = jsonptr::PointerBuf::parse("/spec/kbsSecretResources")?;
    let expected_secrets = existing_secrets
        .iter()
        .map(|s| serde_json::Value::String(s.clone()))
        .collect();
    let test_patch = PatchOperation::Test(TestOperation {
        path: path.clone(),
        value: serde_json::Value::Array(expected_secrets),
    });

    let value = serde_json::Value::String(id.to_string());
    let add_patch = PatchOperation::Add(AddOperation {
        path,
        value: serde_json::Value::Array(vec![value]),
    });

    let json_patch = json_patch::Patch(vec![test_patch, add_patch]);
    let patch: Patch<KbsConfig> = Patch::Json(json_patch);
    let params = PatchParams::default();

    kbs_configs.patch(kbs_config_name, &params, &patch).await?;
    info!("Added secret {id} to {kbs_config_name}");

    Ok(())
}

pub async fn generate_resource_policy(
    client: Client,
    namespace: &str,
    name: &str,
) -> anyhow::Result<()> {
    let policy_rego = include_str!("resource.rego");
    let mut data = BTreeMap::new();
    data.insert("policy.rego".to_string(), policy_rego.to_string());

    let config_map = ConfigMap {
        metadata: kube::api::ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    };

    let config_maps: Api<ConfigMap> = Api::namespaced(client, namespace);
    let create = config_maps
        .create(&PostParams::default(), &config_map)
        .await;
    info_if_exists!(create, "ConfigMap", name);

    Ok(())
}

pub async fn generate_attestation_policy(
    client: Client,
    namespace: &str,
    name: &str,
) -> anyhow::Result<()> {
    let policy_rego = include_str!("tpm.rego");
    let data = BTreeMap::from([
        ("default_cpu.rego".to_string(), policy_rego.to_string()),
        // TODO may be able to remove after resolution of
        // https://github.com/confidential-containers/trustee-operator/issues/100
        // (see also #issuecomment-3299368068)
        ("default_gpu.rego".to_string(), String::new()),
    ]);

    let config_map = ConfigMap {
        metadata: kube::api::ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    };

    let config_maps: Api<ConfigMap> = Api::namespaced(client, namespace);
    let create = config_maps
        .create(&PostParams::default(), &config_map)
        .await;
    info_if_exists!(create, "ConfigMap", name);

    Ok(())
}

pub async fn generate_kbs(
    client: Client,
    namespace: &str,
    trustee: &Trustee,
) -> anyhow::Result<()> {
    let labels = BTreeMap::from([
        (
            "app.kubernetes.io/name".to_string(),
            "kbsconfig".to_string(),
        ),
        (
            "app.kubernetes.io/instance".to_string(),
            "kbsconfig-sample".to_string(),
        ),
        (
            "app.kubernetes.io/part-of".to_string(),
            "kbs-operator".to_string(),
        ),
        (
            "app.kubernetes.io/managed-by".to_string(),
            "kustomize".to_string(),
        ),
        (
            "app.kubernetes.io/created-by".to_string(),
            "kbs-operator".to_string(),
        ),
    ]);

    let kbs_config = KbsConfig {
        metadata: kube::api::ObjectMeta {
            name: Some(trustee.kbs_config_name.clone()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        spec: KbsConfigSpec {
            kbs_config_map_name: trustee.kbs_configuration.clone(),
            kbs_auth_secret_name: trustee.kbs_auth_key.clone(),
            kbs_deployment_type: "AllInOneDeployment".to_string(),
            kbs_rvps_ref_values_config_map_name: trustee.reference_values.clone(),
            kbs_secret_resources: vec![],
            kbs_https_key_secret_name: HTTPS_KEY.to_string(),
            kbs_https_cert_secret_name: HTTPS_CERT.to_string(),
            kbs_resource_policy_config_map_name: trustee.resource_policy.clone(),
            kbs_attestation_policy_config_map_name: trustee.attestation_policy.clone(),
        },
    };

    let kbs_configs: Api<KbsConfig> = Api::namespaced(client, namespace);
    let create = kbs_configs
        .create(&PostParams::default(), &kbs_config)
        .await;
    info_if_exists!(create, "KbsConfig", &trustee.kbs_config_name);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use compute_pcrs_lib::Pcr;
    use http::{Method, Request, Response, StatusCode};
    use kube::client::Body;
    use kube::error::ErrorResponse;
    use rv_store::{ImagePcr, ImagePcrs};
    use std::collections::BTreeMap;
    use std::convert::Infallible;
    use std::sync::{Arc, Mutex};
    use tower::service_fn;

    /// A helper struct to ensure temporary files are cleaned up after a test.
    /// It deletes the specified files when it goes out of scope.
    struct FileCleanup {
        paths: Vec<String>,
    }

    impl Drop for FileCleanup {
        fn drop(&mut self) {
            for path in &self.paths {
                // .ok() ignores errors if the file doesn't exist, preventing panics in cleanup.
                std::fs::remove_file(path).ok();
            }
        }
    }

    #[derive(Clone)]
    struct CapturingMockClient {
        requests: Arc<Mutex<Vec<Request<Body>>>>,
        response_queue: Arc<Mutex<Vec<Response<Body>>>>,
    }

    impl CapturingMockClient {
        fn new(responses: Vec<Response<Body>>) -> Self {
            Self {
                requests: Arc::new(Mutex::new(vec![])),
                response_queue: Arc::new(Mutex::new(responses.into_iter().rev().collect())),
            }
        }

        fn into_client(self, namespace: &str) -> Client {
            let svc = service_fn(move |req: Request<Body>| {
                self.requests.lock().unwrap().push(req);
                let response = self
                    .response_queue
                    .lock()
                    .unwrap()
                    .pop()
                    .unwrap_or_else(|| {
                        Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Body::from(
                                "Mock client ran out of responses".to_string().into_bytes(),
                            ))
                            .unwrap()
                    });
                async move { Ok::<_, Infallible>(response) }
            });
            Client::new(svc, namespace)
        }
    }

    fn ok_response<T: Serialize>(body: &T) -> Response<Body> {
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::from(
                serde_json::to_string(body).unwrap().into_bytes(),
            ))
            .unwrap()
    }

    fn created_response<T: Serialize>(body: &T) -> Response<Body> {
        Response::builder()
            .status(StatusCode::CREATED)
            .body(Body::from(
                serde_json::to_string(body).unwrap().into_bytes(),
            ))
            .unwrap()
    }

    fn error_response(status_code: StatusCode, reason: &str, message: &str) -> Response<Body> {
        let error = ErrorResponse {
            status: "Failure".to_string(),
            message: message.to_string(),
            reason: reason.to_string(),
            code: status_code.as_u16(),
        };
        Response::builder()
            .status(status_code)
            .body(Body::from(
                serde_json::to_string(&error).unwrap().into_bytes(),
            ))
            .unwrap()
    }

    fn empty_kbs_config(name: &str) -> KbsConfig {
        KbsConfig::new(
            name,
            KbsConfigSpec {
                kbs_config_map_name: String::new(),
                kbs_auth_secret_name: String::new(),
                kbs_deployment_type: String::new(),
                kbs_rvps_ref_values_config_map_name: String::new(),
                kbs_secret_resources: vec![],
                kbs_https_key_secret_name: String::new(),
                kbs_https_cert_secret_name: String::new(),
                kbs_resource_policy_config_map_name: String::new(),
                kbs_attestation_policy_config_map_name: String::new(),
            },
        )
    }

    #[test]
    fn test_get_image_pcrs_success() {
        let mut data = BTreeMap::new();
        let image_pcrs = ImagePcrs(BTreeMap::from([(
            "cos".to_string(),
            ImagePcr {
                first_seen: "2023-01-01T00:00:00Z".parse().unwrap(),
                pcrs: vec![Pcr {
                    id: 0,
                    value: "pcr0_val".to_string(),
                    parts: vec![],
                }],
            },
        )]));
        let pcrs_json = serde_json::to_string(&image_pcrs).unwrap();
        data.insert(PCR_CONFIG_FILE.to_string(), pcrs_json);
        let config_map = ConfigMap {
            data: Some(data),
            ..Default::default()
        };

        let result = get_image_pcrs(config_map);
        assert!(result.is_ok());
        let pcrs = result.unwrap();
        assert_eq!(pcrs.0.get("cos").unwrap().pcrs[0].value, "pcr0_val");
    }

    #[test]
    fn test_get_image_pcrs_no_data() {
        let config_map = ConfigMap::default();
        let result = get_image_pcrs(config_map);
        assert!(result.is_err());
        match result {
            Ok(_) => panic!("Expected error, got Ok"),
            Err(e) => assert!(
                e.to_string()
                    .contains("Image PCRs map existed, but had no data")
            ),
        }
    }

    #[test]
    fn test_get_image_pcrs_invalid_json() {
        let mut data = BTreeMap::new();
        data.insert(PCR_CONFIG_FILE.to_string(), "this is not json".to_string());
        let config_map = ConfigMap {
            data: Some(data),
            ..Default::default()
        };
        let result = get_image_pcrs(config_map);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_luks_key_returns_correct_size() {
        let result = generate_luks_key().unwrap();
        let jwk: serde_json::Value = serde_json::from_slice(&result).unwrap();
        let key = jwk.get("key").and_then(|v| v.as_str()).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[tokio::test]
    async fn test_create_resource_idempotency() {
        let created_cm = ConfigMap::default();
        let mock_client = CapturingMockClient::new(vec![
            created_response(&created_cm),
            error_response(
                StatusCode::CONFLICT,
                "AlreadyExists",
                "configmap already exists",
            ),
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ServerTimeout",
                "internal server error",
            ),
        ]);
        let client = mock_client.clone().into_client("test-ns");

        let result1 =
            create_reference_value_config_map(client.clone(), "test-ns", "test-rv-map").await;
        assert!(result1.is_ok());

        let result2 =
            create_reference_value_config_map(client.clone(), "test-ns", "test-rv-map").await;
        assert!(result2.is_ok());

        let result3 =
            create_reference_value_config_map(client.clone(), "test-ns", "test-rv-map").await;
        assert!(result3.is_err());
    }

    #[tokio::test]
    async fn test_generate_kbs_auth_public_key_success() {
        // Ensure files are cleaned up even if the test panics.
        let _cleanup = FileCleanup {
            paths: vec!["privateKey".to_string(), "publicKey".to_string()],
        };

        let mock_client = CapturingMockClient::new(vec![created_response(&Secret::default())]);
        let client = mock_client.clone().into_client("test-ns");

        let result = generate_kbs_auth_public_key(client, "test-ns", "test-auth-key-secret").await;
        assert!(result.is_ok());

        let requests = mock_client.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let req = &requests[0];
        assert_eq!(req.method(), Method::POST);
        assert_eq!(req.uri().path(), "/api/v1/namespaces/test-ns/secrets");
    }

    #[tokio::test]
    async fn test_recompute_reference_values_flow() {
        let pcr_cm = ConfigMap {
            data: Some(BTreeMap::from([(
                PCR_CONFIG_FILE.to_string(),
                serde_json::to_string(&ImagePcrs(BTreeMap::from([(
                    "cos".to_string(),
                    ImagePcr {
                        first_seen: Utc::now(),
                        pcrs: vec![Pcr {
                            id: 0,
                            value: "pcr0_val".to_string(),
                            parts: vec![],
                        }],
                    },
                )])))
                .unwrap(),
            )])),
            ..Default::default()
        };
        let rv_cm = ConfigMap::default();

        let mock_client = CapturingMockClient::new(vec![
            ok_response(&pcr_cm),
            ok_response(&rv_cm),
            ok_response(&rv_cm),
        ]);
        let client = mock_client.clone().into_client("op-ns");

        let ctx = RvContextData {
            client,
            operator_namespace: "op-ns".to_string(),
            trustee_namespace: "trustee-ns".to_string(),
            pcrs_compute_image: "".to_string(),
            rv_map: "test-rv-map".to_string(),
        };

        let result = recompute_reference_values(ctx).await;
        assert!(result.is_ok());

        let requests = mock_client.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].method(), Method::GET);
        assert!(requests[0].uri().path().contains(PCR_CONFIG_MAP));
        assert_eq!(requests[1].method(), Method::GET);
        assert!(requests[1].uri().path().contains("test-rv-map"));
        assert_eq!(requests[2].method(), Method::PUT);
        assert!(requests[2].uri().path().contains("test-rv-map"));
    }

    #[tokio::test]
    async fn test_generate_secret_flow_with_patch() {
        let kbs_config_before_patch = empty_kbs_config("test-kbs-config");
        let mock_client = CapturingMockClient::new(vec![
            created_response(&Secret::default()),
            ok_response(&kbs_config_before_patch),
            ok_response(&empty_kbs_config("test-kbs-config")),
        ]);
        let client = mock_client.clone().into_client("test-ns");

        let result = generate_secret(client, "test-ns", "test-kbs-config", "new-secret-id").await;
        assert!(result.is_ok());

        let requests = mock_client.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].method(), Method::POST);
        assert_eq!(requests[1].method(), Method::GET);
        assert_eq!(requests[2].method(), Method::PATCH);
        assert!(requests[2].uri().path().contains("test-kbs-config"));
    }

    #[tokio::test]
    async fn test_generate_secret_already_present_in_spec() {
        let mut kbs_config_with_secret = empty_kbs_config("test-kbs-config");
        kbs_config_with_secret.spec.kbs_secret_resources = vec!["existing-secret".to_string()];

        let mock_client = CapturingMockClient::new(vec![
            created_response(&Secret::default()),
            ok_response(&kbs_config_with_secret),
        ]);
        let client = mock_client.clone().into_client("test-ns");

        let result = generate_secret(client, "test-ns", "test-kbs-config", "existing-secret").await;
        assert!(result.is_ok());

        let requests = mock_client.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
    }
}
