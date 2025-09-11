use base64::{Engine as _, engine::general_purpose};
use crds::{KbsConfig, KbsConfigSpec, Trustee};
use futures_util::StreamExt;
use json_patch::{AddOperation, PatchOperation, TestOperation};
use k8s_openapi::api::{
    batch::v1::{Job, JobSpec},
    core::v1::{
        ConfigMap, Container, ImageVolumeSource, PodSpec, PodTemplateSpec, Secret, Volume,
        VolumeMount,
    },
};
use kube::api::{DeleteParams, ObjectMeta, Patch, PatchParams, PostParams};
use kube::runtime::{
    controller::{Action, Controller},
    watcher,
};
use kube::{Api, Client};
use log::info;
use openssl::pkey::PKey;
use std::{collections::BTreeMap, fs, path::PathBuf, sync::Arc, time::Duration};
use thiserror::Error;

#[derive(Debug, Error)]
enum Error {}

#[derive(Clone)]
struct ContextData {
    #[allow(dead_code)]
    client: Client,
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

const BOOT_IMAGE: &str = "quay.io/fedora/fedora-coreos:42.20250705.3.0";

const HTTPS_KEY: &str = "kbs-https-key";
const HTTPS_CERT: &str = "kbs-https-certificate";

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
    let as_config = include_str!("as-config.json");
    let rvps_config = include_str!("rvps-config.json");

    for (filename, content, configmap) in [
        ("kbs-config.toml", kbs_config, &trustee.kbs_configuration),
        ("as-config.json", as_config, &trustee.as_configuration),
        ("rvps-config.json", rvps_config, &trustee.rvps_configuration),
    ] {
        let data = BTreeMap::from([(filename.to_string(), content.to_string())]);
        let config_map = ConfigMap {
            metadata: kube::api::ObjectMeta {
                name: Some(configmap.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            data: Some(data),
            ..Default::default()
        };

        let create = config_maps
            .create(&PostParams::default(), &config_map)
            .await;
        info_if_exists!(create, "ConfigMap", configmap);
    }

    Ok(())
}

async fn reconcile(job: Arc<Job>, ctx: Arc<ContextData>) -> Result<Action, Error> {
    if let Some(status) = &job.status
        && status.completion_time.is_some()
        && let Some(ns) = &job.metadata.namespace
        && let Some(name) = &job.metadata.name
    {
        let jobs: Api<Job> = Api::namespaced(ctx.client.clone(), ns);
        if jobs.delete(name, &DeleteParams::default()).await.is_ok() {
            return Ok(Action::await_change());
        }
    }
    Ok(Action::requeue(Duration::from_secs(300)))
}

fn error_policy(_obj: Arc<Job>, _error: &Error, _ctx: Arc<ContextData>) -> Action {
    Action::requeue(Duration::from_secs(60))
}

pub async fn launch_rv_job_controller(client: Client, namespace: &str) {
    let jobs: Api<Job> = Api::namespaced(client.clone(), namespace);
    let context = Arc::new(ContextData { client });
    // refine watcher if we handle more than one type of job
    tokio::spawn(
        Controller::new(jobs, watcher::Config::default())
            .run::<_, ContextData>(reconcile, error_policy, context)
            .for_each(|res| async move {
                match res {
                    Ok(o) => info!("reconciled {o:?}"),
                    Err(e) => info!("reconcile failed: {e:?}"),
                }
            }),
    );
}

pub async fn generate_reference_values(
    client: Client,
    job_namespace: &str,
    trustee_namespace: &str,
    name: &str,
    pcrs_compute_image: &str,
) -> anyhow::Result<()> {
    let job_name = "compute-pcrs";
    let volume_name = "image";
    let mountpoint = PathBuf::from("/image");

    let mut cmd = vec![job_name.to_string()];
    let mut add_flag = |flag: &str, value: &str| {
        cmd.push(format!("--{flag}"));
        cmd.push(value.to_string());
    };
    for (flag, path_suffix) in [
        ("kernels", "usr/lib/modules"),
        ("esp", "usr/lib/bootupd/updates"),
    ] {
        let full_path = mountpoint.join(path_suffix);
        add_flag(flag, full_path.to_str().unwrap());
    }
    for (flag, value) in [
        ("configmap", name),
        ("namespace", trustee_namespace),
        ("efivars", "/reference-values/efivars/qemu-ovmf/fedora-42"),
        ("mokvars", "/reference-values/mok-variables/fedora-42"),
    ] {
        add_flag(flag, value);
    }

    let pod_spec = PodSpec {
        service_account_name: Some("compute-pcrs".to_string()),
        containers: vec![Container {
            name: job_name.to_string(),
            image: Some(pcrs_compute_image.to_string()),
            command: Some(cmd),
            volume_mounts: Some(vec![VolumeMount {
                name: volume_name.to_string(),
                mount_path: mountpoint.to_str().unwrap().to_string(),
                ..Default::default()
            }]),
            ..Default::default()
        }],
        volumes: Some(vec![Volume {
            name: volume_name.to_string(),
            image: Some(ImageVolumeSource {
                reference: Some(BOOT_IMAGE.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        }]),
        restart_policy: Some("Never".to_string()),
        ..Default::default()
    };
    let job = Job {
        metadata: ObjectMeta {
            name: Some(job_name.to_string()),
            namespace: Some(job_namespace.to_string()),
            ..Default::default()
        },
        spec: Some(JobSpec {
            template: PodTemplateSpec {
                spec: Some(pod_spec),
                ..Default::default()
            },
            ..Default::default()
        }),
        ..Default::default()
    };

    let jobs: Api<Job> = Api::namespaced(client.clone(), job_namespace);
    let create = jobs.create(&PostParams::default(), &job).await;
    info_if_exists!(create, "Job", job_name);
    Ok(())
}

fn generate_luks_key() -> anyhow::Result<[u8; 32]> {
    let mut pass = [0; 32];
    openssl::rand::rand_bytes(&mut pass)?;
    Ok(pass)
}

pub async fn generate_secret(
    client: Client,
    namespace: &str,
    kbs_config_name: &str,
    id: &str,
) -> anyhow::Result<()> {
    let pass = generate_luks_key()?;
    let secret_data = k8s_openapi::ByteString(pass.to_vec());
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
    let mut data = BTreeMap::new();
    data.insert("default_cpu.rego".to_string(), policy_rego.to_string());

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
            kbs_as_config_map_name: trustee.as_configuration.clone(),
            kbs_rvps_config_map_name: trustee.rvps_configuration.clone(),
            kbs_auth_secret_name: trustee.kbs_auth_key.clone(),
            kbs_deployment_type: "MicroservicesDeployment".to_string(),
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
    info_if_exists!(create, "KbsConfig", trustee.kbs_config_name);

    Ok(())
}
