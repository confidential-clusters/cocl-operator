use anyhow::anyhow;
use base64::{Engine as _, engine::general_purpose};
use crds::{KbsConfig, KbsConfigSpec, Trustee};
use json_patch::{AddOperation, PatchOperation, TestOperation};
use k8s_openapi::api::core::v1::{ConfigMap, Secret};
use kube::api::{Patch, PatchParams, PostParams};
use kube::{Api, Client, Error};
use log::info;
use openssl::pkey::PKey;
use std::collections::BTreeMap;
use std::fs;

use crate::reference_values::ReferenceValue;

const HTTPS_KEY: &str = "kbs-https-key";
const HTTPS_CERT: &str = "kbs-https-certificate";

macro_rules! info_if_exists {
    ($result:ident, $resource_type:literal, $resource_name:expr) => {
        match $result {
            Ok(_) => info!("Create {} {}", $resource_type, $resource_name),
            Err(Error::Api(ae)) if ae.code == 409 => {
                info!("{} {} already exists", $resource_type, $resource_name)
            }
            Err(e) => return Err(e.into()),
        }
    };
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

pub async fn generate_reference_values(
    client: Client,
    namespace: &str,
    name: &str,
) -> anyhow::Result<()> {
    let reference_values_in_json = include_str!("reference-values-in.json");
    let mut reference_values_in = match serde_json::from_str(reference_values_in_json)? {
        serde_json::Value::Object(vals) => vals,
        _ => return Err(anyhow!("Reference values had unexpected shape")),
    };
    reference_values_in.insert(
        "svn".to_string(),
        serde_json::Value::String("1".to_string()),
    );
    let reference_values = reference_values_in
        .iter()
        .map(|(name, value)| {
            if let serde_json::Value::String(hex) = value
                && hex.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
            {
                Ok(ReferenceValue {
                    version: "0.1.0".to_string(),
                    name: format!("tpm_{name}"),
                    expiration: chrono::DateTime::<chrono::Utc>::MAX_UTC,
                    value: serde_json::Value::Array(vec![value.clone()]),
                })
            } else {
                Err(anyhow!("Reference value '{value}' had unexpected shape"))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let reference_values_json = serde_json::to_string(&reference_values)?;

    let mut data = BTreeMap::new();
    data.insert(
        "reference-values.json".to_string(),
        reference_values_json.to_string(),
    );

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

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use hyper::http;
    use kube::client::Body;
    use serde_json::json;
    use tower::ServiceBuilder;
    use tower_test::mock;

    #[tokio::test]
    async fn test_generate_kbs_auth_public_key_creates_secret() {
        // 1. Setup the mock K8s API server
        let (mock_service, mut handle) = mock::pair::<http::Request<Body>, http::Response<Body>>();
        let service = ServiceBuilder::new().service(mock_service);
        let client = Client::new(service, "default");

        // 2. Define the expected API call and the response in a separate task
        let handle = tokio::spawn(async move {
            // Expect a single request to create a Secret
            let (request, send) = handle
                .next_request()
                .await
                .expect("service received a request");

            // Assertions on the request
            assert_eq!(request.method(), "POST");
            assert_eq!(
                request.uri().path(),
                "/api/v1/namespaces/test-namespace/secrets"
            );

            // Extract and deserialize the body to check its content
            let body_bytes = request.into_body().collect().await.unwrap().to_bytes();
            let secret: Secret = serde_json::from_slice(&body_bytes).unwrap();
            assert_eq!(secret.metadata.name.as_deref(), Some("test-secret-name"));

            // Check that the publicKey field exists and is not empty
            let data = secret.data.unwrap();
            let public_key_b64 = data.get("publicKey").unwrap();
            assert!(!public_key_b64.0.is_empty());

            // Send back a successful response
            let response_secret = json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": "test-secret-name",
                    "namespace": "test-namespace"
                }
            });
            let response = http::Response::builder()
                .status(201)
                .body(Body::from(response_secret.to_string().into_bytes()))
                .unwrap();
            send.send_response(response);
        });

        // 3. Call the function under test
        let result =
            generate_kbs_auth_public_key(client, "test-namespace", "test-secret-name").await;

        // 4. Assert the function's result
        assert!(result.is_ok());

        // Wait for the mock server task to finish its assertions
        handle.await.unwrap();

        // 5. Cleanup filesystem side effects
        let _ = fs::remove_file("privateKey");
        let _ = fs::remove_file("publicKey");
    }
}
