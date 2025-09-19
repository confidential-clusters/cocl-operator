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
#[derive(Serialize, serde::Deserialize)]
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
    // Import necessary items from external crates and parent modules
    use super::*;
    use crds::{KbsConfig, KbsConfigSpec, Trustee};
    use http::{Method, Request, Response, StatusCode};
    use k8s_openapi::api::core::v1::{ConfigMap, Secret};
    use kube::client::Body;
    use kube::error::ErrorResponse;
    use std::convert::Infallible;
    use tower::service_fn;

    // -----------------------------------------------------------------
    // Core helper functions for mocking the K8s API Server
    // -----------------------------------------------------------------

    /// A helper function to create a mock `kube::Client`.
    /// It accepts a preset HTTP status code and response body, and returns a client
    /// that always responds with this content. This is the cornerstone of our
    /// K8s API Server simulation.
    fn mock_client<T>(code: StatusCode, body: T) -> Client
    where
        T: Into<Body> + Clone + Send + 'static,
    {
        // `tower::service_fn` creates a lightweight service that takes a closure.
        // This closure is executed on every API call.
        let mock_svc = service_fn(move |_req: Request<Body>| {
            // We ignore the request content and always return the preset response.
            // body.clone() is used to allow the closure to be FnMut
            let response = Response::builder()
                .status(code)
                .body(body.clone().into())
                .unwrap();
            // An async block that returns a future
            async move { Ok::<_, Infallible>(response) }
        });

        // Create a fake Client with our mock service
        Client::new(mock_svc, "default")
    }

    // -----------------------------------------------------------------
    // Category 1: Pure Logic Functions
    // -----------------------------------------------------------------

    #[test]
    fn test_get_image_pcrs_success() {
        // 1. Prepare input data: a valid ConfigMap
        let mut data = BTreeMap::new();
        // THIS IS THE FIX: The JSON now includes all required fields for the `Os` struct.
        let pcrs_json = r#"{
            "cos": {
                "first_seen": "2023-01-01T00:00:00Z",
                "pcrs": [
                    {"id": 0, "value": "pcr0_val", "parts": []},
                    {"id": 1, "value": "pcr1_val", "parts": []}
                ]
            }
        }"#;
        data.insert(PCR_CONFIG_FILE.to_string(), pcrs_json.to_string());

        let config_map = ConfigMap {
            data: Some(data),
            ..Default::default()
        };

        // 2. Call the function under test
        let result = get_image_pcrs(config_map);

        // 3. Assert the result
        assert!(result.is_ok(), "get_image_pcrs failed: {:?}", result.err());
        let image_pcrs = result.unwrap();
        assert_eq!(image_pcrs.0["cos"].pcrs.len(), 2);
        assert_eq!(image_pcrs.0["cos"].pcrs[0].value, "pcr0_val");
    }

    #[test]
    fn test_get_image_pcrs_no_data() {
        // 1. Prepare a ConfigMap without a `data` field
        let config_map = ConfigMap::default();

        // 2. Call and assert
        let result = get_image_pcrs(config_map);
        assert!(result.is_err());
        // Check the error message content instead of using unwrap_err()
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("but had no data")
        );
    }

    #[test]
    fn test_get_image_pcrs_invalid_json() {
        // 1. Prepare a ConfigMap with invalid JSON
        let mut data = BTreeMap::new();
        data.insert(PCR_CONFIG_FILE.to_string(), "this is not json".to_string());
        let config_map = ConfigMap {
            data: Some(data),
            ..Default::default()
        };

        // 2. Call and assert
        let result = get_image_pcrs(config_map);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_luks_key_returns_correct_size() {
        let result = generate_luks_key();
        assert!(result.is_ok());
        let jwk: ClevisKey = serde_json::from_slice(&result.unwrap()).unwrap();
        assert_eq!(jwk.key.len(), 32);
    }

    // -----------------------------------------------------------------
    // Category 2: Functions Interacting with the Kubernetes API
    // -----------------------------------------------------------------

    // --- Tests for `create_reference_value_config_map` ---
    #[tokio::test]
    async fn test_create_rv_config_map_success() {
        // 1. Prepare mock response: K8s API usually returns 200 OK with the created object on success.
        let created_cm_json = serde_json::to_string(&ConfigMap {
            metadata: ObjectMeta {
                name: Some("test-rv-map".to_string()),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();

        // 2. Create the mock client
        let client = mock_client(StatusCode::OK, created_cm_json.into_bytes());

        // 3. Call the function under test
        let result = create_reference_value_config_map(client, "test-ns", "test-rv-map").await;

        // 4. Assert the result: We expect the function to complete successfully without any errors.
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_create_rv_config_map_already_exists() {
        // 1. Prepare the JSON body for a K8s API error response
        let error_response = ErrorResponse {
            status: "Failure".to_string(),
            message: "configmaps \"test-rv-map\" already exists".to_string(),
            reason: "AlreadyExists".to_string(),
            code: 409,
        };
        let error_body = serde_json::to_string(&error_response).unwrap();

        // 2. Create a mock client that returns 409 Conflict
        let client = mock_client(StatusCode::CONFLICT, error_body.into_bytes());

        // 3. Call the function under test
        let result = create_reference_value_config_map(client, "test-ns", "test-rv-map").await;

        // 4. Assert the result: Because the `info_if_exists!` macro catches the 409 error
        // and treats it as non-fatal, we expect the function to still return Ok(()).
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_create_rv_config_map_generic_error() {
        // 1. Prepare a response body for a 500 error
        let error_response = ErrorResponse {
            status: "Failure".to_string(),
            message: "internal server error".to_string(),
            reason: "ServerTimeout".to_string(),
            code: 500,
        };
        let error_body = serde_json::to_string(&error_response).unwrap();

        // 2. Create a mock client that returns 500 Internal Server Error
        let client = mock_client(StatusCode::INTERNAL_SERVER_ERROR, error_body.into_bytes());

        // 3. Call the function under test
        let result = create_reference_value_config_map(client, "test-ns", "test-rv-map").await;

        // 4. Assert the result: This time, we expect the function to return an error.
        assert!(result.is_err());
    }

    // --- Tests for other simple creation functions ---
    #[tokio::test]
    async fn test_generate_resource_policy_success() {
        let created_cm_json = serde_json::to_string(&ConfigMap {
            metadata: ObjectMeta {
                name: Some("test-policy".to_string()),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
        let client = mock_client(StatusCode::OK, created_cm_json.into_bytes());

        let result = generate_resource_policy(client, "test-ns", "test-policy").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_generate_kbs_https_certificate_success() {
        // This function creates two secrets. The mock client will be called twice.
        // Since our simple mock is stateless, it will return the same success response both times.
        let created_secret_json = serde_json::to_string(&Secret {
            metadata: ObjectMeta {
                name: Some("dummy-secret".to_string()),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
        let client = mock_client(StatusCode::OK, created_secret_json.into_bytes());

        let result = generate_kbs_https_certificate(client, "test-ns").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_generate_kbs_configurations_success() {
        // This function creates three configmaps in a loop.
        let created_cm_json = serde_json::to_string(&ConfigMap {
            metadata: ObjectMeta {
                name: Some("dummy-cm".to_string()),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
        let client = mock_client(StatusCode::OK, created_cm_json.into_bytes());
        let trustee = Trustee::default(); // We need a dummy Trustee object

        let result = generate_kbs_configurations(client, "test-ns", &trustee).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_generate_attestation_policy_success() {
        let created_cm_json = serde_json::to_string(&ConfigMap {
            metadata: ObjectMeta {
                name: Some("test-attestation-policy".to_string()),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
        let client = mock_client(StatusCode::OK, created_cm_json.into_bytes());

        let result =
            generate_attestation_policy(client, "test-ns", "test-attestation-policy").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_generate_kbs_success() {
        let created_kbs_config_json = serde_json::to_string(&KbsConfig {
            metadata: ObjectMeta {
                name: Some("test-kbs-config".to_string()),
                ..Default::default()
            },
            spec: KbsConfigSpec::default(),
        })
        .unwrap();
        let client = mock_client(StatusCode::OK, created_kbs_config_json.into_bytes());
        let trustee = Trustee {
            kbs_config_name: "test-kbs-config".to_string(),
            ..Default::default()
        };

        let result = generate_kbs(client, "test-ns", &trustee).await;
        assert!(result.is_ok());
    }

    // --- Test for `recompute_reference_values` ---
    /// A smarter Mock Client that can return different responses based on the request URL and method.
    async fn mock_get_then_replace_client() -> Client {
        let mock_svc = service_fn(move |req: Request<Body>| async move {
            let response =
                if req.method() == Method::GET && req.uri().path().contains(PCR_CONFIG_MAP) {
                    // This is the GET request for the PCR ConfigMap
                    // THIS IS THE FIX: The JSON now includes all required fields for the `Os` struct.
                    let pcrs_json = r#"{
                        "cos": {
                            "first_seen": "2023-01-01T00:00:00Z",
                            "pcrs": [{"id": 0, "value": "pcr0_val", "parts": []}]
                        }
                    }"#;
                let mut data = BTreeMap::new();
                data.insert(PCR_CONFIG_FILE.to_string(), pcrs_json.to_string());
                let cm = ConfigMap {
                    data: Some(data),
                    ..Default::default()
                };
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(
                        serde_json::to_string(&cm).unwrap().into_bytes(),
                    ))
                    .unwrap()
            } else if req.method() == Method::GET && req.uri().path().contains("test-rv-map") {
                // This is the GET request for the target RV ConfigMap
                let cm = ConfigMap::default();
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(
                        serde_json::to_string(&cm).unwrap().into_bytes(),
                    ))
                    .unwrap()
            } else if req.method() == Method::PUT && req.uri().path().contains("test-rv-map") {
                // This is the REPLACE (PUT) request for the target RV ConfigMap
                let cm = ConfigMap::default(); // Return a success response
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(
                        serde_json::to_string(&cm).unwrap().into_bytes(),
                    ))
                    .unwrap()
            } else {
                // For any unexpected request, return 404 Not Found
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::empty())
                    .unwrap()
            };
            Ok::<_, Infallible>(response)
        });

        Client::new(mock_svc, "default")
    }

    #[tokio::test]
    async fn test_recompute_reference_values_flow() {
        // 1. Prepare context data and the smart mock client
        let client = mock_get_then_replace_client().await;
        let ctx = RvContextData {
            client,
            operator_namespace: "op-ns".to_string(),
            trustee_namespace: "trustee-ns".to_string(),
            pcrs_compute_image: "".to_string(),
            rv_map: "test-rv-map".to_string(),
        };

        // 2. Call the function under test
        let result = recompute_reference_values(ctx).await;

        // 3. Assert
        assert!(result.is_ok());
    }

    // --- Tests for `generate_secret` ---
    // This is a more complex test because it involves creating a Secret, getting a KbsConfig, and patching a KbsConfig.
    async fn mock_generate_secret_client() -> Client {
        let mock_svc = service_fn(move |req: Request<Body>| async move {
            let response = if req.method() == Method::POST && req.uri().path().contains("/secrets")
            {
                // 1. The initial `create` call for the new Secret
                let secret = Secret::default();
                Response::builder()
                    .status(StatusCode::CREATED)
                    .body(Body::from(
                        serde_json::to_string(&secret).unwrap().into_bytes(),
                    ))
                    .unwrap()
            } else if req.method() == Method::GET && req.uri().path().contains("/kbsconfigs/") {
                // 2. The `get` call for the KbsConfig to check existing secrets
                let kbs_config = KbsConfig {
                    spec: KbsConfigSpec {
                        // Start with an empty list of secrets
                        kbs_secret_resources: vec![],
                        ..Default::default()
                    },
                    metadata: ObjectMeta::default(),
                };
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(
                        serde_json::to_string(&kbs_config).unwrap().into_bytes(),
                    ))
                    .unwrap()
            } else if req.method() == Method::PATCH && req.uri().path().contains("/kbsconfigs/") {
                // 3. The `patch` call to add the new secret to the KbsConfig
                let kbs_config = KbsConfig {
                    metadata: ObjectMeta::default(),
                    spec: KbsConfigSpec::default(),
                };
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(
                        serde_json::to_string(&kbs_config).unwrap().into_bytes(),
                    ))
                    .unwrap()
            } else {
                // For any other request, return an error
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::from(
                        format!("Unexpected request: {} {}", req.method(), req.uri().path())
                            .into_bytes(),
                    ))
                    .unwrap()
            };
            Ok::<_, Infallible>(response)
        });
        Client::new(mock_svc, "default")
    }

    #[tokio::test]
    async fn test_generate_secret_flow_success() {
        // 1. Get the specialized mock client
        let client = mock_generate_secret_client().await;

        // 2. Call the function under test
        let result = generate_secret(client, "test-ns", "test-kbs-config", "new-secret-id").await;

        // 3. Assert success
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_generate_secret_already_present_in_spec() {
        // Test the case where the secret ID is already in the KbsConfig spec
        let mock_svc = service_fn(move |req: Request<Body>| async move {
            let response = if req.method() == Method::POST && req.uri().path().contains("/secrets")
            {
                // The create secret call still happens
                let secret = Secret::default();
                Response::builder()
                    .status(StatusCode::CREATED)
                    .body(Body::from(
                        serde_json::to_string(&secret).unwrap().into_bytes(),
                    ))
                    .unwrap()
            } else if req.method() == Method::GET && req.uri().path().contains("/kbsconfigs/") {
                // The GET call returns a KbsConfig that *already contains* the secret
                let kbs_config = KbsConfig {
                    spec: KbsConfigSpec {
                        kbs_secret_resources: vec!["existing-secret".to_string()],
                        ..Default::default()
                    },
                    metadata: ObjectMeta::default(),
                };
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(
                        serde_json::to_string(&kbs_config).unwrap().into_bytes(),
                    ))
                    .unwrap()
            } else {
                // The PATCH call should NOT happen. If it does, this will fail.
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from(
                        "PATCH should not have been called".as_bytes().to_vec(),
                    ))
                    .unwrap()
            };
            Ok::<_, Infallible>(response)
        });
        let client = Client::new(mock_svc, "default");

        // Call with an ID that the mock says is already present
        let result = generate_secret(client, "test-ns", "test-kbs-config", "existing-secret").await;

        // The function should exit early and succeed without trying to patch.
        assert!(result.is_ok());
    }
}
