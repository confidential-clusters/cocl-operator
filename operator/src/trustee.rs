// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::Context;
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, TimeDelta, Utc};
use clevis_pin_trustee_lib::Key as ClevisKey;
use json_patch::{AddOperation, PatchOperation, TestOperation};
use k8s_openapi::api::core::v1::{ConfigMap, Secret};
use kube::api::{ObjectMeta, Patch, PatchParams, PostParams};
use kube::{Api, Client};
use log::info;
use openssl::pkey::PKey;
use serde::{Serialize, Serializer};
use serde_json::{Value::Array as JsonArray, Value::String as JsonString};
use std::{collections::BTreeMap, fs};

use crds::{KbsConfig, KbsConfigSpec, Trustee};
use operator::{ClevisContextData, RvContextData, info_if_exists};
use rv_store::*;

const HTTPS_KEY: &str = "kbs-https-key";
const HTTPS_CERT: &str = "kbs-https-certificate";
const REFERENCE_VALUES_FILE: &str = "reference-values.json";

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
            metadata: ObjectMeta {
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
        metadata: ObjectMeta {
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
        Api::namespaced(ctx.client.clone(), ctx.client.default_namespace());
    let image_pcrs_map = operator_config_maps.get(PCR_CONFIG_MAP).await?;
    let image_pcrs = get_image_pcrs(image_pcrs_map)?;
    // TODO many grub+shim:many OS image recompute once supported
    let mut reference_values_in =
        BTreeMap::from([("svn".to_string(), vec![JsonString("1".to_string())])]);
    for pcr in image_pcrs.0.values().flat_map(|v| &v.pcrs) {
        reference_values_in
            .entry(format!("pcr{}", pcr.id))
            .or_default()
            .push(JsonString(pcr.value.clone()));
    }
    let reference_values: Vec<_> = reference_values_in
        .iter()
        .map(|(name, values)| ReferenceValue {
            version: "0.1.0".to_string(),
            name: format!("tpm_{name}"),
            expiration: Utc::now() + TimeDelta::days(365),
            value: JsonArray(values.to_vec()),
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

pub async fn generate_secret(ctx: ClevisContextData, id: &str) -> anyhow::Result<()> {
    let key = generate_luks_key()?;
    let secret_data = k8s_openapi::ByteString(key);
    let data = BTreeMap::from([("root".to_string(), secret_data)]);

    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(id.to_string()),
            namespace: Some(ctx.trustee_namespace.to_string()),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    };

    let secrets: Api<Secret> = Api::namespaced(ctx.client.clone(), &ctx.trustee_namespace);
    let create = secrets.create(&PostParams::default(), &secret).await;
    info_if_exists!(create, "Secret", id);

    let kbs_configs: Api<KbsConfig> = Api::namespaced(ctx.client, &ctx.trustee_namespace);

    let existing_secrets = kbs_configs
        .get(&ctx.kbs_config)
        .await?
        .spec
        .kbs_secret_resources;
    if existing_secrets.contains(&id.to_string()) {
        info!("Secret with ID {id} already present");
        return Ok(());
    }

    let path = jsonptr::PointerBuf::parse("/spec/kbsSecretResources")?;
    let mut secrets_json: Vec<_> = existing_secrets
        .iter()
        .map(|s| JsonString(s.clone()))
        .collect();
    let test_patch = PatchOperation::Test(TestOperation {
        path: path.clone(),
        value: JsonArray(secrets_json.clone()),
    });

    secrets_json.push(JsonString(id.to_string()));
    let add_patch = PatchOperation::Add(AddOperation {
        path,
        value: JsonArray(secrets_json),
    });

    let json_patch = json_patch::Patch(vec![test_patch, add_patch]);
    let patch: Patch<KbsConfig> = Patch::Json(json_patch);
    let params = PatchParams::default();

    kbs_configs.patch(&ctx.kbs_config, &params, &patch).await?;
    info!("Added secret {id} to {}", ctx.kbs_config);

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
        metadata: ObjectMeta {
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
        metadata: ObjectMeta {
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
        metadata: ObjectMeta {
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
    info_if_exists!(create, "KbsConfig", trustee.kbs_config_name);

    Ok(())
}
