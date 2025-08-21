use anyhow::Result;
use chrono::{DateTime, TimeDelta, Utc};
use clap::Parser;
use compute_pcrs_lib::*;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::{ObjectMeta, PostParams};
use kube::{Api, Client};
use log::info;
use serde::{Serialize, Serializer};
use std::collections::BTreeMap;

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

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the kernel modules directory
    #[arg(short, long)]
    kernels: String,
    /// Path to the ESP directory
    #[arg(short, long)]
    esp: String,
    /// Path to the directory storing EFIVar files
    #[arg(short = 's', long)]
    efivars: String,
    /// Path to directory storing MokListRT, MokListTrustedRT and MokListXRT
    #[arg(short, long)]
    mokvars: String,
    /// ConfigMap name to write to
    #[arg(short, long)]
    configmap: String,
    /// Namespace to write ConfigMap to
    #[arg(short, long)]
    namespace: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let mut pcrs: Vec<_> = [
        compute_pcr4(&args.kernels, &args.esp, false, true),
        compute_pcr7(Some(&args.efivars), &args.esp, true),
        compute_pcr14(&args.mokvars),
    ]
    .iter()
    .map(|pcr| (format!("pcr{}", pcr.id), pcr.value.clone()))
    .collect();
    pcrs.push(("svn".to_string(), "1".to_string()));

    let reference_values: Vec<_> = pcrs
        .iter()
        .map(|(name, value)| ReferenceValue {
            version: "0.1.0".to_string(),
            name: format!("tpm_{name}"),
            expiration: Utc::now() + TimeDelta::days(365),
            value: serde_json::Value::Array(vec![serde_json::Value::String(value.to_string())]),
        })
        .collect();
    let reference_values_json = serde_json::to_string(&reference_values)?;
    let data = BTreeMap::from([(
        "reference-values.json".to_string(),
        reference_values_json.to_string(),
    )]);

    let config_map = ConfigMap {
        metadata: ObjectMeta {
            name: Some(args.configmap.clone()),
            namespace: Some(args.namespace.clone()),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    };

    let client = Client::try_default().await?;
    let config_maps: Api<ConfigMap> = Api::namespaced(client, &args.namespace);
    match config_maps
        .create(&PostParams::default(), &config_map)
        .await
    {
        Ok(_) => info!("Create ConfigMap {}", args.configmap),
        Err(kube::Error::Api(ae)) if ae.code == 409 => {
            info!("ConfigMap {} already exists", args.configmap)
        }
        Err(e) => return Err(e.into()),
    }

    Ok(())
}
