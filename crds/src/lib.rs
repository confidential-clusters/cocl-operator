use chrono::{DateTime, Utc};
use compute_pcrs_lib::Pcr;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(CustomResource, Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "confidential-containers.io",
    version = "v1alpha1",
    kind = "ConfidentialCluster",
    namespaced,
    plural = "confidentialclusters"
)]
#[serde(rename_all = "camelCase")]
pub struct ConfidentialClusterSpec {
    pub trustee: Trustee,
    pub pcrs_compute_image: String,
}

pub const PCR_CONFIG_MAP: &str = "image-pcrs";
pub const PCR_CONFIG_FILE: &str = "image-pcrs.json";

#[derive(Deserialize, Serialize)]
pub struct ImagePcr {
    pub first_seen: DateTime<Utc>,
    pub pcrs: Vec<Pcr>,
}

#[derive(Deserialize, Serialize)]
pub struct ImagePcrs {
    pub pcrs: BTreeMap<String, ImagePcr>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Trustee {
    pub namespace: String,
    pub kbs_configuration: String,
    pub as_configuration: String,
    pub rvps_configuration: String,
    pub attestation_policy: String,
    pub resource_policy: String,
    pub reference_values: String,
    pub kbs_auth_key: String,
    pub kbs_config_name: String,
}

#[derive(CustomResource, Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "confidentialcontainers.org",
    version = "v1alpha1",
    kind = "KbsConfig",
    namespaced,
    plural = "kbsconfigs"
)]
#[serde(rename_all = "camelCase")]
pub struct KbsConfigSpec {
    pub kbs_config_map_name: String,
    pub kbs_as_config_map_name: String,
    pub kbs_rvps_config_map_name: String,
    pub kbs_auth_secret_name: String,
    pub kbs_deployment_type: String,
    pub kbs_rvps_ref_values_config_map_name: String,
    pub kbs_secret_resources: Vec<String>,
    pub kbs_https_key_secret_name: String,
    pub kbs_https_cert_secret_name: String,
    pub kbs_resource_policy_config_map_name: String,
    pub kbs_attestation_policy_config_map_name: String,
}
