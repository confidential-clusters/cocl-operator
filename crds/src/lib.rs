use kube::CustomResource;
use kube::Resource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "confidential-containers.io",
    version = "v1alpha1",
    kind = "ConfidentialCluster",
    namespaced,
    plural = "confidentialclusters"
)]
pub struct ConfidentialClusterSpec {
    pub trustee: Trustee,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Trustee {
    pub namespace: String,
    pub kbs_configuration: String,
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
pub struct KbsConfigSpec {
    #[serde(rename = "kbsConfigMapName")]
    pub kbs_config_map_name: String,
    #[serde(rename = "kbsAuthSecretName")]
    pub kbs_auth_secret_name: String,
    #[serde(rename = "kbsDeploymentType")]
    pub kbs_deployment_type: String,
    #[serde(rename = "kbsRvpsRefValuesConfigMapName")]
    pub kbs_rvps_ref_values_config_map_name: String,
    #[serde(rename = "kbsSecretResources")]
    pub kbs_secret_resources: Vec<String>,
    #[serde(rename = "kbsHttpsKeySecretName")]
    pub kbs_https_key_secret_name: String,
    #[serde(rename = "kbsHttpsCertSecretName")]
    pub kbs_https_cert_secret_name: String,
    #[serde(rename = "kbsResourcePolicyConfigMapName")]
    pub kbs_resource_policy_config_map_name: String,
}
