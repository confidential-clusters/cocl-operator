// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use kube_derive::CustomResource;
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
#[serde(rename_all = "camelCase")]
pub struct ConfidentialClusterSpec {
    pub trustee: Trustee,
    pub pcrs_compute_image: String,
    pub register_server_image: String,
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
#[serde(rename_all = "camelCase")]
pub struct KbsConfigSpec {
    pub kbs_config_map_name: String,
    pub kbs_auth_secret_name: String,
    pub kbs_deployment_type: String,
    pub kbs_rvps_ref_values_config_map_name: String,
    pub kbs_secret_resources: Vec<String>,
    pub kbs_https_key_secret_name: String,
    pub kbs_https_cert_secret_name: String,
    pub kbs_resource_policy_config_map_name: String,
    pub kbs_attestation_policy_config_map_name: String,
}

#[derive(CustomResource, Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "confidential-containers.io",
    version = "v1alpha1",
    kind = "Machine",
    namespaced,
    plural = "machines"
)]
pub struct MachineSpec {
    pub id: String,
    pub address: String,
}
