// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use kube_derive::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Default, Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "confidential-containers.io",
    version = "v1alpha1",
    kind = "ConfidentialCluster",
    namespaced,
    plural = "confidentialclusters"
)]
#[serde(rename_all = "camelCase")]
pub struct ConfidentialClusterSpec {
    pub trustee_image: String,
    pub pcrs_compute_image: String,
    pub register_server_image: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trustee_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub register_server_port: Option<i32>,
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
