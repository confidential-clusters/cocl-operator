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
    pub trustee_image: String,
    pub pcrs_compute_image: String,
}
