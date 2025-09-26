// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
//
// SPDX-License-Identifier: MIT

mod common;

use crate::common::wait_for_resource_deleted;
use crds::ConfidentialCluster;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::{Api, api::DeleteParams};

#[tokio::test]
async fn test_confidential_cluster_uninstall() -> anyhow::Result<()> {
    let test_ctx = setup!().await?;

    let client = test_ctx.client();
    let namespace = test_ctx.namespace();
    let name = "confidential-cluster";

    let configmap_api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);

    // Delete the cocl cr
    let api: Api<ConfidentialCluster> = Api::namespaced(client.clone(), namespace);
    let dp = DeleteParams::default();
    api.delete(name, &dp).await?;

    // Wait until it disappears
    wait_for_resource_deleted(&api, name, 120, 5).await?;

    let deployments_api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    wait_for_resource_deleted(&deployments_api, "trustee-deployment", 120, 1).await?;
    wait_for_resource_deleted(&deployments_api, "register-server", 120, 1).await?;
    wait_for_resource_deleted(&configmap_api, "image-pcrs", 120, 1).await?;

    test_ctx.cleanup().await?;

    Ok(())
}
