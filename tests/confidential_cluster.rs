// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
//
// SPDX-License-Identifier: MIT

mod common;

use crate::common::Poller;
use crds::ConfidentialCluster;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::{api::DeleteParams, Api, Error};
use std::time::Duration;

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
    let poller = Poller::new()
        .with_timeout(Duration::from_secs(120))
        .with_interval(Duration::from_secs(5))
        .with_error_message(format!(
            "waiting the confidential cluster cr to be deleted"
        ));
    poller
        .poll_async(|| {
            let api = api.clone();
            async move {
                match api.get(&name).await {
                    Ok(_) => {
                        Err("Object still exists, retrying...")
                    }
                    Err(Error::Api(ae)) if ae.code == 404 => {
                        Ok(())
                    }
                    Err(e) => {
                        panic!("Unexpected error while fetching {}: {:?}", name, e);
                    }
                }
            }
        })
        .await?;

    // Wait until the trustee deployment is cleaned up
    let deployments_api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let poller = Poller::new()
        .with_timeout(Duration::from_secs(120))
        .with_interval(Duration::from_secs(1))
        .with_error_message(format!(
            "waiting the trustee deployment to be deleted"
        ));
    poller
        .poll_async(|| {
            let api = deployments_api.clone();
            async move {
                match api.get("trustee-deployment").await {
                    Ok(_) => {
                        Err("trustee deployment still exists, retrying...")
                    }
                    Err(Error::Api(ae)) if ae.code == 404 => {
                        Ok(())
                    }
                    Err(e) => {
                        panic!("Unexpected error while fetching trustee deployment: {:?}", e);
                    }
                }
            }
        })
        .await?;

    // Wait until the register-server deployment is cleaned up
    let poller = Poller::new()
        .with_timeout(Duration::from_secs(120))
        .with_interval(Duration::from_secs(1))
        .with_error_message(format!(
            "waiting the register-server deployment to be deleted"
        ));
    poller
        .poll_async(|| {
            let api = deployments_api.clone();
            async move {
                match api.get("register-server").await {
                    Ok(_) => {
                        Err("register-server deployment still exists, retrying...")
                    }
                    Err(Error::Api(ae)) if ae.code == 404 => {
                        Ok(())
                    }
                    Err(e) => {
                        panic!("Unexpected error while fetching register-server deployment: {:?}", e);
                    }
                }
            }
        })
        .await?;

    // Wait until the configmap is cleaned up as well
    let poller = Poller::new()
        .with_timeout(Duration::from_secs(120))
        .with_interval(Duration::from_secs(1))
        .with_error_message(format!(
            "waiting the configmap is cleaned up as well"
        ));
    poller
        .poll_async(|| {
            let api = configmap_api.clone();
            async move {
                match api.get("image-pcrs").await {
                    Ok(_) => {
                        Err("image-pcrs ConfigMap still exists, retrying...")
                    }
                    Err(Error::Api(ae)) if ae.code == 404 => {
                        Ok(())
                    }
                    Err(e) => {
                        panic!("Unexpected error while fetching image-pcrs ConfigMap: {:?}", e);
                    }
                }
            }
        })
        .await?;

    test_ctx.cleanup().await?;

    Ok(())
}
