// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
//
// SPDX-License-Identifier: MIT

use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{ConfigMap, Namespace};
use kube::api::DeleteParams;
use kube::{Api, Client};
use log::info;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Once;
use std::time::Duration;
use tokio::process::Command;

pub mod timer;
pub use timer::Poller;

static INIT: Once = Once::new();

pub struct TestContext {
    client: Client,
    test_namespace: String,
}

impl TestContext {
    pub async fn new() -> anyhow::Result<Self> {
        INIT.call_once(|| {
            let _ = env_logger::builder().is_test(true).try_init();
        });

        let client = setup_test_client().await?;
        let namespace = test_namespace_name();

        create_test_namespace(&client, &namespace).await?;
        apply_operator_manifests(&namespace).await?;

        Ok(Self {
            client,
            test_namespace: namespace,
        })
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn namespace(&self) -> &str {
        &self.test_namespace
    }

    pub async fn cleanup(&self) -> anyhow::Result<()> {
        cleanup_test_namespace(&self.client, &self.test_namespace).await
    }
}

#[macro_export]
macro_rules! setup {
    () => {{ $crate::common::TestContext::new() }};
}

pub async fn setup_test_client() -> anyhow::Result<Client> {
    let client = Client::try_default().await?;
    Ok(client)
}

pub async fn create_test_namespace(client: &Client, name: &str) -> anyhow::Result<()> {
    info!("Execute tests in the namespace: {name}");

    let namespace_api: Api<Namespace> = Api::all(client.clone());
    let namespace = Namespace {
        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(BTreeMap::from([("test".to_string(), "true".to_string())])),
            ..Default::default()
        },
        ..Default::default()
    };

    namespace_api
        .create(&Default::default(), &namespace)
        .await?;
    Ok(())
}

pub async fn cleanup_test_namespace(client: &Client, name: &str) -> anyhow::Result<()> {
    let namespace_api: Api<Namespace> = Api::all(client.clone());
    let dp = DeleteParams::default();

    match namespace_api.get(name).await {
        Ok(_) => {
            namespace_api.delete(name, &dp).await?;
            info!("Deleted namespace {name}");
        }
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            info!("Namespace already deleted");
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

pub fn test_namespace_name() -> String {
    format!("test-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

async fn wait_for_deployment_ready(
    deployments_api: &Api<Deployment>,
    deployment_name: &str,
    timeout_secs: u64,
) -> anyhow::Result<()> {
    let poller = Poller::new()
        .with_timeout(Duration::from_secs(timeout_secs))
        .with_interval(Duration::from_secs(5))
        .with_error_message(format!(
            "{deployment_name} deployment does not have 1 available replica after {timeout_secs} seconds"
        ));

    poller
        .poll_async(|| {
            let api = deployments_api.clone();
            let name = deployment_name.to_string();
            async move {
                let deployment = api.get(&name).await?;

                if let Some(status) = &deployment.status {
                    if let Some(available_replicas) = status.available_replicas {
                        if available_replicas == 1 {
                            info!("{name} deployment has 1 available replica");
                            return Ok(());
                        }
                    }
                }

                Err(anyhow::anyhow!(
                    "{name} deployment does not have 1 available replica yet"
                ))
            }
        })
        .await
}

pub async fn wait_for_resource_deleted<K>(
    api: &Api<K>,
    resource_name: &str,
    timeout_secs: u64,
    interval_secs: u64,
) -> anyhow::Result<()>
where
    K: kube::Resource<DynamicType = ()> + Clone + std::fmt::Debug,
    K: k8s_openapi::serde::de::DeserializeOwned,
{
    let poller = Poller::new()
        .with_timeout(Duration::from_secs(timeout_secs))
        .with_interval(Duration::from_secs(interval_secs))
        .with_error_message(format!("waiting for {resource_name} to be deleted"));

    poller
        .poll_async(|| {
            let api = api.clone();
            let name = resource_name.to_string();
            async move {
                match api.get(&name).await {
                    Ok(_) => Err("{name} still exists, retrying..."),
                    Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(()),
                    Err(e) => {
                        panic!("Unexpected error while fetching {name}: {e:?}");
                    }
                }
            }
        })
        .await
}

pub async fn apply_operator_manifests(namespace: &str) -> anyhow::Result<()> {
    let manifests_dir = Path::new("../manifests");
    if !manifests_dir.exists() {
        std::fs::create_dir_all(manifests_dir)?;
    }

    let manifest_gen_output = Command::new("../target/debug/manifest-gen")
        .args([
            "--namespace",
            namespace,
            "--output-dir",
            "../manifests",
            "--image",
            "localhost:5000/confidential-clusters/cocl-operator:latest",
            "--pcrs-compute-image",
            "localhost:5000/confidential-clusters/compute-pcrs:latest",
            "--trustee-image",
            "quay.io/confidential-clusters/key-broker-service:tpm-verifier-built-in-as-20250711",
            "--register-server-image",
            "localhost:5000/confidential-clusters/registration-server:latest",
            "--register-server-port",
            "8000",
        ])
        .output()
        .await?;

    if !manifest_gen_output.status.success() {
        let stderr = String::from_utf8_lossy(&manifest_gen_output.stderr);
        return Err(anyhow::anyhow!("Failed to generate manifests: {stderr}"));
    }

    let manifest_files = [
        "confidential_cluster_crd.yaml",
        "operator.yaml",
        "confidential_cluster_cr.yaml",
    ];

    for manifest_file in &manifest_files {
        let manifest_path = manifests_dir.join(manifest_file);
        let manifest_path_str = manifest_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid path: {manifest_path:?}"))?;

        let output = Command::new("kubectl")
            .args(["apply", "-f", manifest_path_str])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Failed to apply {manifest_file}: {stderr}"));
        }
    }

    let client = setup_test_client().await?;
    let deployments_api: Api<Deployment> = Api::namespaced(client.clone(), namespace);

    wait_for_deployment_ready(&deployments_api, "cocl-operator", 120).await?;
    wait_for_deployment_ready(&deployments_api, "register-server", 180).await?;
    wait_for_deployment_ready(&deployments_api, "trustee-deployment", 180).await?;

    // Wait for the image-pcrs ConfigMap to be created
    let configmap_api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);

    let poller = Poller::new()
        .with_timeout(Duration::from_secs(60))
        .with_interval(Duration::from_secs(5))
        .with_error_message(format!(
            "image-pcrs ConfigMap in the namespace {namespace} not found"
        ));

    poller
        .poll_async(|| {
            let api = configmap_api.clone();
            async move { api.get("image-pcrs").await }
        })
        .await?;

    Ok(())
}
