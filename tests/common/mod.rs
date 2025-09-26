// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
//
// SPDX-License-Identifier: MIT

use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{ConfigMap, Namespace};
use kube::api::DeleteParams;
use kube::{Api, Client, Config};
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
    () => {{
        crate::common::TestContext::new()
    }};
}

pub async fn setup_test_client() -> anyhow::Result<Client> {
    let config = Config::infer().await?;
    let client = Client::try_from(config)?;
    Ok(client)
}

pub async fn create_test_namespace(client: &Client, name: &str) -> anyhow::Result<()> {
    info!("Execute tests in the namespace: {}", name);

    let namespace_api: Api<Namespace> = Api::all(client.clone());
    let namespace = Namespace {
        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some(name.to_string()),
            labels: Some({
                let mut labels = BTreeMap::new();
                labels.insert("test".to_string(), "true".to_string());
                labels
            }),
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

    if namespace_api.get(name).await.is_ok() {
        namespace_api.delete(name, &dp).await?;
        info!("Deleted namespace {}", name);
    }

    Ok(())
}

pub fn test_namespace_name() -> String {
    format!("test-{}", uuid::Uuid::new_v4().to_string()[..8].to_string())
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
            "--register-server-port", "8000"

        ])
        .output()
        .await?;

    if !manifest_gen_output.status.success() {
        let stderr = String::from_utf8_lossy(&manifest_gen_output.stderr);
        return Err(anyhow::anyhow!("Failed to generate manifests: {}", stderr));
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
            .ok_or_else(|| anyhow::anyhow!("Invalid path: {:?}", manifest_path))?;

        let output = Command::new("kubectl")
            .args(["apply", "-f", manifest_path_str])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!(
                "Failed to apply {}: {}",
                manifest_file,
                stderr
            ));
        }
    }

    let client = setup_test_client().await?;
    let deployments_api: Api<Deployment> = Api::namespaced(client.clone(), namespace);

    let poller = Poller::new()
        .with_timeout(Duration::from_secs(120))
        .with_interval(Duration::from_secs(5))
        .with_error_message(format!("cocl-operator deployment in namespace {namespace} does not have 1 available replica after 120 seconds"));

    poller
        .poll_async(|| {
            let api = deployments_api.clone();
            async move {
                let deployment = api.get("cocl-operator").await?;

                if let Some(status) = &deployment.status {
                    if let Some(available_replicas) = status.available_replicas {
                        if available_replicas == 1 {
                            info!("cocl-operator deployment has 1 available replica");
                            return Ok(());
                        }
                    }
                }

                Err(anyhow::anyhow!(
                    "cocl-operator deployment does not have 1 available replica yet"
                ))
            }
        })
        .await?;

    // Wait for register-server deployment
    let poller = Poller::new()
        .with_timeout(Duration::from_secs(180))
        .with_interval(Duration::from_secs(5))
        .with_error_message(format!("register-server deployment in namespace {namespace} does not have 1 available replica after 120 seconds"));

    poller
        .poll_async(|| {
            let api = deployments_api.clone();
            async move {
                let deployment = api.get("register-server").await?;

                if let Some(status) = &deployment.status {
                    if let Some(available_replicas) = status.available_replicas {
                        if available_replicas == 1 {
                            info!("register-server deployment has 1 available replica");
                            return Ok(());
                        }
                    }
                }

                Err(anyhow::anyhow!(
                    "register-server deployment does not have 1 available replica yet"
                ))
            }
        })
        .await?;

    // Wait for trustee deployment
    let poller = Poller::new()
        .with_timeout(Duration::from_secs(180))
        .with_interval(Duration::from_secs(5))
        .with_error_message(format!("trustee deployment in namespace {namespace} does not have 1 available replica after 120 seconds"));

    poller
        .poll_async(|| {
            let api = deployments_api.clone();
            async move {
                let deployment = api.get("trustee-deployment").await?;

                if let Some(status) = &deployment.status {
                    if let Some(available_replicas) = status.available_replicas {
                        if available_replicas == 1 {
                            info!("trustee deployment has 1 available replica");
                            return Ok(());
                        }
                    }
                }

                Err(anyhow::anyhow!(
                    "trustee deployment does not have 1 available replica yet"
                ))
            }
        })
        .await?;

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
