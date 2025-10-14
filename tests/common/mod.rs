// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
//
// SPDX-License-Identifier: MIT

#![allow(dead_code)]

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

use compute_pcrs_lib::Pcr;

pub fn compare_pcrs(actual: &[Pcr], expected: &[Pcr]) -> bool {
    if actual.len() != expected.len() {
        return false;
    }

    for (a, e) in actual.iter().zip(expected.iter()) {
        if a.id != e.id || a.value != e.value {
            return false;
        }
    }

    true
}

#[macro_export]
macro_rules! test_info {
    ($test_name:expr, $($arg:tt)*) => {{
        const GREEN: &str = "\x1b[32m";
        const RESET: &str = "\x1b[0m";
        println!("{}INFO{}: {}: {}", GREEN, RESET, $test_name, format!($($arg)*));
    }}
}

static INIT: Once = Once::new();

pub struct TestContext {
    client: Client,
    test_namespace: String,
    manifests_dir: String,
    test_name: String,
}

impl TestContext {
    pub async fn new(test_name: &str) -> anyhow::Result<Self> {
        INIT.call_once(|| {
            let _ = env_logger::builder().is_test(true).try_init();
        });

        let client = setup_test_client().await?;
        let namespace = test_namespace_name();

        let ctx = Self {
            client,
            test_namespace: namespace,
            manifests_dir: String::new(), // Will be set by create_temp_manifests_dir
            test_name: test_name.to_string(),
        };

        let manifests_dir = ctx.create_temp_manifests_dir()?;
        let mut ctx = ctx;
        ctx.manifests_dir = manifests_dir;

        ctx.create_namespace().await?;
        ctx.apply_operator_manifests().await?;

        test_info!(
            &ctx.test_name,
            "Execute test in the namespace {}",
            ctx.test_namespace
        );

        Ok(ctx)
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn namespace(&self) -> &str {
        &self.test_namespace
    }

    pub fn info(&self, message: impl std::fmt::Display) {
        test_info!(&self.test_name, "{}", message);
    }

    pub async fn cleanup(&self) -> anyhow::Result<()> {
        self.cleanup_namespace().await?;
        self.cleanup_manifests_dir()?;
        Ok(())
    }

    async fn create_namespace(&self) -> anyhow::Result<()> {
        test_info!(
            &self.test_name,
            "Creating test namespace: {}",
            self.test_namespace
        );
        let namespace_api: Api<Namespace> = Api::all(self.client.clone());
        let namespace = Namespace {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(self.test_namespace.clone()),
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

    async fn cleanup_namespace(&self) -> anyhow::Result<()> {
        let namespace_api: Api<Namespace> = Api::all(self.client.clone());
        let dp = DeleteParams::default();

        match namespace_api.get(&self.test_namespace).await {
            Ok(_) => {
                namespace_api.delete(&self.test_namespace, &dp).await?;
                test_info!(&self.test_name, "Deleted namespace {}", self.test_namespace);
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                test_info!(&self.test_name, "Namespace already deleted");
            }
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }

    fn create_temp_manifests_dir(&self) -> anyhow::Result<String> {
        let temp_dir = std::env::temp_dir();
        let manifests_dir = temp_dir.join(format!("manifests-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&manifests_dir)?;
        let dir_str = manifests_dir
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid temp directory path"))?
            .to_string();
        test_info!(
            &self.test_name,
            "Created temp manifests directory: {}",
            dir_str
        );
        Ok(dir_str)
    }

    fn cleanup_manifests_dir(&self) -> anyhow::Result<()> {
        if Path::new(&self.manifests_dir).exists() {
            std::fs::remove_dir_all(&self.manifests_dir)?;
            test_info!(
                &self.test_name,
                "Removed manifests directory: {}",
                self.manifests_dir
            );
        }
        Ok(())
    }

    async fn wait_for_deployment_ready(
        &self,
        deployments_api: &Api<Deployment>,
        deployment_name: &str,
        timeout_secs: u64,
    ) -> anyhow::Result<()> {
        test_info!(
            &self.test_name,
            "Waiting for deployment {} to be ready",
            deployment_name
        );
        let poller = Poller::new()
            .with_timeout(Duration::from_secs(timeout_secs))
            .with_interval(Duration::from_secs(5))
            .with_error_message(format!(
                "{deployment_name} deployment does not have 1 available replica after {timeout_secs} seconds"
            ));

        let test_name_owned = self.test_name.clone();
        poller
            .poll_async(move || {
                let api = deployments_api.clone();
                let name = deployment_name.to_string();
                let tn = test_name_owned.clone();
                async move {
                    let deployment = api.get(&name).await?;

                    if let Some(status) = &deployment.status {
                        if let Some(available_replicas) = status.available_replicas {
                            if available_replicas == 1 {
                                test_info!(&tn, "{} deployment has 1 available replica", name);
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

    async fn apply_operator_manifests(&self) -> anyhow::Result<()> {
        test_info!(
            &self.test_name,
            "Generating manifests in {}",
            self.manifests_dir
        );
        let manifest_gen_output = Command::new("../target/debug/manifest-gen")
            .args([
                "--namespace",
                &self.test_namespace,
                "--output-dir",
                &self.manifests_dir,
                "--image",
                "localhost:5000/confidential-clusters/cocl-operator:latest",
                "--pcrs-compute-image",
                "localhost:5000/confidential-clusters/compute-pcrs:latest",
                "--trustee-image",
                "quay.io/confidential-clusters/key-broker-service:tpm-verifier-built-in-as-20250711",
                "--register-server-image",
                "localhost:5000/confidential-clusters/registration-server:latest"
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

        let manifests_path = Path::new(&self.manifests_dir);
        for manifest_file in &manifest_files {
            test_info!(&self.test_name, "Applying manifest: {}", manifest_file);
            let manifest_path = manifests_path.join(manifest_file);
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

        test_info!(
            &self.test_name,
            "Patching ConfidentialCluster with trusteeAddr"
        );
        let trustee_addr = format!("kbs-service.{}.svc.cluster.local:80", self.test_namespace);
        let patch_json = format!(r#"{{"spec":{{"trusteeAddr":"{}"}}}}"#, trustee_addr);

        let patch_output = Command::new("kubectl")
            .args([
                "patch",
                "confidentialcluster",
                "confidential-cluster",
                "-n",
                &self.test_namespace,
                "--type=merge",
                "-p",
                &patch_json,
            ])
            .output()
            .await?;

        if !patch_output.status.success() {
            let stderr = String::from_utf8_lossy(&patch_output.stderr);
            return Err(anyhow::anyhow!(
                "Failed to patch ConfidentialCluster: {}",
                stderr
            ));
        }

        test_info!(
            &self.test_name,
            "Successfully patched ConfidentialCluster with trusteeAddr: {}",
            trustee_addr
        );

        let deployments_api: Api<Deployment> =
            Api::namespaced(self.client.clone(), &self.test_namespace);

        self.wait_for_deployment_ready(&deployments_api, "cocl-operator", 120)
            .await?;
        self.wait_for_deployment_ready(&deployments_api, "register-server", 180)
            .await?;
        self.wait_for_deployment_ready(&deployments_api, "trustee-deployment", 180)
            .await?;

        // Wait for the image-pcrs ConfigMap to be created
        test_info!(
            &self.test_name,
            "Waiting for image-pcrs ConfigMap to be created"
        );
        let configmap_api: Api<ConfigMap> =
            Api::namespaced(self.client.clone(), &self.test_namespace);

        let poller = Poller::new()
            .with_timeout(Duration::from_secs(60))
            .with_interval(Duration::from_secs(5))
            .with_error_message(format!(
                "image-pcrs ConfigMap in the namespace {} not found",
                self.test_namespace
            ));

        let test_name_owned = self.test_name.clone();
        poller
            .poll_async(move || {
                let api = configmap_api.clone();
                let tn = test_name_owned.clone();
                async move {
                    let result = api.get("image-pcrs").await;
                    if result.is_ok() {
                        test_info!(&tn, "image-pcrs ConfigMap created");
                    }
                    result
                }
            })
            .await?;

        test_info!(
            &self.test_name,
            "Patching ConfidentialCluster with trusteeAddr"
        );
        let trustee_addr = format!("kbs-service.{}.svc.cluster.local:80", self.test_namespace);
        let patch_json = format!(r#"{{"spec":{{"trusteeAddr":"{}"}}}}"#, trustee_addr);

        let patch_output = Command::new("kubectl")
            .args([
                "patch",
                "confidentialcluster",
                "confidential-cluster",
                "-n",
                &self.test_namespace,
                "--type=merge",
                "-p",
                &patch_json,
            ])
            .output()
            .await?;

        if !patch_output.status.success() {
            let stderr = String::from_utf8_lossy(&patch_output.stderr);
            return Err(anyhow::anyhow!(
                "Failed to patch ConfidentialCluster: {}",
                stderr
            ));
        }

        test_info!(
            &self.test_name,
            "Successfully patched ConfidentialCluster with trusteeAddr: {}",
            trustee_addr
        );

        Ok(())
    }
}

#[macro_export]
macro_rules! named_test {
    (async fn $name:ident() -> anyhow::Result<()> { $($body:tt)* }) => {
        #[tokio::test]
        async fn $name() -> anyhow::Result<()> {
            const TEST_NAME: &str = stringify!($name);
            $($body)*
        }
    };
}

// virt_test labels the tests that require virtualization
#[macro_export]
macro_rules! virt_test {
    (async fn $name:ident() -> anyhow::Result<()> { $($body:tt)* }) => {
        #[cfg(feature = "virtualization")]
        #[tokio::test]
        async fn $name() -> anyhow::Result<()> {
            const TEST_NAME: &str = stringify!($name);
            $($body)*
        }
    };
}

#[macro_export]
macro_rules! named_test {
    (async fn $name:ident() -> anyhow::Result<()> { $($body:tt)* }) => {
        #[tokio::test]
        async fn $name() -> anyhow::Result<()> {
            const TEST_NAME: &str = stringify!($name);
            $($body)*
        }
    };
}

// virt_test labels the tests that require virtualization
#[macro_export]
macro_rules! virt_test {
    (async fn $name:ident() -> anyhow::Result<()> { $($body:tt)* }) => {
        #[cfg(feature = "virtualization")]
        #[tokio::test]
        async fn $name() -> anyhow::Result<()> {
            const TEST_NAME: &str = stringify!($name);
            $($body)*
        }
    };
}

#[macro_export]
macro_rules! setup {
    () => {{ $crate::common::TestContext::new(TEST_NAME) }};
}

async fn setup_test_client() -> anyhow::Result<Client> {
    let client = Client::try_default().await?;
    Ok(client)
}

fn test_namespace_name() -> String {
    format!("test-{}", &uuid::Uuid::new_v4().to_string()[..8])
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

pub async fn create_curl_test_pod(
    client: &Client,
    namespace: &str,
    pod_name: &str,
    curl_command: &str,
) -> anyhow::Result<()> {
    use k8s_openapi::api::core::v1::{Container, Pod, PodSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    let test_pod = Pod {
        metadata: ObjectMeta {
            name: Some(pod_name.to_string()),
            ..Default::default()
        },
        spec: Some(PodSpec {
            restart_policy: Some("Never".to_string()),
            containers: vec![Container {
                name: "curl".to_string(),
                image: Some("curlimages/curl:latest".to_string()),
                command: Some(vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    curl_command.to_string(),
                ]),
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    };

    let pod_api: Api<k8s_openapi::api::core::v1::Pod> = Api::namespaced(client.clone(), namespace);
    pod_api.create(&Default::default(), &test_pod).await?;

    Ok(())
}

pub async fn wait_for_pod_completion(
    client: &Client,
    namespace: &str,
    pod_name: &str,
    timeout_secs: u64,
) -> anyhow::Result<()> {
    use k8s_openapi::api::core::v1::Pod;

    let pod_api: Api<Pod> = Api::namespaced(client.clone(), namespace);

    let poller = Poller::new()
        .with_timeout(Duration::from_secs(timeout_secs))
        .with_interval(Duration::from_secs(2))
        .with_error_message(format!("Pod {} did not complete", pod_name));

    poller
        .poll_async(|| {
            let api = pod_api.clone();
            let name = pod_name.to_string();
            async move {
                let pod = api.get(&name).await?;

                if let Some(status) = &pod.status {
                    if let Some(phase) = &status.phase {
                        if phase == "Succeeded" || phase == "Failed" {
                            return Ok(());
                        }
                    }
                }

                Err(anyhow::anyhow!("Pod still running"))
            }
        })
        .await?;

    Ok(())
}

#[cfg(feature = "virtualization")]
pub fn generate_ssh_key_pair() -> anyhow::Result<(String, String, std::path::PathBuf)> {
    use rand_core::OsRng;
    use ssh_key::{Algorithm, LineEnding, PrivateKey};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command as StdCommand;

    let private_key = PrivateKey::random(&mut OsRng, Algorithm::Rsa { hash: None })?;
    let private_key_str = private_key.to_openssh(LineEnding::LF)?.to_string();
    let public_key = private_key.public_key();
    let public_key_str = public_key.to_openssh()?;

    // Save private key to a temporary file
    let temp_dir = std::env::temp_dir();
    let key_path = temp_dir.join(format!("ssh_key_{}", uuid::Uuid::new_v4()));
    fs::write(&key_path, &private_key_str)?;

    // Set proper permissions (0600) for SSH key
    let mut perms = fs::metadata(&key_path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&key_path, perms)?;

    // Add key to ssh-agent using synchronous command
    let ssh_add_output = StdCommand::new("ssh-add")
        .arg(key_path.to_str().unwrap())
        .output()?;

    if !ssh_add_output.status.success() {
        let stderr = String::from_utf8_lossy(&ssh_add_output.stderr);
        // Clean up the key file if ssh-add fails
        let _ = fs::remove_file(&key_path);
        return Err(anyhow::anyhow!(
            "Failed to add SSH key to agent: {}",
            stderr
        ));
    }

    Ok((private_key_str, public_key_str, key_path))
}

// TODO create or find a rust crate for ignition
#[cfg(feature = "virtualization")]
pub fn generate_ignition_config(
    ssh_public_key: &str,
    register_server_url: &str,
) -> serde_json::Value {
    serde_json::json!({
        "ignition": {
            "config": {
                "merge": [
                    {
                        "source": register_server_url
                    }
                ]
            },
            "version": "3.5.0"
        },
        "passwd": {
            "users": [
                {
                    "name": "core",
                    "sshAuthorizedKeys": [ssh_public_key]
                }
            ]
        },
        "storage": {
            "files": [
                {
                    "path": "/etc/profile.d/systemd-pager.sh",
                    "contents": {
                        "compression": "",
                        "source": "data:,%23%20Tell%20systemd%20to%20not%20use%20a%20pager%20when%20printing%20information%0Aexport%20SYSTEMD_PAGER%3Dcat%0A"
                    },
                    "mode": 420
                }
            ]
        },
        "systemd": {
            "units": [
                {
                    "enabled": false,
                    "name": "zincati.service"
                },
                {
                    "dropins": [
                        {
                            "contents": "[Service]\n# Override Execstart in main unit\nExecStart=\n# Add new Execstart with `-` prefix to ignore failure`\nExecStart=-/usr/sbin/agetty --autologin core --noclear %I $TERM\n",
                            "name": "autologin-core.conf"
                        }
                    ],
                    "name": "serial-getty@ttyS0.service"
                }
            ]
        }
    })
}

/// Create a KubeVirt VirtualMachine with the specified configuration
/// TODO create rust a create for KubeVirt virtual machines
#[cfg(feature = "virtualization")]
pub async fn create_kubevirt_vm(
    client: &Client,
    namespace: &str,
    vm_name: &str,
    ssh_public_key: &str,
    register_server_url: &str,
    image: &str,
) -> anyhow::Result<()> {
    use kube::Api;
    use kube::api::PostParams;
    use kube::core::DynamicObject;
    use kube::discovery;

    let ignition_config = generate_ignition_config(ssh_public_key, register_server_url);
    let ignition_json = serde_json::to_string(&ignition_config)?;

    let vm_spec = serde_json::json!({
        "apiVersion": "kubevirt.io/v1",
        "kind": "VirtualMachine",
        "metadata": {
            "name": vm_name,
            "namespace": namespace
        },
        "spec": {
            "runStrategy": "Always",
            "template": {
                "metadata": {
                    "annotations": {
                        "kubevirt.io/ignitiondata": ignition_json
                    }
                },
                "spec": {
                    "domain": {
                        "features": {
                            "smm": {
                                "enabled": true
                            }
                        },
                        "firmware": {
                            "bootloader": {
                                "efi": {
                                    "persistent": true
                                }
                            }
                        },
                        "devices": {
                            "tpm": {
                                "persistent": true
                            },
                            "disks": [
                                {
                                    "name": "containerdisk",
                                    "disk": {
                                        "bus": "virtio"
                                    }
                                }
                            ],
                            "rng": {}
                        },
                        "resources": {
                            "requests": {
                                "memory": "4096M"
                            }
                        }
                    },
                    "volumes": [
                        {
                            "name": "containerdisk",
                            "containerDisk": {
                                "image": image,
                                "imagePullPolicy": "Always"
                            }
                        }
                    ]
                }
            }
        }
    });

    let discovery = discovery::Discovery::new(client.clone()).run().await?;

    let apigroup = discovery
        .groups()
        .find(|g| g.name() == "kubevirt.io")
        .ok_or_else(|| anyhow::anyhow!("kubevirt.io API group not found"))?;

    let (ar, _caps) = apigroup
        .recommended_kind("VirtualMachine")
        .ok_or_else(|| anyhow::anyhow!("VirtualMachine kind not found"))?;

    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);
    let vm_object: DynamicObject = serde_json::from_value(vm_spec)?;

    api.create(&PostParams::default(), &vm_object).await?;

    Ok(())
}

/// Wait for a KubeVirt VirtualMachine to reach Running phase
#[cfg(feature = "virtualization")]
pub async fn wait_for_vm_running(
    client: &Client,
    namespace: &str,
    vm_name: &str,
    timeout_secs: u64,
) -> anyhow::Result<()> {
    use kube::api::Api;
    use kube::core::DynamicObject;
    use kube::discovery;

    // Discover the VirtualMachine API
    let discovery = discovery::Discovery::new(client.clone()).run().await?;

    let apigroup = discovery
        .groups()
        .find(|g| g.name() == "kubevirt.io")
        .ok_or_else(|| anyhow::anyhow!("kubevirt.io API group not found"))?;

    let (ar, _caps) = apigroup
        .recommended_kind("VirtualMachine")
        .ok_or_else(|| anyhow::anyhow!("VirtualMachine kind not found"))?;

    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);

    let poller = Poller::new()
        .with_timeout(Duration::from_secs(timeout_secs))
        .with_interval(Duration::from_secs(5))
        .with_error_message(format!(
            "VirtualMachine {} did not reach Running phase after {} seconds",
            vm_name, timeout_secs
        ));

    poller
        .poll_async(|| {
            let api = api.clone();
            let name = vm_name.to_string();
            async move {
                let vm = api.get(&name).await?;

                // Check VM status phase
                if let Some(status) = vm.data.get("status") {
                    if let Some(phase) = status.get("printableStatus") {
                        if let Some(phase_str) = phase.as_str() {
                            if phase_str == "Running" {
                                return Ok(());
                            }
                        }
                    }
                }

                Err(anyhow::anyhow!(
                    "VirtualMachine {} is not in Running phase yet",
                    name
                ))
            }
        })
        .await
}

#[cfg(feature = "virtualization")]
pub async fn get_vm_status(
    client: &Client,
    namespace: &str,
    vm_name: &str,
) -> anyhow::Result<String> {
    use kube::api::Api;
    use kube::core::DynamicObject;
    use kube::discovery;

    let discovery = discovery::Discovery::new(client.clone()).run().await?;

    let apigroup = discovery
        .groups()
        .find(|g| g.name() == "kubevirt.io")
        .ok_or_else(|| anyhow::anyhow!("kubevirt.io API group not found"))?;

    let (ar, _caps) = apigroup
        .recommended_kind("VirtualMachine")
        .ok_or_else(|| anyhow::anyhow!("VirtualMachine kind not found"))?;

    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);
    let vm = api.get(vm_name).await?;

    // Extract phase from status
    if let Some(status) = vm.data.get("status") {
        if let Some(phase) = status.get("printableStatus") {
            if let Some(phase_str) = phase.as_str() {
                return Ok(phase_str.to_string());
            }
        }
    }

    Ok("Unknown".to_string())
}

#[cfg(feature = "virtualization")]
pub async fn virtctl_ssh_exec(
    namespace: &str,
    vm_name: &str,
    key_path: &std::path::Path,
    command: &str,
) -> anyhow::Result<String> {
    let _vm_target = format!("core@vmi/{}/{}", vm_name, namespace);
    let full_cmd = format!(
        "virtctl ssh -i {} core@vmi/{}/{} -t '-o IdentitiesOnly=yes' -t '-o StrictHostKeyChecking=no' --known-hosts /dev/null -c '{}'",
        key_path.display(),
        vm_name,
        namespace,
        command
    );

    let output = Command::new("sh").arg("-c").arg(full_cmd).output().await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("virtctl ssh command failed: {}", stderr));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(feature = "virtualization")]
pub async fn wait_for_vm_ssh_ready(
    namespace: &str,
    vm_name: &str,
    key_path: &std::path::Path,
    timeout_secs: u64,
) -> anyhow::Result<()> {
    let poller = Poller::new()
        .with_timeout(Duration::from_secs(timeout_secs))
        .with_interval(Duration::from_secs(10))
        .with_error_message(format!(
            "SSH access to VM {}/{} did not become available after {} seconds",
            namespace, vm_name, timeout_secs
        ));

    poller
        .poll_async(|| {
            let ns = namespace.to_string();
            let vm = vm_name.to_string();
            let key = key_path.to_path_buf();
            async move {
                // Try a simple command to check if SSH is ready
                match virtctl_ssh_exec(&ns, &vm, &key, "echo ready").await {
                    Ok(_) => Ok(()),
                    Err(e) => {
                        println!("XXX failed to ssh {}", e);
                        Err(anyhow::anyhow!("SSH not ready yet: {}", e))
                    }
                }
            }
        })
        .await
}

#[cfg(feature = "virtualization")]
pub async fn verify_encrypted_root(
    namespace: &str,
    vm_name: &str,
    key_path: &std::path::Path,
) -> anyhow::Result<bool> {
    let output = virtctl_ssh_exec(namespace, vm_name, key_path, "lsblk -o NAME,TYPE -J").await?;

    // Parse JSON output
    let lsblk_output: serde_json::Value = serde_json::from_str(&output)?;

    // Look for a device with name "root" and type "crypt"
    if let Some(blockdevices) = lsblk_output.get("blockdevices") {
        if let Some(devices) = blockdevices.as_array() {
            for device in devices {
                // Check the device itself
                if is_root_crypt_device(device) {
                    return Ok(true);
                }

                // Check children devices recursively
                if let Some(children) = device.get("children") {
                    if let Some(children_arr) = children.as_array() {
                        for child in children_arr {
                            if is_root_crypt_device(child) {
                                return Ok(true);
                            }
                            // Check nested children
                            if let Some(nested_children) = child.get("children") {
                                if let Some(nested_arr) = nested_children.as_array() {
                                    for nested in nested_arr {
                                        if is_root_crypt_device(nested) {
                                            return Ok(true);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(false)
}

#[cfg(feature = "virtualization")]
fn is_root_crypt_device(device: &serde_json::Value) -> bool {
    let name = device.get("name").and_then(|n| n.as_str());
    let dev_type = device.get("type").and_then(|t| t.as_str());

    if let (Some(n), Some(t)) = (name, dev_type) {
        if n == "root" && t == "crypt" {
            return true;
        }
    }

    false
}

/// Wait for a deployment to be ready
pub async fn wait_for_deployment_ready(
    client: &Client,
    namespace: &str,
    deployment_name: &str,
    timeout_secs: u64,
) -> anyhow::Result<()> {
    let deployments_api: Api<Deployment> = Api::namespaced(client.clone(), namespace);

    let poller = Poller::new()
        .with_timeout(Duration::from_secs(timeout_secs))
        .with_interval(Duration::from_secs(5))
        .with_error_message(format!(
            "{} deployment does not have 1 available replica after {} seconds",
            deployment_name, timeout_secs
        ));

    poller
        .poll_async(move || {
            let api = deployments_api.clone();
            let name = deployment_name.to_string();
            async move {
                let deployment = api.get(&name).await?;

                if let Some(status) = &deployment.status {
                    if let Some(available_replicas) = status.available_replicas {
                        if available_replicas >= 1 {
                            return Ok(());
                        }
                    }
                }

                Err(anyhow::anyhow!(
                    "{} deployment does not have 1 available replica yet",
                    name
                ))
            }
        })
        .await
}

#[cfg(feature = "virtualization")]
pub async fn check_vm_console_contains(
    namespace: &str,
    vm_name: &str,
    s: &str,
) -> anyhow::Result<()> {
    use std::process::Stdio;
    let vmi_name = format!("{}/{}", namespace, vm_name);

    let output = Command::new("timeout")
        .args(["10s", "virtctl", "console", &vmi_name])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let all_output = format!("{}\n{}", stdout, stderr);

    if all_output.contains(s) {
        return Ok(());
    }

    anyhow::bail!("Timeout: emergency shell indicator not found in console output")
}
