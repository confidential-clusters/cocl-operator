// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::Result;
use clap::Parser;
use crds::{ConfidentialCluster, ConfidentialClusterSpec, Machine};
use k8s_openapi::{
    api::{
        apps::v1::Deployment,
        batch::v1::Job,
        core::v1::{
            ConfigMap, Container, Namespace, PodSpec, PodTemplateSpec, Secret, Service,
            ServiceAccount,
        },
        rbac::v1::{PolicyRule, Role, RoleBinding, RoleRef, Subject},
    },
    apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta},
};
use kube::CustomResourceExt;
use kube::Resource;
use log::info;
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Write,
    path::PathBuf,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Output directory to save rendered YAML
    #[arg(long, default_value = "manifests")]
    output_dir: PathBuf,

    /// Container image to use in the deployment
    #[arg(
        long,
        default_value = "quay.io/confidential-clusters/cocl-operator:latest"
    )]
    image: String,

    /// Namespace where to install the operator
    #[arg(long, default_value = "confidential-clusters")]
    namespace: String,

    /// Container image with all-in-one Trustee
    #[arg(long, default_value = "operators")]
    trustee_image: String,

    /// Container image with the cocl compute-pcrs binary
    #[arg(
        long,
        default_value = "quay.io/confidential-clusters/compute-pcrs:latest"
    )]
    pcrs_compute_image: String,

    /// Register server image to use in the deployment
    #[arg(
        long,
        default_value = "quay.io/confidential-clusters/register-server:latest"
    )]
    register_server_image: String,
}

fn generate_operator(args: &Args) -> Result<()> {
    let ns = Namespace {
        metadata: ObjectMeta {
            name: Some(args.namespace.clone()),
            ..Default::default()
        },
        ..Default::default()
    };
    let ns_yaml = serde_yaml::to_string(&ns)?;

    let name = "cocl-operator";
    let app_label = "cocl-operator";
    let labels = BTreeMap::from([("app".to_string(), app_label.to_string())]);

    let deployment = Deployment {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(args.namespace.clone()),
            labels: Some(labels.clone()),
            ..Default::default()
        },
        spec: Some(k8s_openapi::api::apps::v1::DeploymentSpec {
            replicas: Some(1),
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    service_account_name: Some(name.to_string()),
                    containers: vec![Container {
                        name: name.to_string(),
                        image: Some(args.image.clone()),
                        command: Some(vec!["/usr/bin/operator".to_string()]),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    };

    let operator_yaml = serde_yaml::to_string(&deployment)?;

    fs::create_dir_all(&args.output_dir)?;

    let output_path = args.output_dir.join("operator.yaml");

    // RBAC
    let operator_service_account_name = "cocl-operator";
    let namespace = args.namespace.to_string();

    let operator_service_account = ServiceAccount {
        metadata: ObjectMeta {
            name: Some(operator_service_account_name.to_string()),
            namespace: Some(namespace.clone()),
            ..Default::default()
        },
        ..Default::default()
    };

    let operator_role = Role {
        metadata: ObjectMeta {
            name: Some(format!("{operator_service_account_name}-role")),
            namespace: Some(namespace.clone()),
            ..Default::default()
        },
        rules: Some(vec![
            PolicyRule {
                api_groups: Some(vec!["batch".to_string()]),
                resources: Some(vec![Job::plural(&()).to_string()]),
                verbs: vec!["*".to_string()],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec!["".to_string()]),
                resources: Some(vec![
                    ConfigMap::plural(&()).to_string(),
                    Service::plural(&()).to_string(),
                    Secret::plural(&()).to_string(),
                    ServiceAccount::plural(&()).to_string(),
                ]),
                verbs: vec![
                    "create".to_string(),
                    "get".to_string(),
                    "list".to_string(),
                    "watch".to_string(),
                    "patch".to_string(),
                    "update".to_string(),
                ],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec![ConfidentialCluster::group(&()).to_string()]),
                resources: Some(vec![
                    ConfidentialCluster::plural(&()).to_string(),
                    format!("{}/finalizers", ConfidentialCluster::plural(&())),
                ]),
                verbs: vec![
                    "create".to_string(),
                    "get".to_string(),
                    "list".to_string(),
                    "watch".to_string(),
                    "patch".to_string(),
                    "update".to_string(),
                ],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec![ConfidentialCluster::group(&()).to_string()]),
                resources: Some(vec![format!("{}/status", ConfidentialCluster::plural(&()))]),
                verbs: vec!["patch".to_string(), "update".to_string()],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec!["apps".to_string()]),
                resources: Some(vec![Deployment::plural(&()).to_string()]),
                verbs: vec!["*".to_string()],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec!["rbac.authorization.k8s.io".to_string()]),
                resources: Some(vec![
                    Role::plural(&()).to_string(),
                    RoleBinding::plural(&()).to_string(),
                ]),
                verbs: vec!["*".to_string()],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec![Machine::group(&()).to_string()]),
                resources: Some(vec!["machines".to_string()]),
                verbs: vec![
                    "create".to_string(),
                    "get".to_string(),
                    "list".to_string(),
                    "delete".to_string(),
                    "watch".to_string(),
                ],
                ..Default::default()
            },
        ]),
    };

    let operator_role_binding = RoleBinding {
        metadata: ObjectMeta {
            name: Some(format!("{operator_service_account_name}-rolebinding")),
            namespace: Some(namespace.clone()),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_string(),
            kind: "Role".to_string(),
            name: format!("{operator_service_account_name}-role"),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".to_string(),
            name: operator_service_account_name.to_string(),
            namespace: Some(namespace.clone()),
            ..Default::default()
        }]),
    };

    let compute_pcrs_service_account_name = "compute-pcrs";

    let compute_pcrs_service_account = ServiceAccount {
        metadata: ObjectMeta {
            name: Some(compute_pcrs_service_account_name.to_string()),
            namespace: Some(namespace.clone()),
            ..Default::default()
        },
        ..Default::default()
    };

    let compute_pcrs_role = Role {
        metadata: ObjectMeta {
            name: Some(format!("{compute_pcrs_service_account_name}-role")),
            namespace: Some(namespace.clone()),
            ..Default::default()
        },
        rules: Some(vec![PolicyRule {
            api_groups: Some(vec!["".to_string()]),
            resources: Some(vec![ConfigMap::plural(&()).to_string()]),
            verbs: vec![
                "create".to_string(),
                "get".to_string(),
                "list".to_string(),
                "watch".to_string(),
                "patch".to_string(),
                "update".to_string(),
            ],
            ..Default::default()
        }]),
    };

    let compute_pcrs_role_binding = RoleBinding {
        metadata: ObjectMeta {
            name: Some(format!("{compute_pcrs_service_account_name}-rolebinding")),
            namespace: Some(namespace.clone()),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_string(),
            kind: "Role".to_string(),
            name: format!("{compute_pcrs_service_account_name}-role"),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".to_string(),
            name: compute_pcrs_service_account_name.to_string(),
            namespace: Some(namespace.clone()),
            ..Default::default()
        }]),
    };

    let operator_service_account_yaml = serde_yaml::to_string(&operator_service_account)?;
    let operator_role_yaml = serde_yaml::to_string(&operator_role)?;
    let operator_role_binding_yaml = serde_yaml::to_string(&operator_role_binding)?;
    let compute_pcrs_service_account_yaml = serde_yaml::to_string(&compute_pcrs_service_account)?;
    let compute_pcrs_role_yaml = serde_yaml::to_string(&compute_pcrs_role)?;
    let compute_pcrs_role_binding_yaml = serde_yaml::to_string(&compute_pcrs_role_binding)?;

    let combined_yaml = [
        ns_yaml,
        operator_yaml,
        operator_service_account_yaml,
        operator_role_yaml,
        operator_role_binding_yaml,
        compute_pcrs_service_account_yaml,
        compute_pcrs_role_yaml,
        compute_pcrs_role_binding_yaml,
    ]
    .join("\n---\n");

    fs::write(&output_path, combined_yaml)?;

    info!(
        "Generated operator, namespace, and RBAC at '{}'",
        output_path.display()
    );
    Ok(())
}

pub fn generate_crds(args: &Args) -> Result<()> {
    let confidential_cluster_crd = ConfidentialCluster::crd();
    let machine_crd = Machine::crd();

    let output_path = args.output_dir.join("confidential_cluster_crd.yaml");

    let confidential_cluster_yaml = serde_yaml::to_string(&confidential_cluster_crd)?;
    let machine_yaml = serde_yaml::to_string(&machine_crd)?;

    let combined_yaml = format!("{confidential_cluster_yaml}\n---\n{machine_yaml}");

    let mut file = File::create(&output_path)?;
    file.write_all(combined_yaml.as_bytes())?;

    info!("Generated CRDs at {}", output_path.display());

    Ok(())
}

pub fn generate_confidential_cluster_cr(args: &Args) -> Result<()> {
    let sample = ConfidentialCluster {
        metadata: ObjectMeta {
            name: Some("confidential-cluster".to_string()),
            namespace: Some(args.namespace.clone()),
            ..Default::default()
        },
        spec: ConfidentialClusterSpec {
            trustee_image: args.trustee_image.clone(),
            pcrs_compute_image: args.pcrs_compute_image.clone(),
            register_server_image: args.register_server_image.clone(),
            ..Default::default()
        },
    };

    let output_path = args.output_dir.join("confidential_cluster_cr.yaml");

    let yaml = serde_yaml::to_string(&sample)?;
    let mut file = File::create(&output_path)?;
    file.write_all(yaml.as_bytes())?;

    info!(
        "Generated ConfidentialCluster CR at {}",
        output_path.display()
    );

    Ok(())
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = Args::parse();

    generate_operator(&args)?;
    generate_crds(&args)?;
    generate_confidential_cluster_cr(&args)?;

    Ok(())
}
