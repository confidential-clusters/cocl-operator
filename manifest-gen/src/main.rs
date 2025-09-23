// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::Result;
use clap::Parser;
use crds::{ConfidentialCluster, ConfidentialClusterSpec, Trustee};
use k8s_openapi::{
    api::{
        apps::v1::Deployment,
        batch::v1::Job,
        core::v1::{ConfigMap, Container, Namespace, PodSpec, PodTemplateSpec, ServiceAccount},
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

    /// Trustee namespace where to install trustee configuration
    #[arg(long, default_value = "operators")]
    trustee_namespace: String,

    #[arg(
        long,
        default_value = "quay.io/confidential-clusters/compute-pcrs:latest"
    )]
    pcrs_compute_image: String,
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
                verbs: vec![
                    "create".to_string(),
                    "get".to_string(),
                    "list".to_string(),
                    "watch".to_string(),
                    "patch".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                ],
                ..Default::default()
            },
            PolicyRule {
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
            },
            PolicyRule {
                api_groups: Some(vec![ConfidentialCluster::group(&()).to_string()]),
                resources: Some(vec![ConfidentialCluster::plural(&()).to_string()]),
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

    let trustee_role = Role {
        metadata: ObjectMeta {
            name: Some("trustee-role".to_string()),
            namespace: Some(args.trustee_namespace.clone()),
            ..Default::default()
        },
        rules: Some(vec![
            PolicyRule {
                api_groups: Some(vec!["".to_string()]),
                resources: Some(vec!["secrets".to_string(), "configmaps".to_string()]),
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
                api_groups: Some(vec!["confidentialcontainers.org".to_string()]),
                resources: Some(vec!["kbsconfigs".to_string()]),
                verbs: vec![
                    "create".to_string(),
                    "get".to_string(),
                    "watch".to_string(),
                    "patch".to_string(),
                    "update".to_string(),
                ],
                ..Default::default()
            },
        ]),
    };

    let trustee_role_binding = RoleBinding {
        metadata: ObjectMeta {
            name: Some("trustee-role-binding".to_string()),
            namespace: Some(args.trustee_namespace.clone()),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_string(),
            kind: "Role".to_string(),
            name: "trustee-role".to_string(),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".to_string(),
            name: operator_service_account_name.to_string(),
            namespace: Some(namespace),
            ..Default::default()
        }]),
    };

    let operator_service_account_yaml = serde_yaml::to_string(&operator_service_account)?;
    let operator_role_yaml = serde_yaml::to_string(&operator_role)?;
    let operator_role_binding_yaml = serde_yaml::to_string(&operator_role_binding)?;
    let compute_pcrs_service_account_yaml = serde_yaml::to_string(&compute_pcrs_service_account)?;
    let compute_pcrs_role_yaml = serde_yaml::to_string(&compute_pcrs_role)?;
    let compute_pcrs_role_binding_yaml = serde_yaml::to_string(&compute_pcrs_role_binding)?;
    let trustee_role_yaml = serde_yaml::to_string(&trustee_role)?;
    let trustee_role_binding_yaml = serde_yaml::to_string(&trustee_role_binding)?;

    let combined_yaml = [
        ns_yaml,
        operator_yaml,
        operator_service_account_yaml,
        operator_role_yaml,
        operator_role_binding_yaml,
        compute_pcrs_service_account_yaml,
        compute_pcrs_role_yaml,
        compute_pcrs_role_binding_yaml,
        trustee_role_yaml,
        trustee_role_binding_yaml,
    ]
    .join("\n---\n");

    fs::write(&output_path, combined_yaml)?;

    info!(
        "Generated operator, namespace, and RBAC at '{}'",
        output_path.display()
    );
    Ok(())
}

pub fn generate_crd(args: &Args) -> Result<()> {
    let crd = ConfidentialCluster::crd();

    let output_path = args.output_dir.join("confidential_cluster_crd.yaml");

    let yaml = serde_yaml::to_string(&crd)?;
    let mut file = File::create(&output_path)?;
    file.write_all(yaml.as_bytes())?;

    info!("Generated CRD at {}", output_path.display());

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
            trustee: Trustee {
                namespace: args.trustee_namespace.clone(),
                kbs_configuration: "kbs-config-map".to_string(),
                attestation_policy: "attestation-policy-data".to_string(),
                resource_policy: "resource-policy-data".to_string(),
                reference_values: "reference-values-data".to_string(),
                kbs_auth_key: "kbs-auth-key".to_string(),
                kbs_config_name: "kbsconfig".to_string(),
            },
            pcrs_compute_image: args.pcrs_compute_image.clone(),
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
    generate_crd(&args)?;
    generate_confidential_cluster_cr(&args)?;

    Ok(())
}
