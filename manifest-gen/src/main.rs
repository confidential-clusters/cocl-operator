use anyhow::Result;
use clap::Parser;
use crds::{ConfidentialCluster, ConfidentialClusterSpec, Trustee};
use k8s_openapi::{
    api::{
        apps::v1::Deployment,
        core::v1::{Container, Namespace, PodSpec, PodTemplateSpec, ServiceAccount},
        rbac::v1::{
            ClusterRole, ClusterRoleBinding, PolicyRule, Role, RoleBinding, RoleRef, Subject,
        },
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
struct Args {
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
    #[arg(long, default_value = "trustee")]
    trustee_namespace: String,
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
                        command: Some(vec![
                            "/usr/bin/operator".to_string(),
                        ]),
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
    let service_account_name = "cocl-operator";
    let namespace = args.namespace.to_string();

    let sa = ServiceAccount {
        metadata: ObjectMeta {
            name: Some(service_account_name.to_string()),
            namespace: Some(namespace.clone()),
            ..Default::default()
        },
        ..Default::default()
    };

    let cluster_role = ClusterRole {
        metadata: ObjectMeta {
            name: Some(format!("{}-role", service_account_name)),
            ..Default::default()
        },
        rules: Some(vec![
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
        ..Default::default()
    };

    let cluster_role_binding = ClusterRoleBinding {
        metadata: ObjectMeta {
            name: Some(format!("{}-rolebinding", service_account_name)),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_string(),
            kind: "ClusterRole".to_string(),
            name: format!("{}-role", service_account_name),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".to_string(),
            name: service_account_name.to_string(),
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
            name: service_account_name.to_string(),
            namespace: Some(namespace),
            ..Default::default()
        }]),
    };

    let sa_yaml = serde_yaml::to_string(&sa)?;
    let cluster_role_yaml = serde_yaml::to_string(&cluster_role)?;
    let cluster_role_binding_yaml = serde_yaml::to_string(&cluster_role_binding)?;
    let trustee_role_yaml = serde_yaml::to_string(&trustee_role)?;
    let trustee_role_binding_yaml = serde_yaml::to_string(&trustee_role_binding)?;

    let combined_yaml = format!(
        "{}\n---\n{}\n---\n{}\n---\n{}\n---\n{}\n---\n{}\n---\n{}",
        ns_yaml,
        operator_yaml,
        sa_yaml,
        cluster_role_yaml,
        cluster_role_binding_yaml,
        trustee_role_yaml,
        trustee_role_binding_yaml
    );

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
