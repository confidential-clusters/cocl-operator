// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::Result;
use clap::Parser;
use k8s_openapi::{
    api::{
        apps::v1::Deployment,
        core::v1::{Container, Namespace, PodSpec, PodTemplateSpec},
    },
    apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta},
};
use log::info;
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Write,
    path::PathBuf,
};

use cocl_operator_lib::{ConfidentialCluster, ConfidentialClusterSpec};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Output directory to save rendered YAML
    #[arg(long, default_value = "config/deploy")]
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
    let combined_yaml = format!("{ns_yaml}\n---\n{operator_yaml}");
    fs::write(&output_path, combined_yaml)?;

    info!(
        "Generated operator deployment and namespace at '{}'",
        output_path.display()
    );
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
            public_trustee_addr: None,
            trustee_kbs_port: None,
            register_server_port: None,
        },
        status: None,
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
    generate_confidential_cluster_cr(&args)?;

    Ok(())
}
