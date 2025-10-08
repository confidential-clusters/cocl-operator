// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use env_logger::Env;
use futures_util::StreamExt;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::{Api, Client, Resource};
use kube::{
    api::ObjectMeta,
    runtime::{
        controller::{Action, Controller},
        watcher,
    },
};
use log::{error, info, warn};

use crds::ConfidentialCluster;
#[cfg(test)]
mod mock_client;
mod reference_values;
mod register_server;
mod trustee;

const BOOT_IMAGE: &str = "quay.io/confidential-clusters/fedora-coreos:latest";

async fn reconcile(
    cocl: Arc<ConfidentialCluster>,
    client: Arc<Client>,
) -> Result<Action, operator::ControllerError> {
    let name = operator::name_or_default(&cocl.metadata);
    if cocl.metadata.deletion_timestamp.is_some() {
        info!("Registered deletion of ConfidentialCluster {name}");
        return Ok(Action::await_change());
    }
    let kube_client = Arc::unwrap_or_clone(client);

    let cocls: Api<ConfidentialCluster> = Api::default_namespaced(kube_client.clone());
    let list = cocls.list(&Default::default()).await;
    let cocl_list = list.map_err(Into::<anyhow::Error>::into)?;
    if cocl_list.items.len() > 1 {
        let namespace = kube_client.default_namespace();
        warn!(
            "More than one ConfidentialCluster found in namespace {namespace}. \
              cocl-operator does not support more than one ConfidentialCluster. Requeueing...",
        );
        return Ok(Action::requeue(Duration::from_secs(60)));
    }

    info!("Setting up ConfidentialCluster {name}");
    install_trustee_configuration(kube_client.clone(), &cocl).await?;
    install_register_server(kube_client, &cocl).await?;
    Ok(Action::await_change())
}

fn generate_owner_reference(metadata: &ObjectMeta) -> Result<OwnerReference> {
    let name = metadata.name.clone();
    let uid = metadata.uid.clone();
    Ok(OwnerReference {
        api_version: ConfidentialCluster::api_version(&()).to_string(),
        block_owner_deletion: Some(true),
        controller: Some(true),
        kind: ConfidentialCluster::kind(&()).to_string(),
        name: name.context("ConfidentialCluster had no name")?,
        uid: uid.context("ConfidentialCluster had no UID")?,
    })
}

async fn install_trustee_configuration(client: Client, cocl: &ConfidentialCluster) -> Result<()> {
    let owner_reference = generate_owner_reference(&cocl.metadata)?;

    match trustee::generate_trustee_data(client.clone(), owner_reference.clone()).await {
        Ok(_) => info!("Generate configmap for the KBS configuration",),
        Err(e) => error!("Failed to create the KBS configuration configmap: {e}"),
    }

    let rv_ctx = operator::RvContextData {
        client: client.clone(),
        owner_reference: owner_reference.clone(),
        pcrs_compute_image: cocl.spec.pcrs_compute_image.clone(),
    };
    reference_values::launch_rv_job_controller(rv_ctx.clone()).await;
    match reference_values::create_pcrs_config_map(client.clone()).await {
        Ok(_) => info!("Created bare configmap for PCRs"),
        Err(e) => error!("Failed to create the PCRs configmap: {e}"),
    }

    // TODO machine config input
    match reference_values::handle_new_image(rv_ctx, BOOT_IMAGE).await {
        Ok(_) => info!("Computed or retrieved reference values for image: {BOOT_IMAGE}",),
        Err(e) => {
            error!("Failed to compute or retrieve reference values for image {BOOT_IMAGE}: {e}",)
        }
    }

    match trustee::generate_attestation_policy(client.clone(), owner_reference.clone()).await {
        Ok(_) => info!("Generate configmap for the attestation policy",),
        Err(e) => error!("Failed to create the attestation policy configmap: {e}"),
    }

    let name = operator::name_or_default(&cocl.metadata);
    let err = format!("ConfidentialCluster {name} did not specify a Trustee address");
    let trustee_addr = cocl.spec.trustee_addr.clone().context(err)?;
    let mut split = trustee_addr.split(":");
    // TODO upgrade to 443 once supported
    let kbs_port: i32 = split.nth(1).and_then(|s| s.parse().ok()).unwrap_or(80);
    match trustee::generate_kbs_service(client.clone(), owner_reference.clone(), kbs_port).await {
        Ok(_) => info!("Generate the KBS service"),
        Err(e) => error!("Failed to create the KBS service: {e}"),
    }

    match trustee::generate_kbs_deployment(client, owner_reference, &cocl.spec.trustee_image).await
    {
        Ok(_) => info!("Generate the KBS deployment"),
        Err(e) => error!("Failed to create the KBS deployment: {e}"),
    }

    Ok(())
}

async fn install_register_server(client: Client, cocl: &ConfidentialCluster) -> Result<()> {
    let owner_reference = generate_owner_reference(&cocl.metadata)?;

    match register_server::create_register_server_rbac(client.clone()).await {
        Ok(_) => info!("Register server RBAC created/updated successfully"),
        Err(e) => error!("Failed to create register server RBAC: {e}"),
    }

    match register_server::create_register_server_deployment(
        client.clone(),
        owner_reference.clone(),
        &cocl.spec.register_server_image,
    )
    .await
    {
        Ok(_) => info!("Register server deployment created/updated successfully"),
        Err(e) => error!("Failed to create register server deployment: {e}"),
    }

    let name = operator::name_or_default(&cocl.metadata);
    let err = format!("ConfidentialCluster {name} did not specify a register server port");
    let port = cocl.spec.register_server_port.context(err)?;
    match register_server::create_register_server_service(client.clone(), owner_reference, port)
        .await
    {
        Ok(_) => info!("Register server service created/updated successfully"),
        Err(e) => error!("Failed to create register server service: {e}"),
    }

    register_server::launch_keygen_controller(client).await;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let kube_client = Client::try_default().await?;
    info!("Confidential clusters operator",);
    let cl: Api<ConfidentialCluster> = Api::default_namespaced(kube_client.clone());

    let client = Arc::new(kube_client);
    Controller::new(cl, watcher::Config::default())
        .run(reconcile, operator::controller_error_policy, client)
        .for_each(operator::controller_info)
        .await;

    Ok(())
}
