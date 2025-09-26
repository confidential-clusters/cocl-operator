// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use env_logger::Env;
use futures_util::StreamExt;
use kube::runtime::{
    controller::{Action, Controller},
    watcher,
};
use kube::{Api, Client};
use log::{error, info, warn};

use crds::ConfidentialCluster;
mod reference_values;
mod trustee;

const BOOT_IMAGE: &str = "quay.io/fedora/fedora-coreos:42.20250705.3.0";

async fn reconcile(
    cocl: Arc<ConfidentialCluster>,
    client: Arc<Client>,
) -> Result<Action, operator::ControllerError> {
    let name = cocl.metadata.name.as_deref().unwrap_or("<no name>");
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
    install_trustee_configuration(kube_client, &cocl).await?;
    Ok(Action::await_change())
}

async fn install_trustee_configuration(client: Client, cocl: &ConfidentialCluster) -> Result<()> {
    let trustee_namespace = cocl.spec.trustee.namespace.clone();

    match trustee::generate_kbs_auth_public_key(
        client.clone(),
        &trustee_namespace,
        &cocl.spec.trustee.kbs_auth_key,
    )
    .await
    {
        Ok(_) => info!(
            "Generate secret authentication key: {}",
            cocl.spec.trustee.kbs_auth_key
        ),
        Err(e) => error!("Failed to create the secret authentication key: {e}"),
    }

    match trustee::generate_kbs_configurations(
        client.clone(),
        &trustee_namespace,
        &cocl.spec.trustee,
    )
    .await
    {
        Ok(_) => info!(
            "Generate configmap for the KBS configuration: {}",
            cocl.spec.trustee.kbs_configuration
        ),
        Err(e) => error!("Failed to create the KBS configuration configmap: {e}"),
    }

    match trustee::generate_kbs_https_certificate(client.clone(), &trustee_namespace).await {
        Ok(_) => info!("Generated HTTPS certificates for the KBS"),
        Err(e) => error!("Failed to create HTTPS certificates for the KBS: {e}"),
    }

    let rv_ctx = operator::RvContextData {
        client: client.clone(),
        trustee_namespace: trustee_namespace.clone(),
        pcrs_compute_image: cocl.spec.pcrs_compute_image.clone(),
        rv_map: cocl.spec.trustee.reference_values.clone(),
    };
    reference_values::launch_rv_job_controller(rv_ctx.clone()).await;
    match reference_values::create_pcrs_config_map(client.clone()).await {
        Ok(_) => info!("Created bare configmap for PCRs"),
        Err(e) => error!("Failed to create the PCRs configmap: {e}"),
    }
    match trustee::create_reference_value_config_map(
        client.clone(),
        &trustee_namespace,
        &cocl.spec.trustee.reference_values,
    )
    .await
    {
        Ok(_) => info!(
            "Created bare configmap for the reference values: {}",
            cocl.spec.trustee.reference_values
        ),
        Err(e) => error!("Failed to create the reference values configmap: {e}"),
    }
    // TODO machine config input
    match reference_values::handle_new_image(rv_ctx, BOOT_IMAGE).await {
        Ok(_) => info!("Computed or retrieved reference values for image: {BOOT_IMAGE}",),
        Err(e) => {
            error!("Failed to compute or retrieve reference values for image {BOOT_IMAGE}: {e}",)
        }
    }

    match trustee::generate_resource_policy(
        client.clone(),
        &trustee_namespace,
        &cocl.spec.trustee.resource_policy,
    )
    .await
    {
        Ok(_) => info!(
            "Generate configmap for the resource policy: {}",
            cocl.spec.trustee.resource_policy
        ),
        Err(e) => error!("Failed to create the resource policy configmap: {e}"),
    }

    match trustee::generate_attestation_policy(
        client.clone(),
        &trustee_namespace,
        &cocl.spec.trustee.attestation_policy,
    )
    .await
    {
        Ok(_) => info!(
            "Generate configmap for the attestation policy: {}",
            cocl.spec.trustee.attestation_policy
        ),
        Err(e) => error!("Failed to create the attestation policy configmap: {e}"),
    }

    match trustee::generate_kbs(client.clone(), &trustee_namespace, &cocl.spec.trustee).await {
        Ok(_) => info!(
            "Generate the KBS configuration: {}",
            cocl.spec.trustee.kbs_config_name
        ),
        Err(e) => error!("Failed to create the KBS configuration: {e}"),
    }

    // TODO replace this creation with a per-machine one.
    // This secret's address is `default/machine/root`.
    match trustee::generate_secret(
        client,
        &trustee_namespace,
        &cocl.spec.trustee.kbs_config_name,
        "machine",
    )
    .await
    {
        Ok(_) => info!("Generate test secret"),
        Err(e) => error!("Failed to create test secret: {e}"),
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let kube_client = Client::try_default().await?;
    info!("Confidential clusters operator",);
    let cl = Api::<ConfidentialCluster>::default_namespaced(kube_client.clone());

    let client = Arc::new(kube_client);
    Controller::new(cl, watcher::Config::default())
        .run::<_, Client>(reconcile, operator::controller_error_policy, client)
        .for_each(operator::controller_info)
        .await;

    Ok(())
}
