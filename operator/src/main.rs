// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use env_logger::Env;
use futures_util::StreamExt;
use kube::runtime::{
    controller::{Action, Controller},
    watcher,
};
use kube::{Api, Client, api::ListParams};

use log::{error, info};
use thiserror::Error;

use crds::ConfidentialCluster;
mod reference_values;
mod trustee;

#[derive(Debug, Error)]
enum Error {}

#[derive(Clone)]
struct ContextData {
    #[allow(dead_code)]
    client: Client,
}

const BOOT_IMAGE: &str = "quay.io/fedora/fedora-coreos:42.20250705.3.0";

async fn list_confidential_clusters(client: Client) -> anyhow::Result<ConfidentialCluster> {
    info!(
        "Listing ConfidentialClusters in namespace '{}'",
        client.default_namespace()
    );
    let api: Api<ConfidentialCluster> = Api::default_namespaced(client.clone());
    let lp = ListParams::default();
    let list = api.list(&lp).await?;
    match list.items.len() {
        0 => bail!("No confidential cluster resource found"),
        1 => {
            let item = &list.items[0];
            info!(
                "Found ConfidentialCluster: {}",
                item.metadata.name.as_deref().unwrap_or("<no name>"),
            );
            Ok(item.clone())
        }
        _ => bail!("too many confidential cluster resources defined in the namespace"),
    }
}

async fn reconcile(_g: Arc<ConfidentialCluster>, _ctx: Arc<ContextData>) -> Result<Action, Error> {
    Ok(Action::requeue(Duration::from_secs(300)))
}

async fn install_trustee_configuration(client: Client) -> Result<()> {
    let cocl = list_confidential_clusters(client.clone()).await?;
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
        pcrs_compute_image: cocl.spec.pcrs_compute_image,
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

    let client = Client::try_default().await?;
    let context = Arc::new(ContextData {
        client: client.clone(),
    });
    info!("Confidential clusters operator",);
    let cl = Api::<ConfidentialCluster>::default_namespaced(client.clone());

    tokio::spawn(install_trustee_configuration(client.clone()));
    Controller::new(cl, watcher::Config::default())
        .run::<_, ContextData>(reconcile, operator::controller_error_policy, context)
        .for_each(|res| async move {
            match res {
                Ok(o) => info!("reconciled {o:?}"),
                Err(e) => info!("reconcile failed: {e:?}"),
            }
        })
        .await;

    Ok(())
}
