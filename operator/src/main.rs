use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use env_logger::Env;
use futures_util::StreamExt;
use kube::runtime::reflector::Lookup;
use kube::runtime::{
    controller::{Action, Controller},
    watcher,
};
use kube::{api::ListParams, Api, Client};

use log::{error, info};
use thiserror::Error;

use crds::ConfidentialCluster;
mod trustee;

#[derive(Debug, Error)]
enum Error {}

#[derive(Clone)]
struct ContextData {
    client: Client,
}

async fn list_confidential_clusters(client: Client) -> anyhow::Result<ConfidentialCluster> {
    let namespace = client.default_namespace();
    info!("Listing ConfidentialClusters in namespace '{}'", namespace);
    let api: Api<ConfidentialCluster> = Api::namespaced(client.clone(), namespace);
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
            return Ok(item.deref().clone());
        }
        _ => bail!("too many confidential cluster resources defined in the namespace"),
    }
}

async fn reconcile(g: Arc<ConfidentialCluster>, _ctx: Arc<ContextData>) -> Result<Action, Error> {
    Ok(Action::requeue(Duration::from_secs(300)))
}
fn error_policy(obj: Arc<ConfidentialCluster>, _error: &Error, _ctx: Arc<ContextData>) -> Action {
    Action::requeue(Duration::from_secs(60))
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

    match trustee::generate_kbs_configuration(
        client.clone(),
        &trustee_namespace,
        &cocl.spec.trustee.kbs_configuration,
    )
    .await
    {
        Ok(_) => info!(
            "Generate configmap for the KBS configuration: {}",
            cocl.spec.trustee.kbs_configuration
        ),
        Err(e) => error!("Failed to create the KBS configuration configmap: {e}"),
    }

    match trustee::generate_reference_values(
        client.clone(),
        &trustee_namespace,
        &cocl.spec.trustee.reference_values,
    )
    .await
    {
        Ok(_) => info!(
            "Generate configmap for the reference values: {}",
            cocl.spec.trustee.reference_values
        ),
        Err(e) => error!("Failed to create the reference values configmap: {e}"),
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

    // TODO: remove, right now only for testing
    let secret = "test-secret".to_string();
    match trustee::generate_secret(client.clone(), &trustee_namespace, &secret).await {
        Ok(_) => info!("Generate test secret",),
        Err(e) => error!("Failed to create test secret: {e}"),
    }

    match trustee::generate_kbs(
        client.clone(),
        &trustee_namespace,
        &cocl.spec.trustee,
        &secret,
    )
    .await
    {
        Ok(_) => info!(
            "Generate the KBS configuration: {}",
            cocl.spec.trustee.kbs_config_name
        ),
        Err(e) => error!("Failed to create the KBS configuration: {e}"),
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
    info!(
        "Confidential clusters operator",
    );
    let cl = Api::<ConfidentialCluster>::all(client.clone());

    tokio::spawn(install_trustee_configuration(
        client.clone(),
    ));
    Controller::new(cl, watcher::Config::default())
        .run::<_, ContextData>(reconcile, error_policy, context)
        .for_each(|res| async move {
            match res {
                Ok(o) => info!("reconciled {:?}", o),
                Err(e) => info!("reconcile failed: {:?}", e),
            }
        })
        .await;

    Ok(())
}
