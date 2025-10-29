// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::Result;
use futures_util::StreamExt;
use k8s_openapi::{
    api::{
        apps::v1::{Deployment, DeploymentSpec},
        core::v1::{
            Container, ContainerPort, PodSpec, PodTemplateSpec, Service, ServicePort, ServiceSpec,
        },
    },
    apimachinery::pkg::{
        apis::meta::v1::{LabelSelector, ObjectMeta, OwnerReference},
        util::intstr::IntOrString,
    },
};
use kube::runtime::{
    controller::{Action, Controller},
    watcher,
};
use kube::{Api, Client, Resource, ResourceExt};
use log::info;
use std::{collections::BTreeMap, sync::Arc};

use crate::trustee;
use cocl_operator_lib::Machine;
use operator::{ControllerError, controller_error_policy, create_or_update};

const INTERNAL_REGISTER_SERVER_PORT: i32 = 8000;

pub async fn create_register_server_deployment(
    client: Client,
    owner_reference: OwnerReference,
    image: &str,
) -> Result<()> {
    let name = "register-server";
    let app_label = "register-server";
    let labels = BTreeMap::from([("app".to_string(), app_label.to_string())]);

    let mut deployment = Deployment {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            owner_references: Some(vec![owner_reference]),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(1),
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels.clone()),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    service_account_name: Some("cocl-operator".to_string()),
                    containers: vec![Container {
                        name: name.to_string(),
                        image: Some(image.to_string()),
                        ports: Some(vec![ContainerPort {
                            container_port: INTERNAL_REGISTER_SERVER_PORT,
                            ..Default::default()
                        }]),
                        args: Some(vec![
                            "--port".to_string(),
                            INTERNAL_REGISTER_SERVER_PORT.to_string(),
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

    create_or_update!(client, Deployment, deployment);
    info!("Register server deployment created/updated successfully");
    Ok(())
}

pub async fn create_register_server_service(
    client: Client,
    owner_reference: OwnerReference,
    register_server_port: Option<i32>,
) -> Result<()> {
    let name = "register-server";
    let app_label = "register-server";
    let labels = BTreeMap::from([("app".to_string(), app_label.to_string())]);

    let mut service = Service {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(labels.clone()),
            owner_references: Some(vec![owner_reference]),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            selector: Some(labels),
            ports: Some(vec![ServicePort {
                name: Some("http".to_string()),
                port: register_server_port.unwrap_or(INTERNAL_REGISTER_SERVER_PORT),
                target_port: Some(IntOrString::Int(INTERNAL_REGISTER_SERVER_PORT)),
                protocol: Some("TCP".to_string()),
                ..Default::default()
            }]),
            type_: Some("ClusterIP".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    create_or_update!(client, Service, service);
    info!("Register server service created/updated successfully");
    Ok(())
}

async fn keygen_reconcile(
    machine: Arc<Machine>,
    client: Arc<Client>,
) -> Result<Action, ControllerError> {
    let client = Arc::unwrap_or_clone(client);
    let id = &machine.spec.id;
    trustee::generate_secret(client.clone(), id).await?;
    trustee::mount_secret(client.clone(), id).await?;
    Ok(Action::await_change())
}

pub async fn launch_keygen_controller(client: Client) {
    let machines: Api<Machine> = Api::default_namespaced(client.clone());
    tokio::spawn(
        Controller::new(machines, watcher::Config::default())
            .run(keygen_reconcile, controller_error_policy, Arc::new(client))
            .for_each(|res| async move {
                match res {
                    Ok(o) => info!("reconciled {o:?}"),
                    Err(e) => info!("reconcile failed: {e:?}"),
                }
            }),
    );
}
