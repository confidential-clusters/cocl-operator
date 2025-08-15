use anyhow::Result;
use crds::Machine;
use k8s_openapi::{
    api::{
        apps::v1::{Deployment, DeploymentSpec},
        core::v1::{Container, ContainerPort, PodSpec, PodTemplateSpec, Service, ServiceAccount, ServicePort, ServiceSpec},
        rbac::v1::{PolicyRule, Role, RoleBinding, RoleRef, Subject},
    },
    apimachinery::pkg::{
        apis::meta::v1::{LabelSelector, ObjectMeta},
        util::intstr::IntOrString,
    },
};
use kube::{Api, Client, Resource};
use log::info;
use std::collections::BTreeMap;

pub async fn create_register_server_rbac(
    client: Client,
    namespace: &str,
) -> Result<()> {
    let name = "register-server";

    // Create ServiceAccount
    let service_account = ServiceAccount {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        ..Default::default()
    };

    let sa_api: Api<ServiceAccount> = Api::namespaced(client.clone(), namespace);
    match sa_api.get(name).await {
        Ok(_) => {
            info!("Register server service account already exists");
        }
        Err(_) => {
            info!("Creating register server service account...");
            sa_api.create(&Default::default(), &service_account).await?;
        }
    }

    // Create Role for Machine permissions
    let role = Role {
        metadata: ObjectMeta {
            name: Some(format!("{}-role", name)),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        rules: Some(vec![
            PolicyRule {
                api_groups: Some(vec![Machine::group(&()).to_string()]),
                resources: Some(vec![Machine::plural(&()).to_string()]),
                verbs: vec![
                    "create".to_string(),
                    "get".to_string(),
                    "list".to_string(),
                    "delete".to_string(),
                ],
                ..Default::default()
            },
        ]),
    };

    let role_api: Api<Role> = Api::namespaced(client.clone(), namespace);
    let role_name = format!("{}-role", name);
    match role_api.get(&role_name).await {
        Ok(_) => {
            info!("Register server role already exists, updating...");
            role_api.replace(&role_name, &Default::default(), &role).await?;
        }
        Err(_) => {
            info!("Creating register server role...");
            role_api.create(&Default::default(), &role).await?;
        }
    }

    // Create RoleBinding
    let role_binding = RoleBinding {
        metadata: ObjectMeta {
            name: Some(format!("{}-rolebinding", name)),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_string(),
            kind: "Role".to_string(),
            name: role_name,
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".to_string(),
            name: name.to_string(),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        }]),
    };

    let rb_api: Api<RoleBinding> = Api::namespaced(client.clone(), namespace);
    let rb_name = format!("{}-rolebinding", name);
    match rb_api.get(&rb_name).await {
        Ok(_) => {
            info!("Register server role binding already exists, updating...");
            rb_api.replace(&rb_name, &Default::default(), &role_binding).await?;
        }
        Err(_) => {
            info!("Creating register server role binding...");
            rb_api.create(&Default::default(), &role_binding).await?;
        }
    }

    info!("Register server RBAC created/updated successfully");
    Ok(())
}

pub async fn create_register_server_deployment(
    client: Client,
    namespace: &str,
    image: &str,
) -> Result<()> {
    let name = "register-server";
    let app_label = "register-server";
    let labels = BTreeMap::from([("app".to_string(), app_label.to_string())]);

    let deployment = Deployment {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels.clone()),
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
                    service_account_name: Some(name.to_string()),
                    containers: vec![Container {
                        name: name.to_string(),
                        image: Some(image.to_string()),
                        ports: Some(vec![ContainerPort {
                            container_port: 3030,
                            name: Some("http".to_string()),
                            protocol: Some("TCP".to_string()),
                            ..Default::default()
                        }]),
                        args: Some(vec![
                            "--port".to_string(), "3030".to_string(),
                            "--namespace".to_string(), namespace.to_string()
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

    let api: Api<Deployment> = Api::namespaced(client, namespace);

    match api.get(name).await {
        Ok(_) => {
            info!("Register server deployment already exists, updating...");
            api.replace(name, &Default::default(), &deployment).await?;
        }
        Err(_) => {
            info!("Creating register server deployment...");
            api.create(&Default::default(), &deployment).await?;
        }
    }

    info!("Register server deployment created/updated successfully");
    Ok(())
}

pub async fn create_register_server_service(
    client: Client,
    namespace: &str,
) -> Result<()> {
    let name = "register-server";
    let app_label = "register-server";
    let labels = BTreeMap::from([("app".to_string(), app_label.to_string())]);

    let service = Service {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels.clone()),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            selector: Some(labels),
            ports: Some(vec![ServicePort {
                name: Some("http".to_string()),
                port: 3030,
                target_port: Some(IntOrString::Int(3030)),
                protocol: Some("TCP".to_string()),
                ..Default::default()
            }]),
            type_: Some("ClusterIP".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let api: Api<Service> = Api::namespaced(client, namespace);

    match api.get(name).await {
        Ok(_) => {
            info!("Register server service already exists, updating...");
            api.replace(name, &Default::default(), &service).await?;
        }
        Err(_) => {
            info!("Creating register server service...");
            api.create(&Default::default(), &service).await?;
        }
    }

    info!("Register server service created/updated successfully");
    Ok(())
}
