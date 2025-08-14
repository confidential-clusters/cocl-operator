// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
//
// SPDX-License-Identifier: MIT

use clap::Parser;
use crds::Machine;
use env_logger::Env;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::{api::ListParams, Api, Client};
use log::{error, info};
use serde::Serialize;
use std::convert::Infallible;
use std::net::SocketAddr;
use uuid::Uuid;
use warp::Filter;

#[derive(Parser)]
#[command(name = "register-server")]
#[command(about = "HTTP server that generates random UUIDs")]
struct Args {
    #[arg(short, long, default_value = "3030")]
    port: u16,
}

#[derive(Serialize)]
struct Metadata {
    id: String,
}

async fn register_handler(remote_addr: Option<SocketAddr>) -> Result<impl warp::Reply, Infallible> {
    let id = Uuid::new_v4().to_string();
    let client_ip = remote_addr
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    info!("Registration request from IP: {client_ip}");

    match create_machine(&id, &client_ip).await {
        Ok(_) => info!("Machine created successfully: machine-{id}"),
        Err(e) => error!("Failed to create Machine: {e}"),
    }

    let response = Metadata { id };
    Ok(warp::reply::json(&response))
}

async fn create_machine(
    uuid: &str,
    client_ip: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::try_default().await?;
    let machines: Api<Machine> = Api::default_namespaced(client);

    // Check for existing machines with the same IP
    let list_params = ListParams::default();
    let machine_list = machines.list(&list_params).await?;

    for existing_machine in machine_list.items {
        if existing_machine.spec.address == client_ip {
            if let Some(name) = &existing_machine.metadata.name {
                info!("Found existing machine {name} with IP {client_ip}, deleting...");
                machines.delete(name, &Default::default()).await?;
                info!("Deleted existing machine: {name}");
            }
        }
    }

    let machine_name = format!("machine-{uuid}");
    let machine = Machine {
        metadata: ObjectMeta {
            name: Some(machine_name.clone()),
            ..Default::default()
        },
        spec: crds::MachineSpec {
            id: uuid.to_string(),
            address: client_ip.to_string(),
        },
    };

    machines.create(&Default::default(), &machine).await?;
    info!("Created Machine: {machine_name} with IP: {client_ip}");
    Ok(())
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    let register_route = warp::path("register")
        .and(warp::get())
        .and(warp::addr::remote())
        .and_then(register_handler);

    let routes = register_route;

    info!("Starting server on http://localhost:{}", args.port);
    warp::serve(routes).run(([127, 0, 0, 1], args.port)).await;
}
