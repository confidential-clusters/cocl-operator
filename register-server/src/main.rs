// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use clap::Parser;
use clevis_pin_trustee_lib::{Config as ClevisConfig, Server as ClevisServer};
use crds::Machine;
use env_logger::Env;
use ignition_config::v3_5::{
    Clevis, ClevisCustom, Config as IgnitionConfig, Filesystem, Luks, Storage,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::{Api, Client};
use log::{error, info};
use std::convert::Infallible;
use std::net::SocketAddr;
use uuid::Uuid;
use warp::{http::StatusCode, reply, Filter};

#[derive(Parser)]
#[command(name = "register-server")]
#[command(about = "HTTP server that generates Clevis PINs with random UUIDs")]
struct Args {
    #[arg(short, long, default_value = "8000")]
    port: u16,

    #[arg(long)]
    public_addr: String,
}

fn generate_ignition(id: &str, public_addr: &str) -> IgnitionConfig {
    let clevis_conf = ClevisConfig {
        servers: vec![ClevisServer {
            url: format!("http://{public_addr}"),
            cert: "".to_string(),
        }],
        path: format!("default/{id}/root"),
        // TODO add initdata, e.g.
        // #[derive(Serialize)]
        // struct Initdata {
        //     uuid: String,
        // }
        // let initdata = Initdata {
        //     uuid: id.to_string(),
        // };
        // ... initdata: serde_json::to_string(&initdata)?,
        // depending on ultimate design decision
    };

    let luks_root = "root";

    let mut fs = Filesystem::new(format!("/dev/mapper/{luks_root}"));
    fs.format = Some("ext4".to_string());
    fs.label = Some(luks_root.to_string());
    fs.wipe_filesystem = Some(true);

    let mut luks = Luks::new(luks_root.to_string());
    luks.clevis = Some(Clevis {
        custom: Some(ClevisCustom {
            config: Some(serde_json::to_string(&clevis_conf).unwrap()),
            needs_network: Some(true),
            pin: Some("trustee".to_string()),
        }),
        ..Default::default()
    });
    luks.device = Some(format!("/dev/disk/by-partlabel/{luks_root}"));
    luks.label = Some(luks_root.to_string());
    luks.wipe_volume = Some(true);

    IgnitionConfig {
        storage: Some(Storage {
            filesystems: Some(vec![fs]),
            luks: Some(vec![luks]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn register_handler(
    remote_addr: Option<SocketAddr>,
    public_addr: String,
) -> Result<impl warp::Reply, Infallible> {
    let id = Uuid::new_v4().to_string();
    let client_ip = remote_addr
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    info!("Registration request from IP: {client_ip}");

    let internal_error = |e: anyhow::Error| {
        let code = StatusCode::INTERNAL_SERVER_ERROR;
        error!("{e}");
        let msg = serde_json::json!({
            "code": code.as_u16(),
            "message": e.to_string(),
        });
        Ok(reply::with_status(reply::json(&msg), code))
    };

    match create_machine(&id, &client_ip).await {
        Ok(_) => info!("Machine created successfully: machine-{id}"),
        Err(e) => return internal_error(e.context("Failed to create machine")),
    }

    Ok(reply::with_status(
        reply::json(&generate_ignition(&id, &public_addr)),
        StatusCode::OK,
    ))
}

async fn create_machine(uuid: &str, client_ip: &str) -> anyhow::Result<()> {
    let client = Client::try_default().await?;
    let machines: Api<Machine> = Api::default_namespaced(client);

    // Check for existing machines with the same IP
    let machine_list = machines.list(&Default::default()).await?;

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

    let register_route = warp::path("ignition-clevis-pin-trustee")
        .and(warp::get())
        .and(warp::addr::remote())
        .and(warp::any().map(move || args.public_addr.clone()))
        .and_then(register_handler);

    let routes = register_route;

    info!("Starting server on http://localhost:{}", args.port);
    warp::serve(routes).run(([0, 0, 0, 0], args.port)).await;
}
