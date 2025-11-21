// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use chrono::Utc;
use clap::Parser;
use compute_pcrs_lib::*;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::{Api, Client};

use trusted_cluster_operator_lib::{reference_values::*, update_image_pcrs};

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the kernel modules directory
    #[arg(short, long)]
    kernels: String,
    /// Path to the ESP directory
    #[arg(short, long)]
    esp: String,
    /// Path to the directory storing EFIVar files
    #[arg(short = 's', long)]
    efivars: String,
    /// Path to directory storing MokListRT, MokListTrustedRT and MokListXRT
    #[arg(short, long)]
    mokvars: String,
    /// Image reference
    #[arg(short, long)]
    image: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let pcrs = vec![
        compute_pcr4(&args.kernels, &args.esp, false, true),
        compute_pcr7(Some(&args.efivars), &args.esp, true),
        compute_pcr14(&args.mokvars),
    ];

    let client = Client::try_default().await?;
    let config_maps: Api<ConfigMap> = Api::default_namespaced(client);

    let mut image_pcrs_map = config_maps.get(PCR_CONFIG_MAP).await?;
    let image_pcrs_data = image_pcrs_map
        .data
        .context("Image PCRs map existed, but had no data")?;
    let image_pcrs_str = image_pcrs_data
        .get(PCR_CONFIG_FILE)
        .context("Image PCRs data existed, but had no file")?;
    let mut image_pcrs: ImagePcrs = serde_json::from_str(image_pcrs_str)?;

    let image_pcr = ImagePcr {
        first_seen: Utc::now(),
        pcrs,
    };
    image_pcrs.0.insert(args.image, image_pcr);
    update_image_pcrs!(config_maps, image_pcrs_map, image_pcrs);
    Ok(())
}
