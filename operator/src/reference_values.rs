// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::Context;
use chrono::Utc;
use compute_pcrs_lib::Pcr;
use futures_util::StreamExt;
use k8s_openapi::api::{
    batch::v1::{Job, JobSpec},
    core::v1::{
        ConfigMap, ConfigMapVolumeSource, Container, ImageVolumeSource, KeyToPath, PodSpec,
        PodTemplateSpec, Volume, VolumeMount,
    },
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::{DeleteParams, ObjectMeta, PostParams};
use kube::runtime::{
    controller::{Action, Controller},
    watcher,
};
use kube::{Api, Client};
use log::info;
use oci_client::secrets::RegistryAuth;
use oci_spec::image::ImageConfiguration;
use openssl::hash::{MessageDigest, hash};
use serde::Deserialize;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};

use crate::trustee::{self, get_image_pcrs};
use operator::{ControllerError, RvContextData, controller_error_policy, info_if_exists};
use rv_store::*;

const JOB_LABEL_KEY: &str = "kind";
const PCR_COMMAND_NAME: &str = "compute-pcrs";
const PCR_LABEL: &str = "org.coreos.pcrs";

/// Synchronize with compute_pcrs_cli::Output
#[derive(Deserialize)]
struct ComputePcrsOutput {
    pcrs: Vec<Pcr>,
}

pub async fn create_pcrs_config_map(client: Client) -> anyhow::Result<()> {
    let empty_data = BTreeMap::from([(
        PCR_CONFIG_FILE.to_string(),
        serde_json::to_string(&ImagePcrs::default())?,
    )]);
    let config_maps: Api<ConfigMap> = Api::default_namespaced(client);
    let config_map = ConfigMap {
        metadata: ObjectMeta {
            name: Some(PCR_CONFIG_MAP.to_string()),
            ..Default::default()
        },
        data: Some(empty_data),
        ..Default::default()
    };
    let create = config_maps
        .create(&PostParams::default(), &config_map)
        .await;
    info_if_exists!(create, "ConfigMap", PCR_CONFIG_MAP);

    Ok(())
}

async fn fetch_pcr_label(image_ref: &str) -> anyhow::Result<Option<Vec<Pcr>>> {
    let reference: oci_client::Reference = image_ref.parse()?;
    let client = oci_client::Client::new(Default::default());
    let (_, _, raw_config) = client
        .pull_manifest_and_config(&reference, &RegistryAuth::Anonymous)
        .await?;
    let config: ImageConfiguration = serde_json::from_str(&raw_config)?;
    config
        .labels_of_config()
        .and_then(|m| m.get(PCR_LABEL))
        .map(|l| serde_json::from_str::<ComputePcrsOutput>(l).map(|o| o.pcrs))
        .transpose()
        .map_err(Into::into)
}

fn build_compute_pcrs_pod_spec(boot_image: &str, pcrs_compute_image: &str) -> PodSpec {
    let image_volume_name = "image";
    let image_mountpoint = PathBuf::from(format!("/{image_volume_name}"));
    let pcrs_volume_name = "pcrs";
    let pcrs_mountpoint = PathBuf::from(format!("/{pcrs_volume_name}"));

    let mut cmd = vec![PCR_COMMAND_NAME.to_string()];
    let mut add_flag = |flag: &str, value: &str| {
        cmd.push(format!("--{flag}"));
        cmd.push(value.to_string());
    };
    for (flag, path_suffix) in [
        ("kernels", "usr/lib/modules"),
        ("esp", "usr/lib/bootupd/updates"),
    ] {
        let full_path = image_mountpoint.clone().join(path_suffix);
        add_flag(flag, full_path.to_str().unwrap());
    }
    for (flag, value) in [
        ("efivars", "/reference-values/efivars/qemu-ovmf/fedora-42"),
        ("mokvars", "/reference-values/mok-variables/fedora-42"),
        ("image", boot_image),
    ] {
        add_flag(flag, value);
    }

    PodSpec {
        service_account_name: Some("compute-pcrs".to_string()),
        containers: vec![Container {
            name: PCR_COMMAND_NAME.to_string(),
            image: Some(pcrs_compute_image.to_string()),
            command: Some(cmd),
            volume_mounts: Some(vec![
                VolumeMount {
                    name: image_volume_name.to_string(),
                    mount_path: image_mountpoint.to_str().unwrap().to_string(),
                    ..Default::default()
                },
                VolumeMount {
                    name: pcrs_volume_name.to_string(),
                    mount_path: pcrs_mountpoint.to_str().unwrap().to_string(),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        }],
        volumes: Some(vec![
            Volume {
                name: image_volume_name.to_string(),
                image: Some(ImageVolumeSource {
                    reference: Some(boot_image.to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            Volume {
                name: pcrs_volume_name.to_string(),
                config_map: Some(ConfigMapVolumeSource {
                    name: PCR_CONFIG_MAP.to_string(),
                    items: Some(vec![KeyToPath {
                        key: PCR_CONFIG_FILE.to_string(),
                        path: PCR_CONFIG_FILE.to_string(),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ]),
        restart_policy: Some("Never".to_string()),
        ..Default::default()
    }
}

async fn job_reconcile(job: Arc<Job>, ctx: Arc<RvContextData>) -> Result<Action, ControllerError> {
    let err = "Job changed, but had no name";
    let name = &job.metadata.name.clone().context(err)?;
    let err = format!("Job {name} changed, but had no status");
    let status = &job.status.clone().context(err)?;
    if status.completion_time.is_none() {
        info!("Job {name} changed, but had not completed");
        return Ok(Action::requeue(Duration::from_secs(300)));
    }
    let jobs: Api<Job> = Api::default_namespaced(ctx.client.clone());
    // Foreground deletion: Delete the pod too
    let delete = jobs.delete(name, &DeleteParams::foreground()).await;
    delete.map_err(Into::<anyhow::Error>::into)?;
    trustee::recompute_reference_values(Arc::unwrap_or_clone(ctx)).await?;
    Ok(Action::await_change())
}

pub async fn launch_rv_job_controller(ctx: RvContextData) {
    let jobs: Api<Job> = Api::default_namespaced(ctx.client.clone());
    let watcher = watcher::Config {
        label_selector: Some(format!("{JOB_LABEL_KEY}={PCR_COMMAND_NAME}")),
        ..Default::default()
    };
    tokio::spawn(
        Controller::new(jobs, watcher)
            .run(job_reconcile, controller_error_policy, Arc::new(ctx))
            .for_each(|res| async move {
                match res {
                    Ok(o) => info!("reconciled {o:?}"),
                    Err(e) => info!("reconcile failed: {e:?}"),
                }
            }),
    );
}

async fn compute_fresh_pcrs(
    client: Client,
    owner_reference: OwnerReference,
    boot_image: &str,
    pcrs_compute_image: &str,
) -> anyhow::Result<()> {
    // Name job by sanitized image name, plus a hash to disambiguate
    // tags that differed only beyond the truncation limit
    let rfc1035_boot_image = boot_image.replace(['.', ':', '/', '@', '_'], "-");
    let boot_image_hash = hash(MessageDigest::sha1(), boot_image.as_bytes())?;
    let mut boot_image_hash_str = hex::encode(boot_image_hash);
    boot_image_hash_str.truncate(10);
    let mut job_name = format!("{PCR_COMMAND_NAME}-{boot_image_hash_str}-{rfc1035_boot_image}");
    job_name.truncate(63);

    let pod_spec = build_compute_pcrs_pod_spec(boot_image, pcrs_compute_image);
    let job = Job {
        metadata: ObjectMeta {
            name: Some(job_name.clone()),
            labels: Some(BTreeMap::from([(
                JOB_LABEL_KEY.to_string(),
                PCR_COMMAND_NAME.to_string(),
            )])),
            owner_references: Some(vec![owner_reference]),
            ..Default::default()
        },
        spec: Some(JobSpec {
            template: PodTemplateSpec {
                spec: Some(pod_spec),
                ..Default::default()
            },
            ..Default::default()
        }),
        ..Default::default()
    };

    let jobs: Api<Job> = Api::default_namespaced(client);
    let create = jobs.create(&PostParams::default(), &job).await;
    info_if_exists!(create, "Job", job_name);
    Ok(())
}

pub async fn handle_new_image(ctx: RvContextData, boot_image: &str) -> anyhow::Result<()> {
    let config_maps: Api<ConfigMap> = Api::default_namespaced(ctx.client.clone());
    let mut image_pcrs_map = config_maps.get(PCR_CONFIG_MAP).await?;
    let mut image_pcrs = get_image_pcrs(image_pcrs_map.clone())?;
    if image_pcrs.0.contains_key(boot_image) {
        return Ok(());
    }
    let label = fetch_pcr_label(boot_image).await?;
    if label.is_none() {
        let client = ctx.client.clone();
        let owner = ctx.owner_reference.clone();
        let comp_img = &ctx.pcrs_compute_image;
        return compute_fresh_pcrs(client, owner, boot_image, comp_img).await;
    }

    let image_pcr = ImagePcr {
        first_seen: Utc::now(),
        pcrs: label.unwrap(),
    };
    // Non-goal: Support tags whose referenced versions change (e.g. `latest`).
    // This would introduce hard-to-define behavior for disallowing older versions that were
    // introduced as a tag that is still allowed.
    image_pcrs.0.insert(boot_image.to_string(), image_pcr);
    let image_pcrs_json = serde_json::to_string(&image_pcrs)?;
    let data = BTreeMap::from([(PCR_CONFIG_FILE.to_string(), image_pcrs_json.to_string())]);
    image_pcrs_map.data = Some(data);
    config_maps
        .replace(PCR_CONFIG_MAP, &PostParams::default(), &image_pcrs_map)
        .await?;
    trustee::recompute_reference_values(ctx).await
}

#[allow(dead_code)]
pub async fn disallow_image(ctx: RvContextData, boot_image: &str) -> anyhow::Result<()> {
    let config_maps: Api<ConfigMap> = Api::default_namespaced(ctx.client.clone());
    let mut image_pcrs_map = config_maps.get(PCR_CONFIG_MAP).await?;
    let mut image_pcrs = get_image_pcrs(image_pcrs_map.clone())?;
    if image_pcrs.0.remove(boot_image).is_none() {
        info!("Image {boot_image} was to be disallowed, but already was not allowed");
    }

    let image_pcrs_json = serde_json::to_string(&image_pcrs)?;
    let data = BTreeMap::from([(PCR_CONFIG_FILE.to_string(), image_pcrs_json.to_string())]);
    image_pcrs_map.data = Some(data);
    config_maps
        .replace(PCR_CONFIG_MAP, &PostParams::default(), &image_pcrs_map)
        .await?;
    trustee::recompute_reference_values(ctx).await
}
