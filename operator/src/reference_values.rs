use anyhow::Context;
use chrono::Utc;
use compute_pcrs_lib::Pcr;
use crds::{ImagePcr, ImagePcrs, PCR_CONFIG_FILE, PCR_CONFIG_MAP};
use k8s_openapi::api::{
    batch::v1::{Job, JobSpec},
    core::v1::{
        ConfigMap, ConfigMapVolumeSource, Container, ImageVolumeSource, KeyToPath, PodSpec,
        PodTemplateSpec, Volume, VolumeMount,
    },
};
use kube::api::{DeleteParams, ObjectMeta, PostParams};
use kube::runtime::wait::{await_condition, conditions::is_job_completed};
use kube::{Api, Client};
use log::info;
use oci_client::secrets::RegistryAuth;
use oci_spec::image::ImageConfiguration;
use serde::Deserialize;
use std::{collections::BTreeMap, path::PathBuf, time::Duration};
use tokio::time::timeout;

use crate::macros::info_if_exists;

const PCR_COMMAND_NAME: &str = "compute-pcrs";
const PCR_LABEL: &str = "org.coreos.pcrs";

/// Synchronize with compute_pcrs_cli::Output
#[derive(Deserialize)]
struct ComputePcrsOutput {
    pcrs: Vec<Pcr>,
}

pub async fn create_pcrs_config_map(client: Client, namespace: &str) -> anyhow::Result<()> {
    let empty_data = BTreeMap::from([(PCR_CONFIG_FILE.to_string(), r#"{"pcrs": {}}"#.to_string())]);
    let config_maps: Api<ConfigMap> = Api::namespaced(client, namespace);
    let config_map = ConfigMap {
        metadata: ObjectMeta {
            name: Some(PCR_CONFIG_MAP.to_string()),
            namespace: Some(namespace.to_string()),
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

pub fn get_image_pcrs(image_pcrs_map: ConfigMap) -> anyhow::Result<ImagePcrs> {
    let image_pcrs_data = image_pcrs_map
        .data
        .context("Image PCRs map existed, but had no data")?;
    let image_pcrs_str = image_pcrs_data
        .get(PCR_CONFIG_FILE)
        .context("Image PCRs data existed, but had no file")?;
    serde_json::from_str(image_pcrs_str).map_err(Into::into)
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

fn build_compute_pcrs_pod_spec(
    namespace: &str,
    boot_image: &str,
    pcrs_compute_image: &str,
) -> PodSpec {
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
        ("efivars", "/reference-values/efivars/qemu-ovmf/fcos-42"),
        ("mokvars", "/reference-values/mok-variables/fcos-42"),
        ("image", boot_image),
        ("namespace", namespace),
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

async fn compute_fresh_pcrs(
    client: Client,
    namespace: &str,
    boot_image: &str,
    pcrs_compute_image: &str,
) -> anyhow::Result<()> {
    let pod_spec = build_compute_pcrs_pod_spec(namespace, boot_image, pcrs_compute_image);
    let job = Job {
        metadata: ObjectMeta {
            name: Some(PCR_COMMAND_NAME.to_string()),
            namespace: Some(namespace.to_string()),
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

    let jobs: Api<Job> = Api::namespaced(client.clone(), namespace);
    let create = jobs.create(&PostParams::default(), &job).await;
    info_if_exists!(create, "Job", PCR_COMMAND_NAME);
    let completed = await_condition(jobs.clone(), PCR_COMMAND_NAME, is_job_completed());
    let _ = timeout(Duration::from_secs(900), completed).await?;
    jobs.delete(PCR_COMMAND_NAME, &DeleteParams::default())
        .await?;
    Ok(())
}

pub async fn handle_new_image(
    client: Client,
    namespace: &str,
    boot_image: &str,
    pcrs_compute_image: &str,
) -> anyhow::Result<()> {
    let config_maps: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    let mut image_pcrs_map = config_maps.get(PCR_CONFIG_MAP).await?;
    let mut image_pcrs = get_image_pcrs(image_pcrs_map.clone())?;
    if image_pcrs.pcrs.contains_key(boot_image) {
        return Ok(());
    }
    let label = fetch_pcr_label(boot_image).await?;
    if label.is_none() {
        return compute_fresh_pcrs(client, namespace, boot_image, pcrs_compute_image).await;
    }

    let image_pcr = ImagePcr {
        first_seen: Utc::now(),
        pcrs: label.unwrap(),
    };
    image_pcrs.pcrs.insert(boot_image.to_string(), image_pcr);
    let image_pcrs_json = serde_json::to_string(&image_pcrs)?;
    let data = BTreeMap::from([(PCR_CONFIG_FILE.to_string(), image_pcrs_json.to_string())]);
    image_pcrs_map.data = Some(data);
    config_maps
        .replace(PCR_CONFIG_MAP, &PostParams::default(), &image_pcrs_map)
        .await?;
    Ok(())
}

pub async fn disallow_image(
    client: Client,
    namespace: &str,
    boot_image: &str,
) -> anyhow::Result<()> {
    let config_maps: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    let mut image_pcrs_map = config_maps.get(PCR_CONFIG_MAP).await?;
    let mut image_pcrs = get_image_pcrs(image_pcrs_map.clone())?;
    if image_pcrs.pcrs.remove(boot_image).is_none() {
        info!("Image {boot_image} was to be disallowed, but already was not allowed");
    }

    let image_pcrs_json = serde_json::to_string(&image_pcrs)?;
    let data = BTreeMap::from([(PCR_CONFIG_FILE.to_string(), image_pcrs_json.to_string())]);
    image_pcrs_map.data = Some(data);
    config_maps
        .replace(PCR_CONFIG_MAP, &PostParams::default(), &image_pcrs_map)
        .await?;
    Ok(())
}
