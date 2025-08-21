use anyhow::anyhow;
use chrono::{DateTime, Utc};
use compute_pcrs_lib::Pcr;
use futures_util::{AsyncBufReadExt, StreamExt};
use k8s_openapi::api::{
    batch::v1::{Job, JobSpec},
    core::v1::{Container, ImageVolumeSource, Pod, PodSpec, PodTemplateSpec, Volume, VolumeMount},
};
use kube::api::{ListParams, LogParams, ObjectMeta, PostParams};
use kube::runtime::wait::{await_condition, conditions::is_job_completed};
use kube::{Api, Client};
use log::info;
use serde::{Deserialize, Serialize, Serializer};
use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::macros::info_if_exists;

const BOOT_IMAGE: &str = "quay.io/fedora/fedora-coreos:42.20250705.3.0";
const COMPUTE_IMAGE: &str = "quay.io/jnaucke/compute-pcrs:latest";
// from https://github.com/confidential-clusters/reference-values
const EFIVARS_PATH: &str = "efivars/qemu-ovmf/fcos-42";
const MOKVARS_PATH: &str = "mok-variables/fcos-42";

fn primitive_date_time_to_str<S>(d: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// Sync with Trustee
/// reference_value_provider_service::reference_value::ReferenceValue
/// (cannot import directly because its expiration doesn't serialize
/// right)
#[derive(Serialize)]
pub struct ReferenceValue {
    pub version: String,
    pub name: String,
    #[serde(serialize_with = "primitive_date_time_to_str")]
    pub expiration: DateTime<Utc>,
    pub value: serde_json::Value,
}

/// Sync with compute-pcrs cli::Output (is not public)
#[derive(Deserialize)]
struct ComputePcrsOutput {
    pcrs: Vec<Pcr>,
}

pub type ComputedPcrs = BTreeMap<u64, String>;

pub async fn compute_pcrs(client: Client, namespace: &str) -> anyhow::Result<ComputedPcrs> {
    let job_name = "compute-pcrs";
    let volume_name = "image";
    let mountpoint = PathBuf::from("/image");
    let reference_values = PathBuf::from("reference-values");

    let mut command = vec!["compute-pcrs".to_string(), "all".to_string()];
    for (flag, base_path, path) in [
        ("kernels", mountpoint.clone(), "usr/lib/modules"),
        ("esp", mountpoint.clone(), "usr/lib/bootupd/updates"),
        ("efivars", reference_values.clone(), EFIVARS_PATH),
        ("mok-variables", reference_values, MOKVARS_PATH),
    ] {
        command.push(format!("--{flag}"));
        command.push(base_path.join(path).to_str().unwrap().to_string());
    }
    command.push("2> /dev/null".to_string());
    let sh_command = vec!["sh".to_string(), "-c".to_string(), command.join(" ")];

    let pod_spec = PodSpec {
        containers: vec![Container {
            name: job_name.to_string(),
            image: Some(COMPUTE_IMAGE.to_string()),
            command: Some(sh_command),
            volume_mounts: Some(vec![VolumeMount {
                name: volume_name.to_string(),
                mount_path: mountpoint.to_str().unwrap().to_string(),
                ..Default::default()
            }]),
            ..Default::default()
        }],
        volumes: Some(vec![Volume {
            name: volume_name.to_string(),
            image: Some(ImageVolumeSource {
                reference: Some(BOOT_IMAGE.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        }]),
        restart_policy: Some("Never".to_string()),
        ..Default::default()
    };
    let job = Job {
        metadata: ObjectMeta {
            name: Some(job_name.to_string()),
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
    info_if_exists!(create, "Job", job_name);
    await_condition(jobs, job_name, is_job_completed()).await?;

    // k8s can log a pod, but not the Rust crate
    let pods: Api<Pod> = Api::namespaced(client, namespace);
    let lp = ListParams::default().labels(&format!("job-name={job_name}"));
    let pods_list = pods.list(&lp).await?;
    let pod = pods_list.items.first();
    let pod = pod.ok_or(anyhow!("Job {job_name} completed, but had no pod"))?;
    let pod_name = pod.metadata.name.clone();
    let pod_name = pod_name.ok_or(anyhow!("Job {job_name} had a pod, but pod had no name"))?;

    let logs = pods.log_stream(&pod_name, &LogParams::default()).await?;
    let mut iter = logs.lines();
    let mut json = String::new();
    while let Some(Ok(line)) = iter.next().await {
        json.push_str(&line);
    }
    let parsed: ComputePcrsOutput = serde_json::from_str(&json)?;
    let res = parsed.pcrs.iter().map(|s| (s.id, s.value.clone()));
    Ok(res.collect())
}
