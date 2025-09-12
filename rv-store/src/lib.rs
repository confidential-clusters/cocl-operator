use chrono::{DateTime, Utc};
use compute_pcrs_lib::Pcr;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const PCR_CONFIG_MAP: &str = "image-pcrs";
pub const PCR_CONFIG_FILE: &str = "image-pcrs.json";

#[derive(Deserialize, Serialize)]
pub struct ImagePcr {
    pub first_seen: DateTime<Utc>,
    pub pcrs: Vec<Pcr>,
}

#[derive(Default, Deserialize, Serialize)]
pub struct ImagePcrs(pub BTreeMap<String, ImagePcr>);
