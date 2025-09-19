// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

// This file has two intended purposes:
// - Speed up development by allowing for building dependencies in a lower container image layer.
// - Provide definitions and functionalities to be used across modules in this crate.
//
// Use in other crates is not an intended purpose.

use kube::{Client, runtime::controller::Action};
use std::{fmt::Display, sync::Arc, time::Duration};

#[derive(Clone)]
pub struct RvContextData {
    pub client: Client,
    pub trustee_namespace: String,
    pub pcrs_compute_image: String,
    pub rv_map: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ControllerError {
    #[error("{0}")]
    Anyhow(#[from] anyhow::Error),
}

pub fn controller_error_policy<R, E: Display, C>(_obj: Arc<R>, error: &E, _ctx: Arc<C>) -> Action {
    log::error!("{error}");
    Action::requeue(Duration::from_secs(60))
}

#[macro_export]
macro_rules! info_if_exists {
    ($result:ident, $resource_type:literal, $resource_name:expr) => {
        match $result {
            Ok(_) => info!("Create {} {}", $resource_type, $resource_name),
            Err(kube::Error::Api(ae)) if ae.code == 409 => {
                info!("{} {} already exists", $resource_type, $resource_name)
            }
            Err(e) => return Err(e.into()),
        }
    };
}
