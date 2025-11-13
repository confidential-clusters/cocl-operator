// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

pub mod conditions;
pub mod reference_values;

mod kopium;
pub use kopium::machines::*;
pub use kopium::trustedexecutionclusters::*;

#[macro_export]
macro_rules! update_status {
    ($api:ident, $name:expr, $status:expr) => {{
        let patch = kube::api::Patch::Merge(serde_json::json!({"status": $status}));
        $api.patch_status($name, &Default::default(), &patch).await
            .map_err(Into::<anyhow::Error>::into)
    }}
}

pub fn condition_status(status: bool) -> String {
    match status {
        true => "True".to_string(),
        false => "False".to_string(),
    }
}
