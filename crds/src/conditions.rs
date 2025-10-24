// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use chrono::Utc;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};

use super::NotInstalledReason;

pub fn condition_status(status: bool) -> String {
    match status {
        true => "True".to_string(),
        false => "False".to_string(),
    }
}

pub fn known_trustee_address_condition(known: bool, generation: Option<i64>) -> Condition {
    let err = "No publicTrusteeAddr specified. Components can deploy, \
               but register-server will not be able to point to Trustee until you add an address";
    let (reason, message) = match known {
        true => (super::ADDRESS_FOUND_REASON.to_string(), ""),
        false => (format!("No{}", super::ADDRESS_FOUND_REASON), err),
    };
    Condition {
        type_: super::KNOWN_TRUSTEE_ADDRESS_CONDITION.to_string(),
        status: condition_status(known),
        reason,
        message: message.to_string(),
        last_transition_time: Time(Utc::now()),
        observed_generation: generation,
    }
}

pub fn installed_condition(
    reason: Option<NotInstalledReason>,
    generation: Option<i64>,
) -> Condition {
    Condition {
        type_: super::INSTALLED_CONDITION.to_string(),
        status: condition_status(reason.is_none()),
        reason: match reason {
            Some(ref r) => format!("{r:?}"),
            None => super::INSTALLED_REASON.to_string(),
        },
        message: match reason {
            Some(NotInstalledReason::NonUnique) => {
                "Another ConfidentialCluster definition was detected. \
                 Only one at a time is supported."
            }
            Some(NotInstalledReason::Installing) => "Installation is in progress",
            Some(NotInstalledReason::Uninstalling) => "Uninstalling",
            None => "",
        }
        .to_string(),
        last_transition_time: Time(Utc::now()),
        observed_generation: generation,
    }
}
