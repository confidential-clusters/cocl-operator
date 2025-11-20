// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

pub const INSTALLED_CONDITION: &str = "Installed";
pub const INSTALLED_REASON: &str = "Installed";
pub const NOT_INSTALLED_REASON_NON_UNIQUE: &str = "NonUnique";
pub const NOT_INSTALLED_REASON_INSTALLING: &str = "Installing";
pub const NOT_INSTALLED_REASON_UNINSTALLING: &str = "Uninstalling";

pub const KNOWN_TRUSTEE_ADDRESS_CONDITION: &str = "KnownTrusteeAddress";
pub const KNOWN_TRUSTEE_ADDRESS_REASON: &str = "AddressFound";
pub const UNKNOWN_TRUSTEE_ADDRESS_REASON: &str = "NoAddressFound";

pub const COMMITTED_CONDITION: &str = "Committed";
pub const COMMITTED_REASON: &str = "Committed";
pub const NOT_COMMITTED_REASON_COMPUTING: &str = "Computing";
pub const NOT_COMMITTED_REASON_NO_DIGEST: &str = "NoDigestGiven";
pub const NOT_COMMITTED_REASON_FAILED: &str = "ComputationFailed";
