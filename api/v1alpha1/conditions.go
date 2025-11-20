// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

package v1alpha1

const (
	InstalledCondition string = "Installed"
	InstalledReason string = "Installed"
	NotInstalledReasonNonUnique string = "NonUnique"
	NotInstalledReasonInstalling string = "Installing"
	NotInstalledReasonUninstalling string = "Uninstalling"

	KnownTrusteeAddressCondition string = "KnownTrusteeAddress"
	KnownTrusteeAddressReason string = "AddressFound"
	UnknownTrusteeAddressReason string = "NoAddressFound"

	CommittedCondition string = "Committed"
	CommittedReason string = "Committed"
	NotCommittedReasonComputing string = "Computing"
	NotCommittedReasonNoDigest string = "NoDigestGiven"
	NotCommittedReasonFailed string = "ComputationFailed"
)
