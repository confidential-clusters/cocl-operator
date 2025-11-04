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
)
