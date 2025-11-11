//  SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
//  SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
//  SPDX-License-Identifier: MIT

// Package v1alpha1 contains API Schema definitions for the confidential-clusters v1alpha1 API group.
// +kubebuilder:object:generate=true
// +groupName=confidential-clusters.io
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	// GroupVersion is group version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: "confidential-clusters.io", Version: "v1alpha1"}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;create;patch;update
// +kubebuilder:rbac:groups="",resources=services,verbs=create
// +kubebuilder:rbac:groups="",resources=secrets,verbs=create
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;create;update
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=create;delete;list;watch
// +kubebuilder:rbac:groups=confidential-clusters.io,resources=confidentialclusters,verbs=list;watch
// +kubebuilder:rbac:groups=confidential-clusters.io,resources=confidentialclusters/status,verbs=patch
// +kubebuilder:rbac:groups=confidential-clusters.io,resources=machines,verbs=create;list;delete;watch

// ConfidentialClusterSpec defines the desired state of ConfidentialCluster
type ConfidentialClusterSpec struct {
	// Image reference to Trustee all-in-one image
  // +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	TrusteeImage *string `json:"trusteeImage"`

	// Image reference to cocl-operator's compute-pcrs image
  // +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	PcrsComputeImage *string `json:"pcrsComputeImage"`

	// Image reference to cocl-operator's register-server image
  // +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	RegisterServerImage *string `json:"registerServerImage"`

	// Address where attester can connect to Trustee
	// +optional
	PublicTrusteeAddr *string `json:"publicTrusteeAddr,omitempty"`

	// Port that Trustee serves on
	// +optional
  // +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	TrusteeKbsPort int32 `json:"trusteeKbsPort,omitempty"`

	// Port that cocl-operator's register-server serves on
	// +optional
  // +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	RegisterServerPort int32 `json:"registerServerPort,omitempty"`
}

// ConfidentialClusterStatus defines the observed state of ConfidentialCluster.
type ConfidentialClusterStatus struct {
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// ConfidentialCluster is the Schema for the confidentialclusters API
type ConfidentialCluster struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of ConfidentialCluster
	// +required
	Spec ConfidentialClusterSpec `json:"spec"`

	// status defines the observed state of ConfidentialCluster
	// +optional
	Status ConfidentialClusterStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// ConfidentialClusterList contains a list of ConfidentialCluster
type ConfidentialClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []ConfidentialCluster `json:"items"`
}

// MachineSpec defines the desired state of Machine
type MachineSpec struct {
	// Machine ID, typically a UUID
	Id *string `json:"id"`
	// Machine address
	Address *string `json:"address"`
}

// MachineStatus defines the observed state of Machine.
type MachineStatus struct {
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// Machine is the Schema for the machines API
type Machine struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of Machine
	// +required
	Spec MachineSpec `json:"spec"`

	// status defines the observed state of Machine
	// +optional
	Status MachineStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// MachineList contains a list of Machine
type MachineList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []Machine `json:"items"`
}
