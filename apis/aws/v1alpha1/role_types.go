/*
Copyright 2022 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
)

// RoleParameters are the configurable fields of a Role.
type RoleParameters struct {
	// Backend - (Required) The path the AWS secret backend is mounted at, with no leading or trailing /s.
	// +required
	Backend string `json:"authBackend"`

	// CredentialType - (Required) Specifies the type of credential to be used when retrieving credentials from the role. Must be one of iam_user, assumed_role, or federation_token.
	// https://www.vaultproject.io/docs/secrets/aws
	// +required
	CredentialType string `json:"credentialType"`

	// IamRolesArn - (Optional) Specifies the ARNs of the AWS roles this Vault role is allowed to assume. Required when credential_type is assumed_role and prohibited otherwise.
	// +optional
	IamRolesArn []string `json:"iamRolesArn,omitempty"`

	// PoliciesArn - (Optional) Specifies a list of AWS managed policy ARNs. The behavior depends on the credential type. With iam_user, the policies will be attached to IAM users when they are requested. With assumed_role and federation_token, the policy ARNs will act as a filter on what the credentials can do, similar to policy_document. When credential_type is iam_user or federation_token, at least one of policy_document or policy_arns must be specified.
	// +optional
	PoliciesArn []string `json:"policiesArn,omitempty"`

	// PolicyDocument - (Optional) The IAM policy document for the role. The behavior depends on the credential type. With iam_user, the policy document will be attached to the IAM user generated and augment the permissions the IAM user has. With assumed_role and federation_token, the policy document will act as a filter on what the credentials can do, similar to policy_arns.
	// +optional
	PolicyDocument string `json:"policyDocument,omitempty"`

	// IamGroups - (Optional) A list of IAM group names. IAM users generated against this vault role will be added to these IAM Groups. For a credential type of assumed_role or federation_token, the policies sent to the corresponding AWS call (sts:AssumeRole or sts:GetFederation) will be the policies from each group in iam_groups combined with the policy_document and policy_arns parameters.
	// +optional
	IamGroups []string `json:"iamGroups,omitempty"`

	// UserPath - (Optional) The path for the user name. Valid only when credential_type is iam_user. Default is /.
	// +optional
	UserPath string `json:"userPath,omitempty"`

	// PermissionBoundaryArn - (Optional) The ARN of the AWS Permissions Boundary to attach to IAM users created in the role. Valid only when credential_type is iam_user. If not specified, then no permissions boundary policy will be attached.
	// +optional
	PermissionBoundaryArn string `json:"permissionsBoundaryArn,omitempty"`

	// DefaultStsTTL -  (Optional) The default TTL in seconds for STS credentials. When a TTL is not specified when STS credentials are requested, and a default TTL is specified on the role, then this default TTL will be used. Valid only when credential_type is one of assumed_role or federation_token.
	// +optional
	DefaultStsTTL int `json:"defaultStsTtl,omitempty"`

	// MaxStsTTL - (Optional) The max allowed TTL in seconds for STS credentials (credentials TTL are capped to max_sts_ttl). Valid only when credential_type is one of assumed_role or federation_token.
	// +optional
	MaxStsTTL int `json:"maxStsTtl,omitempty"`
}

// RoleObservation are the observable fields of a Role.
type RoleObservation struct {
	ObservableField string `json:"observableField,omitempty"`
}

// A RoleSpec defines the desired state of a Role.
type RoleSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       RoleParameters `json:"forProvider"`
}

// A RoleStatus represents the observed state of a Role.
type RoleStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          RoleObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A Role is an example API type.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,vault}
type Role struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RoleSpec   `json:"spec"`
	Status RoleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RoleList contains a list of Role
type RoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Role `json:"items"`
}

// Role type metadata.
var (
	RoleKind             = reflect.TypeOf(Role{}).Name()
	RoleGroupKind        = schema.GroupKind{Group: Group, Kind: RoleKind}.String()
	RoleKindAPIVersion   = RoleKind + "." + SchemeGroupVersion.String()
	RoleGroupVersionKind = SchemeGroupVersion.WithKind(RoleKind)
)

func init() {
	SchemeBuilder.Register(&Role{}, &RoleList{})
}
