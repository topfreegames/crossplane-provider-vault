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

// JwtParameters are the configurable fields of a Jwt Auth Backend Role.
type JwtParameters struct {

	// The namespace to provision the resource in. The value should not contain
	// leading or trailing forward slashes. The namespace is always relative to
	// the provider's configured namespace
	// +optional
	Namespace *string `json:"namespace"`

	// Type of role, either "oidc" (default) or "jwt"
	// +kubebuilder:default:="oidc"
	// +kubebuilder:validation:Enum:=jwt;oidc
	// +optional
	RoleType *string `json:"type,omitempty"`

	// List of aud claims to match against. Any match is sufficient.
	// Required for roles of type jwt, optional for roles of type oidc)
	// +optional
	BoundAudiences []string `json:"boundAudiences,omitempty"`

	// The claim to use to uniquely identify the user; this will be used
	// as the name for the Identity entity alias created due to a successful login.
	UserClaim *string `json:"userClaim"`

	// Specifies if the user_claim value uses JSON pointer syntax for referencing claims.
	// By default, the user_claim value will not use JSON pointer. Requires Vault 1.11+.
	// +optional
	// +kubebuilder:default:=false
	UserClaimJSONPointer *bool `json:"userClaimJSONPointer,omitempty"`

	// If set, requires that the sub claim matches this value.
	// +optional
	// +kubebuilder:default:=""
	BoundSubject *string `json:"boundSubject,omitempty"`

	// f set, a map of claims to values to match against. A claim's value must be a string,
	//  which may contain one value or multiple comma-separated values, e.g. "red" or "red,green,blue"
	// +optional
	BoundClaims map[string]string `json:"boundClaims,omitempty"`

	// How to interpret values in the claims/values map (bound_claims): can be either string (exact match) or glob (wildcard match). Requires Vault 1.4.0 or above.
	// +optional
	// +kubebuilder:default:="string"
	// +kubebuilder:validation:Enum:=string;glob
	BoundClaimsType *string `json:"boundClaimsType,omitempty"`

	// If set, a map of claims (keys) to be copied to specified metadata fields (values).
	// +optional
	ClaimMappings map[string]string `json:"claimMappings,omitempty"`

	// If set, a list of OIDC scopes to be used with an OIDC role. The standard scope "openid" is
	//  automatically included and need not be specified.
	// +optional
	OIDCScopes []string `json:"oidcScopes,omitempty"`

	// The claim to use to uniquely identify the set of groups to which the user belongs;
	// this will be used as the names for the Identity group aliases created due to a successful login.
	// The claim value must be a list of strings.
	// +optional
	// +kubebuilder:default:=""
	GroupsClaim *string `json:"groupsClaim,omitempty"`

	// The unique name of the auth backend to configure. Defaults to jwt.
	// +optional
	// +kubebuilder:default:=jwt
	Backend *string `json:"backend,omitempty"`

	// The list of allowed values for redirect_uri during OIDC logins. Required for OIDC roles
	// +optional
	AllowedRedirectURIs []string `json:"allowedRedirectURIs,omitempty"`

	// The amount of leeway to add to all claims to account for clock skew, in seconds. Defaults to 60 seconds
	// if set to 0 and can be disabled if set to -1. Only applicable with "jwt" roles.
	// +optional
	ClockSkewLeeway *int `json:"clockSkewLeeway,omitempty"`

	// The amount of leeway to add to expiration (exp) claims to account for clock skew, in seconds.
	// Defaults to 60 seconds if set to 0 and can be disabled if set to -1. Only applicable with "jwt" roles.
	// +optional
	ExpirationLeeway *int `json:"expirationLeeway,omitempty"`

	// The amount of leeway to add to not before (nbf) claims to account for clock skew, in seconds.
	//  Defaults to 60 seconds if set to 0 and can be disabled if set to -1. Only applicable with "jwt" roles.
	// +optional
	NotBeforeLeeway *int `json:"notBeforeLeeway,omitempty"`

	// Log received OIDC tokens and claims when debug-level logging is active. Not recommended in production
	// since sensitive information may be present in OIDC responses.
	// +optional
	// +kubebuilder:default:=false
	VerboseOIDCLogging *bool `json:"verboseOIDCLogging,omitempty"`

	// Specifies the allowable elapsed time in seconds since the last time the user was actively
	// authenticated with the OIDC provider.
	// +optional
	// +kubebuilder:default:=0
	MaxAge *int `json:"maxAge,omitempty"`

	// The incremental lifetime for generated tokens. This current value of this will be referenced at renewal time.
	// +optional
	// +kubebuilder:default:=0
	TokenTTL *int `json:"tokenTTL,omitempty"`

	// The maximum lifetime for generated tokens. This current value of this will be referenced at renewal time.
	// +optional
	// +kubebuilder:default:=0
	TokenMaxTTL *int `json:"tokenMaxTTL,omitempty"`

	// List of policies to encode onto generated tokens.
	// Depending on the auth method, this list may be supplemented by user/group/other values.
	// +optional
	TokenPolicies []string `json:"tokenPolicies,omitempty"`

	// List of CIDR blocks; if set, specifies blocks of IP addresses which can authenticate successfully,
	// and ties the resulting token to these blocks as well.
	// +optional
	TokenBoundCIDRS []string `json:"tokenBoundCIDRs,omitempty"`

	// If set, will encode an explicit max TTL onto the token. This is a hard cap even if token_ttl
	// and token_max_ttl would otherwise allow a renewal.
	// +optional
	// +kubebuilder:default:=0
	TokenExplicitMaxTTL *int `json:"tokenExplicitMaxTTL,omitempty"`

	// If set, the default policy will not be set on generated tokens; otherwise it will be added to the policies set in token_policies.
	// +optional
	// +kubebuilder:default:=false
	TokenNoDefaultPolicy *bool `json:"tokenNoDefaultPolicy,omitempty"`

	// The maximum number of times a generated token may be used (within its lifetime); 0 means unlimited.
	// If you require the token to have the ability to create child tokens, you will need to set this value to 0.
	// +optional
	// +kubebuilder:default:=0
	TokenNumUses *int `json:"tokenNumUses,omitempty"`

	// The period, if any, to set on the token.
	// +optional
	// +kubebuilder:default:=0
	TokenPeriod *int `json:"tokenPeriod,omitempty"`

	// The type of token that should be generated. Can be service, batch, or default to use the mount's tuned
	// default (which unless changed will be service tokens). For token store roles, there are two additional
	// possibilities: default-service and default-batch which specify the type to return unless the client requests
	// a different type at generation time.
	// +optional
	// +kubebuilder:default:="default"
	// +kubebuilder:validation:Enum:=service;batch;default
	TokenType *string `json:"tokenType,omitempty"`
}

// JwtObservation are the observable fields of a Jwt.
type JwtObservation struct {
	ObservableField string `json:"observableField,omitempty"`
}

// A JwtSpec defines the desired state of a Jwt.
type JwtSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       JwtParameters `json:"forProvider"`
}

// A JwtStatus represents the observed state of a Jwt.
type JwtStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          JwtObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A Jwt is an example API type.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,vault}
type Jwt struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   JwtSpec   `json:"spec"`
	Status JwtStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// JwtList contains a list of Jwt
type JwtList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Jwt `json:"items"`
}

// Jwt type metadata.
var (
	JwtKind             = reflect.TypeOf(Jwt{}).Name()
	JwtGroupKind        = schema.GroupKind{Group: Group, Kind: JwtKind}.String()
	JwtKindAPIVersion   = JwtKind + "." + SchemeGroupVersion.String()
	JwtGroupVersionKind = SchemeGroupVersion.WithKind(JwtKind)
)

func init() {
	SchemeBuilder.Register(&Jwt{}, &JwtList{})
}
