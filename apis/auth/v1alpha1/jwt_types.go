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

// JwtParameters are the configurable fields of a Jwt.
type JwtParameters struct {
	ConfigurableField string `json:"configurableField"`
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
