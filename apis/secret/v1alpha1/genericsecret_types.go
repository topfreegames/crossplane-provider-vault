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

// GenericSecretParameters are the configurable fields of a GenericSecret.
type GenericSecretParameters struct {
	ConfigurableField string `json:"configurableField"`
}

// GenericSecretObservation are the observable fields of a GenericSecret.
type GenericSecretObservation struct {
	ObservableField string `json:"observableField,omitempty"`
}

// A GenericSecretSpec defines the desired state of a GenericSecret.
type GenericSecretSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       GenericSecretParameters `json:"forProvider"`
}

// A GenericSecretStatus represents the observed state of a GenericSecret.
type GenericSecretStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          GenericSecretObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A GenericSecret is an example API type.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,vault}
type GenericSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GenericSecretSpec   `json:"spec"`
	Status GenericSecretStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// GenericSecretList contains a list of GenericSecret
type GenericSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GenericSecret `json:"items"`
}

// GenericSecret type metadata.
var (
	GenericSecretKind             = reflect.TypeOf(GenericSecret{}).Name()
	GenericSecretGroupKind        = schema.GroupKind{Group: Group, Kind: GenericSecretKind}.String()
	GenericSecretKindAPIVersion   = GenericSecretKind + "." + SchemeGroupVersion.String()
	GenericSecretGroupVersionKind = SchemeGroupVersion.WithKind(GenericSecretKind)
)

func init() {
	SchemeBuilder.Register(&GenericSecret{}, &GenericSecretList{})
}
