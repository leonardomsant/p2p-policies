/*
Copyright 2025.

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

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// P2PSecurityPolicySpec defines the desired state of P2PSecurityPolicy
type P2PSecurityPolicySpec struct {
	Nodes     []string `json:"nodes"`
	Policies  []string `json:"policies"`
	Protocols []string `json:"protocols"`
}

// P2PSecurityPolicyStatus defines the observed state of P2PSecurityPolicy
type P2PSecurityPolicyStatus struct {
	LastUpdated metav1.Time `json:"lastUpdated,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// P2PSecurityPolicy is the Schema for the p2psecuritypolicies API
type P2PSecurityPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   P2PSecurityPolicySpec   `json:"spec,omitempty"`
	Status P2PSecurityPolicyStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// P2PSecurityPolicyList contains a list of P2PSecurityPolicy
type P2PSecurityPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []P2PSecurityPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&P2PSecurityPolicy{}, &P2PSecurityPolicyList{})
}
