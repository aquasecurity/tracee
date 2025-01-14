package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:generate=false

// PolicyInterface is the interface of the policy object,
// it is used to allow tracee to support policies coming from kubernetes,
// or directly from the filesystem.
type PolicyInterface interface {
	GetName() string
	GetDescription() string
	GetScope() []string
	GetDefaultActions() []string
	GetRules() []Rule
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
type Policy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// tracee policy spec
	Spec PolicySpec `json:"spec"`
}

func (p Policy) GetName() string {
	return p.Name
}

func (p Policy) GetDescription() string {
	return p.Annotations["description"]
}

func (p Policy) GetScope() []string {
	return p.Spec.Scope
}

func (p Policy) GetDefaultActions() []string {
	return p.Spec.DefaultActions
}

func (p Policy) GetRules() []Rule {
	return p.Spec.Rules
}

// PolicySpec is the structure of the policy file
type PolicySpec struct {
	Scope []string `yaml:"scope" json:"scope"`
	// +optional
	DefaultActions []string `yaml:"defaultActions" json:"defaultActions"`
	Rules          []Rule   `yaml:"rules" json:"rules"`
}

// Rule is the structure of the rule in the policy file
type Rule struct {
	Event string `yaml:"event" json:"event"`
	// +optional
	Filters []string `yaml:"filters" json:"filters"`
	// +optional
	Actions []string `yaml:"actions" json:"actions"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// PolicyList contains a list of Policy
type PolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Policy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Policy{}, &PolicyList{})
}
