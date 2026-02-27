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

// +kubebuilder:object:generate=false

// DetectorInterface is the interface of the detector object,
// it is used to allow tracee to support detectors coming from kubernetes,
// or directly from the filesystem.
type DetectorInterface interface {
	GetID() string
	GetName() string
	GetSpec() *DetectorSpec
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
type Detector struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// tracee detector spec
	Spec DetectorSpec `json:"spec"`
}

func (d Detector) GetID() string {
	return d.Spec.ID
}

func (d Detector) GetName() string {
	return d.Name
}

func (d Detector) GetSpec() *DetectorSpec {
	return &d.Spec
}

// DetectorSpec is the structure of the detector spec (mirrors YAMLDetectorSpec)
// This type exists in v1beta1 for kubebuilder code generation
type DetectorSpec struct {
	// ID is the unique detector identifier (e.g., "TRC-YAML-001", "DRV-YAML-001")
	ID string `json:"id" yaml:"id"`

	// ProducedEvent defines the event this detector emits
	ProducedEvent ProducedEventSpec `json:"produced_event" yaml:"produced_event"`

	// Requirements specifies what this detector needs
	Requirements RequirementsSpec `json:"requirements" yaml:"requirements"`

	// Threat metadata (optional - presence determines if this is a threat detector)
	Threat *ThreatSpec `json:"threat,omitempty" yaml:"threat,omitempty"`

	// AutoPopulate specifies which fields the engine should auto-populate
	AutoPopulate AutoPopulateSpec `json:"auto_populate" yaml:"auto_populate"`

	// Conditions are CEL expressions that must all evaluate to true for detection
	Conditions []string `json:"conditions,omitempty" yaml:"conditions,omitempty"`

	// Output specifies how to extract fields from input events
	Output *OutputSpec `json:"output,omitempty" yaml:"output,omitempty"`
}

// ProducedEventSpec defines the event that this detector produces
type ProducedEventSpec struct {
	Name        string           `json:"name" yaml:"name"`
	Version     string           `json:"version" yaml:"version"`
	Description string           `json:"description" yaml:"description"`
	Tags        []string         `json:"tags,omitempty" yaml:"tags,omitempty"`
	Fields      []EventFieldSpec `json:"fields,omitempty" yaml:"fields,omitempty"`
}

// EventFieldSpec defines a single field in the event schema
type EventFieldSpec struct {
	Name        string `json:"name" yaml:"name"`
	Type        string `json:"type" yaml:"type"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Optional    bool   `json:"optional,omitempty" yaml:"optional,omitempty"`
}

// RequirementsSpec specifies detector dependencies and constraints
type RequirementsSpec struct {
	Events            []EventRequirementSpec    `json:"events,omitempty" yaml:"events,omitempty"`
	Enrichments       []EnrichmentRequirementSpec `json:"enrichments,omitempty" yaml:"enrichments,omitempty"`
	Architectures     []string                  `json:"architectures,omitempty" yaml:"architectures,omitempty"`
	MinTraceeVersion  string                    `json:"min_tracee_version,omitempty" yaml:"min_tracee_version,omitempty"`
	MaxTraceeVersion  string                    `json:"max_tracee_version,omitempty" yaml:"max_tracee_version,omitempty"`
}

// EventRequirementSpec specifies a required event and optional filters
type EventRequirementSpec struct {
	Name         string   `json:"name" yaml:"name"`
	Dependency   string   `json:"dependency,omitempty" yaml:"dependency,omitempty"`
	MinVersion   string   `json:"min_version,omitempty" yaml:"min_version,omitempty"`
	MaxVersion   string   `json:"max_version,omitempty" yaml:"max_version,omitempty"`
	DataFilters  []string `json:"data_filters,omitempty" yaml:"data_filters,omitempty"`
	ScopeFilters []string `json:"scope_filters,omitempty" yaml:"scope_filters,omitempty"`
}

// EnrichmentRequirementSpec specifies a required enrichment option
type EnrichmentRequirementSpec struct {
	Name       string `json:"name" yaml:"name"`
	Dependency string `json:"dependency,omitempty" yaml:"dependency,omitempty"`
	Config     string `json:"config,omitempty" yaml:"config,omitempty"`
}

// ThreatSpec defines threat metadata for threat detectors
type ThreatSpec struct {
	Name        string            `json:"name,omitempty" yaml:"name,omitempty"`
	Description string            `json:"description" yaml:"description"`
	Severity    string            `json:"severity" yaml:"severity"`
	Mitre       *MitreSpec        `json:"mitre,omitempty" yaml:"mitre,omitempty"`
	Properties  map[string]string `json:"properties,omitempty" yaml:"properties,omitempty"`
}

// MitreSpec defines MITRE ATT&CK framework mapping
type MitreSpec struct {
	Tactic    *MitreTacticSpec    `json:"tactic,omitempty" yaml:"tactic,omitempty"`
	Technique *MitreTechniqueSpec `json:"technique,omitempty" yaml:"technique,omitempty"`
}

// MitreTacticSpec defines a MITRE tactic
type MitreTacticSpec struct {
	Name string `json:"name" yaml:"name"`
}

// MitreTechniqueSpec defines a MITRE technique
type MitreTechniqueSpec struct {
	ID   string `json:"id" yaml:"id"`
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
}

// AutoPopulateSpec specifies which fields the engine should auto-populate
type AutoPopulateSpec struct {
	Threat          bool `json:"threat,omitempty" yaml:"threat,omitempty"`
	DetectedFrom    bool `json:"detected_from,omitempty" yaml:"detected_from,omitempty"`
	ProcessAncestry bool `json:"process_ancestry,omitempty" yaml:"process_ancestry,omitempty"`
}

// OutputSpec specifies how to extract and populate output event fields
type OutputSpec struct {
	Fields []FieldSpec `json:"fields,omitempty" yaml:"fields,omitempty"`
}

// FieldSpec defines a single field extraction rule
type FieldSpec struct {
	Name       string `json:"name" yaml:"name"`
	Expression string `json:"expression" yaml:"expression"`
	Optional   bool   `json:"optional,omitempty" yaml:"optional,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// DetectorList contains a list of Detector
type DetectorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Detector `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Policy{}, &PolicyList{})
	SchemeBuilder.Register(&Detector{}, &DetectorList{})
}
