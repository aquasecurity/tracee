package yaml

import (
	k8s "github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
)

// File type identifiers
const (
	TypeDetector = "detector"
)

// YAMLDetectorSpec represents the complete YAML detector specification.
// Only the Type field is specific to plain YAML format (not in CRD).
type YAMLDetectorSpec struct {
	// Type identifies the file type (REQUIRED for plain format, not present in CRD)
	// Value: "detector"
	Type string `yaml:"type"`

	// Embed k8s.DetectorSpec - all detector fields are defined here
	// Fields are promoted, so you can access spec.ID, spec.ProducedEvent, etc. directly
	k8s.DetectorSpec `yaml:",inline"`
}

// Type aliases for nested types - these are the same as k8s types, avoiding duplication
// When you add a field to k8s.ProducedEventSpec, it automatically appears here
type (
	// ProducedEventSpec is an alias for k8s.ProducedEventSpec
	// Add fields to k8s.ProducedEventSpec in tracee_types.go, they appear here automatically
	ProducedEventSpec = k8s.ProducedEventSpec

	// EventFieldSpec is an alias for k8s.EventFieldSpec
	EventFieldSpec = k8s.EventFieldSpec

	// RequirementsSpec is an alias for k8s.RequirementsSpec
	RequirementsSpec = k8s.RequirementsSpec

	// EventRequirementSpec is an alias for k8s.EventRequirementSpec
	EventRequirementSpec = k8s.EventRequirementSpec

	// EnrichmentRequirementSpec is an alias for k8s.EnrichmentRequirementSpec
	EnrichmentRequirementSpec = k8s.EnrichmentRequirementSpec

	// ThreatSpec is an alias for k8s.ThreatSpec
	ThreatSpec = k8s.ThreatSpec

	// MitreSpec is an alias for k8s.MitreSpec
	MitreSpec = k8s.MitreSpec

	// MitreTacticSpec is an alias for k8s.MitreTacticSpec
	MitreTacticSpec = k8s.MitreTacticSpec

	// MitreTechniqueSpec is an alias for k8s.MitreTechniqueSpec
	MitreTechniqueSpec = k8s.MitreTechniqueSpec

	// AutoPopulateSpec is an alias for k8s.AutoPopulateSpec
	AutoPopulateSpec = k8s.AutoPopulateSpec

	// OutputSpec is an alias for k8s.OutputSpec
	OutputSpec = k8s.OutputSpec

	// FieldSpec is an alias for k8s.FieldSpec
	FieldSpec = k8s.FieldSpec
)
