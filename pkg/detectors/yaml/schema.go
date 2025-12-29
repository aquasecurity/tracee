package yaml

// YAMLDetectorSpec represents the complete YAML detector specification.
// It maps directly to the YAML file structure and provides full parity
// with Go DetectorDefinition from api/v1beta1/detection.
type YAMLDetectorSpec struct {
	// ID is the unique detector identifier (e.g., "TRC-YAML-001", "DRV-YAML-001")
	ID string `yaml:"id"`

	// ProducedEvent defines the event this detector emits
	ProducedEvent ProducedEventSpec `yaml:"produced_event"`

	// Requirements specifies what this detector needs
	Requirements RequirementsSpec `yaml:"requirements"`

	// Threat metadata (optional - presence determines if this is a threat detector)
	// If nil, this is a derived event detector
	Threat *ThreatSpec `yaml:"threat,omitempty"`

	// AutoPopulate specifies which fields the engine should auto-populate
	AutoPopulate AutoPopulateSpec `yaml:"auto_populate"`

	// Conditions are CEL expressions that must all evaluate to true for detection
	// Each condition is evaluated with access to the 'event' variable
	// Example: ["event.workload.container.id != \"\"", "hasData(event, \"pathname\")"]
	Conditions []string `yaml:"conditions,omitempty"`

	// Output specifies how to extract fields from input events
	Output *OutputSpec `yaml:"output,omitempty"`
}

// ProducedEventSpec defines the event that this detector produces
type ProducedEventSpec struct {
	// Name is the event name (e.g., "suspicious_shadow_write")
	Name string `yaml:"name"`

	// Version is the semantic version (e.g., "1.0.0")
	Version string `yaml:"version"`

	// Description is a human-readable description
	Description string `yaml:"description"`

	// Tags are event categories/tags (e.g., ["credential-access", "persistence"])
	Tags []string `yaml:"tags,omitempty"`

	// Fields define the schema for custom output fields (optional)
	// If present, extracted fields will be validated against this schema
	Fields []EventFieldSpec `yaml:"fields,omitempty"`
}

// EventFieldSpec defines a single field in the event schema
type EventFieldSpec struct {
	// Name is the field name
	Name string `yaml:"name"`

	// Type is the field type (string, int32, uint64, bool, bytes)
	Type string `yaml:"type"`

	// Description is a human-readable description
	Description string `yaml:"description,omitempty"`

	// Optional indicates if the field can be missing
	Optional bool `yaml:"optional,omitempty"`
}

// RequirementsSpec specifies detector dependencies and constraints
type RequirementsSpec struct {
	// Events lists the events this detector needs to receive
	Events []EventRequirementSpec `yaml:"events,omitempty"`

	// Enrichments lists required enrichment options (e.g., exec-hash)
	Enrichments []EnrichmentRequirementSpec `yaml:"enrichments,omitempty"`

	// Architectures lists supported CPU architectures (e.g., ["amd64", "arm64"])
	// Empty means all architectures supported
	Architectures []string `yaml:"architectures,omitempty"`

	// MinTraceeVersion specifies minimum Tracee version (e.g., "1.5.0")
	MinTraceeVersion string `yaml:"min_tracee_version,omitempty"`

	// MaxTraceeVersion specifies maximum Tracee version (e.g., "2.0.0")
	MaxTraceeVersion string `yaml:"max_tracee_version,omitempty"`
}

// EventRequirementSpec specifies a required event and optional filters
type EventRequirementSpec struct {
	// Name is the event name to subscribe to (e.g., "openat", "execve")
	Name string `yaml:"name"`

	// Dependency controls if this event is required or optional
	// Values: "required" (default if omitted) or "optional"
	Dependency string `yaml:"dependency,omitempty"`

	// MinVersion specifies minimum event version (e.g., "1.2.0")
	MinVersion string `yaml:"min_version,omitempty"`

	// MaxVersion specifies maximum event version (e.g., "2.0.0")
	MaxVersion string `yaml:"max_version,omitempty"`

	// DataFilters are event data filters using policy syntax
	// Examples: "pathname=/etc/shadow", "uid!=0"
	// Multiple filters for same field are OR'd, different fields are AND'd
	DataFilters []string `yaml:"data_filters,omitempty"`

	// ScopeFilters are event scope filters using policy syntax
	// Examples: "container=started", "pid=1000"
	ScopeFilters []string `yaml:"scope_filters,omitempty"`
}

// EnrichmentRequirementSpec specifies a required enrichment option
type EnrichmentRequirementSpec struct {
	// Name is the enrichment option name (e.g., "exec-hash", "exec-env")
	Name string `yaml:"name"`

	// Dependency controls if this enrichment is required or optional
	// Values: "required" (default if omitted) or "optional"
	Dependency string `yaml:"dependency,omitempty"`

	// Config contains enrichment-specific configuration
	// For exec-hash: "inode", "dev-inode", "digest-inode"
	Config string `yaml:"config,omitempty"`
}

// ThreatSpec defines threat metadata for threat detectors
type ThreatSpec struct {
	// Name is the threat name (e.g., "Shadow File Modification")
	Name string `yaml:"name,omitempty"`

	// Description is a detailed threat description
	Description string `yaml:"description"`

	// Severity is the threat severity level
	// Values: "low", "medium", "high", "critical"
	Severity string `yaml:"severity"`

	// Mitre contains MITRE ATT&CK framework mapping
	Mitre *MitreSpec `yaml:"mitre,omitempty"`

	// Properties are additional threat metadata key-value pairs
	Properties map[string]string `yaml:"properties,omitempty"`
}

// MitreSpec defines MITRE ATT&CK framework mapping
type MitreSpec struct {
	// Tactic is the MITRE tactic
	Tactic *MitreTacticSpec `yaml:"tactic,omitempty"`

	// Technique is the MITRE technique
	Technique *MitreTechniqueSpec `yaml:"technique,omitempty"`
}

// MitreTacticSpec defines a MITRE tactic
type MitreTacticSpec struct {
	// Name is the tactic name (e.g., "Credential Access")
	Name string `yaml:"name"`
}

// MitreTechniqueSpec defines a MITRE technique
type MitreTechniqueSpec struct {
	// ID is the technique ID (e.g., "T1003")
	ID string `yaml:"id"`

	// Name is the technique name (e.g., "OS Credential Dumping")
	Name string `yaml:"name,omitempty"`
}

// AutoPopulateSpec specifies which fields the engine should auto-populate
type AutoPopulateSpec struct {
	// Threat: Copy ThreatMetadata to output event's Threat field
	Threat bool `yaml:"threat,omitempty"`

	// DetectedFrom: Populate DetectedFrom field with reference to input event
	DetectedFrom bool `yaml:"detected_from,omitempty"`

	// ProcessAncestry: Populate process ancestry chain (requires ProcessStore)
	ProcessAncestry bool `yaml:"process_ancestry,omitempty"`
}

// OutputSpec specifies how to extract and populate output event fields
type OutputSpec struct {
	// Fields defines fields to extract from input events
	Fields []FieldSpec `yaml:"fields,omitempty"`
}

// FieldSpec defines a single field extraction rule
type FieldSpec struct {
	// Name is the output field name (required)
	Name string `yaml:"name"`

	// Expression is the CEL expression to compute the field value (required)
	// Examples: "getData("pathname")", "workload.container.id"
	Expression string `yaml:"expression"`

	// Optional indicates if the field can be missing without failing detection
	// If false (default), missing field causes detection to be skipped with warning
	// If true, missing field is silently ignored
	Optional bool `yaml:"optional,omitempty"`
}
