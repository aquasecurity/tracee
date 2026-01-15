package detection

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

// EventDetector is the core interface that all detectors must implement.
// Detectors analyze events and produce derived events or threat detections.
type EventDetector interface {
	// GetDefinition returns the static definition of what this detector produces
	// and requires. This is called once during registration and the result is cached.
	GetDefinition() DetectorDefinition

	// Init is called once when the detector is registered, before any events are processed.
	// Detectors should initialize any required state and validate their requirements.
	Init(params DetectorParams) error

	// OnEvent processes a single event and returns zero or more detection outputs.
	// Returning nil or empty slice means no detection occurred.
	// Detectors should not modify the input event.
	// The engine constructs full v1beta1.Event objects from the returned outputs.
	OnEvent(ctx context.Context, event *v1beta1.Event) ([]DetectorOutput, error)
}

// DetectorOutput represents a single detection result from a detector.
// Detectors return this lightweight struct; the engine constructs the full v1beta1.Event.
type DetectorOutput struct {
	// Data contains the detector's findings (required)
	// These become the Event.Data field in the output event
	Data []*v1beta1.EventValue

	// AutoPopulate specifies which fields the engine should populate for this output.
	// If nil, engine uses defaults from DetectorDefinition.AutoPopulate.
	// Use case: vary auto-population based on detection confidence/severity
	AutoPopulate *AutoPopulateFields

	// Threat overrides the static ThreatMetadata from DetectorDefinition.
	// If set, engine uses this instead of Definition.ThreatMetadata.
	// Use case: dynamic severity, runtime threat properties, custom threat per detection
	// If nil and AutoPopulate.Threat=true, engine uses Definition.ThreatMetadata
	Threat *v1beta1.Threat

	// AncestryDepth overrides the process ancestry depth for this detection.
	// Priority: output.AncestryDepth > definition.ProcessAncestry (default 5).
	// Values: nil (use ProcessAncestry boolean), 0 (disable), 1+ (fetch N levels)
	// Use case: request deep ancestry for high-severity detections, or disable for performance
	AncestryDepth *uint32

	// Future extensibility (commented for documentation):
	// Timestamp *timestamppb.Timestamp  // Override input timestamp (rare)
	// Workload  *v1beta1.Workload       // Override input workload (rare)
}

// Detected returns a single detection with no additional data.
// Use this when all relevant information is already present in the triggering
// event and will be auto-populated by the engine according to the detector's
// AutoPopulate settings from DetectorDefinition.
//
// Example:
//
//	if d.isThreat(event) {
//	    return detection.Detected(), nil
//	}
func Detected() []DetectorOutput {
	return []DetectorOutput{{}}
}

// DetectedWithData returns a single detection with additional event data.
// Use this when you need to include extra information beyond what's available
// in the triggering event. The provided data will be included in the output
// event's Data field, in addition to any auto-populated fields.
//
// Example:
//
//	return detection.DetectedWithData([]*v1beta1.EventValue{
//	    v1beta1.NewStringValue("env_var", envValue),
//	}), nil
func DetectedWithData(data []*v1beta1.EventValue) []DetectorOutput {
	return []DetectorOutput{{Data: data}}
}

// DetectorCloser is an optional interface for detectors that need cleanup.
// If implemented, Close() will be called during shutdown.
type DetectorCloser interface {
	EventDetector
	Close() error
}

// DetectorDefinition describes what a detector produces and what it requires.
type DetectorDefinition struct {
	// ID is a unique identifier for this detector (e.g., "TRC-001", "DRV-001")
	ID string

	// Requirements specifies what events and data stores this detector needs
	Requirements DetectorRequirements

	// ProducedEvent defines the event that this detector emits
	ProducedEvent v1beta1.EventDefinition

	// ThreatMetadata is populated for threat detectors (optional for derived events)
	ThreatMetadata *v1beta1.Threat

	// AutoPopulate specifies which fields the engine should automatically populate
	AutoPopulate AutoPopulateFields
}

// DetectorRequirements specifies dependencies and requirements for a detector.
type DetectorRequirements struct {
	// Events lists the events this detector needs to receive
	Events []EventRequirement `yaml:"events,omitempty"`

	// DataStores lists required datastores with their dependency types
	DataStores []DataStoreRequirement `yaml:"datastores,omitempty"`

	// Enrichments lists required event enrichment options
	Enrichments []EnrichmentRequirement `yaml:"enrichments,omitempty"`

	// Architectures lists supported CPU architectures (e.g., "amd64", "arm64")
	// Empty slice means the detector supports all architectures
	// Values should use Go's GOARCH format: "amd64" (x86-64), "arm64" (AArch64), etc.
	Architectures []string `yaml:"architectures,omitempty"`

	// MinTraceeVersion specifies minimum Tracee version (optional, inclusive)
	MinTraceeVersion *v1beta1.Version `yaml:"min_tracee_version,omitempty"`

	// MaxTraceeVersion specifies maximum Tracee version (optional, exclusive)
	MaxTraceeVersion *v1beta1.Version `yaml:"max_tracee_version,omitempty"`
}

// DependencyType specifies how a detector depends on an event
type DependencyType int

const (
	DependencyRequired DependencyType = iota // 0 (zero value) - Hard dependency, fail if unavailable
	DependencyOptional                       // 1 - Soft dependency, graceful degradation
)

// EventRequirement specifies a required event and optional filters.
// Combines dependency declaration, version constraints, and dispatch filtering.
type EventRequirement struct {
	// Name is the event name to subscribe to (e.g., "openat", "execve")
	Name string `yaml:"name"`

	// Dependency controls whether this event is required or optional
	// Zero value (0) = DependencyRequired (default)
	Dependency DependencyType `yaml:"dependency,omitempty"`

	// MinVersion specifies minimum event version (optional, inclusive)
	MinVersion *v1beta1.Version `yaml:"min_version,omitempty"`

	// MaxVersion specifies maximum event version (optional, exclusive)
	MaxVersion *v1beta1.Version `yaml:"max_version,omitempty"`

	// DataFilters are event data filters using policy syntax
	// Examples: "pathname=/etc/shadow", "uid!=0"
	DataFilters []string `yaml:"data_filters,omitempty"`

	// ScopeFilters are event scope filters using policy syntax
	ScopeFilters []string `yaml:"scope_filters,omitempty"`
}

// DataStoreRequirement specifies a required datastore with dependency type.
type DataStoreRequirement struct {
	// Name is the datastore name: "process", "container", "symbol", "dns"
	Name string `yaml:"name"`

	// Dependency controls whether this datastore is required or optional
	// Zero value (0) = DependencyRequired (default)
	// - Required: Registration fails if datastore unavailable
	// - Optional: Detector handles absence gracefully
	Dependency DependencyType `yaml:"dependency,omitempty"`
}

// EnrichmentRequirement specifies a required event enrichment option.
type EnrichmentRequirement struct {
	// Name is the enrichment option name: "environment", "executable-hash"
	Name string `yaml:"name"`

	// Dependency controls whether this enrichment is required or optional
	// Zero value (0) = DependencyRequired (default)
	Dependency DependencyType `yaml:"dependency,omitempty"`

	// Config contains enrichment-specific configuration (e.g., executable-hash mode)
	// For executable-hash: "inode", "dev-inode", "digest-inode"
	Config string `yaml:"config,omitempty"`
}

// AutoPopulateFields specifies which output event fields the engine should populate.
type AutoPopulateFields struct {
	// Threat: Copy ThreatMetadata to output event's Threat field
	Threat bool

	// DetectedFrom: Populate DetectedBy field with detector ID
	DetectedFrom bool

	// ProcessAncestry: Populate process ancestry chain (requires ProcessStore)
	ProcessAncestry bool
}

// DetectorParams provides context and resources to detectors during initialization.
type DetectorParams struct {
	// Logger for detector to use (scoped to detector ID)
	Logger Logger

	// DataStores provides access to system state information
	DataStores datastores.Registry

	// Config provides detector-specific configuration
	Config DetectorConfig
}

// Logger is the logging interface for detectors.
// It uses structured logging with key-value pairs, matching Tracee's logging style.
// Engine implementations typically wrap Tracee's logger and automatically inject detector_id.
type Logger interface {
	// Debugw logs a debug message with structured key-value pairs
	Debugw(msg string, keysAndValues ...any)

	// Infow logs an informational message with structured key-value pairs
	Infow(msg string, keysAndValues ...any)

	// Warnw logs a warning message with structured key-value pairs
	Warnw(msg string, keysAndValues ...any)

	// Errorw logs an error message with structured key-value pairs
	Errorw(msg string, keysAndValues ...any)
}
