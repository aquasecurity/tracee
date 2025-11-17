package yaml

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

// YAMLDetector implements the EventDetector interface for YAML-defined detectors
type YAMLDetector struct {
	// Store definition fields individually to avoid copying protobuf structs with locks
	id string

	// ProducedEvent fields (stored individually to avoid copying EventDefinition)
	eventName        string
	eventVersion     *v1beta1.Version
	eventDescription string
	eventTags        []string
	eventFields      []*v1beta1.EventField

	requirements   detection.DetectorRequirements
	threatMetadata *v1beta1.Threat
	autoPopulate   detection.AutoPopulateFields

	// CEL fields
	celEnv          *cel.Env            // CEL environment (created once, rebuilt in Init if datastores available)
	conditions      []cel.Program       // Compiled condition expressions
	conditionExprs  []string            // Original condition expressions (for recompilation with datastores)
	fieldExtractors []celFieldExtractor // Compiled field extractors
	fieldSpecs      []FieldSpec         // Original field specs (for recompilation with datastores)
	lists           map[string][]string // Shared list variables for CEL

	// Detector runtime fields
	logger     detection.Logger
	datastores datastores.Registry // Access to system state
	source     string              // YAML file path for debugging
	timeout    time.Duration       // CEL evaluation timeout (default 5ms)
}

// celFieldExtractor holds compiled CEL program for field extraction
type celFieldExtractor struct {
	name     string
	program  cel.Program // CEL program for expression evaluation
	optional bool        // true if field is optional
}

// NewDetector creates a new YAML detector from a parsed and validated specification
// lists: optional map of shared list variables to expose in CEL environment
func NewDetector(def *detection.DetectorDefinition, spec *YAMLDetectorSpec, lists map[string][]string, source string) (*YAMLDetector, error) {
	// Extract fields from definition to avoid copying protobuf structs with locks
	// Store EventDefinition fields individually to avoid copying the struct
	detector := &YAMLDetector{
		id:               def.ID,
		eventName:        def.ProducedEvent.Name,
		eventVersion:     def.ProducedEvent.Version,
		eventDescription: def.ProducedEvent.Description,
		eventTags:        def.ProducedEvent.Tags,
		eventFields:      def.ProducedEvent.Fields,
		requirements:     def.Requirements,
		threatMetadata:   def.ThreatMetadata,
		autoPopulate:     def.AutoPopulate,
		lists:            lists,
		source:           source,
		timeout:          5 * time.Millisecond, // Default timeout: 5x the "Critical" (>1ms) metric threshold
	}

	// Store condition expressions and field specs for compilation/recompilation
	detector.conditionExprs = spec.Conditions
	if spec.Output != nil {
		detector.fieldSpecs = spec.Output.Fields
	}

	// Create CEL environment and compile expressions (no datastores yet - will be added in Init)
	if err := detector.compileCELPrograms(nil); err != nil {
		return nil, err
	}

	return detector, nil
}

// GetDefinition returns the detector definition (called once at registration)
// Constructs the definition inline to avoid copying protobuf structs with locks
func (d *YAMLDetector) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: d.id,
		ProducedEvent: v1beta1.EventDefinition{
			Name:        d.eventName,
			Version:     d.eventVersion,
			Description: d.eventDescription,
			Tags:        d.eventTags,
			Fields:      d.eventFields,
		},
		Requirements:   d.requirements,
		ThreatMetadata: d.threatMetadata,
		AutoPopulate:   d.autoPopulate,
	}
}

// Init initializes the detector with provided parameters
func (d *YAMLDetector) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.datastores = params.DataStores // Store for CEL datastore functions

	// Rebuild CEL environment with datastores now available and recompile all expressions
	if d.datastores != nil {
		if err := d.compileCELPrograms(d.datastores); err != nil {
			return fmt.Errorf("failed to recompile with datastores: %w", err)
		}
	}

	if d.logger != nil {
		d.logger.Debugw("YAML detector initialized",
			"detector_id", d.id,
			"source", d.source,
			"event", d.eventName,
		)
	}

	return nil
}

// compileCELPrograms creates CEL environment and compiles all conditions and field extractors
// registry: optional registry for datastore access (nil during initial load, non-nil during Init)
func (d *YAMLDetector) compileCELPrograms(registry datastores.Registry) error {
	// Create CEL environment
	var err error
	d.celEnv, err = createCELEnvironment(d.lists, registry)
	if err != nil {
		return fmt.Errorf("failed to create CEL environment: %w", err)
	}

	// Compile conditions
	d.conditions = d.conditions[:0] // Clear existing if recompiling
	for i, condExpr := range d.conditionExprs {
		prog, err := CompileCondition(d.celEnv, condExpr)
		if err != nil {
			return fmt.Errorf("failed to compile condition %d (%s): %w", i, condExpr, err)
		}
		d.conditions = append(d.conditions, prog)
	}

	// Compile field extractors
	d.fieldExtractors = d.fieldExtractors[:0] // Clear existing if recompiling
	for _, fieldSpec := range d.fieldSpecs {
		prog, err := CompileExpression(d.celEnv, fieldSpec.Expression)
		if err != nil {
			return fmt.Errorf("failed to compile expression for field %s (%s): %w", fieldSpec.Name, fieldSpec.Expression, err)
		}
		d.fieldExtractors = append(d.fieldExtractors, celFieldExtractor{
			name:     fieldSpec.Name,
			program:  prog,
			optional: fieldSpec.Optional,
		})
	}

	return nil
}

// OnEvent processes an event and returns zero or more detection outputs
func (d *YAMLDetector) OnEvent(_ context.Context, event *v1beta1.Event) (outputs []detection.DetectorOutput, err error) {
	// Recover from panics to prevent a single malformed detector from crashing Tracee
	defer func() {
		if r := recover(); r != nil {
			if d.logger != nil {
				d.logger.Errorw("Panic in YAML detector OnEvent",
					"detector_id", d.id,
					"source", d.source,
					"panic", r,
				)
			}
			// Return error instead of propagating panic
			err = fmt.Errorf("panic in detector %s: %v", d.id, r)
			outputs = nil
		}
	}()

	// Evaluate CEL conditions (all must be true)
	for i, condProg := range d.conditions {
		result, evalErr := EvaluateCondition(condProg, event, d.lists, d.timeout)
		if evalErr != nil {
			if d.logger != nil {
				d.logger.Warnw("CEL condition evaluation error, treating as false",
					"detector_id", d.id,
					"condition_index", i,
					"error", evalErr.Error(),
				)
			}
			return nil, nil // Treat evaluation error as false
		}

		if !result {
			// Condition is false, don't fire detection
			return nil, nil
		}
	}

	// Extract fields using CEL expressions
	var dataValues []*v1beta1.EventValue

	for _, extractor := range d.fieldExtractors {
		// Evaluate CEL expression
		value, evalErr := EvaluateExpression(extractor.program, event, d.lists, d.timeout)
		if evalErr != nil {
			if !extractor.optional {
				if d.logger != nil {
					d.logger.Warnw("Required field extraction failed, skipping detection",
						"detector_id", d.id,
						"field", extractor.name,
						"error", evalErr.Error(),
					)
				}
				return nil, nil
			}
			// Optional field failed - skip it
			continue
		}

		// Convert to EventValue
		eventValue, convErr := convertToEventValue(extractor.name, value)
		if convErr != nil {
			if d.logger != nil {
				d.logger.Warnw("Failed to convert field value",
					"detector_id", d.id,
					"field", extractor.name,
					"error", convErr.Error(),
				)
			}
			if !extractor.optional {
				return nil, nil
			}
			continue
		}

		dataValues = append(dataValues, eventValue)
	}

	// Engine will auto-populate Threat, DetectedFrom, ProcessAncestry based on AutoPopulate settings
	// Engine will also assign EventID and Name based on ProducedEvent

	return []detection.DetectorOutput{{Data: dataValues}}, nil
}

// convertToEventValue converts a Go value to an EventValue
func convertToEventValue(name string, value interface{}) (*v1beta1.EventValue, error) {
	if value == nil {
		return nil, errors.New("value is nil")
	}

	// Handle CEL NullValue (when field doesn't exist)
	// CEL returns types.Null as the actual null value
	if value == types.NullValue {
		return nil, errors.New("field not found (null value)")
	}

	switch v := value.(type) {
	case string:
		return v1beta1.NewStringValue(name, v), nil
	case int:
		// Safe conversion: check for overflow
		if v > math.MaxInt32 || v < math.MinInt32 {
			return nil, fmt.Errorf("int value %d overflows int32 range", v)
		}
		return v1beta1.NewInt32Value(name, int32(v)), nil
	case int32:
		return v1beta1.NewInt32Value(name, v), nil
	case int64:
		// Safe conversion: check for overflow
		if v > math.MaxInt32 || v < math.MinInt32 {
			return nil, fmt.Errorf("int64 value %d overflows int32 range", v)
		}
		return v1beta1.NewInt32Value(name, int32(v)), nil
	case uint:
		// Safe conversion: check for overflow
		if v > math.MaxUint32 {
			return nil, fmt.Errorf("uint value %d overflows uint32 range", v)
		}
		return v1beta1.NewUInt32Value(name, uint32(v)), nil
	case uint32:
		return v1beta1.NewUInt32Value(name, v), nil
	case uint64:
		// Use uint64 type if value doesn't fit in uint32
		if v > math.MaxUint32 {
			return v1beta1.NewUInt64Value(name, v), nil
		}
		return v1beta1.NewUInt32Value(name, uint32(v)), nil
	case bool:
		return v1beta1.NewBoolValue(name, v), nil
	case []byte:
		return v1beta1.NewBytesValue(name, v), nil
	default:
		return nil, fmt.Errorf("unsupported value type: %T", value)
	}
}

// LoadFromFile loads a YAML detector from a file (convenience function for testing)
// For production use, call LoadFromDirectory which handles shared lists
func LoadFromFile(filePath string) (*YAMLDetector, error) {
	// No shared lists when loading individual files
	return loadFromFile(filePath, nil)
}

// loadFromFile loads a YAML detector from a file with optional shared lists
func loadFromFile(filePath string, lists map[string][]string) (*YAMLDetector, error) {
	// Parse and validate the YAML file (pass lists for validation)
	def, spec, err := ParseAndValidate(filePath, lists)
	if err != nil {
		return nil, fmt.Errorf("failed to load YAML detector from %s: %w", filePath, err)
	}

	// Create the detector with shared lists
	detector, err := NewDetector(def, spec, lists, filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create detector from %s: %w", filePath, err)
	}

	return detector, nil
}
