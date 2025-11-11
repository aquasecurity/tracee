package yaml

import (
	"context"
	"fmt"
	"time"

	"github.com/aquasecurity/tracee/api/v1beta1"
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

	// Detector runtime fields
	extractors []FieldExtractor
	logger     detection.Logger
	source     string        // YAML file path for debugging
	timeout    time.Duration // Execution timeout for OnEvent
}

// NewDetector creates a new YAML detector from a parsed and validated specification
func NewDetector(def *detection.DetectorDefinition, spec *YAMLDetectorSpec, source string) (*YAMLDetector, error) {
	// Build extractors if output is specified
	var extractors []FieldExtractor
	var err error

	if spec.Output != nil {
		extractors, err = BuildExtractors(spec.Output)
		if err != nil {
			return nil, fmt.Errorf("failed to build extractors: %w", err)
		}
	}

	// Extract fields from definition to avoid copying protobuf structs with locks
	// Store EventDefinition fields individually to avoid copying the struct
	return &YAMLDetector{
		id:               def.ID,
		eventName:        def.ProducedEvent.Name,
		eventVersion:     def.ProducedEvent.Version,
		eventDescription: def.ProducedEvent.Description,
		eventTags:        def.ProducedEvent.Tags,
		eventFields:      def.ProducedEvent.Fields,
		requirements:     def.Requirements,
		threatMetadata:   def.ThreatMetadata,
		autoPopulate:     def.AutoPopulate,
		extractors:       extractors,
		source:           source,
		timeout:          5 * time.Millisecond, // Default timeout: 5x the "Critical" (>1ms) metric threshold
	}, nil
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

	if d.logger != nil {
		d.logger.Debugw("YAML detector initialized",
			"detector_id", d.id,
			"source", d.source,
			"event", d.eventName,
		)
	}

	return nil
}

// OnEvent processes an event and returns zero or more detection outputs
func (d *YAMLDetector) OnEvent(_ context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Extract fields if extractors are defined
	var dataValues []*v1beta1.EventValue

	if len(d.extractors) > 0 {
		dataValues = make([]*v1beta1.EventValue, 0, len(d.extractors))

		for _, extractor := range d.extractors {
			value, err := extractor.Extract(event)
			if err != nil {
				if !extractor.IsOptional() {
					// Required field missing - skip detection gracefully
					if d.logger != nil {
						d.logger.Warnw("Required field missing, skipping detection",
							"detector_id", d.id,
							"field", extractor.Name(),
							"source", d.source,
							"error", err.Error(),
						)
					}
					return nil, nil
				}
				// Optional field missing - continue without it
				continue
			}

			dataValues = append(dataValues, value)
		}
	}

	// Engine will auto-populate Threat, DetectedFrom, ProcessAncestry based on AutoPopulate settings
	// Engine will also assign EventID and Name based on ProducedEvent

	return []detection.DetectorOutput{{Data: dataValues}}, nil
}

// LoadFromFile loads a YAML detector from a file
// This is a convenience function that combines parsing, validation, and detector creation
func LoadFromFile(filePath string) (*YAMLDetector, error) {
	// Parse and validate the YAML file
	def, spec, err := ParseAndValidate(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load YAML detector from %s: %w", filePath, err)
	}

	// Create the detector
	detector, err := NewDetector(def, spec, filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create detector from %s: %w", filePath, err)
	}

	return detector, nil
}
