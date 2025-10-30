package detectors

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() {
	register(&ExampleDetector{})
}

// ExampleDetector is a demonstration detector that shows the detector API patterns.
// It detects all execve events and produces an example_detection event.
// This detector is for testing and documentation purposes only.
type ExampleDetector struct {
	logger detection.Logger
}

func (d *ExampleDetector) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "EXAMPLE-001",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "execve",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "example_detection",
			Description: "Example detection demonstrating the detector API",
			Version: &v1beta1.Version{
				Major: 1,
				Minor: 0,
				Patch: 0,
			},
			Fields: []*v1beta1.EventField{
				{
					Name: "binary_path",
					Type: "const char*",
				},
				{
					Name: "detection_reason",
					Type: "const char*",
				},
				{
					Name: "confidence",
					Type: "int",
				},
			},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Example Threat",
			Description: "This is an example threat detection for testing purposes",
			Severity:    v1beta1.Severity_LOW,
			Mitre: &v1beta1.Mitre{
				Tactic: &v1beta1.MitreTactic{
					Name: "Execution",
				},
				Technique: &v1beta1.MitreTechnique{
					Id:   "T1059",
					Name: "Command and Scripting Interpreter",
				},
			},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *ExampleDetector) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("ExampleDetector initialized")
	return nil
}

func (d *ExampleDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]*v1beta1.Event, error) {
	// This is a demonstration detector - it triggers on all execve events
	// Real detectors would have actual detection logic here
	if event.Name != "execve" {
		return nil, nil
	}

	// Get the binary path from the event
	binaryPath := ""
	if event.Workload != nil && event.Workload.Process != nil && event.Workload.Process.Executable != nil {
		binaryPath = event.Workload.Process.Executable.Path
	}

	d.logger.Debugw("ExampleDetector triggered",
		"event_name", event.Name,
		"binary_path", binaryPath)

	// Create output event with field data
	outputEvent := v1beta1.CreateEventFromBase(event)
	outputEvent.Data = []*v1beta1.EventValue{
		{
			Name:  "binary_path",
			Value: &v1beta1.EventValue_Str{Str: binaryPath},
		},
		{
			Name:  "detection_reason",
			Value: &v1beta1.EventValue_Str{Str: "Example detection - all execve events"},
		},
		{
			Name:  "confidence",
			Value: &v1beta1.EventValue_Int32{Int32: 100},
		},
	}

	return []*v1beta1.Event{outputEvent}, nil
}

func (d *ExampleDetector) Close() error {
	d.logger.Debugw("ExampleDetector closed")
	return nil
}
