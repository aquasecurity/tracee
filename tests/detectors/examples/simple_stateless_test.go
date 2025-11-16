package examples

import (
	"context"
	"testing"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/tests/detectors"
)

// TestSimpleStatelessDetector demonstrates testing a simple stateless detector
// This is the most basic use case - single input, single output
func TestSimpleStatelessDetector(t *testing.T) {
	detector := &StatelessExampleDetector{}
	test := detectors.NewSimpleTest(t, detector)
	defer test.Close()

	// Test 1: Event that should trigger detection
	input := detectors.NewExecveEvent("/usr/bin/nc")
	output := test.ExpectOutput(input)

	// Verify output data
	detectors.AssertFieldValue(t, output.Data, "binary_path", "/usr/bin/nc")
}

// TestSimpleStatelessNoMatch demonstrates testing negative cases
func TestSimpleStatelessNoMatch(t *testing.T) {
	detector := &StatelessExampleDetector{}
	test := detectors.NewSimpleTest(t, detector)
	defer test.Close()

	// Event that should NOT trigger detection
	input := detectors.NewExecveEvent("/usr/bin/ls")
	test.ExpectNoOutput(input)
}

// StatelessExampleDetector is a simple detector for demonstration
type StatelessExampleDetector struct{}

func (d *StatelessExampleDetector) Init(params detection.DetectorParams) error {
	return nil
}

func (d *StatelessExampleDetector) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "stateless-example",
		ProducedEvent: v1beta1.EventDefinition{
			Name:    "suspicious_binary",
			Version: &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
			Fields: []*v1beta1.EventField{
				{Name: "binary_path", Type: "string"},
			},
		},
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "execve"},
			},
		},
	}
}

func (d *StatelessExampleDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Extract pathname from event data
	var pathname string
	for _, field := range event.Data {
		if field.Name == "pathname" {
			pathname = field.GetStr()
			break
		}
	}

	if pathname == "" {
		return nil, nil
	}

	// Simple check: detect nc binary
	if pathname == "/usr/bin/nc" {
		return []detection.DetectorOutput{{
			Data: []*v1beta1.EventValue{
				{Name: "binary_path", Value: &v1beta1.EventValue_Str{Str: pathname}},
			},
		}}, nil
	}

	return nil, nil
}

func (d *StatelessExampleDetector) Close() {}
