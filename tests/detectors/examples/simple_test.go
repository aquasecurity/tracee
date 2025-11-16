package examples

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/tests/detectors"
)

// SimpleDetector is an example detector that detects execution of netcat
type SimpleDetector struct {
	id string
}

func (d *SimpleDetector) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: d.id,
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "netcat_execution",
			Version:     &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
			Description: "Detects execution of netcat binary",
			Tags:        []string{"execution", "network"},
			Fields: []*v1beta1.EventField{
				{Name: "binary_path", Type: "string"},
			},
		},
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "execve", Dependency: detection.DependencyRequired},
			},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Netcat Execution",
			Description: "Netcat binary executed, commonly used for reverse shells",
			Severity:    v1beta1.Severity_MEDIUM,
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

func (d *SimpleDetector) Init(params detection.DetectorParams) error {
	return nil
}

func (d *SimpleDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Extract pathname from event data
	var pathname string
	for _, field := range event.Data {
		if field.Name == "pathname" {
			if strVal, ok := field.Value.(*v1beta1.EventValue_Str); ok {
				pathname = strVal.Str
			}
		}
	}

	// Check if it's netcat
	if pathname != "/bin/nc" && pathname != "/usr/bin/nc" {
		return nil, nil // Not netcat, no detection
	}

	// Create detection data
	data := []*v1beta1.EventValue{
		v1beta1.NewStringValue("binary_path", pathname),
	}

	return []detection.DetectorOutput{{Data: data}}, nil
}

func (d *SimpleDetector) Close() error {
	return nil
}

// TestSimpleDetector demonstrates basic detector testing
func TestSimpleDetector(t *testing.T) {
	// Create test harness
	harness := detectors.NewTestHarness(t, events.Execve)

	// Create and register detector
	detector := &SimpleDetector{id: "simple-001"}
	require.NoError(t, harness.RegisterDetector(detector))

	t.Run("DetectsNetcat", func(t *testing.T) {
		// Create input event
		input := detectors.NewExecveEvent("/bin/nc")

		// Dispatch to detector
		outputs := harness.DispatchEvent(input)

		// Verify detection
		harness.AssertOutputCount(outputs, 1)
		harness.AssertOutputEvent(outputs[0], "netcat_execution")
		harness.AssertThreatPopulated(outputs[0])
		harness.AssertDetectedFromPopulated(outputs[0], "execve")

		// Verify extracted field
		detectors.AssertFieldValue(t, outputs[0], "binary_path", "/bin/nc")
		detectors.AssertThreatSeverity(t, outputs[0], v1beta1.Severity_MEDIUM)
		detectors.AssertMitreTechnique(t, outputs[0], "T1059")
	})

	t.Run("IgnoresOtherBinaries", func(t *testing.T) {
		// Create input event for non-netcat binary
		input := detectors.NewExecveEvent("/bin/ls")

		// Dispatch to detector
		outputs := harness.DispatchEvent(input)

		// Verify no detection
		harness.AssertOutputCount(outputs, 0)
	})
}
