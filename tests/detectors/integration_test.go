package detectors

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/pkg/events"
)

// =============================================================================
// YAML Detector Integration Tests
// =============================================================================

// TestYAMLDetectorIntegration tests a YAML detector through the full harness
// This validates policy filtering, auto-population, and field extraction work correctly
func TestYAMLDetectorIntegration(t *testing.T) {
	yamlContent := `
type: detector
id: TEST-YAML-001
produced_event:
  name: yaml_test_detection
  version: 1.0.0
  description: "Test YAML detector for integration testing"
requirements:
  events:
    - name: sched_process_exec
      data_filters:
        - "pathname=/bin/nc"
        - "pathname=/usr/bin/ncat"
threat:
  name: "Suspicious Binary Execution"
  description: "Execution of networking tool"
  severity: medium
  mitre:
    tactic:
      name: "Execution"
    technique:
      id: "T1059"
      name: "Command and Scripting Interpreter"
auto_populate:
  threat: true
  detected_from: true
output:
  fields:
    - name: binary_path
      expression: getEventData("pathname")
`

	harness := NewYAMLTestHarness(t, yamlContent, events.SchedProcessExec)

	t.Run("DetectsMatchingEvent", func(t *testing.T) {
		input := &v1beta1.Event{
			Id:        v1beta1.EventId(events.SchedProcessExec),
			Name:      "sched_process_exec",
			Timestamp: timestamppb.Now(),
			Data: []*v1beta1.EventValue{
				v1beta1.NewStringValue("pathname", "/bin/nc"),
			},
		}

		outputs := harness.DispatchEvent(input)

		require.Len(t, outputs, 1)
		assert.Equal(t, "yaml_test_detection", outputs[0].Name)

		// Verify field extraction
		binaryPath, found := v1beta1.GetData[string](outputs[0], "binary_path")
		require.True(t, found)
		assert.Equal(t, "/bin/nc", binaryPath)

		// Verify auto-population
		harness.AssertThreatPopulated(outputs[0])
		assert.Equal(t, v1beta1.Severity_MEDIUM, outputs[0].Threat.Severity)
		assert.Equal(t, "T1059", outputs[0].Threat.Mitre.Technique.Id)

		harness.AssertDetectedFromPopulated(outputs[0], "sched_process_exec")
	})

	t.Run("IgnoresNonMatchingPathname", func(t *testing.T) {
		input := &v1beta1.Event{
			Id:        v1beta1.EventId(events.SchedProcessExec),
			Name:      "sched_process_exec",
			Timestamp: timestamppb.Now(),
			Data: []*v1beta1.EventValue{
				v1beta1.NewStringValue("pathname", "/bin/ls"),
			},
		}

		outputs := harness.DispatchEvent(input)
		assert.Empty(t, outputs, "Should not detect non-matching binary")
	})
}

// TestYAMLDetectorWithScopeFilters tests YAML detector scope filtering
func TestYAMLDetectorWithScopeFilters(t *testing.T) {
	yamlContent := `
type: detector
id: TEST-YAML-SCOPE
produced_event:
  name: container_exec_detection
  version: 1.0.0
requirements:
  events:
    - name: sched_process_exec
      scope_filters:
        - "container"
      data_filters:
        - "pathname=/bin/sh"
auto_populate:
  detected_from: true
output:
  fields:
    - name: container_id
      expression: workload.container.id
`

	harness := NewYAMLTestHarness(t, yamlContent, events.SchedProcessExec)

	t.Run("DetectsInContainer", func(t *testing.T) {
		input := &v1beta1.Event{
			Id:        v1beta1.EventId(events.SchedProcessExec),
			Name:      "sched_process_exec",
			Timestamp: timestamppb.Now(),
			Workload: &v1beta1.Workload{
				Container: &v1beta1.Container{
					Id:      "abc123",
					Name:    "test-container",
					Started: true,
				},
			},
			Data: []*v1beta1.EventValue{
				v1beta1.NewStringValue("pathname", "/bin/sh"),
			},
		}

		outputs := harness.DispatchEvent(input)

		require.Len(t, outputs, 1)
		containerID, found := v1beta1.GetData[string](outputs[0], "container_id")
		require.True(t, found)
		assert.Equal(t, "abc123", containerID)
	})

	t.Run("IgnoresHostExecution", func(t *testing.T) {
		// Event without container context
		input := &v1beta1.Event{
			Id:        v1beta1.EventId(events.SchedProcessExec),
			Name:      "sched_process_exec",
			Timestamp: timestamppb.Now(),
			Data: []*v1beta1.EventValue{
				v1beta1.NewStringValue("pathname", "/bin/sh"),
			},
		}

		outputs := harness.DispatchEvent(input)
		assert.Empty(t, outputs, "Should not detect on host (no container)")
	})
}

// =============================================================================
// Detector Chaining Tests
// =============================================================================

// level1Detector produces an intermediate event that level2Detector consumes
type level1Detector struct {
	id string
}

func (d *level1Detector) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: d.id,
		ProducedEvent: v1beta1.EventDefinition{
			Name:    "level1_detection",
			Version: &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
			Fields: []*v1beta1.EventField{
				{Name: "binary_path", Type: "string"},
			},
		},
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "sched_process_exec", Dependency: detection.DependencyRequired},
			},
		},
		AutoPopulate: detection.AutoPopulateFields{
			DetectedFrom: true,
		},
	}
}

func (d *level1Detector) Init(params detection.DetectorParams) error { return nil }
func (d *level1Detector) Close() error                               { return nil }

func (d *level1Detector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	pathname, ok := v1beta1.GetData[string](event, "pathname")
	if !ok {
		return nil, nil
	}

	// Detect suspicious binaries
	if pathname == "/bin/nc" || pathname == "/usr/bin/ncat" {
		return []detection.DetectorOutput{{
			Data: []*v1beta1.EventValue{
				v1beta1.NewStringValue("binary_path", pathname),
			},
		}}, nil
	}
	return nil, nil
}

// level2Detector consumes level1_detection events and adds container context
type level2Detector struct {
	id string
}

func (d *level2Detector) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: d.id,
		ProducedEvent: v1beta1.EventDefinition{
			Name:    "level2_container_alert",
			Version: &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
			Fields: []*v1beta1.EventField{
				{Name: "binary_path", Type: "string"},
				{Name: "container_id", Type: "string"},
			},
		},
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				// Consumes output from level1Detector
				{Name: "level1_detection", Dependency: detection.DependencyRequired},
			},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Container Suspicious Execution",
			Description: "Suspicious binary executed in container",
			Severity:    v1beta1.Severity_HIGH,
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *level2Detector) Init(params detection.DetectorParams) error { return nil }
func (d *level2Detector) Close() error                               { return nil }

func (d *level2Detector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Only fire if in container
	if event.Workload == nil || event.Workload.Container == nil || event.Workload.Container.Id == "" {
		return nil, nil
	}

	binaryPath, _ := v1beta1.GetData[string](event, "binary_path")

	return []detection.DetectorOutput{{
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("binary_path", binaryPath),
			v1beta1.NewStringValue("container_id", event.Workload.Container.Id),
		},
	}}, nil
}

// TestDetectorChaining validates that detector outputs can feed into other detectors
func TestDetectorChaining(t *testing.T) {
	harness := NewTestHarness(t, events.SchedProcessExec)

	// Register level 1 detector
	level1 := &level1Detector{id: "chain-level1"}
	require.NoError(t, harness.RegisterDetector(level1))

	// Register level 2 detector (consumes level1 output)
	level2 := &level2Detector{id: "chain-level2"}
	require.NoError(t, harness.RegisterDetector(level2))

	t.Run("FullChainWithContainer", func(t *testing.T) {
		// Create input event with container context
		input := &v1beta1.Event{
			Id:        v1beta1.EventId(events.SchedProcessExec),
			Name:      "sched_process_exec",
			Timestamp: timestamppb.Now(),
			Workload: &v1beta1.Workload{
				Process: &v1beta1.Process{
					Pid: &wrapperspb.UInt32Value{Value: 1234},
				},
				Container: &v1beta1.Container{
					Id:      "container-xyz",
					Name:    "app-container",
					Started: true,
				},
			},
			Data: []*v1beta1.EventValue{
				v1beta1.NewStringValue("pathname", "/bin/nc"),
			},
		}

		// Level 1: Base event → level1_detection
		level1Outputs := harness.DispatchEvent(input)
		require.Len(t, level1Outputs, 1)
		assert.Equal(t, "level1_detection", level1Outputs[0].Name)

		binaryPath, found := v1beta1.GetData[string](level1Outputs[0], "binary_path")
		require.True(t, found)
		assert.Equal(t, "/bin/nc", binaryPath)

		// Verify DetectedFrom chain starts correctly
		harness.AssertDetectedFromPopulated(level1Outputs[0], "sched_process_exec")

		// Level 2: level1_detection → level2_container_alert
		level2Outputs := harness.DispatchEvent(level1Outputs[0])
		require.Len(t, level2Outputs, 1)
		assert.Equal(t, "level2_container_alert", level2Outputs[0].Name)

		// Verify level 2 output has both fields
		binaryPath2, found := v1beta1.GetData[string](level2Outputs[0], "binary_path")
		require.True(t, found)
		assert.Equal(t, "/bin/nc", binaryPath2)

		containerID, found := v1beta1.GetData[string](level2Outputs[0], "container_id")
		require.True(t, found)
		assert.Equal(t, "container-xyz", containerID)

		// Verify threat auto-population at level 2
		harness.AssertThreatPopulated(level2Outputs[0])
		assert.Equal(t, v1beta1.Severity_HIGH, level2Outputs[0].Threat.Severity)

		// Verify DetectedFrom chain: level2 → level1 → original
		harness.AssertDetectedFromPopulated(level2Outputs[0], "level1_detection")
		require.NotNil(t, level2Outputs[0].DetectedFrom.Parent)
		assert.Equal(t, "sched_process_exec", level2Outputs[0].DetectedFrom.Parent.Name)
	})

	t.Run("ChainBreaksWithoutContainer", func(t *testing.T) {
		// Create input event WITHOUT container context
		input := &v1beta1.Event{
			Id:        v1beta1.EventId(events.SchedProcessExec),
			Name:      "sched_process_exec",
			Timestamp: timestamppb.Now(),
			Data: []*v1beta1.EventValue{
				v1beta1.NewStringValue("pathname", "/bin/nc"),
			},
		}

		// Level 1 still fires
		level1Outputs := harness.DispatchEvent(input)
		require.Len(t, level1Outputs, 1)

		// Level 2 should NOT fire (no container)
		level2Outputs := harness.DispatchEvent(level1Outputs[0])
		assert.Empty(t, level2Outputs, "Level 2 should not fire without container context")
	})

	t.Run("ChainBreaksWithNonMatchingBinary", func(t *testing.T) {
		input := &v1beta1.Event{
			Id:        v1beta1.EventId(events.SchedProcessExec),
			Name:      "sched_process_exec",
			Timestamp: timestamppb.Now(),
			Data: []*v1beta1.EventValue{
				v1beta1.NewStringValue("pathname", "/bin/ls"),
			},
		}

		// Level 1 should NOT fire (non-suspicious binary)
		level1Outputs := harness.DispatchEvent(input)
		assert.Empty(t, level1Outputs, "Level 1 should not fire for /bin/ls")
	})
}
