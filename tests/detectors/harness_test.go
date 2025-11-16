package detectors

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/pkg/events"
)

// mockDetector is a simple detector for testing the framework
type mockDetector struct {
	id             string
	eventName      string
	requirements   detection.DetectorRequirements
	threatMetadata *v1beta1.Threat
	autoPopulate   detection.AutoPopulateFields
	outputData     []*v1beta1.EventValue
}

func (d *mockDetector) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: d.id,
		ProducedEvent: v1beta1.EventDefinition{
			Name:    d.eventName,
			Version: &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
		},
		Requirements:   d.requirements,
		ThreatMetadata: d.threatMetadata,
		AutoPopulate:   d.autoPopulate,
	}
}

func (d *mockDetector) Init(params detection.DetectorParams) error {
	return nil
}

func (d *mockDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	if d.outputData != nil {
		return []detection.DetectorOutput{{Data: d.outputData}}, nil
	}
	return []detection.DetectorOutput{{Data: nil}}, nil
}

func (d *mockDetector) Close() error {
	return nil
}

// TestNewTestHarness verifies that TestHarness is created correctly
func TestNewTestHarness(t *testing.T) {
	harness := NewTestHarness(t, events.Execve)

	assert.NotNil(t, harness)
	assert.NotNil(t, harness.Engine)
	assert.NotNil(t, harness.Context)
	assert.NotNil(t, harness.T)
	assert.NotNil(t, harness.EventIDMap)
}

// TestRegisterDetector verifies that detectors can be registered
func TestRegisterDetector(t *testing.T) {
	harness := NewTestHarness(t, events.Execve)

	detector := &mockDetector{
		id:        "test-detector-001",
		eventName: "test_event",
		requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "execve", Dependency: detection.DependencyRequired},
			},
		},
	}

	err := harness.RegisterDetector(detector)
	require.NoError(t, err)

	// Verify event was registered
	eventID, exists := harness.EventIDMap["test_event"]
	assert.True(t, exists)
	assert.NotEqual(t, events.ID(0), eventID)
}

// TestDispatchEvent verifies that events are dispatched correctly
func TestDispatchEvent(t *testing.T) {
	harness := NewTestHarness(t, events.Execve)

	detector := &mockDetector{
		id:        "test-detector-002",
		eventName: "test_dispatch_event",
		requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "execve", Dependency: detection.DependencyRequired},
			},
		},
		outputData: []*v1beta1.EventValue{
			v1beta1.NewStringValue("test_field", "test_value"),
		},
	}

	err := harness.RegisterDetector(detector)
	require.NoError(t, err)

	// Create input event
	input := NewExecveEvent("/bin/test")

	// Dispatch event
	outputs := harness.DispatchEvent(input)

	// Verify output
	require.Len(t, outputs, 1)
	assert.Equal(t, "test_dispatch_event", outputs[0].Name)
	AssertFieldValue(t, outputs[0], "test_field", "test_value")
}

// TestEventBuilders verifies that event builders work correctly
func TestEventBuilders(t *testing.T) {
	t.Run("NewExecveEvent", func(t *testing.T) {
		event := NewExecveEvent("/bin/ls")
		assert.Equal(t, v1beta1.EventId(events.Execve), event.Id)
		assert.Equal(t, "execve", event.Name)
		AssertFieldValue(t, event, "pathname", "/bin/ls")
	})

	t.Run("NewSchedProcessExecEvent", func(t *testing.T) {
		event := NewSchedProcessExecEvent("/usr/bin/cat")
		assert.Equal(t, v1beta1.EventId(events.SchedProcessExec), event.Id)
		assert.Equal(t, "sched_process_exec", event.Name)
		AssertFieldValue(t, event, "pathname", "/usr/bin/cat")
	})

	t.Run("NewOpenatEvent", func(t *testing.T) {
		event := NewOpenatEvent("/tmp/file", "O_RDONLY")
		assert.Equal(t, v1beta1.EventId(events.Openat), event.Id)
		assert.Equal(t, "openat", event.Name)
		AssertFieldValue(t, event, "pathname", "/tmp/file")
		AssertFieldValue(t, event, "flags", "O_RDONLY")
	})

	t.Run("WithWorkloadProcess", func(t *testing.T) {
		event := NewExecveEvent("/bin/ls", WithWorkloadProcess(1234, "ls"))
		require.NotNil(t, event.Workload)
		require.NotNil(t, event.Workload.Process)
		AssertProcessPID(t, event, 1234)
		assert.Equal(t, "ls", event.Workload.Process.Thread.Name)
	})

	t.Run("WithContainer", func(t *testing.T) {
		event := NewExecveEvent("/bin/ls", WithContainer("abc123", "test-container"))
		require.NotNil(t, event.Workload)
		require.NotNil(t, event.Workload.Container)
		AssertContainerID(t, event, "abc123")
		assert.Equal(t, "test-container", event.Workload.Container.Name)
	})

	t.Run("WithK8s", func(t *testing.T) {
		event := NewExecveEvent("/bin/ls", WithK8s("test-pod", "default"))
		require.NotNil(t, event.Workload)
		require.NotNil(t, event.Workload.K8S)
		AssertK8sPodName(t, event, "test-pod")
		assert.Equal(t, "default", event.Workload.K8S.Namespace.Name)
	})
}

// TestAssertions verifies that assertion helpers work correctly
func TestAssertions(t *testing.T) {
	t.Run("AssertFieldValue", func(t *testing.T) {
		event := &v1beta1.Event{
			Data: []*v1beta1.EventValue{
				v1beta1.NewStringValue("str_field", "test"),
				v1beta1.NewInt32Value("int_field", 42),
				v1beta1.NewUInt32Value("uint_field", 100),
				v1beta1.NewBoolValue("bool_field", true),
			},
		}

		AssertFieldValue(t, event, "str_field", "test")
		AssertFieldValue(t, event, "int_field", int32(42))
		AssertFieldValue(t, event, "uint_field", uint32(100))
		AssertFieldValue(t, event, "bool_field", true)
	})

	t.Run("AssertFieldExists", func(t *testing.T) {
		event := &v1beta1.Event{
			Data: []*v1beta1.EventValue{
				v1beta1.NewStringValue("existing_field", "value"),
			},
		}

		AssertFieldExists(t, event, "existing_field")
	})

	t.Run("AssertFieldMissing", func(t *testing.T) {
		event := &v1beta1.Event{
			Data: []*v1beta1.EventValue{
				v1beta1.NewStringValue("existing_field", "value"),
			},
		}

		AssertFieldMissing(t, event, "non_existing_field")
	})

	t.Run("AssertThreatSeverity", func(t *testing.T) {
		event := &v1beta1.Event{
			Threat: &v1beta1.Threat{
				Severity: v1beta1.Severity_HIGH,
			},
		}

		AssertThreatSeverity(t, event, v1beta1.Severity_HIGH)
	})

	t.Run("AssertMitreTechnique", func(t *testing.T) {
		event := &v1beta1.Event{
			Threat: &v1beta1.Threat{
				Mitre: &v1beta1.Mitre{
					Technique: &v1beta1.MitreTechnique{
						Id:   "T1059",
						Name: "Command and Scripting Interpreter",
					},
				},
			},
		}

		AssertMitreTechnique(t, event, "T1059")
	})

	t.Run("AssertMitreTactic", func(t *testing.T) {
		event := &v1beta1.Event{
			Threat: &v1beta1.Threat{
				Mitre: &v1beta1.Mitre{
					Tactic: &v1beta1.MitreTactic{
						Name: "Execution",
					},
				},
			},
		}

		AssertMitreTactic(t, event, "Execution")
	})
}

// TestAutoPopulation verifies that auto-population works correctly
func TestAutoPopulation(t *testing.T) {
	t.Run("ThreatAutoPopulation", func(t *testing.T) {
		harness := NewTestHarness(t, events.Execve)

		detector := &mockDetector{
			id:        "test-threat-autopop",
			eventName: "test_threat_event",
			requirements: detection.DetectorRequirements{
				Events: []detection.EventRequirement{
					{Name: "execve", Dependency: detection.DependencyRequired},
				},
			},
			threatMetadata: &v1beta1.Threat{
				Name:        "Test Threat",
				Description: "Test threat description",
				Severity:    v1beta1.Severity_MEDIUM,
			},
			autoPopulate: detection.AutoPopulateFields{
				Threat: true,
			},
		}

		err := harness.RegisterDetector(detector)
		require.NoError(t, err)

		input := NewExecveEvent("/bin/test")
		outputs := harness.DispatchEvent(input)

		require.Len(t, outputs, 1)
		harness.AssertThreatPopulated(outputs[0])
		assert.Equal(t, "Test Threat", outputs[0].Threat.Name)
		AssertThreatSeverity(t, outputs[0], v1beta1.Severity_MEDIUM)
	})

	t.Run("DetectedFromAutoPopulation", func(t *testing.T) {
		harness := NewTestHarness(t, events.Execve)

		detector := &mockDetector{
			id:        "test-detectedfrom-autopop",
			eventName: "test_detectedfrom_event",
			requirements: detection.DetectorRequirements{
				Events: []detection.EventRequirement{
					{Name: "execve", Dependency: detection.DependencyRequired},
				},
			},
			autoPopulate: detection.AutoPopulateFields{
				DetectedFrom: true,
			},
		}

		err := harness.RegisterDetector(detector)
		require.NoError(t, err)

		input := NewExecveEvent("/bin/test")
		outputs := harness.DispatchEvent(input)

		require.Len(t, outputs, 1)
		harness.AssertDetectedFromPopulated(outputs[0], "execve")
	})
}

// TestFindOutputByName verifies finding outputs by name
func TestFindOutputByName(t *testing.T) {
	harness := NewTestHarness(t, events.Execve)

	detector1 := &mockDetector{
		id:        "test-find-001",
		eventName: "event_one",
		requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "execve", Dependency: detection.DependencyRequired},
			},
		},
	}

	detector2 := &mockDetector{
		id:        "test-find-002",
		eventName: "event_two",
		requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "execve", Dependency: detection.DependencyRequired},
			},
		},
	}

	require.NoError(t, harness.RegisterDetector(detector1))
	require.NoError(t, harness.RegisterDetector(detector2))

	input := NewExecveEvent("/bin/test")
	outputs := harness.DispatchEvent(input)

	// Find specific outputs
	event1 := harness.FindOutputByName(outputs, "event_one")
	event2 := harness.FindOutputByName(outputs, "event_two")
	eventMissing := harness.FindOutputByName(outputs, "non_existent")

	assert.NotNil(t, event1)
	assert.NotNil(t, event2)
	assert.Nil(t, eventMissing)
}
