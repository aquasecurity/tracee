package detectors

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1"
)

// AssertFieldValue asserts that an event has a data field with the expected value
func AssertFieldValue(t *testing.T, data interface{}, fieldName string, expected interface{}) {
	var eventData []*v1beta1.EventValue

	// Handle both *v1beta1.Event and []*v1beta1.EventValue
	switch v := data.(type) {
	case *v1beta1.Event:
		require.NotNil(t, v, "Event is nil")
		require.NotNil(t, v.Data, "Event data is nil")
		eventData = v.Data
	case []*v1beta1.EventValue:
		require.NotNil(t, v, "Event data is nil")
		eventData = v
	default:
		t.Fatalf("AssertFieldValue expects *v1beta1.Event or []*v1beta1.EventValue, got %T", data)
	}

	for _, field := range eventData {
		if field.Name == fieldName {
			// Compare based on the value type
			switch v := field.Value.(type) {
			case *v1beta1.EventValue_Str:
				assert.Equal(t, expected, v.Str, "Field %s value mismatch", fieldName)
			case *v1beta1.EventValue_Int32:
				assert.Equal(t, expected, v.Int32, "Field %s value mismatch", fieldName)
			case *v1beta1.EventValue_UInt32:
				assert.Equal(t, expected, v.UInt32, "Field %s value mismatch", fieldName)
			case *v1beta1.EventValue_Int64:
				assert.Equal(t, expected, v.Int64, "Field %s value mismatch", fieldName)
			case *v1beta1.EventValue_UInt64:
				assert.Equal(t, expected, v.UInt64, "Field %s value mismatch", fieldName)
			case *v1beta1.EventValue_Bool:
				assert.Equal(t, expected, v.Bool, "Field %s value mismatch", fieldName)
			default:
				t.Fatalf("Unsupported field type for %s", fieldName)
			}
			return
		}
	}

	t.Fatalf("Field %s not found in event data", fieldName)
}

// AssertFieldExists asserts that an event has a data field with the given name
func AssertFieldExists(t *testing.T, event *v1beta1.Event, fieldName string) {
	require.NotNil(t, event, "Event is nil")
	require.NotNil(t, event.Data, "Event data is nil")

	for _, field := range event.Data {
		if field.Name == fieldName {
			return
		}
	}

	t.Fatalf("Field %s not found in event data", fieldName)
}

// AssertFieldMissing asserts that an event does NOT have a data field with the given name
func AssertFieldMissing(t *testing.T, event *v1beta1.Event, fieldName string) {
	require.NotNil(t, event, "Event is nil")

	if event.Data == nil {
		return // No data, so field is definitely missing
	}

	for _, field := range event.Data {
		if field.Name == fieldName {
			t.Fatalf("Field %s should not be present in event data", fieldName)
		}
	}
}

// AssertThreatSeverity asserts that an event's threat has the expected severity
func AssertThreatSeverity(t *testing.T, event *v1beta1.Event, severity v1beta1.Severity) {
	require.NotNil(t, event, "Event is nil")
	require.NotNil(t, event.Threat, "Threat is nil")
	assert.Equal(t, severity, event.Threat.Severity, "Threat severity mismatch")
}

// AssertMitreTechnique asserts that an event's threat has the expected MITRE technique ID
func AssertMitreTechnique(t *testing.T, event *v1beta1.Event, techniqueID string) {
	require.NotNil(t, event, "Event is nil")
	require.NotNil(t, event.Threat, "Threat is nil")
	require.NotNil(t, event.Threat.Mitre, "MITRE data is nil")
	require.NotNil(t, event.Threat.Mitre.Technique, "MITRE technique is nil")
	assert.Equal(t, techniqueID, event.Threat.Mitre.Technique.Id, "MITRE technique ID mismatch")
}

// AssertMitreTactic asserts that an event's threat has the expected MITRE tactic name
func AssertMitreTactic(t *testing.T, event *v1beta1.Event, tacticName string) {
	require.NotNil(t, event, "Event is nil")
	require.NotNil(t, event.Threat, "Threat is nil")
	require.NotNil(t, event.Threat.Mitre, "MITRE data is nil")
	require.NotNil(t, event.Threat.Mitre.Tactic, "MITRE tactic is nil")
	assert.Equal(t, tacticName, event.Threat.Mitre.Tactic.Name, "MITRE tactic name mismatch")
}

// AssertProcessPID asserts that an event's workload process has the expected PID
func AssertProcessPID(t *testing.T, event *v1beta1.Event, expectedPID uint32) {
	require.NotNil(t, event, "Event is nil")
	require.NotNil(t, event.Workload, "Workload is nil")
	require.NotNil(t, event.Workload.Process, "Process is nil")
	require.NotNil(t, event.Workload.Process.Pid, "Process PID is nil")
	assert.Equal(t, expectedPID, event.Workload.Process.Pid.Value, "Process PID mismatch")
}

// AssertContainerID asserts that an event's workload container has the expected ID
func AssertContainerID(t *testing.T, event *v1beta1.Event, expectedID string) {
	require.NotNil(t, event, "Event is nil")
	require.NotNil(t, event.Workload, "Workload is nil")
	require.NotNil(t, event.Workload.Container, "Container is nil")
	assert.Equal(t, expectedID, event.Workload.Container.Id, "Container ID mismatch")
}

// AssertK8sPodName asserts that an event's workload has the expected Kubernetes pod name
func AssertK8sPodName(t *testing.T, event *v1beta1.Event, expectedName string) {
	require.NotNil(t, event, "Event is nil")
	require.NotNil(t, event.Workload, "Workload is nil")
	require.NotNil(t, event.Workload.K8S, "Kubernetes is nil")
	require.NotNil(t, event.Workload.K8S.Pod, "Pod is nil")
	assert.Equal(t, expectedName, event.Workload.K8S.Pod.Name, "Pod name mismatch")
}
