package detectors

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/detectors/testutil"
)

func TestAntiDebugging_GetDefinition(t *testing.T) {
	detector := &AntiDebugging{}
	def := detector.GetDefinition()

	assert.Equal(t, "TRC-102", def.ID)
	assert.Len(t, def.Requirements.Events, 1)
	assert.Equal(t, "ptrace", def.Requirements.Events[0].Name)
	assert.Equal(t, detection.DependencyRequired, def.Requirements.Events[0].Dependency)

	// Verify data filter is set to only receive PTRACE_TRACEME events
	assert.Len(t, def.Requirements.Events[0].DataFilters, 1)
	assert.Equal(t, "request=0", def.Requirements.Events[0].DataFilters[0])

	// Check produced event
	assert.Equal(t, "anti_debugging", def.ProducedEvent.Name)
	assert.Contains(t, def.ProducedEvent.Description, "anti-debugging")

	// Check threat metadata matches original signature
	require.NotNil(t, def.ThreatMetadata)
	assert.Equal(t, "Anti-Debugging detected", def.ThreatMetadata.Name)
	assert.Equal(t, v1beta1.Severity_LOW, def.ThreatMetadata.Severity)
	assert.Equal(t, "defense-evasion", def.ThreatMetadata.Properties["Category"])

	require.NotNil(t, def.ThreatMetadata.Mitre)
	assert.Equal(t, "Defense Evasion", def.ThreatMetadata.Mitre.Tactic.Name)
	assert.Equal(t, "T1622", def.ThreatMetadata.Mitre.Technique.Id)
	assert.Equal(t, "Debugger Evasion", def.ThreatMetadata.Mitre.Technique.Name)
}

func TestAntiDebugging_Init(t *testing.T) {
	detector := &AntiDebugging{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)
}

func TestAntiDebugging_OnEvent_PtraceTraceme(t *testing.T) {
	detector := &AntiDebugging{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	// Create ptrace event with PTRACE_TRACEME (request = 0)
	// Note: The data filter ensures only PTRACE_TRACEME events reach the detector
	inputEvent := &v1beta1.Event{
		Id: v1beta1.EventId_ptrace,
		Data: []*v1beta1.EventValue{
			v1beta1.NewInt64Value("request", 0), // PTRACE_TRACEME
		},
	}

	ctx := context.Background()
	outputEvents, err := detector.OnEvent(ctx, inputEvent)

	require.NoError(t, err)
	require.Len(t, outputEvents, 1)

	// Verify detection event is produced
	assert.NotNil(t, outputEvents[0])
}

func TestAntiDebugging_OnEvent_MultiplePtraceTracemeCalls(t *testing.T) {
	detector := &AntiDebugging{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	ctx := context.Background()

	// Multiple PTRACE_TRACEME calls should each trigger detection
	for i := 0; i < 3; i++ {
		inputEvent := &v1beta1.Event{
			Id: v1beta1.EventId_ptrace,
			Data: []*v1beta1.EventValue{
				v1beta1.NewInt64Value("request", 0),
			},
		}

		outputEvents, err := detector.OnEvent(ctx, inputEvent)
		require.NoError(t, err)
		require.Len(t, outputEvents, 1, "Call %d should produce detection", i+1)
	}
}

func TestAntiDebugging_Close(t *testing.T) {
	detector := &AntiDebugging{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	err = detector.Close()
	assert.NoError(t, err)
}
