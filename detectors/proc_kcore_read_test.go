package detectors

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/parsers"
	"github.com/aquasecurity/tracee/detectors/testutil"
)

func TestProcKcoreRead_GetDefinition(t *testing.T) {
	detector := &ProcKcoreRead{}
	def := detector.GetDefinition()

	assert.Equal(t, "TRC-1021", def.ID)
	assert.Len(t, def.Requirements.Events, 1)
	assert.Equal(t, "security_file_open", def.Requirements.Events[0].Name)
	assert.Equal(t, detection.DependencyRequired, def.Requirements.Events[0].Dependency)

	// Verify data filter for /proc/kcore
	assert.Len(t, def.Requirements.Events[0].DataFilters, 1)
	assert.Equal(t, "pathname=*/proc/kcore", def.Requirements.Events[0].DataFilters[0])

	// Verify scope filter for container origin
	assert.Len(t, def.Requirements.Events[0].ScopeFilters, 1)
	assert.Equal(t, "container=started", def.Requirements.Events[0].ScopeFilters[0])

	// Check produced event
	assert.Equal(t, "proc_kcore_read", def.ProducedEvent.Name)
	assert.Contains(t, def.ProducedEvent.Description, "kcore")

	// Check threat metadata matches original signature
	require.NotNil(t, def.ThreatMetadata)
	assert.Equal(t, "Kcore memory file read", def.ThreatMetadata.Name)
	assert.Equal(t, v1beta1.Severity_MEDIUM, def.ThreatMetadata.Severity)
	assert.Equal(t, "privilege-escalation", def.ThreatMetadata.Properties["Category"])

	require.NotNil(t, def.ThreatMetadata.Mitre)
	assert.Equal(t, "Privilege Escalation", def.ThreatMetadata.Mitre.Tactic.Name)
	assert.Equal(t, "T1611", def.ThreatMetadata.Mitre.Technique.Id)
	assert.Equal(t, "Escape to Host", def.ThreatMetadata.Mitre.Technique.Name)
}

func TestProcKcoreRead_Init(t *testing.T) {
	detector := &ProcKcoreRead{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)
}

func TestProcKcoreRead_OnEvent_ReadOperation(t *testing.T) {
	detector := &ProcKcoreRead{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	testCases := []struct {
		name         string
		pathname     string
		flags        int
		shouldDetect bool
	}{
		{"exact_path_O_RDONLY", "/proc/kcore", int(parsers.O_RDONLY.Value()), true},
		{"exact_path_O_RDWR", "/proc/kcore", int(parsers.O_RDWR.Value()), true},
		{"suffix_match", "/host/proc/kcore", int(parsers.O_RDONLY.Value()), true},
		{"write_only", "/proc/kcore", int(parsers.O_WRONLY.Value()), false},
		// Note: wrong_path test removed - DataFilter would prevent this event from reaching OnEvent
	}

	ctx := context.Background()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			inputEvent := &v1beta1.Event{
				Id: v1beta1.EventId_security_file_open,
				Data: []*v1beta1.EventValue{
					v1beta1.NewStringValue("pathname", tc.pathname),
					v1beta1.NewInt64Value("flags", int64(tc.flags)),
				},
			}

			outputEvents, err := detector.OnEvent(ctx, inputEvent)

			require.NoError(t, err)
			if tc.shouldDetect {
				require.Len(t, outputEvents, 1, "Should detect for %s", tc.name)
				assert.NotNil(t, outputEvents[0])
			} else {
				assert.Len(t, outputEvents, 0, "Should not detect for %s", tc.name)
			}
		})
	}
}

func TestProcKcoreRead_OnEvent_MissingFields(t *testing.T) {
	detector := &ProcKcoreRead{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	ctx := context.Background()

	testCases := []struct {
		name  string
		event *v1beta1.Event
	}{
		// Note: missing_pathname test removed - DataFilter ensures pathname is present
		{
			"missing_flags",
			&v1beta1.Event{
				Id: v1beta1.EventId_security_file_open,
				Data: []*v1beta1.EventValue{
					v1beta1.NewStringValue("pathname", "/proc/kcore"),
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			outputEvents, err := detector.OnEvent(ctx, tc.event)

			// Should not error, just no detection
			require.NoError(t, err)
			assert.Len(t, outputEvents, 0)
		})
	}
}

func TestProcKcoreRead_OnEvent_MultipleReadOperations(t *testing.T) {
	detector := &ProcKcoreRead{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	ctx := context.Background()

	// Multiple read operations should each trigger detection
	for i := 0; i < 3; i++ {
		inputEvent := &v1beta1.Event{
			Id: v1beta1.EventId_security_file_open,
			Data: []*v1beta1.EventValue{
				v1beta1.NewStringValue("pathname", "/proc/kcore"),
				v1beta1.NewInt64Value("flags", int64(parsers.O_RDONLY.Value())),
			},
		}

		outputEvents, err := detector.OnEvent(ctx, inputEvent)
		require.NoError(t, err)
		require.Len(t, outputEvents, 1, "Read operation %d should produce detection", i+1)
	}
}

func TestProcKcoreRead_Close(t *testing.T) {
	detector := &ProcKcoreRead{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	err = detector.Close()
	assert.NoError(t, err)
}
