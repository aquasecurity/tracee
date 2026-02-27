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

func TestAslrInspection_GetDefinition(t *testing.T) {
	detector := &AslrInspection{}
	def := detector.GetDefinition()

	assert.Equal(t, "TRC-109", def.ID)
	assert.Len(t, def.Requirements.Events, 1)
	assert.Equal(t, "security_file_open", def.Requirements.Events[0].Name)
	assert.Equal(t, detection.DependencyRequired, def.Requirements.Events[0].Dependency)

	// Verify data filter for ASLR config file
	assert.Len(t, def.Requirements.Events[0].DataFilters, 1)
	assert.Equal(t, "pathname=/proc/sys/kernel/randomize_va_space", def.Requirements.Events[0].DataFilters[0])

	// Check produced event
	assert.Equal(t, "aslr_inspection", def.ProducedEvent.Name)
	assert.Contains(t, def.ProducedEvent.Description, "ASLR")

	// Check threat metadata matches original signature
	require.NotNil(t, def.ThreatMetadata)
	assert.Equal(t, "ASLR inspection detected", def.ThreatMetadata.Name)
	assert.Equal(t, v1beta1.Severity_INFO, def.ThreatMetadata.Severity)
	assert.Equal(t, "privilege-escalation", def.ThreatMetadata.Properties["Category"])

	require.NotNil(t, def.ThreatMetadata.Mitre)
	assert.Equal(t, "Privilege Escalation", def.ThreatMetadata.Mitre.Tactic.Name)
	assert.Equal(t, "T1068", def.ThreatMetadata.Mitre.Technique.Id)
	assert.Equal(t, "Exploitation for Privilege Escalation", def.ThreatMetadata.Mitre.Technique.Name)
}

func TestAslrInspection_Init(t *testing.T) {
	detector := &AslrInspection{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)
}

func TestAslrInspection_OnEvent_ReadOperation(t *testing.T) {
	detector := &AslrInspection{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	testCases := []struct {
		name  string
		flags int
	}{
		{"O_RDONLY", int(parsers.O_RDONLY.Value())},
		{"O_RDWR", int(parsers.O_RDWR.Value())},
	}

	ctx := context.Background()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// DataFilter ensures pathname matches
			inputEvent := &v1beta1.Event{
				Id: v1beta1.EventId_security_file_open,
				Data: []*v1beta1.EventValue{
					v1beta1.NewStringValue("pathname", "/proc/sys/kernel/randomize_va_space"),
					v1beta1.NewInt64Value("flags", int64(tc.flags)),
				},
			}

			outputEvents, err := detector.OnEvent(ctx, inputEvent)

			require.NoError(t, err)
			require.Len(t, outputEvents, 1, "Should detect for %s", tc.name)
			assert.NotNil(t, outputEvents[0])
		})
	}
}

func TestAslrInspection_OnEvent_WriteOperation(t *testing.T) {
	detector := &AslrInspection{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	// Test write-only operation (should NOT trigger detection)
	inputEvent := &v1beta1.Event{
		Id: v1beta1.EventId_security_file_open,
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/proc/sys/kernel/randomize_va_space"),
			v1beta1.NewInt64Value("flags", int64(parsers.O_WRONLY.Value())),
		},
	}

	ctx := context.Background()
	outputEvents, err := detector.OnEvent(ctx, inputEvent)

	require.NoError(t, err)
	assert.Len(t, outputEvents, 0, "Should not detect for write-only operation")
}

func TestAslrInspection_OnEvent_MissingFlags(t *testing.T) {
	detector := &AslrInspection{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	// Event without flags argument
	inputEvent := &v1beta1.Event{
		Id: v1beta1.EventId_security_file_open,
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/proc/sys/kernel/randomize_va_space"),
		},
	}

	ctx := context.Background()
	outputEvents, err := detector.OnEvent(ctx, inputEvent)

	// Should not error, just no detection
	require.NoError(t, err)
	assert.Len(t, outputEvents, 0)
}

func TestAslrInspection_OnEvent_MultipleReadOperations(t *testing.T) {
	detector := &AslrInspection{}

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
				v1beta1.NewStringValue("pathname", "/proc/sys/kernel/randomize_va_space"),
				v1beta1.NewInt64Value("flags", int64(parsers.O_RDONLY.Value())),
			},
		}

		outputEvents, err := detector.OnEvent(ctx, inputEvent)
		require.NoError(t, err)
		require.Len(t, outputEvents, 1, "Read operation %d should produce detection", i+1)
	}
}

func TestAslrInspection_Close(t *testing.T) {
	detector := &AslrInspection{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	err = detector.Close()
	assert.NoError(t, err)
}
