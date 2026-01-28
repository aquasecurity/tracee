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

func TestFilelessExecution_OnEvent(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		pathname      string
		expectedMatch bool
	}{
		{
			name:          "memfd pathname - should detect",
			pathname:      "memfd:malicious",
			expectedMatch: true,
		},
		{
			name:          "/dev/shm pathname - should detect",
			pathname:      "/dev/shm/malicious_script",
			expectedMatch: true,
		},
		{
			name:          "/run/shm pathname - should detect",
			pathname:      "/run/shm/executable",
			expectedMatch: true,
		},
		// Note: regular file tests removed - DataFilter would prevent these events from reaching OnEvent
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &FilelessExecution{}
			params := detection.DetectorParams{
				Logger: &testutil.MockLogger{},
			}
			err := detector.Init(params)
			require.NoError(t, err)

			event := &v1beta1.Event{
				Id:   v1beta1.EventId_sched_process_exec,
				Name: "sched_process_exec",
				Data: []*v1beta1.EventValue{
					v1beta1.NewStringValue("pathname", tc.pathname),
				},
			}

			outputs, err := detector.OnEvent(context.Background(), event)
			require.NoError(t, err)

			if tc.expectedMatch {
				assert.Len(t, outputs, 1, "Expected one detection output")
				assert.Nil(t, outputs[0].Data, "No custom data expected")
			} else {
				assert.Len(t, outputs, 0, "Expected no detection output")
			}
		})
	}
}

func TestFilelessExecution_Definition(t *testing.T) {
	t.Parallel()

	detector := &FilelessExecution{}
	def := detector.GetDefinition()

	// Verify basic metadata
	assert.Equal(t, "TRC-105", def.ID)
	assert.Equal(t, "fileless_execution", def.ProducedEvent.Name)
	assert.NotNil(t, def.ThreatMetadata)
	assert.Equal(t, v1beta1.Severity_HIGH, def.ThreatMetadata.Severity)
	assert.Equal(t, "T1620", def.ThreatMetadata.Mitre.Technique.Id)

	// Verify event requirements
	require.Len(t, def.Requirements.Events, 1)
	eventReq := def.Requirements.Events[0]
	assert.Equal(t, "sched_process_exec", eventReq.Name)
	assert.Equal(t, detection.DependencyRequired, eventReq.Dependency)

	// Verify DataFilters for memory paths
	require.Len(t, eventReq.DataFilters, 3)
	assert.Contains(t, eventReq.DataFilters, "pathname=memfd:*")
	assert.Contains(t, eventReq.DataFilters, "pathname=/run/shm/*")
	assert.Contains(t, eventReq.DataFilters, "pathname=/dev/shm/*")

	// Verify auto-populate settings
	assert.True(t, def.AutoPopulate.Threat)
	assert.True(t, def.AutoPopulate.DetectedFrom)
}
