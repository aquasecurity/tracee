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

func TestDiskMount_OnEvent(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		devName       string
		expectedMatch bool
	}{
		{
			name:          "mount /dev/sda - should detect",
			devName:       "/dev/sda",
			expectedMatch: true,
		},
		{
			name:          "mount /dev/sda1 - should detect",
			devName:       "/dev/sda1",
			expectedMatch: true,
		},
		{
			name:          "mount /dev/vda - should detect",
			devName:       "/dev/vda",
			expectedMatch: true,
		},
		// Note: non-/dev/ mount tests removed - DataFilter would prevent these events from reaching OnEvent
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &DiskMount{}
			params := detection.DetectorParams{
				Logger: &testutil.MockLogger{},
			}
			err := detector.Init(params)
			require.NoError(t, err)

			event := &v1beta1.Event{
				Id:   v1beta1.EventId_security_sb_mount,
				Name: "security_sb_mount",
				Workload: &v1beta1.Workload{
					Container: &v1beta1.Container{
						Id:      "test-container",
						Started: true,
					},
				},
				Data: []*v1beta1.EventValue{
					v1beta1.NewStringValue("dev_name", tc.devName),
				},
			}

			outputs, err := detector.OnEvent(context.Background(), event)
			require.NoError(t, err)

			if tc.expectedMatch {
				assert.Len(t, outputs, 1, "Expected detection")
				assert.Nil(t, outputs[0].Data)
			} else {
				assert.Len(t, outputs, 0, "Expected no detection")
			}
		})
	}
}

func TestDiskMount_Definition(t *testing.T) {
	t.Parallel()

	detector := &DiskMount{}
	def := detector.GetDefinition()

	assert.Equal(t, "TRC-1014", def.ID)
	assert.Equal(t, "disk_mount", def.ProducedEvent.Name)
	assert.NotNil(t, def.ThreatMetadata)
	assert.Equal(t, v1beta1.Severity_HIGH, def.ThreatMetadata.Severity)
	assert.Equal(t, "T1611", def.ThreatMetadata.Mitre.Technique.Id)

	require.Len(t, def.Requirements.Events, 1)
	eventReq := def.Requirements.Events[0]
	assert.Equal(t, "security_sb_mount", eventReq.Name)
	assert.Equal(t, detection.DependencyRequired, eventReq.Dependency)

	// Verify container=started filter (critical for parity)
	require.Len(t, eventReq.ScopeFilters, 1)
	assert.Equal(t, "container=started", eventReq.ScopeFilters[0])

	// Verify DataFilter for dev_name
	require.Len(t, eventReq.DataFilters, 1)
	assert.Equal(t, "dev_name=/dev/*", eventReq.DataFilters[0])

	assert.True(t, def.AutoPopulate.Threat)
	assert.True(t, def.AutoPopulate.DetectedFrom)
}
