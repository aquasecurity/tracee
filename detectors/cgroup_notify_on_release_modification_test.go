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

func TestCgroupNotifyOnReleaseModification_OnEvent(t *testing.T) {
	t.Parallel()

	// File flags
	readFlags := int32(parsers.O_RDONLY.Value())
	writeFlags := int32(parsers.O_WRONLY.Value())

	testCases := []struct {
		name          string
		pathname      string
		flags         int32
		expectedMatch bool
	}{
		{
			name:          "notify_on_release write - should detect",
			pathname:      "/sys/fs/cgroup/memory/notify_on_release",
			flags:         writeFlags,
			expectedMatch: true,
		},
		{
			name:          "different path notify_on_release write - should detect",
			pathname:      "/sys/fs/cgroup/cpu/docker/notify_on_release",
			flags:         writeFlags,
			expectedMatch: true,
		},
		{
			name:          "notify_on_release read - should not detect",
			pathname:      "/sys/fs/cgroup/memory/notify_on_release",
			flags:         readFlags,
			expectedMatch: false,
		},
		// Note: different_file test removed - DataFilter would prevent this event from reaching OnEvent
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &CgroupNotifyOnReleaseModification{}
			params := detection.DetectorParams{
				Logger: &testutil.MockLogger{},
			}
			err := detector.Init(params)
			require.NoError(t, err)

			event := &v1beta1.Event{
				Id:   v1beta1.EventId_security_file_open,
				Name: "security_file_open",
				Workload: &v1beta1.Workload{
					Container: &v1beta1.Container{
						Id:      "test-container",
						Started: true,
					},
				},
				Data: []*v1beta1.EventValue{
					v1beta1.NewStringValue("pathname", tc.pathname),
					v1beta1.NewInt32Value("flags", tc.flags),
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

func TestCgroupNotifyOnReleaseModification_Definition(t *testing.T) {
	t.Parallel()

	detector := &CgroupNotifyOnReleaseModification{}
	def := detector.GetDefinition()

	assert.Equal(t, "TRC-106", def.ID)
	assert.Equal(t, "cgroup_notify_on_release", def.ProducedEvent.Name)
	assert.NotNil(t, def.ThreatMetadata)
	assert.Equal(t, v1beta1.Severity_HIGH, def.ThreatMetadata.Severity)
	assert.Equal(t, "T1611", def.ThreatMetadata.Mitre.Technique.Id)

	require.Len(t, def.Requirements.Events, 1)
	eventReq := def.Requirements.Events[0]
	assert.Equal(t, "security_file_open", eventReq.Name)
	assert.Equal(t, detection.DependencyRequired, eventReq.Dependency)

	// Verify container=started filter (critical for parity)
	require.Len(t, eventReq.ScopeFilters, 1)
	assert.Equal(t, "container=started", eventReq.ScopeFilters[0])

	// Verify DataFilter for pathname
	require.Len(t, eventReq.DataFilters, 1)
	assert.Equal(t, "pathname=*/notify_on_release", eventReq.DataFilters[0])

	assert.True(t, def.AutoPopulate.Threat)
	assert.True(t, def.AutoPopulate.DetectedFrom)
}
