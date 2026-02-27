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

func TestIllegitimateShell_OnEvent(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		processName   string
		prevComm      string
		expectedMatch bool
	}{
		{
			name:          "nginx spawns bash - should detect",
			processName:   "bash",
			prevComm:      "nginx",
			expectedMatch: true,
		},
		{
			name:          "apache spawns sh - should detect",
			processName:   "sh",
			prevComm:      "apache2",
			expectedMatch: true,
		},
		{
			name:          "httpd spawns zsh - should detect",
			processName:   "zsh",
			prevComm:      "httpd",
			expectedMatch: true,
		},
		{
			name:          "bash spawns by non-webserver - should not detect",
			processName:   "bash",
			prevComm:      "sshd",
			expectedMatch: false,
		},
		{
			name:          "nginx spawns non-shell - should not detect",
			processName:   "cat",
			prevComm:      "nginx",
			expectedMatch: false,
		},
		{
			name:          "normal process tree - should not detect",
			processName:   "ls",
			prevComm:      "bash",
			expectedMatch: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &IllegitimateShell{}
			params := detection.DetectorParams{
				Logger: &testutil.MockLogger{},
			}
			err := detector.Init(params)
			require.NoError(t, err)

			event := &v1beta1.Event{
				Id:   v1beta1.EventId_sched_process_exec,
				Name: "sched_process_exec",
				Workload: &v1beta1.Workload{
					Process: &v1beta1.Process{
						Thread: &v1beta1.Thread{
							Name: tc.processName,
						},
						Executable: &v1beta1.Executable{
							Path: "/bin/" + tc.processName,
						},
					},
				},
				Data: []*v1beta1.EventValue{
					v1beta1.NewStringValue("prev_comm", tc.prevComm),
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

func TestIllegitimateShell_Definition(t *testing.T) {
	t.Parallel()

	detector := &IllegitimateShell{}
	def := detector.GetDefinition()

	assert.Equal(t, "TRC-1016", def.ID)
	assert.Equal(t, "illegitimate_shell", def.ProducedEvent.Name)
	assert.NotNil(t, def.ThreatMetadata)
	assert.Equal(t, v1beta1.Severity_MEDIUM, def.ThreatMetadata.Severity)
	assert.Equal(t, "T1190", def.ThreatMetadata.Mitre.Technique.Id)

	require.Len(t, def.Requirements.Events, 1)
	assert.Equal(t, "sched_process_exec", def.Requirements.Events[0].Name)
	assert.Equal(t, detection.DependencyRequired, def.Requirements.Events[0].Dependency)

	assert.True(t, def.AutoPopulate.Threat)
	assert.True(t, def.AutoPopulate.DetectedFrom)
}
