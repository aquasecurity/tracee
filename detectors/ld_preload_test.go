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

func TestLdPreload_EnvVar(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		envVars        []string
		expectedOutput bool
		expectedEnv    string
	}{
		{
			name:           "LD_PRELOAD set",
			envVars:        []string{"PATH=/usr/bin", "LD_PRELOAD=/tmp/evil.so", "HOME=/root"},
			expectedOutput: true,
			expectedEnv:    "LD_PRELOAD",
		},
		{
			name:           "LD_LIBRARY_PATH set",
			envVars:        []string{"PATH=/usr/bin", "LD_LIBRARY_PATH=/tmp/evil", "HOME=/root"},
			expectedOutput: true,
			expectedEnv:    "LD_LIBRARY_PATH",
		},
		{
			name:           "no preload vars - should not trigger",
			envVars:        []string{"PATH=/usr/bin", "HOME=/root"},
			expectedOutput: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &LdPreload{}
			err := detector.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
			require.NoError(t, err)

			event := &v1beta1.Event{
				Id:   v1beta1.EventId_sched_process_exec,
				Name: "sched_process_exec",
				Workload: &v1beta1.Workload{
					Process: &v1beta1.Process{
						Executable: &v1beta1.Executable{Path: "/usr/bin/bash"},
					},
				},
				Data: []*v1beta1.EventValue{
					{
						Name: "env",
						Value: &v1beta1.EventValue_StrArray{
							StrArray: &v1beta1.StringArray{Value: tc.envVars},
						},
					},
				},
			}

			output, err := detector.OnEvent(context.Background(), event)
			require.NoError(t, err)

			if tc.expectedOutput {
				assert.Len(t, output, 1, "Expected detection")
				// Verify the env var is in the output
				if tc.expectedEnv != "" {
					found := false
					for _, data := range output[0].Data {
						if data.Name == tc.expectedEnv {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected env var %s in output", tc.expectedEnv)
				}
			} else {
				assert.Len(t, output, 0, "Expected no detection")
			}
		})
	}
}

func TestLdPreload_FileWrite(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		pathname       string
		flags          int32
		expectedOutput bool
	}{
		{
			name:           "write to /etc/ld.so.preload",
			pathname:       "/etc/ld.so.preload",
			flags:          1, // O_WRONLY
			expectedOutput: true,
		},
		{
			name:           "read from /etc/ld.so.preload - should not trigger",
			pathname:       "/etc/ld.so.preload",
			flags:          0, // O_RDONLY
			expectedOutput: false,
		},
		// Note: different file test removed - DataFilter would prevent this event from reaching OnEvent
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &LdPreload{}
			err := detector.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
			require.NoError(t, err)

			event := &v1beta1.Event{
				Id:   v1beta1.EventId_security_file_open,
				Name: "security_file_open",
				Workload: &v1beta1.Workload{
					Process: &v1beta1.Process{
						Executable: &v1beta1.Executable{Path: "/usr/bin/vi"},
					},
				},
				Data: []*v1beta1.EventValue{
					v1beta1.NewStringValue("pathname", tc.pathname),
					v1beta1.NewInt32Value("flags", tc.flags),
				},
			}

			output, err := detector.OnEvent(context.Background(), event)
			require.NoError(t, err)

			if tc.expectedOutput {
				assert.Len(t, output, 1, "Expected detection")
			} else {
				assert.Len(t, output, 0, "Expected no detection")
			}
		})
	}
}

func TestLdPreload_Rename(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		newPath        string
		expectedOutput bool
	}{
		{
			name:           "rename to /etc/ld.so.preload - should detect",
			newPath:        "/etc/ld.so.preload",
			expectedOutput: true,
		},
		// Note: different path test removed - DataFilter would prevent this event from reaching OnEvent
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &LdPreload{}
			err := detector.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
			require.NoError(t, err)

			event := &v1beta1.Event{
				Id:   v1beta1.EventId_security_inode_rename,
				Name: "security_inode_rename",
				Workload: &v1beta1.Workload{
					Process: &v1beta1.Process{
						Executable: &v1beta1.Executable{Path: "/usr/bin/mv"},
					},
				},
				Data: []*v1beta1.EventValue{
					v1beta1.NewStringValue("new_path", tc.newPath),
				},
			}

			output, err := detector.OnEvent(context.Background(), event)
			require.NoError(t, err)

			if tc.expectedOutput {
				assert.Len(t, output, 1, "Expected detection for rename to /etc/ld.so.preload")
			} else {
				assert.Len(t, output, 0, "Expected no detection for rename to different path")
			}
		})
	}
}
