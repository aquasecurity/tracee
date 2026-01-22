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

func TestRcdModification_FileOpen(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		pathname       string
		expectedOutput bool
	}{
		{
			name:           "write to /etc/rc.local",
			pathname:       "/etc/rc.local",
			expectedOutput: true,
		},
		{
			name:           "write to /etc/init.d/rc.local",
			pathname:       "/etc/init.d/rc.local",
			expectedOutput: true,
		},
		{
			name:           "write to /etc/rc1.d/S99test",
			pathname:       "/etc/rc1.d/S99test",
			expectedOutput: true,
		},
		{
			name:           "write to /etc/rc.d/test",
			pathname:       "/etc/rc.d/test",
			expectedOutput: true,
		},
		// Note: unrelated file test removed - DataFilter would prevent this event from reaching OnEvent
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &RcdModification{}
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
					v1beta1.NewInt32Value("flags", 1), // O_WRONLY
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

func TestRcdModification_CommandExecution(t *testing.T) {
	t.Parallel()

	detector := &RcdModification{}
	err := detector.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
	require.NoError(t, err)

	event := &v1beta1.Event{
		Id:   v1beta1.EventId_sched_process_exec,
		Name: "sched_process_exec",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Executable: &v1beta1.Executable{Path: "/usr/sbin/update-rc.d"},
			},
		},
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/usr/sbin/update-rc.d"),
		},
	}

	output, err := detector.OnEvent(context.Background(), event)
	require.NoError(t, err)
	assert.Len(t, output, 1, "Expected detection for update-rc.d execution")
}

func TestRcdModification_Rename(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		newPath        string
		expectedOutput bool
	}{
		{
			name:           "rename to /etc/rc.local - should detect",
			newPath:        "/etc/rc.local",
			expectedOutput: true,
		},
		{
			name:           "rename to /etc/init.d/rc.local - should detect",
			newPath:        "/etc/init.d/rc.local",
			expectedOutput: true,
		},
		{
			name:           "rename to /etc/rc1.d/S99test - should detect",
			newPath:        "/etc/rc1.d/S99test",
			expectedOutput: true,
		},
		// Note: unrelated file test removed - DataFilter would prevent this event from reaching OnEvent
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &RcdModification{}
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
				assert.Len(t, output, 1, "Expected detection for rename to rcd file/dir")
			} else {
				assert.Len(t, output, 0, "Expected no detection for rename to unrelated file")
			}
		})
	}
}
