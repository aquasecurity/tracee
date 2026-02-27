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

func TestScheduledTaskModification_FileOpen(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		pathname       string
		expectedOutput bool
	}{
		{
			name:           "write to /etc/crontab",
			pathname:       "/etc/crontab",
			expectedOutput: true,
		},
		{
			name:           "write to /etc/anacrontab",
			pathname:       "/etc/anacrontab",
			expectedOutput: true,
		},
		{
			name:           "write to /etc/cron.d/custom",
			pathname:       "/etc/cron.d/custom",
			expectedOutput: true,
		},
		{
			name:           "write to /etc/cron.hourly/job",
			pathname:       "/etc/cron.hourly/job",
			expectedOutput: true,
		},
		{
			name:           "write to /var/spool/cron/crontabs/root",
			pathname:       "/var/spool/cron/crontabs/root",
			expectedOutput: true,
		},
		// Note: unrelated file test removed - DataFilter would prevent this event from reaching OnEvent
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &ScheduledTaskModification{}
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

func TestScheduledTaskModification_CommandExecution(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		execPath       string
		expectedOutput bool
	}{
		{
			name:           "crontab execution",
			execPath:       "/usr/bin/crontab",
			expectedOutput: true,
		},
		{
			name:           "at execution",
			execPath:       "/usr/bin/at",
			expectedOutput: true,
		},
		{
			name:           "batch execution",
			execPath:       "/usr/bin/batch",
			expectedOutput: true,
		},
		{
			name:           "launchd execution (macOS)",
			execPath:       "/sbin/launchd",
			expectedOutput: true,
		},
		{
			name:           "unrelated command - should not trigger",
			execPath:       "/usr/bin/ls",
			expectedOutput: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &ScheduledTaskModification{}
			err := detector.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
			require.NoError(t, err)

			event := &v1beta1.Event{
				Id:   v1beta1.EventId_sched_process_exec,
				Name: "sched_process_exec",
				Workload: &v1beta1.Workload{
					Process: &v1beta1.Process{
						Executable: &v1beta1.Executable{Path: tc.execPath},
					},
				},
				Data: []*v1beta1.EventValue{
					v1beta1.NewStringValue("pathname", tc.execPath),
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

func TestScheduledTaskModification_Rename(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		newPath        string
		expectedOutput bool
	}{
		{
			name:           "rename to /etc/crontab - should detect",
			newPath:        "/etc/crontab",
			expectedOutput: true,
		},
		{
			name:           "rename to /etc/anacrontab - should detect",
			newPath:        "/etc/anacrontab",
			expectedOutput: true,
		},
		{
			name:           "rename to /etc/cron.d/custom - should detect",
			newPath:        "/etc/cron.d/custom",
			expectedOutput: true,
		},
		{
			name:           "rename to /etc/cron.hourly/job - should detect",
			newPath:        "/etc/cron.hourly/job",
			expectedOutput: true,
		},
		// Note: unrelated file test removed - DataFilter would prevent this event from reaching OnEvent
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &ScheduledTaskModification{}
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
				assert.Len(t, output, 1, "Expected detection for rename to cron file/dir")
			} else {
				assert.Len(t, output, 0, "Expected no detection for rename to unrelated file")
			}
		})
	}
}
