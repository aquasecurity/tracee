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

func TestCgroupReleaseAgentModification(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		eventId        v1beta1.EventId
		eventName      string
		pathname       string
		flags          int32
		expectedOutput bool
	}{
		{
			name:           "security_file_open on release_agent with write flags",
			eventId:        v1beta1.EventId_security_file_open,
			eventName:      "security_file_open",
			pathname:       "/sys/fs/cgroup/release_agent",
			flags:          1, // O_WRONLY
			expectedOutput: true,
		},
		{
			name:           "security_file_open on nested cgroup release_agent",
			eventId:        v1beta1.EventId_security_file_open,
			eventName:      "security_file_open",
			pathname:       "/sys/fs/cgroup/test/release_agent",
			flags:          1, // O_WRONLY
			expectedOutput: true,
		},
		{
			name:           "security_file_open on release_agent with read flags - should not trigger",
			eventId:        v1beta1.EventId_security_file_open,
			eventName:      "security_file_open",
			pathname:       "/sys/fs/cgroup/release_agent",
			flags:          0, // O_RDONLY
			expectedOutput: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &CgroupReleaseAgentModification{}
			err := detector.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
			require.NoError(t, err)

			event := &v1beta1.Event{
				Id:   tc.eventId,
				Name: tc.eventName,
				Workload: &v1beta1.Workload{
					Process: &v1beta1.Process{
						Executable: &v1beta1.Executable{Path: "/usr/bin/test"},
					},
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

func TestCgroupReleaseAgentModification_Rename(t *testing.T) {
	t.Parallel()

	detector := &CgroupReleaseAgentModification{}
	err := detector.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
	require.NoError(t, err)

	event := &v1beta1.Event{
		Id:   v1beta1.EventId_security_inode_rename,
		Name: "security_inode_rename",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Executable: &v1beta1.Executable{Path: "/usr/bin/mv"},
			},
			Container: &v1beta1.Container{
				Id:      "test-container",
				Started: true,
			},
		},
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("new_path", "/sys/fs/cgroup/release_agent"),
		},
	}

	output, err := detector.OnEvent(context.Background(), event)
	require.NoError(t, err)
	assert.Len(t, output, 1, "Expected detection for rename to release_agent")
}

func TestCgroupReleaseAgentModification_Rename_WrongPath(t *testing.T) {
	t.Parallel()

	detector := &CgroupReleaseAgentModification{}
	err := detector.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
	require.NoError(t, err)

	event := &v1beta1.Event{
		Id:   v1beta1.EventId_security_inode_rename,
		Name: "security_inode_rename",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Executable: &v1beta1.Executable{Path: "/usr/bin/mv"},
			},
			Container: &v1beta1.Container{
				Id:      "test-container",
				Started: true,
			},
		},
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("new_path", "/sys/fs/cgroup/something_else"),
		},
	}

	output, err := detector.OnEvent(context.Background(), event)
	require.NoError(t, err)
	assert.Len(t, output, 0, "Expected no detection for rename to non-release_agent file")
}
