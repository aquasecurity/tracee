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

func TestSudoersModification(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		eventId        v1beta1.EventId
		eventName      string
		pathname       string
		expectedOutput bool
	}{
		{
			name:           "write to /etc/sudoers",
			eventId:        v1beta1.EventId_security_file_open,
			eventName:      "security_file_open",
			pathname:       "/etc/sudoers",
			expectedOutput: true,
		},
		{
			name:           "write to /private/etc/sudoers",
			eventId:        v1beta1.EventId_security_file_open,
			eventName:      "security_file_open",
			pathname:       "/private/etc/sudoers",
			expectedOutput: true,
		},
		{
			name:           "write to /etc/sudoers.d/custom",
			eventId:        v1beta1.EventId_security_file_open,
			eventName:      "security_file_open",
			pathname:       "/etc/sudoers.d/custom",
			expectedOutput: true,
		},
		{
			name:           "write to /private/etc/sudoers.d/custom",
			eventId:        v1beta1.EventId_security_file_open,
			eventName:      "security_file_open",
			pathname:       "/private/etc/sudoers.d/custom",
			expectedOutput: true,
		},
		// Note: unrelated file test removed - DataFilter would prevent this event from reaching OnEvent
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &SudoersModification{}
			err := detector.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
			require.NoError(t, err)

			event := &v1beta1.Event{
				Id:   tc.eventId,
				Name: tc.eventName,
				Workload: &v1beta1.Workload{
					Process: &v1beta1.Process{
						Executable: &v1beta1.Executable{Path: "/usr/bin/vi"},
					},
				},
				Data: []*v1beta1.EventValue{
					v1beta1.NewStringValue("pathname", tc.pathname),
					v1beta1.NewInt32Value("flags", int32(parsers.O_WRONLY.Value())),
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

func TestSudoersModification_Rename(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		newPath        string
		expectedOutput bool
	}{
		{
			name:           "rename to /etc/sudoers - should detect",
			newPath:        "/etc/sudoers",
			expectedOutput: true,
		},
		{
			name:           "rename to /private/etc/sudoers - should detect",
			newPath:        "/private/etc/sudoers",
			expectedOutput: true,
		},
		{
			name:           "rename to /etc/sudoers.d/custom - should detect",
			newPath:        "/etc/sudoers.d/custom",
			expectedOutput: true,
		},
		{
			name:           "rename to /private/etc/sudoers.d/custom - should detect",
			newPath:        "/private/etc/sudoers.d/custom",
			expectedOutput: true,
		},
		// Note: unrelated file test removed - DataFilter would prevent this event from reaching OnEvent
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &SudoersModification{}
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
				assert.Len(t, output, 1, "Expected detection for rename to sudoers file/dir")
			} else {
				assert.Len(t, output, 0, "Expected no detection for rename to unrelated file")
			}
		})
	}
}
