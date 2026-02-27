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

func TestDefaultLoaderModification(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		eventId        v1beta1.EventId
		eventName      string
		pathname       string
		flags          int32 // Only used for security_file_open
		expectedOutput bool
	}{
		{
			name:           "write to /lib/ld-linux.so.2",
			eventId:        v1beta1.EventId_security_file_open,
			eventName:      "security_file_open",
			pathname:       "/lib/ld-linux.so.2",
			flags:          1, // O_WRONLY
			expectedOutput: true,
		},
		{
			name:           "write to /lib64/ld-linux-x86-64.so.2",
			eventId:        v1beta1.EventId_security_file_open,
			eventName:      "security_file_open",
			pathname:       "/lib64/ld-linux-x86-64.so.2",
			flags:          1, // O_WRONLY
			expectedOutput: true,
		},
		{
			name:           "write to /usr/lib/ld.so.1",
			eventId:        v1beta1.EventId_security_file_open,
			eventName:      "security_file_open",
			pathname:       "/usr/lib/ld.so.1",
			flags:          1, // O_WRONLY
			expectedOutput: true,
		},
		{
			name:           "write with combined flags (O_WRONLY|O_CREAT)",
			eventId:        v1beta1.EventId_security_file_open,
			eventName:      "security_file_open",
			pathname:       "/lib/ld-linux.so.2",
			flags:          65, // O_WRONLY (1) | O_CREAT (64)
			expectedOutput: true,
		},
		{
			name:           "rename to /lib/ld-linux.so.2",
			eventId:        v1beta1.EventId_security_inode_rename,
			eventName:      "security_inode_rename",
			pathname:       "/lib/ld-linux.so.2",
			expectedOutput: true,
		},
		{
			name:           "read /usr/lib/ld.so.1 - should not trigger",
			eventId:        v1beta1.EventId_security_file_open,
			eventName:      "security_file_open",
			pathname:       "/usr/lib/ld.so.1",
			flags:          0, // O_RDONLY
			expectedOutput: false,
		},
		{
			name:           "write to unrelated file - should not trigger",
			eventId:        v1beta1.EventId_security_file_open,
			eventName:      "security_file_open",
			pathname:       "/etc/ld.so.conf",
			flags:          1, // O_WRONLY
			expectedOutput: false,
		},
		{
			name:           "write to /home/user/ld.so - should not trigger",
			eventId:        v1beta1.EventId_security_file_open,
			eventName:      "security_file_open",
			pathname:       "/home/user/ld.so",
			flags:          1, // O_WRONLY
			expectedOutput: false,
		},
		{
			name:           "rename to /tmp/something - should not trigger",
			eventId:        v1beta1.EventId_security_inode_rename,
			eventName:      "security_inode_rename",
			pathname:       "/tmp/something",
			expectedOutput: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &DefaultLoaderModification{}
			err := detector.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
			require.NoError(t, err)

			var data []*v1beta1.EventValue
			if tc.eventName == "security_file_open" {
				data = []*v1beta1.EventValue{
					v1beta1.NewStringValue("pathname", tc.pathname),
					v1beta1.NewInt32Value("flags", tc.flags),
				}
			} else {
				data = []*v1beta1.EventValue{
					v1beta1.NewStringValue("new_path", tc.pathname),
				}
			}

			event := &v1beta1.Event{
				Id:   tc.eventId,
				Name: tc.eventName,
				Workload: &v1beta1.Workload{
					Process: &v1beta1.Process{
						Executable: &v1beta1.Executable{Path: "/usr/bin/test"},
					},
				},
				Data: data,
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
