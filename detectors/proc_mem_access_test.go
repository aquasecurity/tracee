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

func TestProcMemAccess(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		pathname       string
		flags          int32
		expectedOutput bool
	}{
		{
			name:           "read /proc/1234/mem",
			pathname:       "/proc/1234/mem",
			flags:          0, // O_RDONLY
			expectedOutput: true,
		},
		{
			name:           "read /proc/self/mem",
			pathname:       "/proc/self/mem",
			flags:          0, // O_RDONLY
			expectedOutput: true,
		},
		{
			name:           "write /proc/1234/mem - should not trigger",
			pathname:       "/proc/1234/mem",
			flags:          1, // O_WRONLY
			expectedOutput: false,
		},
		{
			name:           "read /proc/meminfo - should not trigger",
			pathname:       "/proc/meminfo",
			flags:          0, // O_RDONLY
			expectedOutput: false,
		},
		{
			name:           "read /proc/1234/maps - should not trigger",
			pathname:       "/proc/1234/maps",
			flags:          0, // O_RDONLY
			expectedOutput: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &ProcMemAccess{}
			err := detector.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
			require.NoError(t, err)

			event := &v1beta1.Event{
				Id:   v1beta1.EventId_security_file_open,
				Name: "security_file_open",
				Workload: &v1beta1.Workload{
					Process: &v1beta1.Process{
						Executable: &v1beta1.Executable{Path: "/usr/bin/test"},
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
