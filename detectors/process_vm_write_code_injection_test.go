package detectors

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/detectors/testutil"
)

func TestProcessVmWriteCodeInjection(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		currentPid     int32
		targetPid      int32
		expectedOutput bool
	}{
		{
			name:           "write to different process",
			currentPid:     1234,
			targetPid:      5678,
			expectedOutput: true,
		},
		{
			name:           "write to self - should not trigger",
			currentPid:     1234,
			targetPid:      1234,
			expectedOutput: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &ProcessVmWriteCodeInjection{}
			err := detector.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
			require.NoError(t, err)

			event := &v1beta1.Event{
				Id:   v1beta1.EventId_process_vm_writev,
				Name: "process_vm_writev",
				Workload: &v1beta1.Workload{
					Process: &v1beta1.Process{
						Pid:        wrapperspb.UInt32(uint32(tc.currentPid)),
						Executable: &v1beta1.Executable{Path: "/usr/bin/test"},
					},
				},
				Data: []*v1beta1.EventValue{
					v1beta1.NewInt32Value("pid", tc.targetPid),
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
