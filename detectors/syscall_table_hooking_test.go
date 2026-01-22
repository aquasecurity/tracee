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

func TestSyscallTableHooking(t *testing.T) {
	t.Parallel()

	detector := &SyscallTableHooking{}
	err := detector.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
	require.NoError(t, err)

	event := &v1beta1.Event{
		Id:   v1beta1.EventId_hooked_syscall,
		Name: "hooked_syscall",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Executable: &v1beta1.Executable{Path: "/usr/bin/test"},
			},
		},
		Data: []*v1beta1.EventValue{},
	}

	output, err := detector.OnEvent(context.Background(), event)
	require.NoError(t, err)
	assert.Len(t, output, 1, "Expected detection for hooked_syscall event")
}
