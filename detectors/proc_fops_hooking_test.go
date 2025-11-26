package detectors

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func TestProcFopsHooking(t *testing.T) {
	t.Parallel()

	detector := &ProcFopsHooking{}
	err := detector.Init(detection.DetectorParams{Logger: &mockLogger{}})
	require.NoError(t, err)

	event := &v1beta1.Event{
		Id:   v1beta1.EventId_hooked_proc_fops,
		Name: "hooked_proc_fops",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Executable: &v1beta1.Executable{Path: "/usr/bin/test"},
			},
		},
		Data: []*v1beta1.EventValue{},
	}

	output, err := detector.OnEvent(context.Background(), event)
	require.NoError(t, err)
	assert.Len(t, output, 1, "Expected detection for hooked_proc_fops event")
}
