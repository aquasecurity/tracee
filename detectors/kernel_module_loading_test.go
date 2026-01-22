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

func TestKernelModuleLoading(t *testing.T) {
	t.Parallel()

	detector := &KernelModuleLoading{}
	err := detector.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
	require.NoError(t, err)

	event := &v1beta1.Event{
		Id:   v1beta1.EventId_module_load,
		Name: "module_load",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Executable: &v1beta1.Executable{Path: "/usr/bin/insmod"},
			},
		},
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("module_name", "test_module"),
		},
	}

	output, err := detector.OnEvent(context.Background(), event)
	require.NoError(t, err)
	assert.Len(t, output, 1, "Expected detection for module_load event")
}
