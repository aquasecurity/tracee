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

func TestProcFopsHooking(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		hookedSymbols  []*v1beta1.HookedSymbolData
		expectedOutput bool
	}{
		{
			name: "should trigger detection - with hooked symbols",
			hookedSymbols: []*v1beta1.HookedSymbolData{
				{SymbolName: "struct file_operations pointer", ModuleOwner: "hidden"},
				{SymbolName: "iterate_shared", ModuleOwner: "phide"},
			},
			expectedOutput: true,
		},
		{
			name:           "should not trigger detection - empty slice",
			hookedSymbols:  []*v1beta1.HookedSymbolData{},
			expectedOutput: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &ProcFopsHooking{}
			err := detector.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
			require.NoError(t, err)

			event := &v1beta1.Event{
				Id:   v1beta1.EventId_hooked_proc_fops,
				Name: "hooked_proc_fops",
				Workload: &v1beta1.Workload{
					Process: &v1beta1.Process{
						Executable: &v1beta1.Executable{Path: "/usr/bin/test"},
					},
				},
				Data: []*v1beta1.EventValue{
					{
						Name: "hooked_fops_pointers",
						Value: &v1beta1.EventValue_HookedSyscalls{
							HookedSyscalls: &v1beta1.HookedSyscalls{Value: tc.hookedSymbols},
						},
					},
				},
			}

			output, err := detector.OnEvent(context.Background(), event)
			require.NoError(t, err)

			if tc.expectedOutput {
				assert.Len(t, output, 1, "Expected detection for hooked_proc_fops event")
				// Verify the hooked symbols data is included in the output
				assert.NotNil(t, output[0].Data, "Expected data in output")
				assert.Len(t, output[0].Data, 1, "Expected one data field")
				assert.Equal(t, "Hooked proc file operations", output[0].Data[0].Name)
				// Verify the data contains the hooked symbols
				if hookedSyscallsVal, ok := output[0].Data[0].Value.(*v1beta1.EventValue_HookedSyscalls); ok {
					assert.Equal(t, len(tc.hookedSymbols), len(hookedSyscallsVal.HookedSyscalls.Value))
				} else {
					t.Fatal("Expected HookedSyscalls value type")
				}
			} else {
				assert.Len(t, output, 0, "Expected no detection for empty hooked symbols")
			}
		})
	}
}
