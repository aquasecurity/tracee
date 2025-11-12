package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrepareBuffers(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		testName       string
		flags          []string
		expectedReturn Buffers
		expectedError  string
	}{
		// default values (no flags)
		{
			testName: "default values",
			flags:    []string{},
			expectedReturn: Buffers{
				EventsSize:       GetDefaultPerfBufferSize(),
				BlobSize:         GetDefaultPerfBufferSize(),
				ControlPlaneSize: GetDefaultPerfBufferSize(),
				PipelineSize:     10_000,
			},
		},
		// valid single flag
		{
			testName: "valid kernel-events",
			flags:    []string{"kernel-events=2048"},
			expectedReturn: Buffers{
				EventsSize:       2048,
				BlobSize:         GetDefaultPerfBufferSize(),
				ControlPlaneSize: GetDefaultPerfBufferSize(),
				PipelineSize:     10_000,
			},
		},
		{
			testName: "valid pipeline",
			flags:    []string{"pipeline=4000"},
			expectedReturn: Buffers{
				EventsSize:       GetDefaultPerfBufferSize(),
				BlobSize:         GetDefaultPerfBufferSize(),
				ControlPlaneSize: GetDefaultPerfBufferSize(),
				PipelineSize:     4000,
			},
		},
		{
			testName: "valid blob",
			flags:    []string{"kernel-blob=512"},
			expectedReturn: Buffers{
				EventsSize:       GetDefaultPerfBufferSize(),
				BlobSize:         512,
				ControlPlaneSize: GetDefaultPerfBufferSize(),
				PipelineSize:     10_000,
			},
		},
		{
			testName: "valid control-plane-events",
			flags:    []string{"control-plane-events=256"},
			expectedReturn: Buffers{
				EventsSize:       GetDefaultPerfBufferSize(),
				BlobSize:         GetDefaultPerfBufferSize(),
				ControlPlaneSize: 256,
				PipelineSize:     10_000,
			},
		},
		// valid multiple flags
		{
			testName: "valid multiple flags",
			flags:    []string{"kernel-events=2048", "pipeline=5000"},
			expectedReturn: Buffers{
				EventsSize:       2048,
				BlobSize:         GetDefaultPerfBufferSize(),
				ControlPlaneSize: GetDefaultPerfBufferSize(),
				PipelineSize:     5000,
			},
		},
		{
			testName: "valid all flags",
			flags:    []string{"kernel-events=2048", "pipeline=4000", "kernel-blob=512", "control-plane-events=256"},
			expectedReturn: Buffers{
				EventsSize:       2048,
				BlobSize:         512,
				ControlPlaneSize: 256,
				PipelineSize:     4000,
			},
		},
		{
			testName: "valid flags in different order",
			flags:    []string{"kernel-blob=512", "control-plane-events=256", "kernel-events=2048", "pipeline=40000"},
			expectedReturn: Buffers{
				EventsSize:       2048,
				BlobSize:         512,
				ControlPlaneSize: 256,
				PipelineSize:     40_000,
			},
		},
		// valid duplicate flags (last one wins)
		{
			testName: "valid duplicate flags",
			flags:    []string{"kernel-events=2048", "kernel-events=4096"},
			expectedReturn: Buffers{
				EventsSize:       4096,
				BlobSize:         GetDefaultPerfBufferSize(),
				ControlPlaneSize: GetDefaultPerfBufferSize(),
				PipelineSize:     10_000,
			},
		},
		// invalid flag format (missing =)
		{
			testName:       "invalid flag format missing equals",
			flags:          []string{"kernel-events"},
			expectedReturn: Buffers{},
			expectedError:  "flags.PrepareBuffers: invalid buffer flag: kernel-events, use 'trace man buffers' for more info",
		},
		{
			testName:       "invalid flag format missing equals with value",
			flags:          []string{"kernel-events2048"},
			expectedReturn: Buffers{},
			expectedError:  "flags.PrepareBuffers: invalid buffer flag: kernel-events2048, use 'trace man buffers' for more info",
		},
		{
			testName:       "invalid flag format empty value",
			flags:          []string{"kernel-events="},
			expectedReturn: Buffers{},
			expectedError:  "flags.PrepareBuffers: invalid buffer flag: kernel-events=, use 'trace man buffers' for more info",
		},
		// invalid flag name
		{
			testName:       "invalid flag name",
			flags:          []string{"invalid-flag=2048"},
			expectedReturn: Buffers{},
			expectedError:  "flags.PrepareBuffers: invalid buffer flag: invalid-flag, use 'trace man buffers' for more info",
		},
		{
			testName:       "invalid flag name with typo",
			flags:          []string{"kernel-event=2048"},
			expectedReturn: Buffers{},
			expectedError:  "flags.PrepareBuffers: invalid buffer flag: kernel-event, use 'trace man buffers' for more info",
		},
		{
			testName:       "invalid flag name empty",
			flags:          []string{"=2048"},
			expectedReturn: Buffers{},
			expectedError:  "flags.PrepareBuffers: invalid buffer flag: =2048, use 'trace man buffers' for more info",
		},
		// invalid flag value (non-numeric) - note: parseInt returns 0, doesn't error
		{
			testName:       "invalid flag value non-numeric",
			flags:          []string{"kernel-events=invalid"},
			expectedReturn: Buffers{},
			expectedError:  "flags.PrepareBuffers: invalid buffer flag: kernel-events value must be a positive integer, use 'trace man buffers' for more info",
		},
		{
			testName:       "invalid flag value negative",
			flags:          []string{"kernel-events=-2048"},
			expectedReturn: Buffers{},
			expectedError:  "flags.PrepareBuffers: invalid buffer flag: kernel-events value can't be negative or zero, use 'trace man buffers' for more info",
		},
		// valid edge cases
		{
			testName:       "valid zero value",
			flags:          []string{"kernel-events=0"},
			expectedReturn: Buffers{},
			expectedError:  "flags.PrepareBuffers: invalid buffer flag: kernel-events value can't be negative or zero, use 'trace man buffers' for more info",
		},
		{
			testName: "valid large value",
			flags:    []string{"kernel-events=999999"},
			expectedReturn: Buffers{
				EventsSize:       999999,
				BlobSize:         GetDefaultPerfBufferSize(),
				ControlPlaneSize: GetDefaultPerfBufferSize(),
				PipelineSize:     10_000,
			},
		},
		// mixed valid and invalid
		{
			testName:       "mixed valid and invalid flag name",
			flags:          []string{"kernel-events=2048", "invalid-flag=4096"},
			expectedReturn: Buffers{},
			expectedError:  "flags.PrepareBuffers: invalid buffer flag: invalid-flag, use 'trace man buffers' for more info",
		},
		{
			testName:       "mixed valid and invalid format",
			flags:          []string{"kernel-events=2048", "pipeline"},
			expectedReturn: Buffers{},
			expectedError:  "flags.PrepareBuffers: invalid buffer flag: pipeline, use 'trace man buffers' for more info",
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.testName, func(t *testing.T) {
			t.Parallel()

			buffers, err := PrepareBuffers(tc.flags)
			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Equal(t, tc.expectedError, err.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedReturn.EventsSize, buffers.EventsSize)
				assert.Equal(t, tc.expectedReturn.BlobSize, buffers.BlobSize)
				assert.Equal(t, tc.expectedReturn.ControlPlaneSize, buffers.ControlPlaneSize)
				assert.Equal(t, tc.expectedReturn.PipelineSize, buffers.PipelineSize)
			}
		})
	}
}
