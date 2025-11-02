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
		expectedReturn BuffersConfig
		expectedError  string
	}{
		// default values (no flags)
		{
			testName: "default values",
			flags:    []string{},
			expectedReturn: BuffersConfig{
				Kernel: KernelBuffersConfig{
					Events:       GetDefaultPerfBufferSize(),
					Artifacts:    GetDefaultPerfBufferSize(),
					ControlPlane: GetDefaultPerfBufferSize(),
				},
				Pipeline: 1_000,
			},
		},
		// valid single flag
		{
			testName: "valid kernel.events",
			flags:    []string{"kernel.events=2048"},
			expectedReturn: BuffersConfig{
				Kernel: KernelBuffersConfig{
					Events:       2048,
					Artifacts:    GetDefaultPerfBufferSize(),
					ControlPlane: GetDefaultPerfBufferSize(),
				},
				Pipeline: 1_000,
			},
		},
		{
			testName: "valid pipeline",
			flags:    []string{"pipeline=4000"},
			expectedReturn: BuffersConfig{
				Kernel: KernelBuffersConfig{
					Events:       GetDefaultPerfBufferSize(),
					Artifacts:    GetDefaultPerfBufferSize(),
					ControlPlane: GetDefaultPerfBufferSize(),
				},
				Pipeline: 4000,
			},
		},
		{
			testName: "valid kernel.artifacts",
			flags:    []string{"kernel.artifacts=512"},
			expectedReturn: BuffersConfig{
				Kernel: KernelBuffersConfig{
					Events:       GetDefaultPerfBufferSize(),
					Artifacts:    512,
					ControlPlane: GetDefaultPerfBufferSize(),
				},
				Pipeline: 1_000,
			},
		},
		{
			testName: "valid kernel.control-plane",
			flags:    []string{"kernel.control-plane=256"},
			expectedReturn: BuffersConfig{
				Kernel: KernelBuffersConfig{
					Events:       GetDefaultPerfBufferSize(),
					Artifacts:    GetDefaultPerfBufferSize(),
					ControlPlane: 256,
				},
				Pipeline: 1_000,
			},
		},
		// valid multiple flags
		{
			testName: "valid multiple flags",
			flags:    []string{"kernel.events=2048", "pipeline=5000"},
			expectedReturn: BuffersConfig{
				Kernel: KernelBuffersConfig{
					Events:       2048,
					Artifacts:    GetDefaultPerfBufferSize(),
					ControlPlane: GetDefaultPerfBufferSize(),
				},
				Pipeline: 5000,
			},
		},
		{
			testName: "valid all flags",
			flags:    []string{"kernel.events=2048", "pipeline=4000", "kernel.artifacts=512", "kernel.control-plane=256"},
			expectedReturn: BuffersConfig{
				Kernel: KernelBuffersConfig{
					Events:       2048,
					Artifacts:    512,
					ControlPlane: 256,
				},
				Pipeline: 4000,
			},
		},
		{
			testName: "valid flags in different order",
			flags:    []string{"kernel.artifacts=512", "kernel.control-plane=256", "kernel.events=2048", "pipeline=40000"},
			expectedReturn: BuffersConfig{
				Kernel: KernelBuffersConfig{
					Events:       2048,
					Artifacts:    512,
					ControlPlane: 256,
				},
				Pipeline: 40_000,
			},
		},
		// valid duplicate flags (last one wins)
		{
			testName: "valid duplicate flags",
			flags:    []string{"kernel.events=2048", "kernel.events=4096"},
			expectedReturn: BuffersConfig{
				Kernel: KernelBuffersConfig{
					Events:       4096,
					Artifacts:    GetDefaultPerfBufferSize(),
					ControlPlane: GetDefaultPerfBufferSize(),
				},
				Pipeline: 1_000,
			},
		},
		// invalid flag format (missing =)
		{
			testName:       "invalid flag format missing equals",
			flags:          []string{"kernel.events"},
			expectedReturn: BuffersConfig{},
			expectedError:  invalidBuffersFlagErrorMsg("kernel.events"),
		},
		{
			testName:       "invalid flag format missing equals with value",
			flags:          []string{"kernel.events2048"},
			expectedReturn: BuffersConfig{},
			expectedError:  invalidBuffersFlagErrorMsg("kernel.events2048"),
		},
		{
			testName:       "invalid flag format empty value",
			flags:          []string{"kernel.events="},
			expectedReturn: BuffersConfig{},
			expectedError:  invalidBuffersFlagErrorMsg("kernel.events="),
		},
		// invalid flag name
		{
			testName:       "invalid flag name",
			flags:          []string{"invalid-flag=2048"},
			expectedReturn: BuffersConfig{},
			expectedError:  invalidBuffersFlagErrorMsg("invalid-flag"),
		},
		{
			testName:       "invalid flag name with typo",
			flags:          []string{"kernel.event=2048"},
			expectedReturn: BuffersConfig{},
			expectedError:  invalidBuffersFlagErrorMsg("kernel.event"),
		},
		{
			testName:       "invalid flag name empty",
			flags:          []string{"=2048"},
			expectedReturn: BuffersConfig{},
			expectedError:  invalidBuffersFlagErrorMsg("=2048"),
		},
		// invalid flag value (non-numeric) - note: parseInt returns 0, doesn't error
		{
			testName:       "invalid flag value non-numeric",
			flags:          []string{"kernel.events=invalid"},
			expectedReturn: BuffersConfig{},
			expectedError:  invalidBufferFlagPositiveIntegerError("kernel.events"),
		},
		{
			testName:       "invalid flag value negative",
			flags:          []string{"kernel.events=-2048"},
			expectedReturn: BuffersConfig{},
			expectedError:  invalidBufferFlagNegativeOrZeroError("kernel.events"),
		},
		// valid edge cases
		{
			testName:       "valid zero value",
			flags:          []string{"kernel.events=0"},
			expectedReturn: BuffersConfig{},
			expectedError:  invalidBufferFlagNegativeOrZeroError("kernel.events"),
		},
		{
			testName: "valid large value",
			flags:    []string{"kernel.events=999999"},
			expectedReturn: BuffersConfig{
				Kernel: KernelBuffersConfig{
					Events:       999999,
					Artifacts:    GetDefaultPerfBufferSize(),
					ControlPlane: GetDefaultPerfBufferSize(),
				},
				Pipeline: 1_000,
			},
		},
		// mixed valid and invalid
		{
			testName:       "mixed valid and invalid flag name",
			flags:          []string{"kernel.events=2048", "invalid-flag=4096"},
			expectedReturn: BuffersConfig{},
			expectedError:  invalidBuffersFlagErrorMsg("invalid-flag"),
		},
		{
			testName:       "mixed valid and invalid format",
			flags:          []string{"kernel.events=2048", "pipeline"},
			expectedReturn: BuffersConfig{},
			expectedError:  invalidBuffersFlagErrorMsg("pipeline"),
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.testName, func(t *testing.T) {
			t.Parallel()

			buffers, err := PrepareBuffers(tc.flags)
			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Equal(t, "flags.PrepareBuffers: "+tc.expectedError, err.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedReturn.Kernel.Events, buffers.Kernel.Events)
				assert.Equal(t, tc.expectedReturn.Kernel.Artifacts, buffers.Kernel.Artifacts)
				assert.Equal(t, tc.expectedReturn.Kernel.ControlPlane, buffers.Kernel.ControlPlane)
				assert.Equal(t, tc.expectedReturn.Pipeline, buffers.Pipeline)
			}
		})
	}
}

func TestBuffersConfig_flags(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		testName      string
		config        BuffersConfig
		expectedFlags []string
	}{
		{
			testName:      "empty config returns empty flags",
			config:        BuffersConfig{},
			expectedFlags: []string{},
		},
		{
			testName: "kernel.events only",
			config: BuffersConfig{
				Kernel: KernelBuffersConfig{Events: 2048},
			},
			expectedFlags: []string{"kernel.events=2048"},
		},
		{
			testName: "kernel.artifacts only",
			config: BuffersConfig{
				Kernel: KernelBuffersConfig{Artifacts: 512},
			},
			expectedFlags: []string{"kernel.artifacts=512"},
		},
		{
			testName: "kernel.control-plane only",
			config: BuffersConfig{
				Kernel: KernelBuffersConfig{ControlPlane: 256},
			},
			expectedFlags: []string{"kernel.control-plane=256"},
		},
		{
			testName: "pipeline only",
			config: BuffersConfig{
				Pipeline: 4000,
			},
			expectedFlags: []string{"pipeline=4000"},
		},
		{
			testName: "all flags set",
			config: BuffersConfig{
				Kernel: KernelBuffersConfig{
					Events:       2048,
					Artifacts:    512,
					ControlPlane: 256,
				},
				Pipeline: 4000,
			},
			expectedFlags: []string{
				"kernel.events=2048",
				"kernel.artifacts=512",
				"kernel.control-plane=256",
				"pipeline=4000",
			},
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.testName, func(t *testing.T) {
			t.Parallel()

			flags := tc.config.flags()
			assert.Equal(t, tc.expectedFlags, flags)
		})
	}
}
