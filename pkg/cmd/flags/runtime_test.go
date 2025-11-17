package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrepareRuntime(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		testName       string
		flags          []string
		expectedReturn RuntimeConfig
		expectedError  string
	}{
		// default values (no flags)
		{
			testName: "default values",
			flags:    []string{},
			expectedReturn: RuntimeConfig{
				Workdir: "/tmp/tracee",
			},
		},
		// valid single flag
		{
			testName: "valid workdir",
			flags:    []string{"workdir=/tmp/tracee2"},
			expectedReturn: RuntimeConfig{
				Workdir: "/tmp/tracee2",
			},
		},
		{
			testName: "valid workdir with spaces trimmed",
			flags:    []string{"workdir= /tmp/tracee "},
			expectedReturn: RuntimeConfig{
				Workdir: "/tmp/tracee",
			},
		},
		// valid multiple flags (same flag, last one wins)
		{
			testName: "valid duplicate flags",
			flags:    []string{"workdir=/tmp/tracee", "workdir=/opt/tracee"},
			expectedReturn: RuntimeConfig{
				Workdir: "/opt/tracee",
			},
		},
		// invalid flag format (missing =)
		{
			testName:       "invalid flag format missing equals",
			flags:          []string{"workdir"},
			expectedReturn: RuntimeConfig{},
			expectedError:  "flags.PrepareRuntime: invalid runtime flag: workdir, use 'trace man runtime' for more info",
		},
		// invalid flag value (empty)
		{
			testName:       "invalid flag value empty",
			flags:          []string{"workdir="},
			expectedReturn: RuntimeConfig{},
			expectedError:  "flags.PrepareRuntime: invalid runtime flag: workdir value can't be empty, use 'trace man runtime' for more info",
		},
		// invalid flag name
		{
			testName:       "invalid flag name",
			flags:          []string{"invalid-flag=/tmp/tracee"},
			expectedReturn: RuntimeConfig{},
			expectedError:  "flags.PrepareRuntime: invalid runtime flag: invalid-flag=/tmp/tracee, use 'trace man runtime' for more info",
		},
		{
			testName:       "invalid flag name empty",
			flags:          []string{"=/tmp/tracee"},
			expectedReturn: RuntimeConfig{},
			expectedError:  "flags.PrepareRuntime: invalid runtime flag: =/tmp/tracee, use 'trace man runtime' for more info",
		},
		// valid edge cases
		{
			testName: "valid workdir with relative path",
			flags:    []string{"workdir=./tracee"},
			expectedReturn: RuntimeConfig{
				Workdir: "./tracee",
			},
		},
		{
			testName: "valid workdir with special characters",
			flags:    []string{"workdir=/tmp/tracee-123"},
			expectedReturn: RuntimeConfig{
				Workdir: "/tmp/tracee-123",
			},
		},
		// mixed valid and invalid
		{
			testName:       "mixed valid and invalid flag name",
			flags:          []string{"workdir=/tmp/tracee", "invalid-flag=/opt/tracee"},
			expectedReturn: RuntimeConfig{},
			expectedError:  "flags.PrepareRuntime: invalid runtime flag: invalid-flag=/opt/tracee, use 'trace man runtime' for more info",
		},
		{
			testName:       "mixed valid and invalid format",
			flags:          []string{"workdir=/tmp/tracee", "workdir"},
			expectedReturn: RuntimeConfig{},
			expectedError:  "flags.PrepareRuntime: invalid runtime flag: workdir, use 'trace man runtime' for more info",
		},
		{
			testName:       "mixed valid and invalid empty value",
			flags:          []string{"workdir=/tmp/tracee", "workdir="},
			expectedReturn: RuntimeConfig{},
			expectedError:  "flags.PrepareRuntime: invalid runtime flag: workdir value can't be empty, use 'trace man runtime' for more info",
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.testName, func(t *testing.T) {
			t.Parallel()

			runtime, err := PrepareRuntime(tc.flags)
			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Equal(t, tc.expectedError, err.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedReturn.Workdir, runtime.Workdir)
			}
		})
	}
}
