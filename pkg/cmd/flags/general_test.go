package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrepareGeneral(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		testName       string
		flags          []string
		expectedReturn GeneralConfig
		expectedError  string
	}{
		// default values (no flags)
		{
			testName: "default values",
			flags:    []string{},
			expectedReturn: GeneralConfig{
				Workdir: "/tmp/tracee",
			},
		},
		// valid single flag
		{
			testName: "valid workdir",
			flags:    []string{"workdir=/tmp/tracee2"},
			expectedReturn: GeneralConfig{
				Workdir: "/tmp/tracee2",
			},
		},
		{
			testName: "valid workdir with spaces trimmed",
			flags:    []string{"workdir= /tmp/tracee "},
			expectedReturn: GeneralConfig{
				Workdir: "/tmp/tracee",
			},
		},
		// valid multiple flags (same flag, last one wins)
		{
			testName: "valid duplicate flags",
			flags:    []string{"workdir=/tmp/tracee", "workdir=/opt/tracee"},
			expectedReturn: GeneralConfig{
				Workdir: "/opt/tracee",
			},
		},
		// invalid flag format (missing =)
		{
			testName:       "invalid flag format missing equals",
			flags:          []string{"workdir"},
			expectedReturn: GeneralConfig{},
			expectedError:  "flags.PrepareGeneral: invalid general flag: workdir, use 'trace man general' for more info",
		},
		// invalid flag value (empty)
		{
			testName:       "invalid flag value empty",
			flags:          []string{"workdir="},
			expectedReturn: GeneralConfig{},
			expectedError:  "flags.PrepareGeneral: invalid general flag: workdir value can't be empty, use 'trace man general' for more info",
		},
		// invalid flag name
		{
			testName:       "invalid flag name",
			flags:          []string{"invalid-flag=/tmp/tracee"},
			expectedReturn: GeneralConfig{},
			expectedError:  "flags.PrepareGeneral: invalid general flag: invalid-flag=/tmp/tracee, use 'trace man general' for more info",
		},
		{
			testName:       "invalid flag name empty",
			flags:          []string{"=/tmp/tracee"},
			expectedReturn: GeneralConfig{},
			expectedError:  "flags.PrepareGeneral: invalid general flag: =/tmp/tracee, use 'trace man general' for more info",
		},
		// valid edge cases
		{
			testName: "valid workdir with relative path",
			flags:    []string{"workdir=./tracee"},
			expectedReturn: GeneralConfig{
				Workdir: "./tracee",
			},
		},
		{
			testName: "valid workdir with special characters",
			flags:    []string{"workdir=/tmp/tracee-123"},
			expectedReturn: GeneralConfig{
				Workdir: "/tmp/tracee-123",
			},
		},
		// mixed valid and invalid
		{
			testName:       "mixed valid and invalid flag name",
			flags:          []string{"workdir=/tmp/tracee", "invalid-flag=/opt/tracee"},
			expectedReturn: GeneralConfig{},
			expectedError:  "flags.PrepareGeneral: invalid general flag: invalid-flag=/opt/tracee, use 'trace man general' for more info",
		},
		{
			testName:       "mixed valid and invalid format",
			flags:          []string{"workdir=/tmp/tracee", "workdir"},
			expectedReturn: GeneralConfig{},
			expectedError:  "flags.PrepareGeneral: invalid general flag: workdir, use 'trace man general' for more info",
		},
		{
			testName:       "mixed valid and invalid empty value",
			flags:          []string{"workdir=/tmp/tracee", "workdir="},
			expectedReturn: GeneralConfig{},
			expectedError:  "flags.PrepareGeneral: invalid general flag: workdir value can't be empty, use 'trace man general' for more info",
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.testName, func(t *testing.T) {
			t.Parallel()

			general, err := PrepareGeneral(tc.flags)
			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Equal(t, tc.expectedError, err.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedReturn.Workdir, general.Workdir)
			}
		})
	}
}
