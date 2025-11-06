package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuntimeConfig_flags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   RuntimeConfig
		expected []string
	}{
		{
			name: "empty config",
			config: RuntimeConfig{
				Workdir: "",
			},
			expected: []string{
				"workdir=",
			},
		},
		{
			name: "default workdir",
			config: RuntimeConfig{
				Workdir: "/tmp/tracee",
			},
			expected: []string{
				"workdir=/tmp/tracee",
			},
		},
		{
			name: "custom workdir",
			config: RuntimeConfig{
				Workdir: "/opt/tracee",
			},
			expected: []string{
				"workdir=/opt/tracee",
			},
		},
		{
			name: "workdir with custom path",
			config: RuntimeConfig{
				Workdir: "/var/lib/tracee",
			},
			expected: []string{
				"workdir=/var/lib/tracee",
			},
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.config.flags()
			if !slicesEqualIgnoreOrder(got, tt.expected) {
				t.Errorf("flags() = %v, want %v", got, tt.expected)
			}
		})
	}
}

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
			expectedError:  invalidRuntimeFlagError("workdir"),
		},
		// invalid flag value (empty)
		{
			testName:       "invalid flag value empty",
			flags:          []string{"workdir="},
			expectedReturn: RuntimeConfig{},
			expectedError:  invalidRuntimeFlagEmptyValueError("workdir"),
		},
		// invalid flag name
		{
			testName:       "invalid flag name",
			flags:          []string{"invalid-flag=/tmp/tracee"},
			expectedReturn: RuntimeConfig{},
			expectedError:  invalidRuntimeFlagError("invalid-flag=/tmp/tracee"),
		},
		{
			testName:       "invalid flag name empty",
			flags:          []string{"=/tmp/tracee"},
			expectedReturn: RuntimeConfig{},
			expectedError:  invalidRuntimeFlagError("=/tmp/tracee"),
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
			expectedError:  invalidRuntimeFlagError("invalid-flag=/opt/tracee"),
		},
		{
			testName:       "mixed valid and invalid format",
			flags:          []string{"workdir=/tmp/tracee", "workdir"},
			expectedReturn: RuntimeConfig{},
			expectedError:  invalidRuntimeFlagError("workdir"),
		},
		{
			testName:       "mixed valid and invalid empty value",
			flags:          []string{"workdir=/tmp/tracee", "workdir="},
			expectedReturn: RuntimeConfig{},
			expectedError:  invalidRuntimeFlagEmptyValueError("workdir"),
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.testName, func(t *testing.T) {
			t.Parallel()

			runtime, err := PrepareRuntime(tc.flags)
			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Equal(t, "flags.PrepareRuntime: "+tc.expectedError, err.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedReturn.Workdir, runtime.Workdir)
			}
		})
	}
}
