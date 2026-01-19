package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrepareDetectors(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		testName       string
		flags          []string
		expectedReturn DetectorsConfig
		expectedError  string
	}{
		// default values (no flags)
		{
			testName: "default values",
			flags:    []string{},
			expectedReturn: DetectorsConfig{
				Paths: []string{},
			},
		},
		// valid single flag
		{
			testName: "valid path single",
			flags:    []string{"/etc/tracee/detectors"},
			expectedReturn: DetectorsConfig{
				Paths: []string{"/etc/tracee/detectors"},
			},
		},
		// valid multiple flags
		{
			testName: "valid path multiple",
			flags:    []string{"/etc/tracee/detectors", "/custom/path"},
			expectedReturn: DetectorsConfig{
				Paths: []string{"/etc/tracee/detectors", "/custom/path"},
			},
		},
		// invalid flags
		{
			testName:      "invalid flag format - empty",
			flags:         []string{""},
			expectedError: invalidDetectorsFlagErrorMsg(""),
		},
		{
			testName:      "invalid flag format - equals with empty name",
			flags:         []string{"=/etc/tracee/detectors"},
			expectedError: invalidDetectorsFlagErrorMsg("=/etc/tracee/detectors"),
		},
		{
			testName:      "multiple flags with one invalid",
			flags:         []string{"/etc/tracee/detectors", "bad-flag=/path"},
			expectedError: invalidDetectorsFlagErrorMsg("bad-flag=/path"),
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.testName, func(t *testing.T) {
			t.Parallel()

			config, err := PrepareDetectors(testCase.flags)
			if testCase.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), testCase.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, testCase.expectedReturn, config)
			}
		})
	}
}

func TestDetectorsConfigFlags(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		testName      string
		config        DetectorsConfig
		expectedFlags []string
	}{
		{
			testName: "empty config",
			config: DetectorsConfig{
				Paths: []string{},
			},
			expectedFlags: []string{},
		},
		{
			testName: "single path",
			config: DetectorsConfig{
				Paths: []string{"/etc/tracee/detectors"},
			},
			expectedFlags: []string{"/etc/tracee/detectors"},
		},
		{
			testName: "multiple paths",
			config: DetectorsConfig{
				Paths: []string{"/etc/tracee/detectors", "/custom/path", "./local"},
			},
			expectedFlags: []string{
				"/etc/tracee/detectors",
				"/custom/path",
				"./local",
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.testName, func(t *testing.T) {
			t.Parallel()

			flags := testCase.config.flags()
			assert.Equal(t, testCase.expectedFlags, flags)
		})
	}
}
