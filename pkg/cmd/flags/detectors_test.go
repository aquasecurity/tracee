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
				YAMLDirs: []string{},
			},
		},
		// valid single flag
		{
			testName: "valid yaml-dir single",
			flags:    []string{"yaml-dir=/etc/tracee/detectors"},
			expectedReturn: DetectorsConfig{
				YAMLDirs: []string{"/etc/tracee/detectors"},
			},
		},
		// valid multiple flags
		{
			testName: "valid yaml-dir multiple",
			flags:    []string{"yaml-dir=/etc/tracee/detectors", "yaml-dir=/custom/path"},
			expectedReturn: DetectorsConfig{
				YAMLDirs: []string{"/etc/tracee/detectors", "/custom/path"},
			},
		},
		// invalid flags
		{
			testName:      "invalid flag format - missing value",
			flags:         []string{"yaml-dir="},
			expectedError: invalidDetectorsFlagErrorMsg("yaml-dir="),
		},
		{
			testName:      "invalid flag format - missing equals",
			flags:         []string{"yaml-dir"},
			expectedError: invalidDetectorsFlagErrorMsg("yaml-dir"),
		},
		{
			testName:      "invalid flag format - no name",
			flags:         []string{"=/etc/tracee/detectors"},
			expectedError: invalidDetectorsFlagErrorMsg("=/etc/tracee/detectors"),
		},
		{
			testName:      "invalid flag name",
			flags:         []string{"invalid-flag=/path"},
			expectedError: invalidDetectorsFlagErrorMsg("invalid-flag"),
		},
		{
			testName:      "multiple flags with one invalid",
			flags:         []string{"yaml-dir=/etc/tracee/detectors", "bad-flag=/path"},
			expectedError: invalidDetectorsFlagErrorMsg("bad-flag"),
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
				YAMLDirs: []string{},
			},
			expectedFlags: []string{},
		},
		{
			testName: "single yaml-dir",
			config: DetectorsConfig{
				YAMLDirs: []string{"/etc/tracee/detectors"},
			},
			expectedFlags: []string{"yaml-dir=/etc/tracee/detectors"},
		},
		{
			testName: "multiple yaml-dirs",
			config: DetectorsConfig{
				YAMLDirs: []string{"/etc/tracee/detectors", "/custom/path", "./local"},
			},
			expectedFlags: []string{
				"yaml-dir=/etc/tracee/detectors",
				"yaml-dir=/custom/path",
				"yaml-dir=./local",
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
