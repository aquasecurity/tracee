package environment

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCompareKernelRelease(t *testing.T) {
	testCases := []struct {
		testName           string
		base               string
		given              string
		expectedComparison KernelVersionComparison
		expectedError      error
	}{
		{
			testName:           "older than",
			base:               "5.1.1",
			given:              "4.3.2",
			expectedComparison: KernelVersionOlder,
			expectedError:      nil,
		},
		{
			testName:           "valid with +, older than",
			base:               "5.4.228+",
			given:              "4.18",
			expectedComparison: KernelVersionOlder,
		},
		{
			testName:           "valid with alphabet, older than",
			base:               "5.6b",
			given:              "4.18",
			expectedComparison: KernelVersionOlder,
		},
		{
			testName:           "equal",
			base:               "5.0",
			given:              "5.0",
			expectedComparison: KernelVersionEqual,
			expectedError:      nil,
		},
		{
			testName:           "newer than",
			base:               "3.1.1",
			given:              "4.3.2",
			expectedComparison: KernelVersionNewer,
			expectedError:      nil,
		},
		{
			testName:           "newer than (missing patch)",
			base:               "3.1",
			given:              "4.3.2",
			expectedComparison: KernelVersionNewer,
			expectedError:      nil,
		},
		{
			testName:           "newer than (missing minor and match)",
			base:               "3",
			given:              "4.3.2",
			expectedComparison: KernelVersionNewer,
			expectedError:      nil,
		},
		{
			testName:           "invalid, too many",
			base:               "3.0.0.0",
			given:              "4.3.2",
			expectedComparison: KernelVersionInvalid,
			expectedError:      errors.New("invalid base kernel version format: 3.0.0.0"),
		},
		{
			testName:           "invalid, not a number",
			base:               "X.5.4",
			given:              "4.3.2",
			expectedComparison: KernelVersionInvalid,
			expectedError:      errors.New("invalid base kernel version value: X.5.4 issue with: X"),
		},
	}

	for _, tt := range testCases {
		t.Run(tt.testName, func(test *testing.T) {
			comp, err := CompareKernelRelease(tt.base, tt.given)
			assert.Equal(test, tt.expectedComparison, comp)
			assert.Equal(test, tt.expectedError, err)
		})
	}
}
