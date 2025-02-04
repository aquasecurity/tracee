package proc

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/utils/tests"
)

// TestProcNS_PrintSizes prints the sizes of the structs used in the ProcNS type.
// Run it as DEBUG test to see the output.
func TestTaskInfoFeed_PrintSizes(t *testing.T) {
	procNS := ProcNS{}
	tests.PrintStructSizes(t, os.Stdout, procNS)
}

func Test_extractNSFromLink(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		link          string
		expectedNS    uint32
		expectedError bool
	}{
		{
			name:          "Legal NS link",
			link:          "mnt:[4026531840]",
			expectedError: false,
			expectedNS:    4026531840,
		},
		{
			name:          "Illegal NS link",
			link:          "4026531840",
			expectedError: true,
			expectedNS:    0,
		},
		{
			name:          "Empty link",
			link:          "",
			expectedError: true,
			expectedNS:    0,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			ns, err := extractNSFromLink(testCase.link)
			if testCase.expectedError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, testCase.expectedNS, ns)
			}
		})
	}
}
