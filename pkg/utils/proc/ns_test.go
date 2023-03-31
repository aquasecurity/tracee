package proc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractNSFromLink(t *testing.T) {
	testCases := []struct {
		name          string
		link          string
		expectedNS    int
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
		t.Run(testCase.name, func(t *testing.T) {
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
