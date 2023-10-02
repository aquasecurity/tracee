package flags

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/signatures/rego"
)

func TestPrepareRego(t *testing.T) {
	t.Parallel()

	t.Run("various rego options", func(t *testing.T) {
		testCases := []struct {
			testName      string
			regoSlice     []string
			expectedRego  rego.Config
			expectedError error
		}{
			{
				testName:      "invalid rego option",
				regoSlice:     []string{"foo"},
				expectedError: errors.New("invalid rego option specified"),
			},
			{
				testName:  "default options",
				regoSlice: []string{},
				expectedRego: rego.Config{
					RuntimeTarget: "rego",
					PartialEval:   false,
					AIO:           false,
				},
			},
			{
				testName:  "configure partial-eval",
				regoSlice: []string{"partial-eval"},
				expectedRego: rego.Config{
					RuntimeTarget: "rego",
					PartialEval:   true,
				},
			},
			{
				testName:  "configure aio",
				regoSlice: []string{"aio"},
				expectedRego: rego.Config{
					RuntimeTarget: "rego",
					AIO:           true,
				},
			},
		}

		for _, tc := range testCases {
			tc := tc

			t.Run(tc.testName, func(t *testing.T) {
				t.Parallel()

				rego, err := PrepareRego(tc.regoSlice)
				if tc.expectedError == nil {
					require.NoError(t, err)
					assert.Equal(t, tc.expectedRego, rego, tc.testName)
				} else {
					assert.ErrorContains(t, err, tc.expectedError.Error(), tc.testName)
					assert.Empty(t, rego, tc.testName)
				}
			})
		}
	})
}
