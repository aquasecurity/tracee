package flags

import (
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestPrepareOutput(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		cmd            *cobra.Command
		outputSlice    string
		expectedOutput Output
		expectedError  error
	}{
		{
			name:           "valid stdout",
			cmd:            &cobra.Command{},
			outputSlice:    "stdout",
			expectedOutput: Output{Path: "stdout", Writer: nil},
			expectedError:  nil,
		},
		{
			name:           "valid output file",
			cmd:            &cobra.Command{},
			outputSlice:    "test.txt",
			expectedOutput: Output{Path: "test.txt", Writer: nil},
			expectedError:  nil,
		},
	}
	for _, testcase := range testCases {
		t.Run(testcase.name, func(t *testing.T) {
			t.Parallel()

			output, err := PrepareOutput(testcase.cmd, testcase.outputSlice)
			if testcase.expectedError != nil || err != nil {
				assert.ErrorContains(t, err, testcase.expectedError.Error())
			}
			assert.Equal(t, testcase.expectedOutput.Path, output.Path)
			// assert.Equal(t, testcase.expectedOutput.Writer, output.Writer)
			defer os.Remove(output.Path)
		})
	}
}
