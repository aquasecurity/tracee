package flags

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/printer"
)

func TestPrepareFormat(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		formatSlice    string
		expectedFormat string
		expectedError  error
	}{
		{
			name:           "valid table format",
			formatSlice:    printer.TableFormat,
			expectedFormat: printer.TableFormat,
			expectedError:  nil,
		},
		{
			name:           "valid json format",
			formatSlice:    printer.JsonFormat,
			expectedFormat: printer.JsonFormat,
			expectedError:  nil,
		},
		{
			name:           "invalid format",
			formatSlice:    "invalid",
			expectedFormat: "",
			expectedError:  fmt.Errorf("unsupported format type: invalid"),
		},
	}
	for _, testcase := range testCases {
		t.Run(testcase.name, func(t *testing.T) {
			t.Parallel()

			format, err := PrepareFormat(testcase.formatSlice)
			if testcase.expectedError != nil {
				assert.ErrorContains(t, err, testcase.expectedError.Error())
			}
			assert.Equal(t, testcase.expectedFormat, format)
		})
	}
}
