package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/tests/testutils"
)

// Test_ParseCmd tests the parseCmd function
func Test_ParseCmd(t *testing.T) {
	t.Parallel()

	tt := []struct {
		input          string
		expectedCmd    string
		expectedArgs   []string
		expectedErrMsg string
	}{
		{
			input:          "",
			expectedCmd:    "",
			expectedArgs:   nil,
			expectedErrMsg: "no command specified",
		},
		{
			input:          "/usr/bin/echo hello",
			expectedCmd:    "/usr/bin/echo",
			expectedArgs:   []string{"hello"},
			expectedErrMsg: "",
		},
		{
			input:          "/usr/bin/echo hello",
			expectedCmd:    "/usr/bin/echo",
			expectedArgs:   []string{"hello"},
			expectedErrMsg: "",
		},
		{
			input:          "/usr/bin/echo 'hello world'",
			expectedCmd:    "/usr/bin/echo",
			expectedArgs:   []string{"hello world"},
			expectedErrMsg: "",
		},
		{
			input:          "/usr/bin/bash -c 'echo hello world'",
			expectedCmd:    "/usr/bin/bash",
			expectedArgs:   []string{"-c", "echo hello world"},
			expectedErrMsg: "",
		},
		{
			input:          "invalidcommand",
			expectedCmd:    "",
			expectedArgs:   nil,
			expectedErrMsg: "exec: \"invalidcommand\": executable file not found in $PATH",
		},
	}

	for _, tc := range tt {
		tc := tc

		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()

			cmd, args, err := testutils.ParseCmd(tc.input)

			if err == nil {
				assert.Equal(t, tc.expectedCmd, cmd)
				assert.Len(t, args, len(tc.expectedArgs))
				assert.Equal(t, tc.expectedArgs, args)
			} else if err.Error() != tc.expectedErrMsg {
				t.Errorf("For input \"%s\", expected error message \"%s\", but got \"%s\"", tc.input, tc.expectedErrMsg, err)
			}
		})
	}
}
