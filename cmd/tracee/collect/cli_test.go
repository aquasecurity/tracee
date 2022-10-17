package collect

import (
	"testing"

	"github.com/aquasecurity/tracee/pkg/events"

	"github.com/stretchr/testify/assert"
)

func Test_checkCommandIsHelp(t *testing.T) {
	testCases := []struct {
		testName string
		input    []string
		expected bool
	}{
		{"no flag", []string{""}, false},
		{"help flag", []string{"help"}, true},
		{"capture flag", []string{"capture"}, false},
		{"output flag", []string{"output"}, false},
		{"trace flag", []string{"trace"}, false},
		{"multiple flags", []string{"help", "capture"}, false},
	}

	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			actual := checkCommandIsHelp(testcase.input)
			assert.Equal(t, testcase.expected, actual)
		})
	}
}

func Test_getFormattedEventParams(t *testing.T) {
	testCases := []struct {
		input  events.ID
		output string
	}{
		{
			input:  events.Write,
			output: "(int fd, void* buf, size_t count)",
		},
		{
			input:  events.RtSigreturn,
			output: "()",
		},
		{
			input:  events.RtSigtimedwait,
			output: "(const sigset_t* set, siginfo_t* info, const struct timespec* timeout, size_t sigsetsize)",
		},
		{
			input:  99999999, // unknown event
			output: "()",
		},
	}

	for _, tc := range testCases {
		assert.Equal(t, tc.output, getFormattedEventParams(tc.input))
	}
}
