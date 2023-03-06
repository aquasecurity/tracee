package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/events"
)

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
