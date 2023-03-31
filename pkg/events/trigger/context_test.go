package trigger_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gotest.tools/assert"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/trigger"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestContext_Apply(t *testing.T) {
	testCases := []struct {
		name          string
		invokingEvent trace.Event
		inputEvent    trace.Event
		expectedEvent trace.Event
		expectedError error
	}{
		{
			name: "happy path - successful apply",
			invokingEvent: trace.Event{
				EventID:     int(events.Open),
				EventName:   "open",
				Timestamp:   123,
				ProcessID:   5,
				Container:   trace.Container{ID: "abc123"},
				ProcessName: "insmod",
				ReturnValue: 2,
			},
			inputEvent: trace.Event{
				EventID:     int(events.PrintNetSeqOps),
				EventName:   "print_net_seq_ops",
				Timestamp:   187,
				ProcessID:   0,
				ArgsNum:     3,
				Container:   trace.Container{ID: ""},
				ProcessName: "tracee-ebpf",
				Args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: trigger.ContextArgName,
							Type: "unsigned long",
						},
						Value: uint64(1),
					},
					{
						ArgMeta: trace.ArgMeta{
							Name: "yes",
							Type: "int",
						},
						Value: 5,
					},
					{
						ArgMeta: trace.ArgMeta{
							Name: "no",
							Type: "int",
						},
						Value: 6,
					},
				},
			},
			expectedEvent: trace.Event{
				EventID:     int(events.PrintNetSeqOps),
				EventName:   "print_net_seq_ops",
				Timestamp:   123,
				ProcessID:   5,
				ReturnValue: 0,
				Container:   trace.Container{ID: "abc123"},
				ProcessName: "insmod",
				ArgsNum:     3,
				Args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: trigger.ContextArgName,
							Type: "unsigned long",
						},
						Value: uint64(1),
					},
					{
						ArgMeta: trace.ArgMeta{
							Name: "yes",
							Type: "int",
						},
						Value: 5,
					},
					{
						ArgMeta: trace.ArgMeta{
							Name: "no",
							Type: "int",
						},
						Value: 6,
					},
				},
			},
		},
		{
			name: "error path - wrong context id argument",
			invokingEvent: trace.Event{
				EventID:     int(events.Open),
				EventName:   "open",
				Timestamp:   123,
				ProcessID:   5,
				ReturnValue: 2,
			},
			inputEvent: trace.Event{
				EventID:   int(events.PrintNetSeqOps),
				EventName: "print_net_seq_ops",
				Timestamp: 187,
				ProcessID: 0,
				ArgsNum:   3,
				Args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: trigger.ContextArgName,
							Type: "unsigned long",
						},
						Value: uint64(4),
					},
				},
			},
			expectedError: trigger.NoEventContextError(4),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			triggerContexts := trigger.NewContext()
			triggerContexts.Store(tc.invokingEvent)
			out, err := triggerContexts.Apply(tc.inputEvent)
			if tc.expectedError != nil {
				assert.Error(t, err, tc.expectedError.Error())
			} else {
				require.NoError(t, err)
				assert.DeepEqual(t, tc.expectedEvent, out)
			}
		})
	}
}
