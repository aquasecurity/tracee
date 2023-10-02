package trigger_test

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"gotest.tools/assert"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/trigger"
	"github.com/aquasecurity/tracee/types/trace"
)

func NewFakeTriggerEvent() trace.Event {
	return trace.Event{
		Timestamp:           123,
		ProcessorID:         12,
		ProcessID:           99,
		ThreadID:            99,
		ParentProcessID:     1,
		HostProcessID:       99,
		HostThreadID:        99,
		HostParentProcessID: 1,
		UserID:              1000,
		ProcessName:         "cat",
		HostName:            "tracee",
		EventID:             2,
		EventName:           "open",
		ArgsNum:             3,
		ReturnValue:         2,
	}
}

func EventsMatch(t *testing.T, expected, actual trace.Event) {
	require.Equal(t, expected.Timestamp, actual.Timestamp)
	require.Equal(t, expected.ProcessorID, actual.ProcessorID)
	require.Equal(t, expected.ProcessID, actual.ProcessID)
	require.Equal(t, expected.ThreadID, actual.ThreadID)
	require.Equal(t, expected.ParentProcessID, actual.ParentProcessID)
	require.Equal(t, expected.HostProcessID, actual.HostProcessID)
	require.Equal(t, expected.HostThreadID, actual.HostThreadID)
	require.Equal(t, expected.HostParentProcessID, actual.HostParentProcessID)
	require.Equal(t, expected.UserID, actual.UserID)
	require.Equal(t, expected.ProcessName, actual.ProcessName)
	require.Equal(t, expected.HostName, actual.HostName)
	require.Equal(t, expected.EventID, actual.EventID)
	require.Equal(t, expected.EventName, actual.EventName)
	require.Equal(t, expected.ArgsNum, actual.ArgsNum)
	require.Equal(t, expected.ReturnValue, actual.ReturnValue)
}

func TestStore(t *testing.T) {
	t.Parallel()

	e := NewFakeTriggerEvent()
	c := trigger.NewContext()

	id := c.Store(e)

	require.Equal(t, uint64(1), id)
}

func TestLoad(t *testing.T) {
	t.Parallel()

	e := NewFakeTriggerEvent()
	c := trigger.NewContext()

	id := c.Store(e)
	out, ok := c.Load(id)

	require.True(t, ok)
	EventsMatch(t, e, out)
}

// TestStoreAndLoad_MultipleThreads tests that the context store is thread safe.
func TestStoreAndLoad_MultipleThreads(t *testing.T) {
	t.Parallel()

	c := trigger.NewContext()

	wg := sync.WaitGroup{}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			id := c.Store(NewFakeTriggerEvent())
			c.Load(id) // concurrent load among different threads
			wg.Done()
		}()
	}

	wg.Wait()

	// check if id is incremented correctly after all threads are done
	id := c.Store(NewFakeTriggerEvent())
	require.Equal(t, uint64(101), id)
	id = c.Store(NewFakeTriggerEvent())
	require.Equal(t, uint64(102), id)
}

func TestContext_Apply(t *testing.T) {
	t.Parallel()

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
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

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
