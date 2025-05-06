package pipeline_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gotest.tools/assert"

	"github.com/aquasecurity/tracee/pkg/events/pipeline"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestEventUnmarshalJSON(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name        string
		json        string
		expect      pipeline.Event
		expectError bool
	}

	testCases := []testCase{
		{
			name: "simple event",
			json: `{"timestamp":26018249532,"processId":12434,"threadId":12434,"parentprocessid":23921,
			"hostprocessid":12434,"hostthreadid":12434,"hostparentprocessid":23921,"userid":1000,"mountnamespace":4026531840,
			"pidnamespace":4026531836,"processname":"strace","hostname":"ubuntu","eventid":"101","eventname":"ptrace",
			"argsnum":4,"returnvalue":0,"args":[{"name":"request","type":"int64","value":"ptrace_seize"},
			{"name":"pid","type":"int32","value":12435},{"name":"addr","type":"void*","value":"0x0"},{"name":"data","type":"void*","value":"0x7f6f1eb44b83"}]}`,
			expect: pipeline.Event{Timestamp: 26018249532, ProcessID: 12434, ThreadID: 12434, ParentProcessID: 23921, HostProcessID: 12434, HostThreadID: 12434, HostParentProcessID: 23921, UserID: 1000, MountNS: 4026531840, PIDNS: 4026531836, ProcessName: "strace", HostName: "ubuntu", EventID: 101, EventName: "ptrace", ArgsNum: 4, ReturnValue: 0, Args: []trace.Argument{{ArgMeta: trace.ArgMeta{Name: "request", Type: "int64"}, Value: "ptrace_seize"}, {ArgMeta: trace.ArgMeta{Name: "pid", Type: "int32"}, Value: int32(12435)}, {ArgMeta: trace.ArgMeta{Name: "addr", Type: "void*"}, Value: "0x0"}, {ArgMeta: trace.ArgMeta{Name: "data", Type: "void*"}, Value: "0x7f6f1eb44b83"}}, ContextFlags: trace.ContextFlags{ContainerStarted: false}},
		},
	}
	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var res pipeline.Event
			err := json.Unmarshal([]byte(tc.json), &res)
			if err != nil {
				if tc.expectError {
					return
				}
				t.Error(err)
			}
			if !reflect.DeepEqual(tc.expect, res) {
				for _, arg := range res.Args {
					fmt.Printf("%v (%T)", arg, arg.Value)
				}
				t.Errorf("want %v\n have %v", tc.expect, res)
			}
		})
	}
}

func TestEvent_Origin(t *testing.T) {
	t.Parallel()

	type testCase struct {
		event    pipeline.Event
		expected trace.EventOrigin
	}
	testCases := []testCase{
		{
			event: pipeline.Event{
				EventName:     "execve",
				HostProcessID: 123,
				ProcessID:     123,
				ContextFlags:  trace.ContextFlags{ContainerStarted: false},
			},
			expected: trace.HostOrigin,
		},
		{
			event: pipeline.Event{
				EventName:     "execve",
				HostProcessID: 321,
				ProcessID:     123,
				Container:     trace.Container{ID: "ab123"},
				ContextFlags:  trace.ContextFlags{ContainerStarted: true},
			},
			expected: trace.ContainerOrigin,
		},
		{
			event: pipeline.Event{
				EventName:    "runc",
				Container:    trace.Container{ID: "ab123"},
				ContextFlags: trace.ContextFlags{ContainerStarted: false},
			},
			expected: trace.ContainerInitOrigin,
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.event.EventName, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.expected, trace.Origin(&tc.event))
		})
	}
}

func TestEvent_ToProtocol(t *testing.T) {
	t.Parallel()

	type testCase struct {
		payload  *pipeline.Event
		expected protocol.Event
	}

	testCases := []testCase{
		{
			payload: &pipeline.Event{
				EventName:     "execve",
				HostProcessID: 123,
				ProcessID:     123,
				ContextFlags:  trace.ContextFlags{ContainerStarted: false},
			},
			expected: protocol.Event{
				Headers: protocol.EventHeaders{
					Selector: protocol.Selector{
						Origin: string(trace.HostOrigin),
						Source: "tracee",
						Name:   "execve",
					},
				},
				Payload: &pipeline.Event{
					EventName:     "execve",
					HostProcessID: 123,
					ProcessID:     123,
					ContextFlags:  trace.ContextFlags{ContainerStarted: false},
				},
			},
		},
		{
			payload: &pipeline.Event{
				EventName:     "execve",
				HostProcessID: 123,
				ProcessID:     321,
				ContextFlags:  trace.ContextFlags{ContainerStarted: true},
			},
			expected: protocol.Event{
				Headers: protocol.EventHeaders{
					Selector: protocol.Selector{
						Origin: string(trace.ContainerOrigin),
						Source: "tracee",
						Name:   "execve",
					},
				},
				Payload: &pipeline.Event{
					EventName:     "execve",
					HostProcessID: 123,
					ProcessID:     321,
					ContextFlags:  trace.ContextFlags{ContainerStarted: true},
				},
			},
		},
		{
			payload: &pipeline.Event{
				EventName:    "open",
				Container:    trace.Container{ID: "abc123"},
				ContextFlags: trace.ContextFlags{ContainerStarted: false},
			},
			expected: protocol.Event{
				Headers: protocol.EventHeaders{
					Selector: protocol.Selector{
						Origin: string(trace.ContainerInitOrigin),
						Source: "tracee",
						Name:   "open",
					},
				},
				Payload: &pipeline.Event{
					EventName:    "open",
					Container:    trace.Container{ID: "abc123"},
					ContextFlags: trace.ContextFlags{ContainerStarted: false},
				},
			},
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.payload.EventName, func(t *testing.T) {
			t.Parallel()

			assert.DeepEqual(t, tc.expected, trace.ToProtocol(tc.payload), cmp.AllowUnexported(protocol.EventHeaders{}))
		})
	}
}
