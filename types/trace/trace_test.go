package trace

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/types/protocol"
)

func TestEventUnmarshalJSON(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name        string
		json        string
		expect      Event
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
			expect: Event{Timestamp: 26018249532, ProcessID: 12434, ThreadID: 12434, ParentProcessID: 23921, HostProcessID: 12434, HostThreadID: 12434, HostParentProcessID: 23921, UserID: 1000, MountNS: 4026531840, PIDNS: 4026531836, ProcessName: "strace", HostName: "ubuntu", EventID: 101, EventName: "ptrace", ArgsNum: 4, ReturnValue: 0, Args: []Argument{{ArgMeta: ArgMeta{Name: "request", Type: "int64"}, Value: "ptrace_seize"}, {ArgMeta: ArgMeta{Name: "pid", Type: "int32"}, Value: int32(12435)}, {ArgMeta: ArgMeta{Name: "addr", Type: "void*"}, Value: "0x0"}, {ArgMeta: ArgMeta{Name: "data", Type: "void*"}, Value: "0x7f6f1eb44b83"}}, ContextFlags: ContextFlags{ContainerStarted: false}},
		},
	}
	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var res Event
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

func TestArgumentUnmarshalJSON(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name        string
		json        string
		expect      Argument
		expectError bool
	}

	var maxInt32JSON, maxUint32JSON, maxInt64JSON, maxUint64JSON, maxFloat32JSON, maxFloat64JSON []byte
	maxInt32JSON, _ = json.Marshal(int32(math.MaxInt32))
	maxUint32JSON, _ = json.Marshal(uint32(math.MaxUint32))
	maxInt64JSON, _ = json.Marshal(int64(math.MaxInt64))
	maxUint64JSON, _ = json.Marshal(uint64(math.MaxUint64))
	maxFloat32JSON, _ = json.Marshal(float32(math.MaxFloat32))
	maxFloat64JSON, _ = json.Marshal(float64(math.MaxFloat64))
	testCases := []testCase{
		{
			name:   "int arg",
			json:   `{ "name":"test", "type":"int32", "value": ` + string(maxInt32JSON) + `}`,
			expect: Argument{ArgMeta: ArgMeta{Name: "test", Type: "int32"}, Value: int32(math.MaxInt32)},
		},
		{
			name:   "uint32 arg",
			json:   `{ "name":"test", "type":"uint32", "value": ` + string(maxUint32JSON) + `}`,
			expect: Argument{ArgMeta: ArgMeta{Name: "test", Type: "uint32"}, Value: uint32(math.MaxUint32)},
		},
		{
			name:   "int64 arg",
			json:   `{ "name":"test", "type":"int64", "value": ` + string(maxInt64JSON) + `}`,
			expect: Argument{ArgMeta: ArgMeta{Name: "test", Type: "int64"}, Value: int64(math.MaxInt64)},
		},
		{
			name:   "uint64 arg",
			json:   `{ "name":"test", "type":"uint64", "value": ` + string(maxUint64JSON) + `}`,
			expect: Argument{ArgMeta: ArgMeta{Name: "test", Type: "uint64"}, Value: uint64(math.MaxUint64)},
		},
		{
			name:   "random_struct* arg",
			json:   `{ "name":"test", "type":"random_struct*", "value": ` + string(maxUint64JSON) + `}`,
			expect: Argument{ArgMeta: ArgMeta{Name: "test", Type: "trace.Pointer"}, Value: Pointer(math.MaxUint64)},
		},
		{
			name:   "float arg",
			json:   `{ "name":"test", "type":"float", "value": ` + string(maxFloat32JSON) + `}`,
			expect: Argument{ArgMeta: ArgMeta{Name: "test", Type: "float"}, Value: float32(math.MaxFloat32)},
		},
		{
			name:   "float64 arg",
			json:   `{ "name":"test", "type":"float64", "value": ` + string(maxFloat64JSON) + `}`,
			expect: Argument{ArgMeta: ArgMeta{Name: "test", Type: "float64"}, Value: float64(math.MaxFloat64)},
		},
		{
			name:   "[]string arg",
			json:   `{ "name":"test", "type":"[]string", "value": [ "foo", "bar" ]}`,
			expect: Argument{ArgMeta: ArgMeta{Name: "test", Type: "[]string"}, Value: []string{"foo", "bar"}},
		},
		{
			name:   "[]string arg",
			json:   `{ "name":"test", "type":"[]string", "value": null}`,
			expect: Argument{ArgMeta: ArgMeta{Name: "test", Type: "[]string"}, Value: nil},
		},
		{
			name:        "err arg",
			json:        `{ "name":"test", "type":"err", "value": 0}`,
			expectError: true,
		},
		{
			name:   "time.Time with integer seconds",
			json:   `{ "name":"timeout", "type":"time.Time", "value": 1609459200}`,
			expect: Argument{ArgMeta: ArgMeta{Name: "timeout", Type: "time.Time"}, Value: time.Unix(1609459200, 0)},
		},
		{
			name:   "time.Time with fractional seconds",
			json:   `{ "name":"timeout", "type":"time.Time", "value": 1609459200.5}`,
			expect: Argument{ArgMeta: ArgMeta{Name: "timeout", Type: "time.Time"}, Value: time.Unix(1609459200, 500000000)},
		},
		{
			name:   "time.Time with zero value",
			json:   `{ "name":"timeout", "type":"time.Time", "value": 0}`,
			expect: Argument{ArgMeta: ArgMeta{Name: "timeout", Type: "time.Time"}, Value: time.Unix(0, 0)},
		},
		{
			name:   "time.Time with quarter second",
			json:   `{ "name":"timeout", "type":"time.Time", "value": 1609459200.25}`,
			expect: Argument{ArgMeta: ArgMeta{Name: "timeout", Type: "time.Time"}, Value: time.Unix(1609459200, 250000000)},
		},
		{
			name:   "time.Time with challenging decimal",
			json:   `{ "name":"timeout", "type":"time.Time", "value": 1609459200.123456789}`,
			expect: Argument{ArgMeta: ArgMeta{Name: "timeout", Type: "time.Time"}, Value: time.Unix(1609459200, 123456789)},
		},
	}
	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var res Argument
			err := json.Unmarshal([]byte(tc.json), &res)
			if err != nil {
				if tc.expectError {
					return
				}
				t.Error(err)
			}

			// Special handling for time.Time comparisons to account for floating point precision
			if tc.expect.Type == "time.Time" && res.Type == "time.Time" {
				expectedTime, expectedOk := tc.expect.Value.(time.Time)
				actualTime, actualOk := res.Value.(time.Time)
				if expectedOk && actualOk {
					// Allow small tolerance for floating point precision (~100 nanoseconds)
					tolerance := 100 * time.Nanosecond
					diff := expectedTime.Sub(actualTime).Abs()
					if diff <= tolerance {
						// Times are close enough, check other fields
						if tc.expect.Name != res.Name || tc.expect.Type != res.Type {
							t.Errorf("metadata mismatch: want {%s %s}, have {%s %s}", tc.expect.Name, tc.expect.Type, res.Name, res.Type)
						}
						return
					}
				}
			}

			if !reflect.DeepEqual(tc.expect, res) {
				t.Errorf("want %v (Value type %T), have %v (Value type %T)", tc.expect, tc.expect.Value, res, res.Value)
			}
		})
	}
}

// TestTimeSpecTypeConsistency verifies that TIMESPEC_T arguments are properly handled
func TestTimeSpecTypeConsistency(t *testing.T) {
	t.Parallel()

	// Test case that simulates how timespec arguments would be received from JSON
	testJSON := `{
		"name": "clock_nanosleep_timeout",
		"type": "time.Time",
		"value": 1609459200.5
	}`

	var arg Argument
	err := json.Unmarshal([]byte(testJSON), &arg)
	assert.NoError(t, err, "Should unmarshal time.Time argument without error")

	// Verify the type and value are correct
	assert.Equal(t, "clock_nanosleep_timeout", arg.Name)
	assert.Equal(t, "time.Time", arg.Type)

	// Verify it's actually a time.Time value
	timeValue, ok := arg.Value.(time.Time)
	assert.True(t, ok, "Value should be of type time.Time")

	// Verify the time is correctly parsed (Jan 1, 2021 00:00:00.5 UTC)
	expected := time.Unix(1609459200, 500000000)
	diff := timeValue.Sub(expected).Abs()
	assert.True(t, diff <= 100*time.Nanosecond,
		"Time should be within 100 nanoseconds of expected value")
}

func TestEvent_Origin(t *testing.T) {
	t.Parallel()

	type testCase struct {
		event    Event
		expected EventOrigin
	}
	testCases := []testCase{
		{
			event: Event{
				EventName:     "execve",
				HostProcessID: 123,
				ProcessID:     123,
				ContextFlags:  ContextFlags{ContainerStarted: false},
			},
			expected: HostOrigin,
		},
		{
			event: Event{
				EventName:     "execve",
				HostProcessID: 321,
				ProcessID:     123,
				Container:     Container{ID: "ab123"},
				ContextFlags:  ContextFlags{ContainerStarted: true},
			},
			expected: ContainerOrigin,
		},
		{
			event: Event{
				EventName:    "runc",
				Container:    Container{ID: "ab123"},
				ContextFlags: ContextFlags{ContainerStarted: false},
			},
			expected: ContainerInitOrigin,
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.event.EventName, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.expected, tc.event.Origin())
		})
	}
}

func TestEvent_ToProtocol(t *testing.T) {
	t.Parallel()

	type testCase struct {
		payload  Event
		expected protocol.Event
	}

	testCases := []testCase{
		{
			payload: Event{
				EventName:     "execve",
				HostProcessID: 123,
				ProcessID:     123,
				ContextFlags:  ContextFlags{ContainerStarted: false},
			},
			expected: protocol.Event{
				Headers: protocol.EventHeaders{
					Selector: protocol.Selector{
						Origin: string(HostOrigin),
						Source: "tracee",
						Name:   "execve",
					},
				},
				Payload: Event{
					EventName:     "execve",
					HostProcessID: 123,
					ProcessID:     123,
					ContextFlags:  ContextFlags{ContainerStarted: false},
				},
			},
		},
		{
			payload: Event{
				EventName:     "execve",
				HostProcessID: 123,
				ProcessID:     321,
				ContextFlags:  ContextFlags{ContainerStarted: true},
			},
			expected: protocol.Event{
				Headers: protocol.EventHeaders{
					Selector: protocol.Selector{
						Origin: string(ContainerOrigin),
						Source: "tracee",
						Name:   "execve",
					},
				},
				Payload: Event{
					EventName:     "execve",
					HostProcessID: 123,
					ProcessID:     321,
					ContextFlags:  ContextFlags{ContainerStarted: true},
				},
			},
		},
		{
			payload: Event{
				EventName:    "open",
				Container:    Container{ID: "abc123"},
				ContextFlags: ContextFlags{ContainerStarted: false},
			},
			expected: protocol.Event{
				Headers: protocol.EventHeaders{
					Selector: protocol.Selector{
						Origin: string(ContainerInitOrigin),
						Source: "tracee",
						Name:   "open",
					},
				},
				Payload: Event{
					EventName:    "open",
					Container:    Container{ID: "abc123"},
					ContextFlags: ContextFlags{ContainerStarted: false},
				},
			},
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.payload.EventName, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.expected, tc.payload.ToProtocol())
		})
	}
}
