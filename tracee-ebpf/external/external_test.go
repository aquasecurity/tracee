package external

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventUnmarshalJSON(t *testing.T) {
	type testCase struct {
		json        string
		expect      Event
		expectError bool
	}

	testCases := []testCase{
		{
			json: `{"timestamp":26018249532,"processId":12434,"threadId":12434,"parentprocessid":23921,
			"hostprocessid":12434,"hostthreadid":12434,"hostparentprocessid":23921,"userid":1000,"mountnamespace":4026531840,
			"pidnamespace":4026531836,"processname":"strace","hostname":"ubuntu","eventid":"101","eventname":"ptrace",
			"argsnum":4,"returnvalue":0,"args":[{"name":"request","type":"long","value":"ptrace_seize"},
			{"name":"pid","type":"pid_t","value":12435},{"name":"addr","type":"void*","value":"0x0"},{"name":"data","type":"void*","value":"0x7f6f1eb44b83"}]}`,
			expect: Event{Timestamp: 26018249532, ProcessID: 12434, ThreadID: 12434, ParentProcessID: 23921, HostProcessID: 12434, HostThreadID: 12434, HostParentProcessID: 23921, UserID: 1000, MountNS: 4026531840, PIDNS: 4026531836, ProcessName: "strace", HostName: "ubuntu", EventID: 101, EventName: "ptrace", ArgsNum: 4, ReturnValue: 0, Args: []Argument{{ArgMeta: ArgMeta{Name: "request", Type: "long"}, Value: "ptrace_seize"}, {ArgMeta: ArgMeta{Name: "pid", Type: "pid_t"}, Value: int32(12435)}, {ArgMeta: ArgMeta{Name: "addr", Type: "void*"}, Value: "0x0"}, {ArgMeta: ArgMeta{Name: "data", Type: "void*"}, Value: "0x7f6f1eb44b83"}}},
		},
	}
	for _, tc := range testCases {
		var res Event
		err := json.Unmarshal([]byte(tc.json), &res)
		if err != nil {
			if !tc.expectError {
				t.Error(err)
			} else {
				continue
			}
		}
		if !reflect.DeepEqual(tc.expect, res) {
			for _, arg := range res.Args {
				fmt.Printf("%v (%T)", arg, arg.Value)
			}
			t.Errorf("want %v\n have %v", tc.expect, res)
		}
	}
}

func TestArgumentUnmarshalJSON(t *testing.T) {
	type testCase struct {
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
			json:   `{ "name":"test", "type":"int", "value": ` + string(maxInt32JSON) + `}`,
			expect: Argument{ArgMeta: ArgMeta{Name: "test", Type: "int"}, Value: int32(math.MaxInt32)},
		},
		{
			json:   `{ "name":"test", "type":"unsigned int", "value": ` + string(maxUint32JSON) + `}`,
			expect: Argument{ArgMeta: ArgMeta{Name: "test", Type: "unsigned int"}, Value: uint32(math.MaxUint32)},
		},
		{
			json:   `{ "name":"test", "type":"long", "value": ` + string(maxInt64JSON) + `}`,
			expect: Argument{ArgMeta: ArgMeta{Name: "test", Type: "long"}, Value: int64(math.MaxInt64)},
		},
		{
			json:   `{ "name":"test", "type":"unsigned long", "value": ` + string(maxUint64JSON) + `}`,
			expect: Argument{ArgMeta: ArgMeta{Name: "test", Type: "unsigned long"}, Value: uint64(math.MaxUint64)},
		},
		{
			json:   `{ "name":"test", "type":"float", "value": ` + string(maxFloat32JSON) + `}`,
			expect: Argument{ArgMeta: ArgMeta{Name: "test", Type: "float"}, Value: float32(math.MaxFloat32)},
		},
		{
			json:   `{ "name":"test", "type":"float64", "value": ` + string(maxFloat64JSON) + `}`,
			expect: Argument{ArgMeta: ArgMeta{Name: "test", Type: "float64"}, Value: float64(math.MaxFloat64)},
		},
		{
			json:   `{ "name":"test", "type":"const char*const*", "value": [ "foo", "bar" ]}`,
			expect: Argument{ArgMeta: ArgMeta{Name: "test", Type: "const char*const*"}, Value: []string{"foo", "bar"}},
		},
		{
			json:   `{ "name":"test", "type":"const char*const*", "value": null}`,
			expect: Argument{ArgMeta: ArgMeta{Name: "test", Type: "const char*const*"}, Value: nil},
		},
		{
			json:        `{ "name":"test", "type":"err", "value": 0}`,
			expectError: true,
		},
	}
	for _, tc := range testCases {
		var res Argument
		err := json.Unmarshal([]byte(tc.json), &res)
		if err != nil {
			if !tc.expectError {
				t.Error(err)
			} else {
				continue
			}
		}
		if !reflect.DeepEqual(tc.expect, res) {
			t.Errorf("want %v (Value type %T), have %v (Value type %T)", tc.expect, tc.expect.Value, res, res.Value)
		}
	}
}

func TestEvent_ToUnstructured(t *testing.T) {
	testCases := []struct {
		name  string
		event Event
	}{
		{
			name:  "Should unstructure zero Event",
			event: Event{},
		},
		{
			name: "Should unstructure Event with empty slices",
			event: Event{
				Args:           []Argument{},
				StackAddresses: []uint64{},
			},
		},
		{
			name: "should unstructure args",
			event: Event{
				Args: []Argument{
					{
						ArgMeta: ArgMeta{
							Name: "dirfd",
							Type: "int",
						},
						Value: -100,
					},
					{
						ArgMeta: ArgMeta{
							Name: "pathname",
							Type: "const char",
						},
						Value: "/sys/fs/cgroup/cpu,cpuacct/cpuacct.stat",
					},
					{
						ArgMeta: ArgMeta{
							Name: "flags",
							Type: "int",
						},
						Value: "O_RDONLY|O_CLOEXEC",
					},
					{
						ArgMeta: ArgMeta{
							Name: "mode",
							Type: "mode_t",
						},
						Value: 5038682,
					},
				},
			},
		},
		{
			name: "Should unstructure Event",
			event: Event{
				Timestamp:           7126141189,
				ProcessID:           1,
				ThreadID:            1,
				ParentProcessID:     4798,
				HostProcessID:       4819,
				HostThreadID:        4819,
				HostParentProcessID: 4798,
				UserID:              0,
				MountNS:             4026532256,
				PIDNS:               4026532259,
				ProcessName:         "cadvisor",
				HostName:            "4213291591ab",
				EventID:             257,
				EventName:           "openat",
				ArgsNum:             4,
				ReturnValue:         14,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := tc.event.ToUnstructured()
			require.NoError(t, err)
			expected, err := jsonRoundTrip(tc.event)
			require.NoError(t, err)

			assert.Equal(t, expected, actual)
		})
	}

}

// jsonRoundTrip is a helper to assert that a static serialization to JSON
// compatible object is equivalent to the built-in JSON marshaller.
func jsonRoundTrip(v interface{}) (map[string]interface{}, error) {
	m, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(m)

	var u interface{}
	d := json.NewDecoder(buf)
	d.UseNumber()
	err = d.Decode(&u)
	if err != nil {
		return nil, err
	}
	return u.(map[string]interface{}), nil
}
