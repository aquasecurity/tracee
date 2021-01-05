package external

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"testing"
)

func TestEventUnmarshalJSON(t *testing.T) {
	type testCase struct {
		json        string
		expect      Event
		expectError bool
	}

	testCases := []testCase{
		{
			json: `{"timestamp":260182.49532,"processId":12434,"threadId":12434,"parentprocessid":23921,
			"hostprocessid":12434,"hostthreadid":12434,"hostparentprocessid":23921,"userid":1000,"mountnamespace":4026531840,
			"pidnamespace":4026531836,"processname":"strace","hostname":"ubuntu","eventid":"101","eventname":"ptrace",
			"argsnum":4,"returnvalue":0,"args":[{"name":"request","type":"long","value":"ptrace_seize"},
			{"name":"pid","type":"pid_t","value":12435},{"name":"addr","type":"void*","value":"0x0"},{"name":"data","type":"void*","value":"0x7f6f1eb44b83"}]}`,
			expect: Event{Timestamp: float64(260182.49532), ProcessID: 12434, ThreadID: 12434, ParentProcessID: 23921, HostProcessID: 12434, HostThreadID: 12434, HostParentProcessID: 23921, UserID: 1000, MountNS: 4026531840, PIDNS: 4026531836, ProcessName: "strace", HostName: "ubuntu", EventID: 101, EventName: "ptrace", ArgsNum: 4, ReturnValue: 0, Args: []Argument{{ArgMeta: ArgMeta{Name: "request", Type: "long"}, Value: "ptrace_seize"}, {ArgMeta: ArgMeta{Name: "pid", Type: "pid_t"}, Value: int32(12435)}, {ArgMeta: ArgMeta{Name: "addr", Type: "void*"}, Value: "0x0"}, {ArgMeta: ArgMeta{Name: "data", Type: "void*"}, Value: "0x7f6f1eb44b83"}}},
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
