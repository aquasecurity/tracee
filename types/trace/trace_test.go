package trace

import (
	"encoding/json"
	"math"
	"reflect"
	"testing"
)

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
			if !reflect.DeepEqual(tc.expect, res) {
				t.Errorf("want %v (Value type %T), have %v (Value type %T)", tc.expect, tc.expect.Value, res, res.Value)
			}
		})
	}
}
