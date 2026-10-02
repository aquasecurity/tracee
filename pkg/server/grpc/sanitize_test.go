package grpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/aquasecurity/tracee/types/trace"
)

func Test_sanitizeMapForProtobuf_WithTraceArguments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    map[string]interface{}
		validate func(t *testing.T, result map[string]interface{})
	}{
		{
			name: "map with []trace.Argument",
			input: map[string]interface{}{
				"id":   715,
				"name": "test_event",
				"args": []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "path",
							Type: "string",
						},
						Value: "/tmp/test",
					},
				},
			},
			validate: func(t *testing.T, result map[string]interface{}) {
				assert.Equal(t, 715, result["id"])
				assert.Equal(t, "test_event", result["name"])

				args, ok := result["args"].([]interface{})
				assert.True(t, ok, "args should be []interface{}")
				assert.Len(t, args, 1)

				arg0, ok := args[0].(map[string]interface{})
				assert.True(t, ok, "arg should be map[string]interface{}")
				assert.Equal(t, "path", arg0["name"])
				assert.Equal(t, "string", arg0["type"])
				assert.Equal(t, "/tmp/test", arg0["value"])
			},
		},
		{
			name: "string sanitization",
			input: map[string]interface{}{
				"valid":   "hello",
				"invalid": "test\x80\x81invalid",
			},
			validate: func(t *testing.T, result map[string]interface{}) {
				assert.Equal(t, "hello", result["valid"])
				// Invalid UTF-8 bytes should be replaced
				sanitized, ok := result["invalid"].(string)
				assert.True(t, ok, "invalid should be a string")
				assert.NotContains(t, sanitized, "\x80")
			},
		},
		{
			name: "nested maps",
			input: map[string]interface{}{
				"outer": map[string]interface{}{
					"inner": "value",
				},
			},
			validate: func(t *testing.T, result map[string]interface{}) {
				outer, ok := result["outer"].(map[string]interface{})
				assert.True(t, ok)
				assert.Equal(t, "value", outer["inner"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := sanitizeMapForProtobuf(tt.input)
			tt.validate(t, result)
		})
	}
}

func Test_sanitizeValueForProtobuf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    interface{}
		validate func(t *testing.T, result interface{})
	}{
		{
			name:  "string value",
			input: "hello",
			validate: func(t *testing.T, result interface{}) {
				assert.Equal(t, "hello", result)
			},
		},
		{
			name: "[]trace.Argument value",
			input: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "test",
						Type: "int",
					},
					Value: 42,
				},
			},
			validate: func(t *testing.T, result interface{}) {
				arr, ok := result.([]interface{})
				assert.True(t, ok)
				assert.Len(t, arr, 1)

				arg, ok := arr[0].(map[string]interface{})
				assert.True(t, ok)
				assert.Equal(t, "test", arg["name"])
				assert.Equal(t, "int", arg["type"])
				assert.Equal(t, 42, arg["value"])
			},
		},
		{
			name: "map[string]interface{} value",
			input: map[string]interface{}{
				"key": "value",
			},
			validate: func(t *testing.T, result interface{}) {
				m, ok := result.(map[string]interface{})
				assert.True(t, ok)
				assert.Equal(t, "value", m["key"])
			},
		},
		{
			name:  "int value passthrough",
			input: 123,
			validate: func(t *testing.T, result interface{}) {
				assert.Equal(t, 123, result)
			},
		},
		{
			name:  "trace.Pointer unwraps to uint64",
			input: trace.Pointer(0xC2AD00BF0040),
			validate: func(t *testing.T, result interface{}) {
				v, ok := result.(uint64)
				assert.True(t, ok, "trace.Pointer should be unwrapped to uint64")
				assert.Equal(t, uint64(0xC2AD00BF0040), v)
				_, err := structpb.NewValue(result)
				assert.NoError(t, err, "sanitized trace.Pointer should be accepted by structpb")
			},
		},
		{
			name:  "[]string converts to []interface{}",
			input: []string{"a", "b", "c"},
			validate: func(t *testing.T, result interface{}) {
				arr, ok := result.([]interface{})
				assert.True(t, ok)
				assert.Len(t, arr, 3)
				assert.Equal(t, "a", arr[0])
				assert.Equal(t, "b", arr[1])
				assert.Equal(t, "c", arr[2])
				_, err := structpb.NewValue(result)
				assert.NoError(t, err, "sanitized []string should be accepted by structpb")
			},
		},
		{
			name:  "[]uint64 converts to []interface{}",
			input: []uint64{0, 0, 0, 0},
			validate: func(t *testing.T, result interface{}) {
				arr, ok := result.([]interface{})
				assert.True(t, ok, "[]uint64 should become []interface{}")
				assert.Len(t, arr, 4)
				for _, v := range arr {
					assert.Equal(t, uint64(0), v)
				}
				_, err := structpb.NewValue(result)
				assert.NoError(t, err, "sanitized []uint64 should be accepted by structpb")
			},
		},
		{
			name:  "[2]int32 converts to []interface{}",
			input: [2]int32{10, 20},
			validate: func(t *testing.T, result interface{}) {
				arr, ok := result.([]interface{})
				assert.True(t, ok, "[2]int32 should become []interface{}")
				assert.Len(t, arr, 2)
				assert.Equal(t, int32(10), arr[0])
				assert.Equal(t, int32(20), arr[1])
				_, err := structpb.NewValue(result)
				assert.NoError(t, err, "sanitized [2]int32 should be accepted by structpb")
			},
		},
		{
			name: "map[string]string converts to map[string]interface{}",
			input: map[string]string{
				"sa_family": "AF_INET",
				"sin_addr":  "127.0.0.1",
				"sin_port":  "8080",
			},
			validate: func(t *testing.T, result interface{}) {
				m, ok := result.(map[string]interface{})
				assert.True(t, ok, "map[string]string should become map[string]interface{}")
				assert.Equal(t, "AF_INET", m["sa_family"])
				assert.Equal(t, "127.0.0.1", m["sin_addr"])
				assert.Equal(t, "8080", m["sin_port"])
				_, err := structpb.NewStruct(m)
				assert.NoError(t, err, "sanitized map[string]string should be accepted by structpb")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := sanitizeValueForProtobuf(tt.input)
			tt.validate(t, result)
		})
	}
}
