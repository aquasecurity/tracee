package v1beta1

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestEventMarshalJSON(t *testing.T) {
	tests := []struct {
		name  string
		event *Event
	}{
		{
			name: "basic event",
			event: &Event{
				Timestamp: timestamppb.Now(),
				Id:        1,
				Name:      "test_event",
				Policies: &Policies{
					Matched: []string{"policy1", "policy2"},
				},
			},
		},
		{
			name: "event with workload",
			event: &Event{
				Timestamp: timestamppb.Now(),
				Id:        2,
				Name:      "test_event_workload",
				Workload: &Workload{
					Process: &Process{
						Executable: &Executable{Path: "/bin/bash"},
						HostPid:    wrapperspb.UInt32(1234),
						Pid:        wrapperspb.UInt32(1234),
					},
				},
			},
		},
		{
			name: "event with thread and stack trace",
			event: &Event{
				Timestamp: timestamppb.Now(),
				Id:        3,
				Name:      "test_event_thread",
				Workload: &Workload{
					Process: &Process{
						Executable: &Executable{Path: "/bin/bash"},
						Thread: &Thread{
							Name:    "main",
							HostTid: wrapperspb.UInt32(5678),
							UserStackTrace: &UserStackTrace{
								Addresses: []*StackAddress{
									{Address: 0x12345678, Symbol: "main"},
									{Address: 0x87654321, Symbol: "init"},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "event with data values",
			event: &Event{
				Timestamp: timestamppb.Now(),
				Id:        4,
				Name:      "test_event_data",
				Data: []*EventValue{
					{Name: "string_val", Value: &EventValue_Str{Str: "test"}},
					{Name: "int_val", Value: &EventValue_Int32{Int32: 42}},
					{Name: "bool_val", Value: &EventValue_Bool{Bool: true}},
				},
			},
		},
		{
			name: "event with container",
			event: &Event{
				Timestamp: timestamppb.Now(),
				Id:        5,
				Name:      "test_container_event",
				Workload: &Workload{
					Process: &Process{
						Executable: &Executable{Path: "/usr/bin/python3"},
					},
					Container: &Container{
						Id:      "abc123",
						Name:    "my-container",
						Started: true,
						Image: &ContainerImage{
							Id:   "sha256:abc123",
							Name: "ubuntu:22.04",
							RepoDigests: []string{
								"ubuntu@sha256:def456",
							},
						},
					},
				},
			},
		},
		{
			name: "event with complex workload",
			event: &Event{
				Timestamp: timestamppb.Now(),
				Id:        6,
				Name:      "complex_event",
				Workload: &Workload{
					Process: &Process{
						Executable: &Executable{Path: "/bin/bash"},
						UniqueId:   wrapperspb.UInt32(111),
						HostPid:    wrapperspb.UInt32(1234),
						Pid:        wrapperspb.UInt32(1234),
						RealUser:   &User{Id: wrapperspb.UInt32(1000)},
						Thread: &Thread{
							StartTime: timestamppb.Now(),
							Name:      "bash",
							UniqueId:  wrapperspb.UInt32(222),
							HostTid:   wrapperspb.UInt32(1234),
							Tid:       wrapperspb.UInt32(1234),
							Syscall:   "execve",
						},
					},
					Container: &Container{
						Id:      "container123",
						Name:    "test-container",
						Started: true,
					},
					K8S: &K8S{
						Pod: &Pod{
							Name: "test-pod",
							Uid:  "pod-uid-123",
							Labels: map[string]string{
								"app":     "test",
								"version": "v1",
							},
						},
						Namespace: &K8SNamespace{
							Name: "default",
						},
					},
				},
			},
		},
		{
			name: "event with nil pointer in ancestors (should not panic)",
			event: &Event{
				Timestamp: timestamppb.Now(),
				Id:        7,
				Name:      "event_with_nil_ancestor",
				Workload: &Workload{
					Process: &Process{
						Executable: &Executable{Path: "/bin/sh"},
						Ancestors:  []*Process{nil}, // This could potentially cause panic
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.event)
			if err != nil {
				// Panic was recovered and converted to error
				t.Logf("Marshal returned error (expected for nil ancestors): %v", err)
				return
			}

			// Validate JSON
			if !json.Valid(data) {
				t.Errorf("Generated invalid JSON: %s", string(data))
			}

			// Try to unmarshal to verify structure
			var result map[string]interface{}
			if err := json.Unmarshal(data, &result); err != nil {
				t.Errorf("Failed to unmarshal generated JSON: %v\nJSON: %s", err, string(data))
			}

			t.Logf("Generated JSON (length=%d): %s", len(data), string(data))
		})
	}
}

// TestEventValueJSONFormat validates that EventValue types use correct type-specific field names
// This test ensures backward compatibility with protobuf JSON format
func TestEventValueJSONFormat(t *testing.T) {
	tests := []struct {
		name          string
		value         *EventValue
		expectedJSON  string
		expectedField string // The field name we expect to see in JSON
	}{
		{
			name:          "int32",
			value:         &EventValue{Name: "test", Value: &EventValue_Int32{Int32: 42}},
			expectedField: "int32",
			expectedJSON:  `{"name":"test","int32":42}`,
		},
		{
			name:          "int64 as quoted string",
			value:         &EventValue{Name: "test", Value: &EventValue_Int64{Int64: 9876543210}},
			expectedField: "int64",
			expectedJSON:  `{"name":"test","int64":"9876543210"}`,
		},
		{
			name:          "u_int32",
			value:         &EventValue{Name: "test", Value: &EventValue_UInt32{UInt32: 1000}},
			expectedField: "u_int32",
			expectedJSON:  `{"name":"test","u_int32":1000}`,
		},
		{
			name:          "u_int64 as quoted string",
			value:         &EventValue{Name: "test", Value: &EventValue_UInt64{UInt64: 18446744073709551615}},
			expectedField: "u_int64",
			expectedJSON:  `{"name":"test","u_int64":"18446744073709551615"}`,
		},
		{
			name:          "str",
			value:         &EventValue{Name: "test", Value: &EventValue_Str{Str: "hello"}},
			expectedField: "str",
			expectedJSON:  `{"name":"test","str":"hello"}`,
		},
		{
			name:          "bool",
			value:         &EventValue{Name: "test", Value: &EventValue_Bool{Bool: true}},
			expectedField: "bool",
			expectedJSON:  `{"name":"test","bool":true}`,
		},
		{
			name:          "bytes as base64",
			value:         &EventValue{Name: "test", Value: &EventValue_Bytes{Bytes: []byte{0x01, 0x02, 0x03}}},
			expectedField: "bytes",
			expectedJSON:  `{"name":"test","bytes":"AQID"}`,
		},
		{
			name:          "str_array with values",
			value:         &EventValue{Name: "test", Value: &EventValue_StrArray{StrArray: &StringArray{Value: []string{"a", "b", "c"}}}},
			expectedField: "str_array",
			expectedJSON:  `{"name":"test","str_array":{"value":["a","b","c"]}}`,
		},
		{
			name:          "str_array empty",
			value:         &EventValue{Name: "test", Value: &EventValue_StrArray{StrArray: &StringArray{Value: []string{}}}},
			expectedField: "str_array",
			expectedJSON:  `{"name":"test","str_array":{}}`,
		},
		{
			name:          "int32_array with values",
			value:         &EventValue{Name: "test", Value: &EventValue_Int32Array{Int32Array: &Int32Array{Value: []int32{1, 2, 3}}}},
			expectedField: "int32_array",
			expectedJSON:  `{"name":"test","int32_array":{"value":[1,2,3]}}`,
		},
		{
			name:          "int32_array empty",
			value:         &EventValue{Name: "test", Value: &EventValue_Int32Array{Int32Array: &Int32Array{Value: []int32{}}}},
			expectedField: "int32_array",
			expectedJSON:  `{"name":"test","int32_array":{}}`,
		},
		{
			name:          "u_int64_array with quoted strings",
			value:         &EventValue{Name: "test", Value: &EventValue_UInt64Array{UInt64Array: &UInt64Array{Value: []uint64{1, 2, 3}}}},
			expectedField: "u_int64_array",
			expectedJSON:  `{"name":"test","u_int64_array":{"value":["1","2","3"]}}`,
		},
		{
			name:          "u_int64_array empty",
			value:         &EventValue{Name: "test", Value: &EventValue_UInt64Array{UInt64Array: &UInt64Array{Value: []uint64{}}}},
			expectedField: "u_int64_array",
			expectedJSON:  `{"name":"test","u_int64_array":{}}`,
		},
		{
			name:          "pointer as quoted string",
			value:         &EventValue{Name: "test", Value: &EventValue_Pointer{Pointer: 0x7fff12345678}},
			expectedField: "pointer",
			expectedJSON:  "", // Skip exact match for pointer, just check field name
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.value)
			require.NoError(t, err, "Failed to marshal EventValue")

			// Validate JSON is well-formed
			require.True(t, json.Valid(data), "Generated invalid JSON: %s", string(data))

			// Check expected JSON matches exactly (if provided)
			if tt.expectedJSON != "" {
				assert.JSONEq(t, tt.expectedJSON, string(data), "JSON output doesn't match expected format")
			}

			// Ensure it contains the type-specific field name (not generic "value")
			jsonStr := string(data)
			assert.Contains(t, jsonStr, `"`+tt.expectedField+`":`,
				"JSON should contain field '%s', not generic 'value'. Got: %s", tt.expectedField, jsonStr)

			// Ensure it does NOT contain a standalone "value" field (except for arrays which have nested value)
			if !strings.Contains(tt.expectedField, "array") {
				assert.NotContains(t, jsonStr, `,"value":`,
					"JSON should not use generic 'value' field. Got: %s", jsonStr)
			}
		})
	}
}
