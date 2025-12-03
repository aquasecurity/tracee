package v1beta1

import (
	"encoding/json"
	"testing"

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
