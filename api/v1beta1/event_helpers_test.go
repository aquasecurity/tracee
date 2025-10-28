package v1beta1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// TestGetData tests the generic type-safe data extraction
func TestGetData(t *testing.T) {
	t.Run("string extraction", func(t *testing.T) {
		event := &Event{
			Data: []*EventValue{
				NewStringValue("pathname", "/tmp/test"),
			},
		}
		val, ok := GetData[string](event, "pathname")
		assert.True(t, ok)
		assert.Equal(t, "/tmp/test", val)
	})

	t.Run("int32 extraction", func(t *testing.T) {
		event := &Event{
			Data: []*EventValue{
				NewInt32Value("flags", 42),
			},
		}
		val, ok := GetData[int32](event, "flags")
		assert.True(t, ok)
		assert.Equal(t, int32(42), val)
	})

	t.Run("int64 extraction", func(t *testing.T) {
		event := &Event{
			Data: []*EventValue{
				NewInt64Value("size", 1024),
			},
		}
		val, ok := GetData[int64](event, "size")
		assert.True(t, ok)
		assert.Equal(t, int64(1024), val)
	})

	t.Run("uint32 extraction", func(t *testing.T) {
		event := &Event{
			Data: []*EventValue{
				NewUInt32Value("uid", 1000),
			},
		}
		val, ok := GetData[uint32](event, "uid")
		assert.True(t, ok)
		assert.Equal(t, uint32(1000), val)
	})

	t.Run("uint64 extraction", func(t *testing.T) {
		event := &Event{
			Data: []*EventValue{
				NewUInt64Value("inode", 987654),
			},
		}
		val, ok := GetData[uint64](event, "inode")
		assert.True(t, ok)
		assert.Equal(t, uint64(987654), val)
	})

	t.Run("bytes extraction", func(t *testing.T) {
		bytes := []byte{0x7F, 0x45, 0x4C, 0x46}
		event := &Event{
			Data: []*EventValue{
				NewBytesValue("bytes", bytes),
			},
		}
		val, ok := GetData[[]byte](event, "bytes")
		assert.True(t, ok)
		assert.Equal(t, bytes, val)
	})

	t.Run("bool extraction", func(t *testing.T) {
		event := &Event{
			Data: []*EventValue{
				NewBoolValue("success", true),
			},
		}
		val, ok := GetData[bool](event, "success")
		assert.True(t, ok)
		assert.True(t, val)
	})

	t.Run("field not found", func(t *testing.T) {
		event := &Event{
			Data: []*EventValue{
				NewStringValue("pathname", "/tmp/test"),
			},
		}
		val, ok := GetData[string](event, "missing")
		assert.False(t, ok)
		assert.Equal(t, "", val) // Zero value for string
	})

	t.Run("type mismatch", func(t *testing.T) {
		event := &Event{
			Data: []*EventValue{
				NewStringValue("pathname", "/tmp/test"),
			},
		}
		val, ok := GetData[int32](event, "pathname")
		assert.False(t, ok)
		assert.Equal(t, int32(0), val) // Zero value for int32
	})

	t.Run("nil event", func(t *testing.T) {
		val, ok := GetData[string](nil, "pathname")
		assert.False(t, ok)
		assert.Equal(t, "", val)
	})

	t.Run("nil data", func(t *testing.T) {
		event := &Event{Data: nil}
		val, ok := GetData[string](event, "pathname")
		assert.False(t, ok)
		assert.Equal(t, "", val)
	})
}

// TestGetDataSafe tests the safe extraction with better error reporting
func TestGetDataSafe(t *testing.T) {
	t.Run("successful extraction", func(t *testing.T) {
		event := &Event{
			Data: []*EventValue{
				NewStringValue("pathname", "/tmp/test"),
			},
		}
		val, err := GetDataSafe[string](event, "pathname")
		require.NoError(t, err)
		assert.Equal(t, "/tmp/test", val)
	})

	t.Run("field not found", func(t *testing.T) {
		event := &Event{
			Data: []*EventValue{
				NewStringValue("pathname", "/tmp/test"),
			},
		}
		val, err := GetDataSafe[string](event, "missing")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
		assert.Equal(t, "", val)
	})

	t.Run("type mismatch", func(t *testing.T) {
		event := &Event{
			Data: []*EventValue{
				NewStringValue("pathname", "/tmp/test"),
			},
		}
		val, err := GetDataSafe[int32](event, "pathname")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "incompatible type")
		assert.Equal(t, int32(0), val)
	})
}

// TestProcessHelpers tests process-related helper functions
func TestProcessHelpers(t *testing.T) {
	t.Run("GetProcessPid", func(t *testing.T) {
		event := &Event{
			Workload: &Workload{
				Process: &Process{
					Pid: wrapperspb.UInt32(12345),
				},
			},
		}
		assert.Equal(t, uint32(12345), GetProcessPid(event))

		// Nil cases
		assert.Equal(t, uint32(0), GetProcessPid(nil))
		assert.Equal(t, uint32(0), GetProcessPid(&Event{}))
		assert.Equal(t, uint32(0), GetProcessPid(&Event{Workload: &Workload{}}))
	})

	t.Run("GetProcessEntityId", func(t *testing.T) {
		event := &Event{
			Workload: &Workload{
				Process: &Process{
					UniqueId: wrapperspb.UInt32(99999),
				},
			},
		}
		assert.Equal(t, uint32(99999), GetProcessEntityId(event))

		// Nil cases
		assert.Equal(t, uint32(0), GetProcessEntityId(nil))
		assert.Equal(t, uint32(0), GetProcessEntityId(&Event{}))
	})

	t.Run("GetProcessExecutablePath", func(t *testing.T) {
		event := &Event{
			Workload: &Workload{
				Process: &Process{
					Executable: &Executable{
						Path: "/usr/bin/ls",
					},
				},
			},
		}
		assert.Equal(t, "/usr/bin/ls", GetProcessExecutablePath(event))

		// Nil cases
		assert.Equal(t, "", GetProcessExecutablePath(nil))
		assert.Equal(t, "", GetProcessExecutablePath(&Event{}))
	})

	t.Run("GetProcessHostPid", func(t *testing.T) {
		event := &Event{
			Workload: &Workload{
				Process: &Process{
					HostPid: wrapperspb.UInt32(54321),
				},
			},
		}
		assert.Equal(t, uint32(54321), GetProcessHostPid(event))
	})

	t.Run("GetProcessRealUserId", func(t *testing.T) {
		event := &Event{
			Workload: &Workload{
				Process: &Process{
					RealUser: &User{
						Id: wrapperspb.UInt32(1000),
					},
				},
			},
		}
		assert.Equal(t, uint32(1000), GetProcessRealUserId(event))

		// Nil user
		assert.Equal(t, uint32(0), GetProcessRealUserId(&Event{
			Workload: &Workload{
				Process: &Process{},
			},
		}))
	})
}

// TestThreadHelpers tests thread-related helper functions
func TestThreadHelpers(t *testing.T) {
	t.Run("GetProcessThreadName", func(t *testing.T) {
		event := &Event{
			Workload: &Workload{
				Process: &Process{
					Thread: &Thread{
						Name: "worker-1",
					},
				},
			},
		}
		assert.Equal(t, "worker-1", GetProcessThreadName(event))
		assert.Equal(t, "", GetProcessThreadName(nil))
	})

	t.Run("GetProcessThreadSyscall", func(t *testing.T) {
		event := &Event{
			Workload: &Workload{
				Process: &Process{
					Thread: &Thread{
						Syscall: "openat",
					},
				},
			},
		}
		assert.Equal(t, "openat", GetProcessThreadSyscall(event))
	})

	t.Run("GetProcessThreadTid", func(t *testing.T) {
		event := &Event{
			Workload: &Workload{
				Process: &Process{
					Thread: &Thread{
						Tid: wrapperspb.UInt32(12346),
					},
				},
			},
		}
		assert.Equal(t, uint32(12346), GetProcessThreadTid(event))
	})

	t.Run("GetProcessThreadHostTid", func(t *testing.T) {
		event := &Event{
			Workload: &Workload{
				Process: &Process{
					Thread: &Thread{
						HostTid: wrapperspb.UInt32(54322),
					},
				},
			},
		}
		assert.Equal(t, uint32(54322), GetProcessThreadHostTid(event))
	})

	t.Run("GetProcessThreadEntityId", func(t *testing.T) {
		event := &Event{
			Workload: &Workload{
				Process: &Process{
					Thread: &Thread{
						UniqueId: wrapperspb.UInt32(88888),
					},
				},
			},
		}
		assert.Equal(t, uint32(88888), GetProcessThreadEntityId(event))
	})
}

// TestContainerHelpers tests container-related helper functions
func TestContainerHelpers(t *testing.T) {
	t.Run("GetContainerID", func(t *testing.T) {
		event := &Event{
			Workload: &Workload{
				Container: &Container{
					Id: "abc123def456",
				},
			},
		}
		assert.Equal(t, "abc123def456", GetContainerID(event))
		assert.Equal(t, "", GetContainerID(nil))
		assert.Equal(t, "", GetContainerID(&Event{}))
	})

	t.Run("GetContainerName", func(t *testing.T) {
		event := &Event{
			Workload: &Workload{
				Container: &Container{
					Name: "my-container",
				},
			},
		}
		assert.Equal(t, "my-container", GetContainerName(event))
	})

	t.Run("GetContainerStarted", func(t *testing.T) {
		event := &Event{
			Workload: &Workload{
				Container: &Container{
					Started: true,
				},
			},
		}
		assert.True(t, GetContainerStarted(event))

		event.Workload.Container.Started = false
		assert.False(t, GetContainerStarted(event))

		assert.False(t, GetContainerStarted(nil))
	})

	t.Run("GetContainerImageId", func(t *testing.T) {
		event := &Event{
			Workload: &Workload{
				Container: &Container{
					Image: &ContainerImage{
						Id: "sha256:abc123",
					},
				},
			},
		}
		assert.Equal(t, "sha256:abc123", GetContainerImageId(event))
	})

	t.Run("GetContainerImageName", func(t *testing.T) {
		event := &Event{
			Workload: &Workload{
				Container: &Container{
					Image: &ContainerImage{
						Name: "nginx:latest",
					},
				},
			},
		}
		assert.Equal(t, "nginx:latest", GetContainerImageName(event))
	})
}

// TestK8sHelpers tests Kubernetes-related helper functions
func TestK8sHelpers(t *testing.T) {
	t.Run("GetK8sPodName", func(t *testing.T) {
		event := &Event{
			Workload: &Workload{
				K8S: &K8S{
					Pod: &Pod{
						Name: "web-pod-123",
					},
				},
			},
		}
		assert.Equal(t, "web-pod-123", GetK8sPodName(event))
		assert.Equal(t, "", GetK8sPodName(nil))
	})

	t.Run("GetK8sPodUid", func(t *testing.T) {
		event := &Event{
			Workload: &Workload{
				K8S: &K8S{
					Pod: &Pod{
						Uid: "12345678-abcd-1234-abcd-123456789abc",
					},
				},
			},
		}
		assert.Equal(t, "12345678-abcd-1234-abcd-123456789abc", GetK8sPodUid(event))
	})

	t.Run("GetK8sNamespaceName", func(t *testing.T) {
		event := &Event{
			Workload: &Workload{
				K8S: &K8S{
					Namespace: &K8SNamespace{
						Name: "production",
					},
				},
			},
		}
		assert.Equal(t, "production", GetK8sNamespaceName(event))
	})
}

// TestEventValueConstructors tests EventValue constructor functions
func TestEventValueConstructors(t *testing.T) {
	t.Run("NewStringValue", func(t *testing.T) {
		ev := NewStringValue("test", "value")
		assert.Equal(t, "test", ev.Name)
		str, ok := GetData[string](&Event{Data: []*EventValue{ev}}, "test")
		assert.True(t, ok)
		assert.Equal(t, "value", str)
	})

	t.Run("NewInt32Value", func(t *testing.T) {
		ev := NewInt32Value("test", 42)
		assert.Equal(t, "test", ev.Name)
		val, ok := GetData[int32](&Event{Data: []*EventValue{ev}}, "test")
		assert.True(t, ok)
		assert.Equal(t, int32(42), val)
	})

	t.Run("NewInt64Value", func(t *testing.T) {
		ev := NewInt64Value("test", 9876543210)
		val, ok := GetData[int64](&Event{Data: []*EventValue{ev}}, "test")
		assert.True(t, ok)
		assert.Equal(t, int64(9876543210), val)
	})

	t.Run("NewUInt32Value", func(t *testing.T) {
		ev := NewUInt32Value("test", 1000)
		val, ok := GetData[uint32](&Event{Data: []*EventValue{ev}}, "test")
		assert.True(t, ok)
		assert.Equal(t, uint32(1000), val)
	})

	t.Run("NewUInt64Value", func(t *testing.T) {
		ev := NewUInt64Value("test", 18446744073709551615)
		val, ok := GetData[uint64](&Event{Data: []*EventValue{ev}}, "test")
		assert.True(t, ok)
		assert.Equal(t, uint64(18446744073709551615), val)
	})

	t.Run("NewBytesValue", func(t *testing.T) {
		bytes := []byte{1, 2, 3, 4}
		ev := NewBytesValue("test", bytes)
		val, ok := GetData[[]byte](&Event{Data: []*EventValue{ev}}, "test")
		assert.True(t, ok)
		assert.Equal(t, bytes, val)
	})

	t.Run("NewBoolValue", func(t *testing.T) {
		ev := NewBoolValue("test", false)
		val, ok := GetData[bool](&Event{Data: []*EventValue{ev}}, "test")
		assert.True(t, ok)
		assert.False(t, val)
	})
}

// TestNullSafety tests that all helpers handle nil gracefully
func TestNullSafety(t *testing.T) {
	t.Run("all helpers with nil event", func(t *testing.T) {
		// Should not panic, just return zero values
		assert.Equal(t, uint32(0), GetProcessPid(nil))
		assert.Equal(t, uint32(0), GetProcessEntityId(nil))
		assert.Equal(t, "", GetProcessExecutablePath(nil))
		assert.Equal(t, uint32(0), GetProcessHostPid(nil))
		assert.Equal(t, uint32(0), GetProcessRealUserId(nil))
		assert.Equal(t, "", GetProcessThreadName(nil))
		assert.Equal(t, "", GetProcessThreadSyscall(nil))
		assert.Equal(t, uint32(0), GetProcessThreadTid(nil))
		assert.Equal(t, uint32(0), GetProcessThreadHostTid(nil))
		assert.Equal(t, uint32(0), GetProcessThreadEntityId(nil))
		assert.Equal(t, "", GetContainerID(nil))
		assert.Equal(t, "", GetContainerName(nil))
		assert.False(t, GetContainerStarted(nil))
		assert.Equal(t, "", GetContainerImageId(nil))
		assert.Equal(t, "", GetContainerImageName(nil))
		assert.Equal(t, "", GetK8sPodName(nil))
		assert.Equal(t, "", GetK8sPodUid(nil))
		assert.Equal(t, "", GetK8sNamespaceName(nil))
	})

	t.Run("all helpers with empty event", func(t *testing.T) {
		event := &Event{}
		// Should not panic, just return zero values
		assert.Equal(t, uint32(0), GetProcessPid(event))
		assert.Equal(t, uint32(0), GetProcessEntityId(event))
		assert.Equal(t, "", GetProcessExecutablePath(event))
		assert.Equal(t, "", GetContainerID(event))
		assert.Equal(t, "", GetK8sPodName(event))
	})
}
