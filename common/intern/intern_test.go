package intern

import (
	"fmt"
	"runtime"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestString_EmptyString(t *testing.T) {
	result := String("")
	assert.Equal(t, "", result)
}

func TestString_IdenticalContentSharesMemory(t *testing.T) {
	// Create two distinct string allocations with the same content.
	// Using fmt.Sprintf to prevent the compiler from pooling string literals.
	a := fmt.Sprintf("hello-%s", "world")
	b := fmt.Sprintf("hello-%s", "world")

	// Confirm they are equal but have different backing arrays.
	require.Equal(t, a, b)

	internedA := String(a)
	internedB := String(b)

	assert.Equal(t, a, internedA)
	assert.Equal(t, b, internedB)

	// After interning, both should point to the same underlying data.
	ptrA := (*[2]uintptr)(unsafe.Pointer(&internedA))[0]
	ptrB := (*[2]uintptr)(unsafe.Pointer(&internedB))[0]
	assert.Equal(t, ptrA, ptrB, "interned strings with identical content should share the same backing array")
}

func TestString_DifferentContentDifferentMemory(t *testing.T) {
	a := String("foo")
	b := String("bar")

	assert.NotEqual(t, a, b)

	ptrA := (*[2]uintptr)(unsafe.Pointer(&a))[0]
	ptrB := (*[2]uintptr)(unsafe.Pointer(&b))[0]
	assert.NotEqual(t, ptrA, ptrB, "interned strings with different content should not share backing arrays")
}

func TestString_ValuePreserved(t *testing.T) {
	tests := []string{
		"bash",
		"/usr/bin/bash",
		"tracee-node",
		"my-container-id-abc123",
		"kube-system",
		"a", // single char
		"this is a longer string with spaces and special chars: !@#$%^&*()",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			result := String(input)
			assert.Equal(t, input, result)
		})
	}
}

// BenchmarkString_Interning measures the throughput of interning a string
// that already exists in the intern table (the common/hot case).
func BenchmarkString_Interning(b *testing.B) {
	// Warm up the intern table with a value.
	_ = String("bash")

	b.ResetTimer()
	for b.Loop() {
		_ = String("bash")
	}
}

// BenchmarkString_NoInterning measures baseline: creating a new string from bytes
// on every iteration (simulating what happens without interning).
func BenchmarkString_NoInterning(b *testing.B) {
	src := []byte("bash")

	b.ResetTimer()
	for b.Loop() {
		_ = string(src)
	}
}

// BenchmarkMemory_WithInterning measures memory savings by simulating N events
// with repetitive string fields.
func BenchmarkMemory_WithInterning(b *testing.B) {
	processNames := [][]byte{
		[]byte("bash"), []byte("nginx"), []byte("sshd"),
		[]byte("tracee"), []byte("kubelet"), []byte("containerd"),
	}
	hostname := []byte("worker-node-01.cluster.local")

	b.ResetTimer()
	b.ReportAllocs()

	var sink []string
	for i := range b.N {
		// Simulate per-event string creation + interning.
		comm := String(string(processNames[i%len(processNames)]))
		host := String(string(hostname))
		sink = append(sink, comm, host)
	}
	runtime.KeepAlive(sink)
}

// BenchmarkMemory_WithoutInterning is the baseline: no interning.
func BenchmarkMemory_WithoutInterning(b *testing.B) {
	processNames := [][]byte{
		[]byte("bash"), []byte("nginx"), []byte("sshd"),
		[]byte("tracee"), []byte("kubelet"), []byte("containerd"),
	}
	hostname := []byte("worker-node-01.cluster.local")

	b.ResetTimer()
	b.ReportAllocs()

	var sink []string
	for i := range b.N {
		// Simulate per-event string creation without interning.
		comm := string(processNames[i%len(processNames)])
		host := string(hostname)
		sink = append(sink, comm, host)
	}
	runtime.KeepAlive(sink)
}
