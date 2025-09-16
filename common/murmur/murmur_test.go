package murmur

import (
	"bytes"
	"testing"
)

// Test Murmur32 function with various inputs
func TestMurmur32(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected uint32
	}{
		{
			name:     "empty input",
			input:    []byte{},
			expected: 0xac1e97d9, // Actual output for empty input
		},
		{
			name:     "single byte",
			input:    []byte{0x42},
			expected: 0xd03e2e67, // Actual output for single byte 0x42
		},
		{
			name:     "four bytes",
			input:    []byte{0x01, 0x02, 0x03, 0x04},
			expected: 0xb503cc53, // Actual output
		},
		{
			name:     "eight bytes",
			input:    []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			expected: 0x66cb9e81, // Actual output
		},
		{
			name:     "string hello",
			input:    []byte("hello"),
			expected: 0x6fcfe226, // Actual output for "hello"
		},
		{
			name:     "string world",
			input:    []byte("world"),
			expected: 0xfc89ab3f, // Actual output for "world"
		},
		{
			name:     "longer string",
			input:    []byte("The quick brown fox jumps over the lazy dog"),
			expected: 0x7805e4eb, // Actual output
		},
		{
			name:     "repeated pattern",
			input:    bytes.Repeat([]byte{0xAA}, 16),
			expected: 0x837e5743, // Actual output
		},
		{
			name:     "all zeros",
			input:    make([]byte, 12),
			expected: 0xf6c56b4a, // Actual output for 12 zero bytes
		},
		{
			name:     "all ones",
			input:    bytes.Repeat([]byte{0xFF}, 10),
			expected: 0xaac3b662, // Actual output
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Murmur32(tt.input)
			if result != tt.expected {
				t.Errorf("Murmur32(%v) = 0x%08x, expected 0x%08x", tt.input, result, tt.expected)
			}
		})
	}
}

// Test consistency - same input should always produce same output
func TestMurmur32_Consistency(t *testing.T) {
	testInputs := [][]byte{
		{},
		{0x42},
		[]byte("hello world"),
		{0x01, 0x02, 0x03, 0x04, 0x05},
		bytes.Repeat([]byte{0xAA}, 100),
	}

	for _, input := range testInputs {
		first := Murmur32(input)
		for i := 0; i < 5; i++ {
			result := Murmur32(input)
			if result != first {
				t.Errorf("Murmur32 inconsistent for input %v: first=0x%08x, iteration %d=0x%08x",
					input, first, i, result)
			}
		}
	}
}

// Test that different inputs produce different outputs (avalanche effect)
func TestMurmur32_Avalanche(t *testing.T) {
	baseInput := []byte("hello world")
	baseHash := Murmur32(baseInput)

	// Test single bit changes
	for i := 0; i < len(baseInput); i++ {
		for bit := 0; bit < 8; bit++ {
			modified := make([]byte, len(baseInput))
			copy(modified, baseInput)
			modified[i] ^= 1 << bit // Flip one bit

			modifiedHash := Murmur32(modified)
			if modifiedHash == baseHash {
				t.Errorf("Single bit flip at byte %d bit %d produced same hash: 0x%08x",
					i, bit, baseHash)
			}
		}
	}
}

// Test various input sizes to ensure all code paths are covered
func TestMurmur32_VariousLengths(t *testing.T) {
	// Test different tail lengths (0, 1, 2, 3 bytes after 4-byte blocks)
	testLengths := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 31, 32, 33}

	seen := make(map[uint32]int)

	for _, length := range testLengths {
		input := make([]byte, length)
		for i := range input {
			input[i] = byte(i % 256) // Fill with predictable pattern
		}

		hash := Murmur32(input)

		// Check if we've seen this hash before (very unlikely with good hash function)
		if prevLength, exists := seen[hash]; exists {
			t.Errorf("Hash collision between length %d and %d: 0x%08x",
				prevLength, length, hash)
		}
		seen[hash] = length
	}
}

// Test HashU32AndU64 function
func TestHashU32AndU64(t *testing.T) {
	tests := []struct {
		name     string
		arg1     uint32
		arg2     uint64
		expected uint32
	}{
		{
			name:     "zero values",
			arg1:     0,
			arg2:     0,
			expected: 0xf6c56b4a, // Actual hash of 12 zero bytes
		},
		{
			name:     "small values",
			arg1:     1,
			arg2:     2,
			expected: 0xd25f0e74, // Actual output
		},
		{
			name:     "larger values",
			arg1:     0x12345678,
			arg2:     0x123456789ABCDEF0,
			expected: 0xb065052c, // Actual output
		},
		{
			name:     "max uint32, zero uint64",
			arg1:     0xFFFFFFFF,
			arg2:     0,
			expected: 0x6d045877, // Actual output
		},
		{
			name:     "zero uint32, max uint64",
			arg1:     0,
			arg2:     0xFFFFFFFFFFFFFFFF,
			expected: 0xece98cf5, // Actual output
		},
		{
			name:     "max values",
			arg1:     0xFFFFFFFF,
			arg2:     0xFFFFFFFFFFFFFFFF,
			expected: 0xffa282fc, // Actual hash of 12 0xFF bytes
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HashU32AndU64(tt.arg1, tt.arg2)
			if result != tt.expected {
				t.Errorf("HashU32AndU64(%d, %d) = 0x%08x, expected 0x%08x",
					tt.arg1, tt.arg2, result, tt.expected)
			}
		})
	}
}

// Test HashU32AndU64 consistency
func TestHashU32AndU64_Consistency(t *testing.T) {
	testCases := []struct {
		arg1 uint32
		arg2 uint64
	}{
		{0, 0},
		{1, 2},
		{0x12345678, 0x123456789ABCDEF0},
		{0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
	}

	for _, tc := range testCases {
		first := HashU32AndU64(tc.arg1, tc.arg2)
		for i := 0; i < 5; i++ {
			result := HashU32AndU64(tc.arg1, tc.arg2)
			if result != first {
				t.Errorf("HashU32AndU64 inconsistent for (%d, %d): first=0x%08x, iteration %d=0x%08x",
					tc.arg1, tc.arg2, first, i, result)
			}
		}
	}
}

// Test that HashU32AndU64 produces different outputs for different inputs
func TestHashU32AndU64_Uniqueness(t *testing.T) {
	seen := make(map[uint32]string)

	testCases := []struct {
		arg1 uint32
		arg2 uint64
		name string
	}{
		{0, 0, "0,0"},
		{1, 0, "1,0"},
		{0, 1, "0,1"},
		{1, 1, "1,1"},
		{2, 0, "2,0"},
		{0, 2, "0,2"},
		{0x12345678, 0x123456789ABCDEF0, "large values"},
		{0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF, "max values"},
	}

	for _, tc := range testCases {
		hash := HashU32AndU64(tc.arg1, tc.arg2)

		if prevCase, exists := seen[hash]; exists {
			t.Errorf("Hash collision between %s and %s: 0x%08x",
				prevCase, tc.name, hash)
		}
		seen[hash] = tc.name
	}
}

// Test that HashU32AndU64 uses network byte order (big endian)
func TestHashU32AndU64_ByteOrder(t *testing.T) {
	// This should match manually creating the same byte array with big endian encoding
	arg1 := uint32(0x12345678)
	arg2 := uint64(0x123456789ABCDEF0)

	result := HashU32AndU64(arg1, arg2)

	// Manually create the same byte array
	expected := make([]byte, 12)
	expected[0] = 0x12 // arg1 bytes in big endian
	expected[1] = 0x34
	expected[2] = 0x56
	expected[3] = 0x78
	expected[4] = 0x12 // arg2 bytes in big endian
	expected[5] = 0x34
	expected[6] = 0x56
	expected[7] = 0x78
	expected[8] = 0x9A
	expected[9] = 0xBC
	expected[10] = 0xDE
	expected[11] = 0xF0

	expectedHash := Murmur32(expected)

	if result != expectedHash {
		t.Errorf("HashU32AndU64(0x%08x, 0x%016x) = 0x%08x, expected 0x%08x (network byte order)",
			arg1, arg2, result, expectedHash)
	}
}

// Benchmark tests
func BenchmarkMurmur32_Empty(b *testing.B) {
	data := []byte{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Murmur32(data)
	}
}

func BenchmarkMurmur32_Small(b *testing.B) {
	data := []byte("hello")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Murmur32(data)
	}
}

func BenchmarkMurmur32_Medium(b *testing.B) {
	data := []byte("The quick brown fox jumps over the lazy dog")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Murmur32(data)
	}
}

func BenchmarkMurmur32_Large(b *testing.B) {
	data := bytes.Repeat([]byte("abcdefghijklmnopqrstuvwxyz"), 100) // 2600 bytes
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Murmur32(data)
	}
}

func BenchmarkHashU32AndU64(b *testing.B) {
	arg1 := uint32(0x12345678)
	arg2 := uint64(0x123456789ABCDEF0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HashU32AndU64(arg1, arg2)
	}
}
