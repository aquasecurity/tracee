package utils

import (
	"bytes"
	"testing"
)

var result []byte

func BenchmarkBytesTrimRight_WithNUL(b *testing.B) {
	var arr [64]byte
	for i := 0; i < 61; i++ {
		arr[i] = 'A'
	}
	// last 3 bytes are \x00 by default

	for b.Loop() {
		result = bytes.TrimRight(arr[:], "\x00")
	}
	_ = result
}

func BenchmarkBytesTrimRight_NoNUL(b *testing.B) {
	var arr [64]byte
	for i := 0; i < 64; i++ {
		arr[i] = 'A'
	}

	for b.Loop() {
		result = bytes.TrimRight(arr[:], "\x00")
	}
	_ = result
}

func BenchmarkTrimTrailingNUL_WithNUL(b *testing.B) {
	var arr [64]byte
	for i := 0; i < 61; i++ {
		arr[i] = 'A'
	}
	// last 3 bytes are \x00 by default

	for b.Loop() {
		result = TrimTrailingNUL(arr[:])
	}
	_ = result
}

func BenchmarkTrimTrailingNUL_NoNUL(b *testing.B) {
	var arr [64]byte
	for i := 0; i < 64; i++ {
		arr[i] = 'A'
	}

	for b.Loop() {
		result = TrimTrailingNUL(arr[:])
	}
	_ = result
}
