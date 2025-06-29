package utils

import (
	"bytes"
	"io"
	"testing"
)

func TestNewProtectedReader(t *testing.T) {
	data := []byte("test data")
	reader := NewProtectedReader(data)

	if reader == nil {
		t.Fatal("NewProtectedReader returned nil")
	}

	// Verify it implements io.ReaderAt
	var _ io.ReaderAt = reader
}

func TestProtectedReader_NormalOperation(t *testing.T) {
	// Test that normal reads work the same as bytes.Reader
	data := []byte("hello world")
	protectedReader := NewProtectedReader(data)
	standardReader := bytes.NewReader(data)

	// Test a few basic operations to ensure wrapping works correctly
	tests := []struct {
		offset int64
		length int
	}{
		{0, 5},  // "hello"
		{6, 5},  // "world"
		{0, 11}, // entire string
	}

	for _, tt := range tests {
		protectedBuf := make([]byte, tt.length)
		standardBuf := make([]byte, tt.length)

		protectedN, protectedErr := protectedReader.ReadAt(protectedBuf, tt.offset)
		standardN, standardErr := standardReader.ReadAt(standardBuf, tt.offset)

		// Should behave identically
		if protectedN != standardN {
			t.Errorf("Read count mismatch: protected=%d, standard=%d", protectedN, standardN)
		}

		if (protectedErr == nil) != (standardErr == nil) {
			t.Errorf("Error state mismatch: protected=%v, standard=%v", protectedErr, standardErr)
		}

		if !bytes.Equal(protectedBuf[:protectedN], standardBuf[:standardN]) {
			t.Errorf("Data mismatch: protected=%q, standard=%q",
				string(protectedBuf[:protectedN]), string(standardBuf[:standardN]))
		}
	}
}

func TestErrMemoryAccess(t *testing.T) {
	if ErrMemoryAccess == nil {
		t.Error("ErrMemoryAccess should not be nil")
	}

	expectedMsg := "invalid memory access"
	if ErrMemoryAccess.Error() != expectedMsg {
		t.Errorf("Expected error message %q, got %q", expectedMsg, ErrMemoryAccess.Error())
	}
}

// Note: The core feature of this protected reader is to catch SIGBUS/SIGSEGV
// signals and convert them to ErrMemoryAccess errors. This is extremely
// difficult to test safely in a unit test because it requires:
//
// 1. Memory-mapped files that become invalid during access
// 2. Actual signal generation (SIGBUS/SIGSEGV)
// 3. Controlled memory access violations
//
// The protection mechanism is primarily intended for runtime scenarios with
// memory-mapped files where the underlying file changes, causing mapped
// regions to become invalid. This would be tested in integration tests
// with actual mmap operations rather than unit tests.
//
// The tests above focus on ensuring the wrapper doesn't break normal
// operation and that the error constant is properly defined.
func TestProtectedReader_MemoryProtectionDocumentation(t *testing.T) {
	t.Log("This reader is designed to protect against SIGBUS/SIGSEGV signals")
	t.Log("when reading from memory-mapped files that become invalid.")
	t.Log("The protection mechanism converts fatal signals to ErrMemoryAccess.")
	t.Log("Direct testing requires controlled memory violations which are")
	t.Log("unsafe in unit tests and should be tested in integration scenarios.")
}
