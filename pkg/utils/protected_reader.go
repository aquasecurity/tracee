package utils

import (
	"bytes"
	"errors"
	"io"
	"runtime/debug"
)

var ErrMemoryAccess = errors.New("invalid memory access")

// NewProtectedReader returns an io.ReaderAt that wraps around a byte slice.
// Unlike the reader returned from bytes.NewReader(), this reader protects
// the reading function from fatal errors caused by invalid memory accesses
// to the underlying byte slice.
// If a fatal error occurs (e.g. SIGBUS or SIGSEGV), the read simply fails
// with an error that indicates a bad memory access.
// This is intended for reading from mmap'ed files, where a change to the file
// on disk can cause areas of the mapped memory to become invalid, resulting in
// a SIGBUS when accessing them.
func NewProtectedReader(data []byte) io.ReaderAt {
	return protectedReader{
		internal: bytes.NewReader(data),
	}
}

type protectedReader struct {
	internal io.ReaderAt
}

func (r protectedReader) ReadAt(p []byte, off int64) (n int, err error) {
	// By default, invalid memory access signals are converted by the go runtime
	// into a fatal error, which cannot be recovered. Calling SetPanicOnFault
	// causes these signals to generate a regular panic instead.
	// It only applies to the current goroutine, and we undo the operation after
	// performing the memory access.
	prev := debug.SetPanicOnFault(true)

	// Recover from panics caused by memory access errors (SIGBUS and SIGSEGV)
	defer func() {
		if rec := recover(); rec != nil {
			n = 0
			err = ErrMemoryAccess
		}
		debug.SetPanicOnFault(prev)
	}()

	// Perform the unsafe read
	return r.internal.ReadAt(p, off)
}
