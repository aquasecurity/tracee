package filehash

import (
	"bytes"
	"encoding/hex"
	"io"
	"os"
	"sync"

	miniosha "github.com/minio/sha256-simd"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
)

// ComputeFileHashAtPath attempts to open a file at a path and calculate its
// sha256 hash.
func ComputeFileHashAtPath(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", errfmt.WrapError(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}()
	return ComputeFileHash(f)
}

// Preallocate a copy buffer for use between hash computations.
// This reduces allocations and garbage collection which would happen
// from using io.Copy.
var (
	hashBuffer        = make([]byte, 1024*32)
	hashBufferWrapper = bytes.NewBuffer(hashBuffer)
	bufferMutex       = new(sync.Mutex) // add a mutex to prevent concurrent calls deleting the buffer
)

// ComputeFileHashAtPath attempts to calculate the sha256 hash of a file
// (the file must already be opened).
func ComputeFileHash(file *os.File) (string, error) {
	bufferMutex.Lock()
	defer bufferMutex.Unlock()
	hashBufferWrapper.Reset()
	h := miniosha.New()
	_, err := io.CopyBuffer(h, file, hashBuffer)
	if err != nil {
		return "", errfmt.WrapError(err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
