package filehash

import (
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

// Pool of copy buffers for use between hash computations.
// This reduces allocations and eliminates lock contention that occurred
// with the previous shared buffer approach.
var hashBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 1024*32)
		return &buf
	},
}

// ComputeFileHashAtPath attempts to calculate the sha256 hash of a file
// (the file must already be opened).
func ComputeFileHash(file *os.File) (string, error) {
	// Get a buffer from the pool
	bufValue := hashBufferPool.Get()
	bufPtr, ok := bufValue.(*[]byte)
	if !ok {
		return "", errfmt.Errorf("failed to get buffer from pool: unexpected type %T", bufValue)
	}
	defer hashBufferPool.Put(bufPtr)

	h := miniosha.New()
	_, err := io.CopyBuffer(h, file, *bufPtr)
	if err != nil {
		return "", errfmt.WrapError(err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
