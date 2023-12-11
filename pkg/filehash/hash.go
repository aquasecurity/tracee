package filehash

import (
	"encoding/hex"
	"io"
	"os"

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

func ComputeFileHash(file *os.File) (string, error) {
	h := miniosha.New()
	_, err := io.Copy(h, file)
	if err != nil {
		return "", errfmt.WrapError(err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
