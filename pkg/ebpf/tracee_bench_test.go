package ebpf

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"testing"

	"github.com/aquasecurity/tracee/pkg/errfmt"
)

func computeFileHashOld(file *os.File) (string, error) {
	h := sha256.New()

	_, err := io.Copy(h, file)
	if err != nil {
		return "", errfmt.WrapError(err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func BenchmarkComputeFileHashOld(b *testing.B) {
	file, err := os.Open("/usr/bin/uname")
	if err != nil {
		b.Fatal(err)
	}
	defer file.Close()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := computeFileHashOld(file)
		if err != nil {
			b.Fatalf("Error computing file hash: %v", err)
		}
		// Reset the file pointer to the beginning for the next iteration
		file.Seek(0, 0)
	}
}

func BenchmarkComputeFileHashCurrent(b *testing.B) {
	file, err := os.Open("/usr/bin/uname")
	if err != nil {
		b.Fatal(err)
	}
	defer file.Close()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := computeFileHash(file)
		if err != nil {
			b.Fatalf("Error computing file hash: %v", err)
		}
		// Reset the file pointer to the beginning for the next iteration
		file.Seek(0, 0)
	}
}
