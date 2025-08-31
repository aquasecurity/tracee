package digest_test

import (
	"os"
	"testing"

	"github.com/aquasecurity/tracee/common/digest"
)

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
		_, err := digest.ComputeFileHash(file)
		if err != nil {
			b.Fatalf("Error computing file hash: %v", err)
		}
		// Reset the file pointer to the beginning for the next iteration
		file.Seek(0, 0)
	}
}
