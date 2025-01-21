package proc

import (
	"bytes"
	"os"
	"testing"

	"github.com/aquasecurity/tracee/pkg/utils/tests"
)

func BenchmarkReadFile(b *testing.B) {
	tmpFiles := []struct {
		name    string
		content string
	}{
		{
			name:    "Empty File",
			content: "",
		},
		{
			name:    "Small File",
			content: "Hello, world!",
		},
		{
			name:    "Exact Buffer Size",
			content: string(bytes.Repeat([]byte("A"), StatReadFileInitialBufferSize)),
		},
		//
		// This test is disabled because the temporary file is not an actual /proc file.
		// As a result, os.ReadFile uses the file size retrieved by the stat syscall,
		// which ensures it is always more optimal than ReadFile in this scenario.
		//
		// {
		// 	name:    "Larger Than Buffer Size",
		// 	content: string(bytes.Repeat([]byte("B"), 2*StatReadFileInitialBufferSize)),
		// },
	}

	for _, tt := range tmpFiles {
		b.Run("ProcFSReadFile/"+tt.name, func(b *testing.B) {
			tempFile := tests.CreateTempFile(b, tt.content)
			defer os.Remove(tempFile.Name())

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := ReadFile(tempFile.Name(), StatReadFileInitialBufferSize)
				if err != nil {
					b.Fatalf("ReadFile failed: %v", err)
				}
			}
		})

		b.Run("OsReadFile/"+tt.name, func(b *testing.B) {
			tempFile := tests.CreateTempFile(b, tt.content)
			defer os.Remove(tempFile.Name())

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := os.ReadFile(tempFile.Name())
				if err != nil {
					b.Fatalf("os.ReadFile failed: %v", err)
				}
			}
		})
	}

	// The benchmark for /proc file below is not fully deterministic
	// due to the dynamic nature of their content. However, they still
	// allow for a meaningful comparison of the performance between
	// ReadFile and os.ReadFile, assuming the file content (size)
	// remains relatively stable during the test.

	statFile := "/proc/self/stat"

	b.Run("ProcFSReadFile_"+statFile, func(b *testing.B) {
		tempFile := tests.CreateTempFile(b, statFile)
		defer os.Remove(tempFile.Name())

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := ReadFile(tempFile.Name(), StatReadFileInitialBufferSize)
			if err != nil {
				b.Fatalf("ReadFile failed: %v", err)
			}
		}
	})

	b.Run("OsReadFile_"+statFile, func(b *testing.B) {
		tempFile := tests.CreateTempFile(b, statFile)
		defer os.Remove(tempFile.Name())

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := os.ReadFile(tempFile.Name())
			if err != nil {
				b.Fatalf("os.ReadFile failed: %v", err)
			}
		}
	})
}
