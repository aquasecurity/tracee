package tests

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestGenerateTimestampFileName(t *testing.T) {
	t.Run("basic filename generation", func(t *testing.T) {
		dir := "/tmp"
		prefix := "test"

		filename, err := GenerateTimestampFileName(dir, prefix)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}

		// Check that filename contains the directory
		if !strings.HasPrefix(filename, dir) {
			t.Errorf("Expected filename to start with %s, got %s", dir, filename)
		}

		// Check that filename contains the prefix
		if !strings.Contains(filename, prefix) {
			t.Errorf("Expected filename to contain prefix %s, got %s", prefix, filename)
		}

		// Check timestamp format (YYYYMMDD_HHMMSS)
		timestampPattern := `\d{8}_\d{6}`
		matched, err := regexp.MatchString(timestampPattern, filename)
		if err != nil {
			t.Errorf("Error matching timestamp pattern: %v", err)
		}
		if !matched {
			t.Errorf("Expected filename to contain timestamp in format YYYYMMDD_HHMMSS, got %s", filename)
		}
	})

	t.Run("different directories", func(t *testing.T) {
		testCases := []struct {
			dir    string
			prefix string
		}{
			{"/var/log", "app"},
			{".", "local"},
			{"/tmp/subdir", "data"},
			{"", "empty_dir"},
		}

		for _, tc := range testCases {
			t.Run(fmt.Sprintf("dir_%s_prefix_%s", strings.ReplaceAll(tc.dir, "/", "_"), tc.prefix), func(t *testing.T) {
				filename, err := GenerateTimestampFileName(tc.dir, tc.prefix)
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}

				expectedPath := filepath.Join(tc.dir, fmt.Sprintf("%s_", tc.prefix))
				if !strings.HasPrefix(filename, expectedPath) {
					t.Errorf("Expected filename to start with %s, got %s", expectedPath, filename)
				}
			})
		}
	})

	t.Run("timestamp format consistency", func(t *testing.T) {
		// Generate multiple filenames and ensure they all have valid timestamp format
		for i := 0; i < 3; i++ {
			filename, err := GenerateTimestampFileName("/tmp", "test")
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}

			// Check timestamp format (YYYYMMDD_HHMMSS)
			timestampPattern := `test_\d{8}_\d{6}$`
			matched, err := regexp.MatchString(timestampPattern, filename)
			if err != nil {
				t.Errorf("Error matching timestamp pattern: %v", err)
			}
			if !matched {
				t.Errorf("Expected filename to match pattern, got %s", filename)
			}
		}
	})

	t.Run("special characters in prefix", func(t *testing.T) {
		prefixes := []string{
			"test-file",
			"test_file",
			"test.file",
			"test123",
			"",
		}

		for _, prefix := range prefixes {
			t.Run(fmt.Sprintf("prefix_%s", prefix), func(t *testing.T) {
				filename, err := GenerateTimestampFileName("/tmp", prefix)
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}

				if prefix != "" && !strings.Contains(filename, prefix) {
					t.Errorf("Expected filename to contain prefix %s, got %s", prefix, filename)
				}
			})
		}
	})
}

func TestPrintStructSizes(t *testing.T) {
	// Test structs with different characteristics
	type SimpleStruct struct {
		A int
		B string
	}

	type StructWithPadding struct {
		A byte  // 1 byte
		B int64 // 8 bytes (likely padded)
		C byte  // 1 byte
	}

	type EmptyStruct struct{}

	type NestedStruct struct {
		Inner SimpleStruct
		Value int
	}

	t.Run("simple struct", func(t *testing.T) {
		var buf bytes.Buffer
		s := SimpleStruct{A: 42, B: "test"}

		PrintStructSizes(t, &buf, s)

		output := buf.String()

		// Check that output contains struct name
		if !strings.Contains(output, "SimpleStruct") {
			t.Errorf("Expected output to contain 'SimpleStruct', got: %s", output)
		}

		// Check that output contains field names
		if !strings.Contains(output, "A:int") {
			t.Errorf("Expected output to contain 'A:int', got: %s", output)
		}
		if !strings.Contains(output, "B:string") {
			t.Errorf("Expected output to contain 'B:string', got: %s", output)
		}

		// Check that output contains "bytes"
		if !strings.Contains(output, "bytes") {
			t.Errorf("Expected output to contain 'bytes', got: %s", output)
		}
	})

	t.Run("struct with pointer", func(t *testing.T) {
		var buf bytes.Buffer
		s := &SimpleStruct{A: 42, B: "test"}

		PrintStructSizes(t, &buf, s)

		output := buf.String()
		if !strings.Contains(output, "SimpleStruct") {
			t.Errorf("Expected output to contain 'SimpleStruct' even with pointer, got: %s", output)
		}
	})

	t.Run("struct with padding", func(t *testing.T) {
		var buf bytes.Buffer
		s := StructWithPadding{A: 1, B: 123456789, C: 2}

		PrintStructSizes(t, &buf, s)

		output := buf.String()

		// Should detect padding
		if !strings.Contains(output, "(has padding)") {
			t.Errorf("Expected output to indicate padding, got: %s", output)
		}

		// Check field information
		if !strings.Contains(output, "A:uint8") || !strings.Contains(output, "B:int64") || !strings.Contains(output, "C:uint8") {
			t.Errorf("Expected output to contain field types, got: %s", output)
		}

		// Check offset information
		if !strings.Contains(output, "offset=") {
			t.Errorf("Expected output to contain offset information, got: %s", output)
		}
	})

	t.Run("empty struct", func(t *testing.T) {
		var buf bytes.Buffer
		s := EmptyStruct{}

		PrintStructSizes(t, &buf, s)

		output := buf.String()
		if !strings.Contains(output, "EmptyStruct") {
			t.Errorf("Expected output to contain 'EmptyStruct', got: %s", output)
		}
	})

	t.Run("nested struct", func(t *testing.T) {
		var buf bytes.Buffer
		s := NestedStruct{
			Inner: SimpleStruct{A: 1, B: "nested"},
			Value: 42,
		}

		PrintStructSizes(t, &buf, s)

		output := buf.String()
		if !strings.Contains(output, "NestedStruct") {
			t.Errorf("Expected output to contain 'NestedStruct', got: %s", output)
		}
		if !strings.Contains(output, "Inner:") {
			t.Errorf("Expected output to contain 'Inner:' field, got: %s", output)
		}
	})

	t.Run("non-struct type", func(t *testing.T) {
		var buf bytes.Buffer
		notAStruct := 42

		PrintStructSizes(t, &buf, notAStruct)

		output := buf.String()
		if !strings.Contains(output, "is not a struct") {
			t.Errorf("Expected output to indicate non-struct type, got: %s", output)
		}
	})

	t.Run("different writers", func(t *testing.T) {
		s := SimpleStruct{A: 42, B: "test"}

		// Test with different io.Writer implementations
		writers := []io.Writer{
			&bytes.Buffer{},
			io.Discard,
		}

		for i, w := range writers {
			t.Run(fmt.Sprintf("writer_%d", i), func(t *testing.T) {
				// Should not panic with different writers
				PrintStructSizes(t, w, s)
			})
		}
	})
}

func TestCreateTempFile(t *testing.T) {
	t.Run("basic temp file creation", func(t *testing.T) {
		content := "Hello, World!"

		file := CreateTempFile(t, content)
		defer os.Remove(file.Name())

		// Check that file was created
		if file == nil {
			t.Fatal("Expected non-nil file")
		}

		// Check that file name is not empty
		if file.Name() == "" {
			t.Error("Expected non-empty file name")
		}

		// Check that file exists
		if _, err := os.Stat(file.Name()); os.IsNotExist(err) {
			t.Errorf("Expected file to exist at %s", file.Name())
		}

		// Check file content
		readContent, err := os.ReadFile(file.Name())
		if err != nil {
			t.Errorf("Failed to read file content: %v", err)
		}

		if string(readContent) != content {
			t.Errorf("Expected content %q, got %q", content, string(readContent))
		}
	})

	t.Run("empty content", func(t *testing.T) {
		file := CreateTempFile(t, "")
		defer os.Remove(file.Name())

		// Check file was created even with empty content
		if file == nil {
			t.Fatal("Expected non-nil file")
		}

		// Check content is indeed empty
		readContent, err := os.ReadFile(file.Name())
		if err != nil {
			t.Errorf("Failed to read file content: %v", err)
		}

		if len(readContent) != 0 {
			t.Errorf("Expected empty content, got %q", string(readContent))
		}
	})

	t.Run("multiline content", func(t *testing.T) {
		content := `Line 1
Line 2
Line 3
With special characters: !@#$%^&*()
And unicode: 🚀 ñ 中文`

		file := CreateTempFile(t, content)
		defer os.Remove(file.Name())

		readContent, err := os.ReadFile(file.Name())
		if err != nil {
			t.Errorf("Failed to read file content: %v", err)
		}

		if string(readContent) != content {
			t.Errorf("Expected content %q, got %q", content, string(readContent))
		}
	})

	t.Run("large content", func(t *testing.T) {
		// Create a large string
		content := strings.Repeat("Large content line\n", 1000)

		file := CreateTempFile(t, content)
		defer os.Remove(file.Name())

		readContent, err := os.ReadFile(file.Name())
		if err != nil {
			t.Errorf("Failed to read file content: %v", err)
		}

		if string(readContent) != content {
			t.Errorf("Content mismatch for large file")
		}
	})

	t.Run("multiple temp files are unique", func(t *testing.T) {
		file1 := CreateTempFile(t, "content1")
		file2 := CreateTempFile(t, "content2")
		defer os.Remove(file1.Name())
		defer os.Remove(file2.Name())

		if file1.Name() == file2.Name() {
			t.Errorf("Expected unique filenames, but got same: %s", file1.Name())
		}

		// Check both files have correct content
		content1, err := os.ReadFile(file1.Name())
		if err != nil {
			t.Errorf("Failed to read file1: %v", err)
		}
		if string(content1) != "content1" {
			t.Errorf("Expected 'content1', got %q", string(content1))
		}

		content2, err := os.ReadFile(file2.Name())
		if err != nil {
			t.Errorf("Failed to read file2: %v", err)
		}
		if string(content2) != "content2" {
			t.Errorf("Expected 'content2', got %q", string(content2))
		}
	})

	t.Run("file pattern verification", func(t *testing.T) {
		file := CreateTempFile(t, "test")
		defer os.Remove(file.Name())

		// Check that filename matches expected pattern
		filename := filepath.Base(file.Name())
		matched, err := regexp.MatchString(`^test_temp_file_.*\.txt$`, filename)
		if err != nil {
			t.Errorf("Error matching filename pattern: %v", err)
		}
		if !matched {
			t.Errorf("Expected filename to match pattern 'test_temp_file_*.txt', got %s", filename)
		}
	})
}

// Benchmark tests
func BenchmarkGenerateTimestampFileName(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateTimestampFileName("/tmp", "bench")
		if err != nil {
			b.Errorf("Unexpected error: %v", err)
		}
	}
}

func BenchmarkPrintStructSizes(b *testing.B) {
	type BenchStruct struct {
		A int
		B string
		C float64
		D bool
	}

	s := BenchStruct{A: 42, B: "test", C: 3.14, D: true}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PrintStructSizes(b, io.Discard, s)
	}
}

func BenchmarkCreateTempFile(b *testing.B) {
	content := "benchmark content"
	files := make([]*os.File, b.N)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		files[i] = CreateTempFile(b, content)
	}

	// Cleanup (not included in benchmark timing)
	b.StopTimer()
	for _, file := range files {
		if file != nil {
			os.Remove(file.Name())
		}
	}
}

// Integration test - using all functions together
func TestHelperIntegration(t *testing.T) {
	t.Run("use all helpers together", func(t *testing.T) {
		// Generate a filename
		filename, err := GenerateTimestampFileName("/tmp", "integration")
		if err != nil {
			t.Errorf("Failed to generate filename: %v", err)
		}

		// Create a struct to analyze
		type TestStruct struct {
			Name     string
			Size     int
			Filename string
		}

		testStruct := TestStruct{
			Name:     "integration_test",
			Size:     42,
			Filename: filename,
		}

		// Print struct sizes
		var buf bytes.Buffer
		PrintStructSizes(t, &buf, testStruct)

		output := buf.String()
		if !strings.Contains(output, "TestStruct") {
			t.Errorf("Expected struct analysis output, got: %s", output)
		}

		// Create temp file with the struct analysis
		tempFile := CreateTempFile(t, output)
		defer os.Remove(tempFile.Name())

		// Verify the temp file contains our struct analysis
		content, err := os.ReadFile(tempFile.Name())
		if err != nil {
			t.Errorf("Failed to read temp file: %v", err)
		}

		if !strings.Contains(string(content), "TestStruct") {
			t.Errorf("Expected temp file to contain struct analysis")
		}
	})
}
