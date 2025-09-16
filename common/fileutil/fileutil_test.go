package fileutil

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
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

// Test OpenExistingDir
func TestOpenExistingDir(t *testing.T) {
	t.Run("open existing directory", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "test_open_dir_*")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tempDir)

		file, err := OpenExistingDir(tempDir)
		if err != nil {
			t.Errorf("Failed to open existing directory: %v", err)
		}
		if file != nil {
			defer file.Close()

			// Verify the file descriptor is valid by checking its name
			if file.Name() != tempDir {
				t.Errorf("Expected file name to be %s, got %s", tempDir, file.Name())
			}
		}
	})

	t.Run("open non-existing directory", func(t *testing.T) {
		_, err := OpenExistingDir("/path/that/does/not/exist")
		if err == nil {
			t.Error("Expected error when opening non-existing directory")
		}
	})

	t.Run("open file instead of directory", func(t *testing.T) {
		tempFile, err := os.CreateTemp("", "test_file_*")
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		defer os.Remove(tempFile.Name())
		tempFile.Close()

		_, err = OpenExistingDir(tempFile.Name())
		if err == nil {
			t.Error("Expected error when opening file as directory")
		}
	})
}

// Test OpenAt
func TestOpenAt(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test_openat_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dirFile, err := OpenExistingDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to open temp dir: %v", err)
	}
	defer dirFile.Close()

	t.Run("create new file", func(t *testing.T) {
		file, err := OpenAt(dirFile, "newfile.txt", os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			t.Errorf("Failed to create file with OpenAt: %v", err)
		}
		if file != nil {
			defer file.Close()

			// Write and read to verify it works
			_, err := file.WriteString("test content")
			if err != nil {
				t.Errorf("Failed to write to file: %v", err)
			}
		}
	})

	t.Run("open existing file", func(t *testing.T) {
		// Create a file first
		testFile := filepath.Join(tempDir, "existing.txt")
		err := os.WriteFile(testFile, []byte("existing content"), 0644)
		if err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		file, err := OpenAt(dirFile, "existing.txt", os.O_RDONLY, 0)
		if err != nil {
			t.Errorf("Failed to open existing file: %v", err)
		}
		if file != nil {
			defer file.Close()

			// Read and verify content
			content, err := io.ReadAll(file)
			if err != nil {
				t.Errorf("Failed to read file: %v", err)
			}
			if string(content) != "existing content" {
				t.Errorf("Expected 'existing content', got %s", string(content))
			}
		}
	})
}

// Test RemoveAt
func TestRemoveAt(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test_removeat_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dirFile, err := OpenExistingDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to open temp dir: %v", err)
	}
	defer dirFile.Close()

	t.Run("remove file", func(t *testing.T) {
		// Create a file to remove
		testFile := "remove_me.txt"
		fullPath := filepath.Join(tempDir, testFile)
		err := os.WriteFile(fullPath, []byte("delete me"), 0644)
		if err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		// Remove it using RemoveAt
		err = RemoveAt(dirFile, testFile, 0)
		if err != nil {
			t.Errorf("Failed to remove file: %v", err)
		}

		// Verify it's gone
		_, err = os.Stat(fullPath)
		if !os.IsNotExist(err) {
			t.Error("File should have been removed")
		}
	})

	t.Run("remove directory", func(t *testing.T) {
		// Create a directory to remove
		testDir := "remove_dir"
		fullPath := filepath.Join(tempDir, testDir)
		err := os.Mkdir(fullPath, 0755)
		if err != nil {
			t.Fatalf("Failed to create test dir: %v", err)
		}

		// Remove it using RemoveAt with AT_REMOVEDIR flag
		err = RemoveAt(dirFile, testDir, unix.AT_REMOVEDIR)
		if err != nil {
			t.Errorf("Failed to remove directory: %v", err)
		}

		// Verify it's gone
		_, err = os.Stat(fullPath)
		if !os.IsNotExist(err) {
			t.Error("Directory should have been removed")
		}
	})

	t.Run("remove non-existing file", func(t *testing.T) {
		err := RemoveAt(dirFile, "does_not_exist.txt", 0)
		if err == nil {
			t.Error("Expected error when removing non-existing file")
		}
	})
}

// Test MkdirAt
func TestMkdirAt(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test_mkdirat_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dirFile, err := OpenExistingDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to open temp dir: %v", err)
	}
	defer dirFile.Close()

	t.Run("create new directory", func(t *testing.T) {
		dirName := "new_directory"
		err := MkdirAt(dirFile, dirName, 0755)
		if err != nil {
			t.Errorf("Failed to create directory: %v", err)
		}

		// Verify it was created
		fullPath := filepath.Join(tempDir, dirName)
		stat, err := os.Stat(fullPath)
		if err != nil {
			t.Errorf("Directory was not created: %v", err)
		}
		if stat != nil && !stat.IsDir() {
			t.Error("Created entry is not a directory")
		}
	})

	t.Run("create directory that already exists", func(t *testing.T) {
		dirName := "existing_dir"
		fullPath := filepath.Join(tempDir, dirName)
		err := os.Mkdir(fullPath, 0755)
		if err != nil {
			t.Fatalf("Failed to pre-create directory: %v", err)
		}

		// Try to create again - should fail
		err = MkdirAt(dirFile, dirName, 0755)
		if err == nil {
			t.Error("Expected error when creating existing directory")
		}
	})
}

// Test MkdirAtExist
func TestMkdirAtExist(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test_mkdiratexist_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dirFile, err := OpenExistingDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to open temp dir: %v", err)
	}
	defer dirFile.Close()

	t.Run("create new directory", func(t *testing.T) {
		dirName := "new_dir_exist"
		err := MkdirAtExist(dirFile, dirName, 0755)
		if err != nil {
			t.Errorf("Failed to create directory: %v", err)
		}

		// Verify it was created
		fullPath := filepath.Join(tempDir, dirName)
		stat, err := os.Stat(fullPath)
		if err != nil {
			t.Errorf("Directory was not created: %v", err)
		}
		if stat != nil && !stat.IsDir() {
			t.Error("Created entry is not a directory")
		}
	})

	t.Run("create directory that already exists - should not error", func(t *testing.T) {
		dirName := "existing_dir_ok"
		fullPath := filepath.Join(tempDir, dirName)
		err := os.Mkdir(fullPath, 0755)
		if err != nil {
			t.Fatalf("Failed to pre-create directory: %v", err)
		}

		// Try to create again - should NOT fail
		err = MkdirAtExist(dirFile, dirName, 0755)
		if err != nil {
			t.Errorf("Should not error when directory already exists: %v", err)
		}
	})
}

// Test MkdirAllAtExist
func TestMkdirAllAtExist(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test_mkdirall_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dirFile, err := OpenExistingDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to open temp dir: %v", err)
	}
	defer dirFile.Close()

	testCases := []struct {
		name string
		path string
	}{
		{"simple path", "a/b/c"},
		{"deeper path", "x/y/z/w"},
		{"single level", "single"},
		{"with dots", "a/./b/../c"},
		{"absolute-like", "/a/b/c"}, // Should be treated as relative
		{"current dir", "."},
		{"root", "/"},
		{"empty", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := MkdirAllAtExist(dirFile, tc.path, 0755)
			if err != nil {
				t.Errorf("Failed to create directory path %s: %v", tc.path, err)
				return
			}

			// For non-trivial paths, verify they were created
			if tc.path != "" && tc.path != "." && tc.path != "/" {
				// Clean the path to see what we expect
				cleanPath := filepath.Clean(tc.path)
				if cleanPath != "." && cleanPath != "/" {
					fullPath := filepath.Join(tempDir, cleanPath)
					stat, err := os.Stat(fullPath)
					if err != nil {
						t.Errorf("Directory path %s was not created: %v", cleanPath, err)
					} else if !stat.IsDir() {
						t.Errorf("Path %s is not a directory", cleanPath)
					}
				}
			}
		})
	}

	t.Run("create existing path - should not error", func(t *testing.T) {
		path := "existing/path/structure"

		// Create it first
		err := MkdirAllAtExist(dirFile, path, 0755)
		if err != nil {
			t.Fatalf("Failed to create initial path: %v", err)
		}

		// Create again - should not error
		err = MkdirAllAtExist(dirFile, path, 0755)
		if err != nil {
			t.Errorf("Should not error when path already exists: %v", err)
		}
	})
}

// Test CreateAt
func TestCreateAt(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test_createat_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dirFile, err := OpenExistingDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to open temp dir: %v", err)
	}
	defer dirFile.Close()

	t.Run("create new file", func(t *testing.T) {
		fileName := "created_file.txt"
		file, err := CreateAt(dirFile, fileName)
		if err != nil {
			t.Errorf("Failed to create file: %v", err)
		}
		if file != nil {
			defer file.Close()

			// Write to it to verify it works
			content := "Hello from CreateAt"
			_, err := file.WriteString(content)
			if err != nil {
				t.Errorf("Failed to write to created file: %v", err)
			}

			// Verify file exists and has content
			fullPath := filepath.Join(tempDir, fileName)
			readContent, err := os.ReadFile(fullPath)
			if err != nil {
				t.Errorf("Failed to read created file: %v", err)
			}
			if string(readContent) != content {
				t.Errorf("Expected %s, got %s", content, string(readContent))
			}
		}
	})

	t.Run("create file that already exists - should truncate", func(t *testing.T) {
		fileName := "existing_file.txt"
		fullPath := filepath.Join(tempDir, fileName)

		// Create initial file with content
		err := os.WriteFile(fullPath, []byte("original content"), 0644)
		if err != nil {
			t.Fatalf("Failed to create initial file: %v", err)
		}

		// Create again with CreateAt - should truncate
		file, err := CreateAt(dirFile, fileName)
		if err != nil {
			t.Errorf("Failed to recreate file: %v", err)
		}
		if file != nil {
			defer file.Close()

			// Write new content
			newContent := "new content"
			_, err := file.WriteString(newContent)
			if err != nil {
				t.Errorf("Failed to write to recreated file: %v", err)
			}

			// Close and verify content was replaced
			file.Close()
			readContent, err := os.ReadFile(fullPath)
			if err != nil {
				t.Errorf("Failed to read recreated file: %v", err)
			}
			if string(readContent) != newContent {
				t.Errorf("Expected %s, got %s", newContent, string(readContent))
			}
		}
	})
}

// Test Dup
func TestDup(t *testing.T) {
	tempFile, err := os.CreateTemp("", "test_dup_*")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	t.Run("duplicate file descriptor", func(t *testing.T) {
		// Write some content to original file
		content := "test content for dup"
		_, err := tempFile.WriteString(content)
		if err != nil {
			t.Fatalf("Failed to write to original file: %v", err)
		}

		// Duplicate the file descriptor
		dupFile, err := Dup(tempFile)
		if err != nil {
			t.Errorf("Failed to duplicate file descriptor: %v", err)
		}
		if dupFile != nil {
			defer dupFile.Close()

			// Both should refer to the same file
			if dupFile.Name() != tempFile.Name() {
				t.Errorf("Duplicated file should have same name: %s vs %s",
					dupFile.Name(), tempFile.Name())
			}

			// Seek to beginning and read from duplicate
			_, err := dupFile.Seek(0, 0)
			if err != nil {
				t.Errorf("Failed to seek in duplicated file: %v", err)
			}

			readContent, err := io.ReadAll(dupFile)
			if err != nil {
				t.Errorf("Failed to read from duplicated file: %v", err)
			}

			if string(readContent) != content {
				t.Errorf("Expected %s, got %s", content, string(readContent))
			}
		}
	})
}

// Test RenameAt
func TestRenameAt(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test_renameat_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dirFile, err := OpenExistingDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to open temp dir: %v", err)
	}
	defer dirFile.Close()

	t.Run("rename file", func(t *testing.T) {
		// Create a file to rename
		oldName := "old_name.txt"
		newName := "new_name.txt"
		content := "rename me"

		oldPath := filepath.Join(tempDir, oldName)
		newPath := filepath.Join(tempDir, newName)

		err := os.WriteFile(oldPath, []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		// Rename it
		err = RenameAt(dirFile, oldName, dirFile, newName)
		if err != nil {
			t.Errorf("Failed to rename file: %v", err)
		}

		// Verify old name doesn't exist
		_, err = os.Stat(oldPath)
		if !os.IsNotExist(err) {
			t.Error("Old file should not exist after rename")
		}

		// Verify new name exists with correct content
		readContent, err := os.ReadFile(newPath)
		if err != nil {
			t.Errorf("Failed to read renamed file: %v", err)
		}
		if string(readContent) != content {
			t.Errorf("Expected %s, got %s", content, string(readContent))
		}
	})

	t.Run("rename to different directory", func(t *testing.T) {
		// Create source file and destination directory
		srcName := "source.txt"
		srcPath := filepath.Join(tempDir, srcName)
		err := os.WriteFile(srcPath, []byte("move me"), 0644)
		if err != nil {
			t.Fatalf("Failed to create source file: %v", err)
		}

		destDir := filepath.Join(tempDir, "dest_dir")
		err = os.Mkdir(destDir, 0755)
		if err != nil {
			t.Fatalf("Failed to create dest directory: %v", err)
		}

		destDirFile, err := OpenExistingDir(destDir)
		if err != nil {
			t.Fatalf("Failed to open dest directory: %v", err)
		}
		defer destDirFile.Close()

		destName := "destination.txt"
		destPath := filepath.Join(destDir, destName)

		// Rename across directories
		err = RenameAt(dirFile, srcName, destDirFile, destName)
		if err != nil {
			t.Errorf("Failed to rename across directories: %v", err)
		}

		// Verify source is gone
		_, err = os.Stat(srcPath)
		if !os.IsNotExist(err) {
			t.Error("Source file should not exist after rename")
		}

		// Verify destination exists
		_, err = os.Stat(destPath)
		if err != nil {
			t.Errorf("Destination file should exist: %v", err)
		}
	})
}

// Test CopyRegularFileByPath
func TestCopyRegularFileByPath(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test_copy_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	t.Run("copy regular file", func(t *testing.T) {
		// Create source file
		srcPath := filepath.Join(tempDir, "source.txt")
		content := "copy this content"
		err := os.WriteFile(srcPath, []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to create source file: %v", err)
		}

		dstPath := filepath.Join(tempDir, "destination.txt")

		// Copy the file
		err = CopyRegularFileByPath(srcPath, dstPath)
		if err != nil {
			t.Errorf("Failed to copy file: %v", err)
		}

		// Verify destination exists and has same content
		readContent, err := os.ReadFile(dstPath)
		if err != nil {
			t.Errorf("Failed to read destination file: %v", err)
		}
		if string(readContent) != content {
			t.Errorf("Expected %s, got %s", content, string(readContent))
		}

		// Verify source still exists
		_, err = os.Stat(srcPath)
		if err != nil {
			t.Errorf("Source file should still exist: %v", err)
		}
	})

	t.Run("copy non-existing file", func(t *testing.T) {
		srcPath := filepath.Join(tempDir, "does_not_exist.txt")
		dstPath := filepath.Join(tempDir, "destination2.txt")

		err := CopyRegularFileByPath(srcPath, dstPath)
		if err == nil {
			t.Error("Expected error when copying non-existing file")
		}
	})

	t.Run("copy directory - should fail", func(t *testing.T) {
		srcDir := filepath.Join(tempDir, "source_dir")
		err := os.Mkdir(srcDir, 0755)
		if err != nil {
			t.Fatalf("Failed to create source directory: %v", err)
		}

		dstPath := filepath.Join(tempDir, "destination3.txt")

		err = CopyRegularFileByPath(srcDir, dstPath)
		if err == nil {
			t.Error("Expected error when copying directory as regular file")
		}
		if !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("Expected 'not a regular file' error, got: %v", err)
		}
	})

	t.Run("copy large file", func(t *testing.T) {
		// Create a larger file to test io.Copy
		srcPath := filepath.Join(tempDir, "large_source.txt")
		content := strings.Repeat("large file content\n", 1000)
		err := os.WriteFile(srcPath, []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to create large source file: %v", err)
		}

		dstPath := filepath.Join(tempDir, "large_destination.txt")

		err = CopyRegularFileByPath(srcPath, dstPath)
		if err != nil {
			t.Errorf("Failed to copy large file: %v", err)
		}

		// Verify sizes match
		srcInfo, err := os.Stat(srcPath)
		if err != nil {
			t.Fatalf("Failed to stat source: %v", err)
		}
		dstInfo, err := os.Stat(dstPath)
		if err != nil {
			t.Errorf("Failed to stat destination: %v", err)
		}

		if srcInfo.Size() != dstInfo.Size() {
			t.Errorf("File sizes don't match: src=%d, dst=%d", srcInfo.Size(), dstInfo.Size())
		}
	})
}

// Test CopyRegularFileByRelativePath
func TestCopyRegularFileByRelativePath(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test_copy_rel_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create destination directory
	destDir := filepath.Join(tempDir, "dest")
	err = os.Mkdir(destDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create dest directory: %v", err)
	}

	destDirFile, err := OpenExistingDir(destDir)
	if err != nil {
		t.Fatalf("Failed to open dest directory: %v", err)
	}
	defer destDirFile.Close()

	t.Run("copy regular file to relative path", func(t *testing.T) {
		// Create source file
		srcPath := filepath.Join(tempDir, "rel_source.txt")
		content := "relative copy content"
		err := os.WriteFile(srcPath, []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to create source file: %v", err)
		}

		dstName := "rel_destination.txt"
		dstPath := filepath.Join(destDir, dstName)

		// Copy the file
		err = CopyRegularFileByRelativePath(srcPath, destDirFile, dstName)
		if err != nil {
			t.Errorf("Failed to copy file by relative path: %v", err)
		}

		// Verify destination exists and has same content
		readContent, err := os.ReadFile(dstPath)
		if err != nil {
			t.Errorf("Failed to read destination file: %v", err)
		}
		if string(readContent) != content {
			t.Errorf("Expected %s, got %s", content, string(readContent))
		}
	})

	t.Run("copy non-regular file - should fail", func(t *testing.T) {
		srcDir := filepath.Join(tempDir, "rel_source_dir")
		err := os.Mkdir(srcDir, 0755)
		if err != nil {
			t.Fatalf("Failed to create source directory: %v", err)
		}

		err = CopyRegularFileByRelativePath(srcDir, destDirFile, "should_fail.txt")
		if err == nil {
			t.Error("Expected error when copying directory as regular file")
		}
		if !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("Expected 'not a regular file' error, got: %v", err)
		}
	})
}

// Test IsDirEmpty
func TestIsDirEmpty(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test_isdirempty_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	t.Run("empty directory", func(t *testing.T) {
		emptyDir := filepath.Join(tempDir, "empty")
		err := os.Mkdir(emptyDir, 0755)
		if err != nil {
			t.Fatalf("Failed to create empty directory: %v", err)
		}

		isEmpty, err := IsDirEmpty(emptyDir)
		if err != nil {
			t.Errorf("Failed to check if directory is empty: %v", err)
		}
		if !isEmpty {
			t.Error("Expected directory to be empty")
		}
	})

	t.Run("non-empty directory", func(t *testing.T) {
		nonEmptyDir := filepath.Join(tempDir, "non_empty")
		err := os.Mkdir(nonEmptyDir, 0755)
		if err != nil {
			t.Fatalf("Failed to create non-empty directory: %v", err)
		}

		// Add a file to make it non-empty
		testFile := filepath.Join(nonEmptyDir, "file.txt")
		err = os.WriteFile(testFile, []byte("content"), 0644)
		if err != nil {
			t.Fatalf("Failed to create file in directory: %v", err)
		}

		isEmpty, err := IsDirEmpty(nonEmptyDir)
		if err != nil {
			t.Errorf("Failed to check if directory is empty: %v", err)
		}
		if isEmpty {
			t.Error("Expected directory to be non-empty")
		}
	})

	t.Run("non-existing directory", func(t *testing.T) {
		_, err := IsDirEmpty("/path/that/does/not/exist")
		if err == nil {
			t.Error("Expected error when checking non-existing directory")
		}
	})

	t.Run("file instead of directory", func(t *testing.T) {
		testFile := filepath.Join(tempDir, "not_a_dir.txt")
		err := os.WriteFile(testFile, []byte("content"), 0644)
		if err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		_, err = IsDirEmpty(testFile)
		if err == nil {
			t.Error("Expected error when checking file as directory")
		}
	})
}
