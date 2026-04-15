package fileutil

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewProtectedReader(t *testing.T) {
	data := []byte("test data")
	reader := NewProtectedReader(data)

	if reader == nil {
		t.Fatal("NewProtectedReader returned nil")
	}

	var _ io.ReaderAt = reader
}

func TestProtectedReader_NormalOperation(t *testing.T) {
	data := []byte("hello world")
	protectedReader := NewProtectedReader(data)
	standardReader := bytes.NewReader(data)

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

func TestOpenRootDir(t *testing.T) {
	t.Run("open existing directory", func(t *testing.T) {
		tempDir := t.TempDir()

		root, err := OpenRootDir(tempDir)
		if err != nil {
			t.Fatalf("Failed to open existing directory: %v", err)
		}
		defer root.Close()

		if root.Name() != tempDir {
			t.Errorf("Expected root name %s, got %s", tempDir, root.Name())
		}
	})

	t.Run("open non-existing directory", func(t *testing.T) {
		_, err := OpenRootDir("/path/that/does/not/exist")
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

		_, err = OpenRootDir(tempFile.Name())
		if err == nil {
			t.Error("Expected error when opening file as directory")
		}
	})
}

func TestOpenAt(t *testing.T) {
	tempDir := t.TempDir()

	root, err := OpenRootDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to open root dir: %v", err)
	}
	defer root.Close()

	t.Run("create new file", func(t *testing.T) {
		file, err := OpenAt(root, "newfile.txt", os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			t.Fatalf("Failed to create file with OpenAt: %v", err)
		}
		defer file.Close()

		_, err = file.WriteString("test content")
		if err != nil {
			t.Errorf("Failed to write to file: %v", err)
		}
	})

	t.Run("open existing file", func(t *testing.T) {
		testFile := filepath.Join(tempDir, "existing.txt")
		if err := os.WriteFile(testFile, []byte("existing content"), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		file, err := OpenAt(root, "existing.txt", os.O_RDONLY, 0)
		if err != nil {
			t.Fatalf("Failed to open existing file: %v", err)
		}
		defer file.Close()

		content, err := io.ReadAll(file)
		if err != nil {
			t.Errorf("Failed to read file: %v", err)
		}
		if string(content) != "existing content" {
			t.Errorf("Expected 'existing content', got %s", string(content))
		}
	})
}

func TestRemoveAt(t *testing.T) {
	tempDir := t.TempDir()

	root, err := OpenRootDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to open root dir: %v", err)
	}
	defer root.Close()

	t.Run("remove file", func(t *testing.T) {
		testFile := "remove_me.txt"
		fullPath := filepath.Join(tempDir, testFile)
		if err := os.WriteFile(fullPath, []byte("delete me"), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		if err := RemoveAt(root, testFile, 0); err != nil {
			t.Errorf("Failed to remove file: %v", err)
		}

		if _, err := os.Stat(fullPath); !os.IsNotExist(err) {
			t.Error("File should have been removed")
		}
	})

	t.Run("remove directory", func(t *testing.T) {
		testDirName := "remove_dir"
		fullPath := filepath.Join(tempDir, testDirName)
		if err := os.Mkdir(fullPath, 0755); err != nil {
			t.Fatalf("Failed to create test dir: %v", err)
		}

		if err := RemoveAt(root, testDirName, 0); err != nil {
			t.Errorf("Failed to remove directory: %v", err)
		}

		if _, err := os.Stat(fullPath); !os.IsNotExist(err) {
			t.Error("Directory should have been removed")
		}
	})

	t.Run("remove non-existing file", func(t *testing.T) {
		if err := RemoveAt(root, "does_not_exist.txt", 0); err == nil {
			t.Error("Expected error when removing non-existing file")
		}
	})
}

func TestMkdirAtExist(t *testing.T) {
	tempDir := t.TempDir()

	root, err := OpenRootDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to open root dir: %v", err)
	}
	defer root.Close()

	t.Run("create new directory", func(t *testing.T) {
		dirName := "new_dir_exist"
		if err := MkdirAtExist(root, dirName, 0755); err != nil {
			t.Errorf("Failed to create directory: %v", err)
		}

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
		if err := os.Mkdir(fullPath, 0755); err != nil {
			t.Fatalf("Failed to pre-create directory: %v", err)
		}

		if err := MkdirAtExist(root, dirName, 0755); err != nil {
			t.Errorf("Should not error when directory already exists: %v", err)
		}
	})
}

func TestMkdirAllAtExist(t *testing.T) {
	tempDir := t.TempDir()

	root, err := OpenRootDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to open root dir: %v", err)
	}
	defer root.Close()

	testCases := []struct {
		name string
		path string
	}{
		{"simple path", "a/b/c"},
		{"deeper path", "x/y/z/w"},
		{"single level", "single"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := MkdirAllAtExist(root, tc.path, 0755); err != nil {
				t.Errorf("Failed to create directory path %s: %v", tc.path, err)
				return
			}

			fullPath := filepath.Join(tempDir, tc.path)
			stat, err := os.Stat(fullPath)
			if err != nil {
				t.Errorf("Directory path %s was not created: %v", tc.path, err)
			} else if !stat.IsDir() {
				t.Errorf("Path %s is not a directory", tc.path)
			}
		})
	}

	t.Run("create existing path - should not error", func(t *testing.T) {
		p := "existing/path/structure"

		if err := MkdirAllAtExist(root, p, 0755); err != nil {
			t.Fatalf("Failed to create initial path: %v", err)
		}

		if err := MkdirAllAtExist(root, p, 0755); err != nil {
			t.Errorf("Should not error when path already exists: %v", err)
		}
	})
}

func TestCreateAt(t *testing.T) {
	tempDir := t.TempDir()

	root, err := OpenRootDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to open root dir: %v", err)
	}
	defer root.Close()

	t.Run("create new file", func(t *testing.T) {
		fileName := "created_file.txt"
		file, err := CreateAt(root, fileName)
		if err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}
		defer file.Close()

		content := "Hello from CreateAt"
		if _, err := file.WriteString(content); err != nil {
			t.Errorf("Failed to write to created file: %v", err)
		}

		fullPath := filepath.Join(tempDir, fileName)
		readContent, err := os.ReadFile(fullPath)
		if err != nil {
			t.Errorf("Failed to read created file: %v", err)
		}
		if string(readContent) != content {
			t.Errorf("Expected %s, got %s", content, string(readContent))
		}
	})

	t.Run("create file that already exists - should truncate", func(t *testing.T) {
		fileName := "existing_file.txt"
		fullPath := filepath.Join(tempDir, fileName)

		if err := os.WriteFile(fullPath, []byte("original content"), 0644); err != nil {
			t.Fatalf("Failed to create initial file: %v", err)
		}

		file, err := CreateAt(root, fileName)
		if err != nil {
			t.Fatalf("Failed to recreate file: %v", err)
		}

		newContent := "new content"
		if _, err := file.WriteString(newContent); err != nil {
			t.Errorf("Failed to write to recreated file: %v", err)
		}
		file.Close()

		readContent, err := os.ReadFile(fullPath)
		if err != nil {
			t.Errorf("Failed to read recreated file: %v", err)
		}
		if string(readContent) != newContent {
			t.Errorf("Expected %s, got %s", newContent, string(readContent))
		}
	})
}

func TestDup(t *testing.T) {
	tempFile, err := os.CreateTemp("", "test_dup_*")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	t.Run("duplicate file descriptor", func(t *testing.T) {
		content := "test content for dup"
		if _, err := tempFile.WriteString(content); err != nil {
			t.Fatalf("Failed to write to original file: %v", err)
		}

		dupFile, err := Dup(tempFile)
		if err != nil {
			t.Fatalf("Failed to duplicate file descriptor: %v", err)
		}
		defer dupFile.Close()

		if dupFile.Name() != tempFile.Name() {
			t.Errorf("Duplicated file should have same name: %s vs %s",
				dupFile.Name(), tempFile.Name())
		}

		if _, err := dupFile.Seek(0, 0); err != nil {
			t.Errorf("Failed to seek in duplicated file: %v", err)
		}

		readContent, err := io.ReadAll(dupFile)
		if err != nil {
			t.Errorf("Failed to read from duplicated file: %v", err)
		}

		if string(readContent) != content {
			t.Errorf("Expected %s, got %s", content, string(readContent))
		}
	})
}

func TestRenameAt(t *testing.T) {
	tempDir := t.TempDir()

	root, err := OpenRootDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to open root dir: %v", err)
	}
	defer root.Close()

	t.Run("rename file", func(t *testing.T) {
		oldName := "old_name.txt"
		newName := "new_name.txt"
		content := "rename me"

		oldPath := filepath.Join(tempDir, oldName)
		newPath := filepath.Join(tempDir, newName)

		if err := os.WriteFile(oldPath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		if err := RenameAt(root, oldName, newName); err != nil {
			t.Errorf("Failed to rename file: %v", err)
		}

		if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
			t.Error("Old file should not exist after rename")
		}

		readContent, err := os.ReadFile(newPath)
		if err != nil {
			t.Errorf("Failed to read renamed file: %v", err)
		}
		if string(readContent) != content {
			t.Errorf("Expected %s, got %s", content, string(readContent))
		}
	})

	t.Run("rename to subdirectory", func(t *testing.T) {
		srcName := "source.txt"
		srcPath := filepath.Join(tempDir, srcName)
		if err := os.WriteFile(srcPath, []byte("move me"), 0644); err != nil {
			t.Fatalf("Failed to create source file: %v", err)
		}

		destSubDir := filepath.Join(tempDir, "dest_dir")
		if err := os.Mkdir(destSubDir, 0755); err != nil {
			t.Fatalf("Failed to create dest directory: %v", err)
		}

		destRelPath := "dest_dir/destination.txt"
		destPath := filepath.Join(tempDir, destRelPath)

		if err := RenameAt(root, srcName, destRelPath); err != nil {
			t.Errorf("Failed to rename to subdirectory: %v", err)
		}

		if _, err := os.Stat(srcPath); !os.IsNotExist(err) {
			t.Error("Source file should not exist after rename")
		}

		if _, err := os.Stat(destPath); err != nil {
			t.Errorf("Destination file should exist: %v", err)
		}
	})
}

func TestCopyRegularFileByPath(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("copy regular file", func(t *testing.T) {
		srcPath := filepath.Join(tempDir, "source.txt")
		content := "copy this content"
		if err := os.WriteFile(srcPath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create source file: %v", err)
		}

		dstPath := filepath.Join(tempDir, "destination.txt")

		if err := CopyRegularFileByPath(srcPath, dstPath); err != nil {
			t.Errorf("Failed to copy file: %v", err)
		}

		readContent, err := os.ReadFile(dstPath)
		if err != nil {
			t.Errorf("Failed to read destination file: %v", err)
		}
		if string(readContent) != content {
			t.Errorf("Expected %s, got %s", content, string(readContent))
		}
	})

	t.Run("copy non-existing file", func(t *testing.T) {
		srcPath := filepath.Join(tempDir, "does_not_exist.txt")
		dstPath := filepath.Join(tempDir, "destination2.txt")

		if err := CopyRegularFileByPath(srcPath, dstPath); err == nil {
			t.Error("Expected error when copying non-existing file")
		}
	})

	t.Run("copy directory - should fail", func(t *testing.T) {
		srcDir := filepath.Join(tempDir, "source_dir")
		if err := os.Mkdir(srcDir, 0755); err != nil {
			t.Fatalf("Failed to create source directory: %v", err)
		}

		dstPath := filepath.Join(tempDir, "destination3.txt")

		err := CopyRegularFileByPath(srcDir, dstPath)
		if err == nil {
			t.Error("Expected error when copying directory as regular file")
		}
		if !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("Expected 'not a regular file' error, got: %v", err)
		}
	})

	t.Run("copy large file", func(t *testing.T) {
		srcPath := filepath.Join(tempDir, "large_source.txt")
		content := strings.Repeat("large file content\n", 1000)
		if err := os.WriteFile(srcPath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create large source file: %v", err)
		}

		dstPath := filepath.Join(tempDir, "large_destination.txt")

		if err := CopyRegularFileByPath(srcPath, dstPath); err != nil {
			t.Errorf("Failed to copy large file: %v", err)
		}

		srcInfo, _ := os.Stat(srcPath)
		dstInfo, err := os.Stat(dstPath)
		if err != nil {
			t.Errorf("Failed to stat destination: %v", err)
		}

		if srcInfo.Size() != dstInfo.Size() {
			t.Errorf("File sizes don't match: src=%d, dst=%d", srcInfo.Size(), dstInfo.Size())
		}
	})
}

func TestCopyRegularFileByRelativePath(t *testing.T) {
	tempDir := t.TempDir()

	destDir := filepath.Join(tempDir, "dest")
	if err := os.Mkdir(destDir, 0755); err != nil {
		t.Fatalf("Failed to create dest directory: %v", err)
	}

	destRoot, err := OpenRootDir(destDir)
	if err != nil {
		t.Fatalf("Failed to open dest directory: %v", err)
	}
	defer destRoot.Close()

	t.Run("copy regular file to relative path", func(t *testing.T) {
		srcPath := filepath.Join(tempDir, "rel_source.txt")
		content := "relative copy content"
		if err := os.WriteFile(srcPath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create source file: %v", err)
		}

		dstName := "rel_destination.txt"
		dstPath := filepath.Join(destDir, dstName)

		if err := CopyRegularFileByRelativePath(srcPath, destRoot, dstName); err != nil {
			t.Errorf("Failed to copy file by relative path: %v", err)
		}

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
		if err := os.Mkdir(srcDir, 0755); err != nil {
			t.Fatalf("Failed to create source directory: %v", err)
		}

		err := CopyRegularFileByRelativePath(srcDir, destRoot, "should_fail.txt")
		if err == nil {
			t.Error("Expected error when copying directory as regular file")
		}
		if !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("Expected 'not a regular file' error, got: %v", err)
		}
	})
}

func TestIsRegularFile(t *testing.T) {
	tempDir := t.TempDir()

	regularFile := filepath.Join(tempDir, "regular.txt")
	if err := os.WriteFile(regularFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	testDir := filepath.Join(tempDir, "testdir")
	if err := os.Mkdir(testDir, 0755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	tests := []struct {
		name        string
		path        string
		expectedRes bool
	}{
		{"regular file", regularFile, true},
		{"directory", testDir, false},
		{"non-existent file", filepath.Join(tempDir, "nonexistent.txt"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := IsRegularFile(tt.path)
			if err != nil {
				t.Errorf("IsRegularFile(%q) unexpected error: %v", tt.path, err)
				return
			}
			if result != tt.expectedRes {
				t.Errorf("IsRegularFile(%q) = %v, want %v", tt.path, result, tt.expectedRes)
			}
		})
	}
}

func TestIsDirEmpty(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("empty directory", func(t *testing.T) {
		emptyDir := filepath.Join(tempDir, "empty")
		if err := os.Mkdir(emptyDir, 0755); err != nil {
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
		if err := os.Mkdir(nonEmptyDir, 0755); err != nil {
			t.Fatalf("Failed to create non-empty directory: %v", err)
		}
		testFile := filepath.Join(nonEmptyDir, "file.txt")
		if err := os.WriteFile(testFile, []byte("content"), 0644); err != nil {
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
		if _, err := IsDirEmpty("/path/that/does/not/exist"); err == nil {
			t.Error("Expected error when checking non-existing directory")
		}
	})

	t.Run("file instead of directory", func(t *testing.T) {
		testFile := filepath.Join(tempDir, "not_a_dir.txt")
		if err := os.WriteFile(testFile, []byte("content"), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		if _, err := IsDirEmpty(testFile); err == nil {
			t.Error("Expected error when checking file as directory")
		}
	})
}

// --- SafeOpenFile and SafeRemoveAll tests ---

func TestSafeOpenFile(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("open regular file", func(t *testing.T) {
		p := filepath.Join(tempDir, "regular.txt")
		if err := os.WriteFile(p, []byte("data"), 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}

		f, err := SafeOpenFile(p, os.O_RDONLY, 0)
		if err != nil {
			t.Fatalf("SafeOpenFile should open regular file: %v", err)
		}
		f.Close()
	})

	t.Run("create new file", func(t *testing.T) {
		p := filepath.Join(tempDir, "new.txt")

		f, err := SafeOpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			t.Fatalf("SafeOpenFile should create file: %v", err)
		}
		f.Close()

		if _, err := os.Stat(p); err != nil {
			t.Errorf("File should exist: %v", err)
		}
	})

	t.Run("reject symlink", func(t *testing.T) {
		real := filepath.Join(tempDir, "real_safe.txt")
		if err := os.WriteFile(real, []byte("secret"), 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}
		link := filepath.Join(tempDir, "link_safe.txt")
		if err := os.Symlink(real, link); err != nil {
			t.Fatalf("Failed to create symlink: %v", err)
		}

		_, err := SafeOpenFile(link, os.O_RDONLY, 0)
		if err == nil {
			t.Fatal("SafeOpenFile should reject symlink")
		}
	})
}

func TestSafeRemoveAll(t *testing.T) {
	t.Run("remove real directory", func(t *testing.T) {
		tempDir := t.TempDir()
		target := filepath.Join(tempDir, "removeme")
		if err := os.MkdirAll(filepath.Join(target, "sub"), 0755); err != nil {
			t.Fatalf("Failed to create dirs: %v", err)
		}
		if err := os.WriteFile(filepath.Join(target, "sub", "f.txt"), []byte("x"), 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}

		if err := SafeRemoveAll(target); err != nil {
			t.Fatalf("SafeRemoveAll should remove real dir: %v", err)
		}

		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Error("Directory should have been removed")
		}
	})

	t.Run("reject symlink", func(t *testing.T) {
		tempDir := t.TempDir()
		realDir := filepath.Join(tempDir, "real_dir")
		if err := os.Mkdir(realDir, 0755); err != nil {
			t.Fatalf("Failed to create dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(realDir, "precious.txt"), []byte("keep"), 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}

		symDir := filepath.Join(tempDir, "sym_dir")
		if err := os.Symlink(realDir, symDir); err != nil {
			t.Fatalf("Failed to create symlink: %v", err)
		}

		if err := SafeRemoveAll(symDir); err == nil {
			t.Fatal("SafeRemoveAll should reject symlink")
		}

		if _, err := os.Stat(filepath.Join(realDir, "precious.txt")); err != nil {
			t.Fatal("Real directory contents should not have been deleted")
		}
	})

	t.Run("non-existent path is no-op", func(t *testing.T) {
		if err := SafeRemoveAll("/path/that/does/not/exist"); err != nil {
			t.Errorf("SafeRemoveAll should silently succeed for non-existent path: %v", err)
		}
	})
}

// --- Symlink and path traversal security tests ---

func TestOpenRootDir_RejectsSymlink(t *testing.T) {
	tempDir := t.TempDir()

	realDir := filepath.Join(tempDir, "real")
	if err := os.Mkdir(realDir, 0755); err != nil {
		t.Fatalf("Failed to create real dir: %v", err)
	}

	symDir := filepath.Join(tempDir, "sym")
	if err := os.Symlink(realDir, symDir); err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	_, err := OpenRootDir(symDir)
	if err == nil {
		t.Fatal("OpenRootDir should reject a symlinked directory")
	}
}

func TestOpenAt_AllowsIntraRootSymlink(t *testing.T) {
	tempDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tempDir, "real.txt"), []byte("safe"), 0644); err != nil {
		t.Fatalf("Failed to create real file: %v", err)
	}
	if err := os.Symlink("real.txt", filepath.Join(tempDir, "link.txt")); err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	root, err := os.OpenRoot(tempDir)
	if err != nil {
		t.Fatalf("Failed to open root: %v", err)
	}
	defer root.Close()

	f, err := OpenAt(root, "link.txt", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenAt should allow intra-root symlinks: %v", err)
	}
	f.Close()
}

func TestOpenAt_RejectsEscapingSymlink(t *testing.T) {
	tempDir := t.TempDir()

	if err := os.Symlink("/etc/hostname", filepath.Join(tempDir, "escape.txt")); err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	root, err := os.OpenRoot(tempDir)
	if err != nil {
		t.Fatalf("Failed to open root: %v", err)
	}
	defer root.Close()

	_, err = OpenAt(root, "escape.txt", os.O_RDONLY, 0)
	if err == nil {
		t.Fatal("OpenAt should reject symlink that escapes the root")
	}
}

func TestOpenAt_RejectsPathTraversal(t *testing.T) {
	tempDir := t.TempDir()

	root, err := os.OpenRoot(tempDir)
	if err != nil {
		t.Fatalf("Failed to open root: %v", err)
	}
	defer root.Close()

	traversalPaths := []string{
		"../etc/passwd",
		"..",
		"/etc/passwd",
		"a/../../etc/passwd",
	}

	for _, p := range traversalPaths {
		t.Run(p, func(t *testing.T) {
			if _, err := OpenAt(root, p, os.O_RDONLY, 0); err == nil {
				t.Errorf("OpenAt should reject path traversal %q", p)
			}
		})
	}
}

func TestCreateAt_RejectsEscapingSymlink(t *testing.T) {
	tempDir := t.TempDir()

	victim, err := os.CreateTemp("", "victim_*.txt")
	if err != nil {
		t.Fatalf("Failed to create victim file: %v", err)
	}
	if _, err := victim.WriteString("ORIGINAL"); err != nil {
		t.Fatalf("Failed to write victim: %v", err)
	}
	victim.Close()
	defer os.Remove(victim.Name())

	if err := os.Symlink(victim.Name(), filepath.Join(tempDir, "trap.txt")); err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	root, err := os.OpenRoot(tempDir)
	if err != nil {
		t.Fatalf("Failed to open root: %v", err)
	}
	defer root.Close()

	if _, err := CreateAt(root, "trap.txt"); err == nil {
		t.Fatal("CreateAt should reject symlink escaping the root")
	}

	content, err := os.ReadFile(victim.Name())
	if err != nil {
		t.Fatalf("Failed to read victim: %v", err)
	}
	if string(content) != "ORIGINAL" {
		t.Fatalf("Victim file was modified: %s", content)
	}
}

func TestMkdirAtExist_RejectsTraversal(t *testing.T) {
	tempDir := t.TempDir()

	root, err := OpenRootDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to open root dir: %v", err)
	}
	defer root.Close()

	if err := MkdirAtExist(root, "../escape", 0755); err == nil {
		t.Fatal("MkdirAtExist should reject path traversal")
	}

	if err := MkdirAtExist(root, "/absolute", 0755); err == nil {
		t.Fatal("MkdirAtExist should reject absolute path")
	}
}

func TestMkdirAllAtExist_RejectsTraversal(t *testing.T) {
	tempDir := t.TempDir()

	root, err := OpenRootDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to open root dir: %v", err)
	}
	defer root.Close()

	if err := MkdirAllAtExist(root, "../escape/deep", 0755); err == nil {
		t.Fatal("MkdirAllAtExist should reject path traversal")
	}

	if err := MkdirAllAtExist(root, "a/../../escape", 0755); err == nil {
		t.Fatal("MkdirAllAtExist should reject path that escapes via ..")
	}
}

func TestOpenAt_EscapingSymlinkedSubdirectory(t *testing.T) {
	tempDir := t.TempDir()

	if err := os.Symlink("/tmp", filepath.Join(tempDir, "escape_sub")); err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	root, err := os.OpenRoot(tempDir)
	if err != nil {
		t.Fatalf("Failed to open root: %v", err)
	}
	defer root.Close()

	_, err = OpenAt(root, "escape_sub/some_file", os.O_RDONLY, 0)
	if err == nil {
		t.Fatal("OpenAt should reject path through a symlink that escapes the root")
	}
}
