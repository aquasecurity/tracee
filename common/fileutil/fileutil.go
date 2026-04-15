package fileutil

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"runtime/debug"

	"golang.org/x/sys/unix"

	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
)

// OpenRootDir opens a directory as an os.Root, providing traversal-resistant
// file operations. All file access through the returned Root is confined to
// the directory tree: symlinks that escape the root and ".." traversals are
// rejected. O_NOFOLLOW is applied to the initial open so that if p itself is
// a symlink, the call fails with ELOOP.
func OpenRootDir(p string) (*os.Root, error) {
	fd, err := unix.Open(p, unix.O_DIRECTORY|unix.O_PATH|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	_ = unix.Close(fd)

	return os.OpenRoot(p)
}

// OpenAt opens a file relative to root with the given flags and permissions.
// The operation is traversal-resistant: symlinks that escape root and ".."
// path components that would leave the tree are rejected by os.Root.
func OpenAt(root *os.Root, relativePath string, flags int, perm fs.FileMode) (*os.File, error) {
	f, err := root.OpenFile(relativePath, flags, perm)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	return f, nil
}

// CreateAt creates or truncates a file relative to root.
func CreateAt(root *os.Root, relativePath string) (*os.File, error) {
	f, err := root.Create(relativePath)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	return f, nil
}

// RemoveAt removes a file or (empty) directory relative to root.
// The flags parameter is accepted for API compatibility but is unused;
// os.Root.Remove handles both files and empty directories.
func RemoveAt(root *os.Root, relativePath string, _ int) error {
	return root.Remove(relativePath)
}

// MkdirAtExist creates a directory relative to root, ignoring "already exists"
// errors.
func MkdirAtExist(root *os.Root, relativePath string, perm fs.FileMode) error {
	err := root.Mkdir(relativePath, perm)
	if err != nil && !errors.Is(err, fs.ErrExist) {
		return errfmt.WrapError(err)
	}
	return nil
}

// MkdirAllAtExist recursively creates a directory and all necessary parents
// relative to root, ignoring "already exists" errors.
func MkdirAllAtExist(root *os.Root, relativePath string, perm fs.FileMode) error {
	err := root.MkdirAll(relativePath, perm)
	if err != nil {
		return errfmt.WrapError(err)
	}
	return nil
}

// RenameAt renames a file within a root directory.
func RenameAt(root *os.Root, oldpath string, newpath string) error {
	return root.Rename(oldpath, newpath)
}

// Dup is a wrapper function to the dup syscall using golang types.
func Dup(file *os.File) (*os.File, error) {
	newFD, err := unix.Dup(int(file.Fd()))
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	return os.NewFile(uintptr(newFD), file.Name()), nil
}

// CopyRegularFileByPath copies a file from src to dst
func CopyRegularFileByPath(src, dst string) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return errfmt.WrapError(err)
	}
	if !sourceFileStat.Mode().IsRegular() {
		return errfmt.Errorf("%s is not a regular file", src)
	}
	source, err := os.Open(src)
	if err != nil {
		return errfmt.WrapError(err)
	}
	defer func() {
		if err := source.Close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}()
	destination, err := os.Create(dst)
	if err != nil {
		return errfmt.WrapError(err)
	}
	defer func() {
		if err := destination.Close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}()
	_, err = io.Copy(destination, source)
	if err != nil {
		return errfmt.WrapError(err)
	}
	return nil
}

// CopyRegularFileByRelativePath copies a file from src to dst, where
// destination is relative to a given root directory. This function needs
// capabilities to be set before it is called.
func CopyRegularFileByRelativePath(srcName string, dstRoot *os.Root, dstName string) error {
	sourceFileStat, err := os.Stat(srcName)
	if err != nil {
		return errfmt.WrapError(err)
	}
	if !sourceFileStat.Mode().IsRegular() {
		return errfmt.Errorf("%s is not a regular file", srcName)
	}
	source, err := os.Open(srcName)
	if err != nil {
		return errfmt.WrapError(err)
	}
	defer func() {
		if err := source.Close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}()
	destination, err := CreateAt(dstRoot, dstName)
	if err != nil {
		return errfmt.WrapError(err)
	}
	defer func() {
		if err := destination.Close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}()
	_, err = io.Copy(destination, source)
	if err != nil {
		return errfmt.WrapError(err)
	}
	return nil
}

// IsRegularFile checks if the given file name points to a regular file
func IsRegularFile(name string) (bool, error) {
	info, err := os.Stat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}

		return false, errfmt.WrapError(err)
	}

	return info.Mode().IsRegular(), nil
}

// IsDirEmpty returns true if directory contains no files
func IsDirEmpty(pathname string) (bool, error) {
	dir, err := os.Open(pathname)
	if err != nil {
		return false, errfmt.WrapError(err)
	}
	defer func() {
		if err := dir.Close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}()

	_, err = dir.Readdirnames(1)
	if err == io.EOF {
		return true, nil
	}

	return false, errfmt.WrapError(err)
}

// SafeOpenFile opens a file with O_NOFOLLOW, refusing to follow a symlink at
// the final path component. Use this for absolute or user-supplied paths that
// are not under an os.Root context.
func SafeOpenFile(path string, flag int, perm os.FileMode) (*os.File, error) {
	f, err := os.OpenFile(path, flag|unix.O_NOFOLLOW, perm)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	return f, nil
}

// SafeRemoveAll verifies with Lstat that path is not a symlink before calling
// os.RemoveAll. This prevents a top-level symlink from redirecting the
// recursive delete into an attacker-chosen tree.
func SafeRemoveAll(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return errfmt.WrapError(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errfmt.Errorf("refusing to remove symlink target: %s", path)
	}

	return os.RemoveAll(path)
}

// Protected memory access functionality

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
