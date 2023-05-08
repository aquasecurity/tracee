package utils

import (
	"io"
	"io/fs"
	"os"
	"path"

	"golang.org/x/sys/unix"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
)

// OpenExistingDir open a directory with given path, and return the os.File of it.
func OpenExistingDir(p string) (*os.File, error) {
	outDirFD, err := unix.Open(p, unix.O_DIRECTORY|unix.O_PATH, 0)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	return os.NewFile(uintptr(outDirFD), p), nil
}

// OpenAt is a wrapper function to the `openat` syscall using golang types.
func OpenAt(dir *os.File, relativePath string, flags int, perm fs.FileMode) (*os.File, error) {
	pidFileFD, err := unix.Openat(int(dir.Fd()), relativePath, flags, uint32(perm))
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	return os.NewFile(uintptr(pidFileFD), path.Join(dir.Name(), relativePath)), nil
}

// RemoveAt is a wrapper function to the `unlinkat` syscall using golang types.
func RemoveAt(dir *os.File, relativePath string, flags int) error {
	if err := unix.Unlinkat(int(dir.Fd()), relativePath, flags); err != nil {
		return errfmt.WrapError(err)
	}

	return nil
}

// MkdirAt is a wrapper function to the `mkdirat` syscall using golang types.
func MkdirAt(dir *os.File, relativePath string, perm fs.FileMode) error {
	return unix.Mkdirat(int(dir.Fd()), relativePath, uint32(perm))
}

// MkdirAtExist is a wrapper function to the `mkdirat` syscall using golang types, ignoring EEXIST error.
func MkdirAtExist(dir *os.File, relativePath string, perm fs.FileMode) error {
	err := unix.Mkdirat(int(dir.Fd()), relativePath, uint32(perm))
	if err != nil {
		// Seems that os.ErrExist doesn't catch the error (at least on Manjaro distro)
		if err != os.ErrExist && err.Error() != "file exists" {
			return errfmt.WrapError(err)
		}
	}
	return nil
}

// CreateAt implements the same logic as os.Create using directory FD and relative path.
func CreateAt(dir *os.File, relativePath string) (*os.File, error) {
	return OpenAt(dir, relativePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
}

// Dup is a wrapper function to the `dup` syscall using golang types.
func Dup(file *os.File) (*os.File, error) {
	newFD, err := unix.Dup(int(file.Fd()))
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	return os.NewFile(uintptr(newFD), file.Name()), nil
}

// RenameAt is a wrapper function to the `renameat` syscall using golang types.
func RenameAt(olddir *os.File, oldpath string, newdir *os.File, newpath string) error {
	return unix.Renameat(int(olddir.Fd()), oldpath, int(newdir.Fd()), newpath)
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
// destination is relative to a given directory. This function needs needed
// capabilities to be set before it is called.
func CopyRegularFileByRelativePath(srcName string, dstDir *os.File, dstName string) error {
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
	destination, err := CreateAt(dstDir, dstName)
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
