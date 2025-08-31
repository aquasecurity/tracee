package parsers

import (
	"strings"
	"syscall"
)

//
// File-related Parsing Functions
//

// IsFileWrite returns whether the passed file permissions flags contain
// O_WRONLY or O_RDWR
func IsFileWrite(flags int) bool {
	accessMode := uint64(flags) & syscall.O_ACCMODE
	if accessMode == syscall.O_WRONLY || accessMode == syscall.O_RDWR {
		return true
	}
	return false
}

// IsFileRead returns whether the passed file permissions flags contain
// O_RDONLY or O_RDWR
func IsFileRead(flags int) bool {
	accessMode := uint64(flags) & syscall.O_ACCMODE
	if accessMode == syscall.O_RDONLY || accessMode == syscall.O_RDWR {
		return true
	}
	return false
}

// IsMemoryPath checks if a given file path is located under "memfd", "/run/shm/" or "/dev/shm/".
func IsMemoryPath(pathname string) bool {
	if strings.HasPrefix(pathname, "memfd:") || strings.HasPrefix(pathname, "/run/shm/") ||
		strings.HasPrefix(pathname, "/dev/shm/") {
		return true
	}

	return false
}
