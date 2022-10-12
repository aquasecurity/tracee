package helpers

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/types/trace"
)

// IsFileWrite returns whether the passed file permissions string contains
// o_wronly or o_rdwr
func IsFileWrite(flags string) bool {
	flagsLow := strings.ToLower(flags)
	if strings.Contains(flagsLow, "o_wronly") || strings.Contains(flagsLow, "o_rdwr") {
		return true
	}
	return false
}

// IsFileRead returns whether the passed file permissions string contains
// o_rdonly or o_rdwr
func IsFileRead(flags string) bool {
	flagsLow := strings.ToLower(flags)
	if strings.Contains(flagsLow, "o_rdonly") || strings.Contains(flagsLow, "o_rdwr") {
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

// IsElf checks if the file starts with an ELF magic.
func IsElf(bytesArray []byte) bool {
	if len(bytesArray) >= 4 {
		if bytesArray[0] == 127 && bytesArray[1] == 69 && bytesArray[2] == 76 && bytesArray[3] == 70 {
			return true
		}
	}

	return false
}

func IsInternetFamily(addr trace.SockAddr) bool {
	family := addr.Family()

	return family == "AF_INET" || family == "AF_INET6"
}

func IsUnixFamily(addr trace.SockAddr) bool {
	return addr.Family() == "AF_UNIX"
}

func GetIPFromRawAddr(addr trace.SockAddr) (string, error) {
	if IsInternetFamily(addr) {
		return addr.Address(), nil
	}
	return "", fmt.Errorf("failed to get IP address: family not supported (must be AF_INET/AF_INET6)")
}

func GetPortFromRawAddr(addr trace.SockAddr) (string, error) {
	if IsInternetFamily(addr) {
		return strconv.Itoa(addr.Port()), nil
	}
	return "", fmt.Errorf("failed to get port: address family not supported (must be AF_INET/AF_INET6)")
}

func GetPathFromRawAddr(addr trace.SockAddr) (string, error) {
	if IsUnixFamily(addr) {
		return addr.Address(), nil
	}
	return "", fmt.Errorf("failed to get socket path: address family not supported (must be AF_UNIX")
}
