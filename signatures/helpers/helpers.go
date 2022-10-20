package helpers

import (
	"fmt"
	"strings"
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

func GetFamilyFromRawAddr(addr map[string]string) (string, error) {

	family, exists := addr["sa_family"]
	if !exists {
		return "", fmt.Errorf("family not found in address")
	}

	return family, nil
}

func IsInternetFamily(addr map[string]string) (bool, error) {

	family, err := GetFamilyFromRawAddr(addr)
	if err != nil {
		return false, err
	}

	if family == "AF_INET" || family == "AF_INET6" {
		return true, nil
	}

	return false, nil
}

func IsUnixFamily(addr map[string]string) (bool, error) {

	family, err := GetFamilyFromRawAddr(addr)
	if err != nil {
		return false, err
	}

	if family == "AF_UNIX" {
		return true, nil
	}

	return false, nil
}

func GetIPFromRawAddr(addr map[string]string) (string, error) {

	family, err := GetFamilyFromRawAddr(addr)
	if err != nil {
		return "", err
	}

	ip := ""
	var exists bool

	switch family {

	case "AF_INET":
		ip, exists = addr["sin_addr"]
		if !exists {
			return "", fmt.Errorf("ip not found in address")
		}

	case "AF_INET6":
		ip, exists = addr["sin6_addr"]
		if !exists {
			return "", fmt.Errorf("ip not found in address")
		}

	default:
		return "", fmt.Errorf("address family not supported")

	}

	return ip, nil
}

func GetPortFromRawAddr(addr map[string]string) (string, error) {

	family, err := GetFamilyFromRawAddr(addr)
	if err != nil {
		return "", err
	}

	port := ""
	var exists bool

	switch family {

	case "AF_INET":
		port, exists = addr["sin_port"]
		if !exists {
			return "", fmt.Errorf("port not found in address")
		}

	case "AF_INET6":
		port, exists = addr["sin6_port"]
		if !exists {
			return "", fmt.Errorf("port not found in address")
		}

	default:
		return "", fmt.Errorf("address family not supported")

	}

	return port, nil
}

func GetPathFromRawAddr(addr map[string]string) (string, error) {

	family, err := GetFamilyFromRawAddr(addr)
	if err != nil {
		return "", err
	}

	path := ""
	var exists bool

	switch family {

	case "AF_UNIX":
		path, exists = addr["sun_path"]
		if !exists {
			return "", fmt.Errorf("path not found in address")
		}

	default:
		return "", fmt.Errorf("address family not supported")

	}

	return path, nil
}
