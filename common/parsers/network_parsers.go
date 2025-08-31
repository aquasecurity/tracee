package parsers

import (
	"encoding/binary"
	"errors"
	"net"
)

// Network Address Parsing Functions
//
// These functions parse network addresses from raw sockaddr structures
// returned by network-related syscalls. Raw addresses are typically
// represented as map[string]string where keys correspond to sockaddr
// structure fields.

// ParseUint32IP parses an IPv4 address from a uint32 value.
func ParseUint32IP(in uint32) string {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, in)

	return ip.String()
}

// Parse16BytesSliceIP parses the IP address encoded as 16 bytes long
// PrintBytesSliceIP. It would be more correct to accept a [16]byte instead of
// variable lenth slice, but that would case unnecessary memory copying and
// type conversions.
func Parse16BytesSliceIP(in []byte) string {
	ip := net.IP(in)

	return ip.String()
}

// GetFamilyFromRawAddr extracts the address family from a raw address map.
// Raw addresses are sockaddr structures returned by network syscalls.
func GetFamilyFromRawAddr(addr map[string]string) (string, error) {
	family, exists := addr["sa_family"]
	if !exists {
		return "", errors.New("family not found in address")
	}
	return family, nil
}

// IsInternetFamily returns true if the address family is AF_INET or AF_INET6.
func IsInternetFamily(addr map[string]string) (bool, error) {
	family, err := GetFamilyFromRawAddr(addr)
	if err != nil {
		return false, err
	}
	return family == "AF_INET" || family == "AF_INET6", nil
}

// IsUnixFamily returns true if the address family is AF_UNIX.
func IsUnixFamily(addr map[string]string) (bool, error) {
	family, err := GetFamilyFromRawAddr(addr)
	if err != nil {
		return false, err
	}
	return family == "AF_UNIX", nil
}

// GetIPFromRawAddr extracts the IP address from a raw address map.
func GetIPFromRawAddr(addr map[string]string) (string, error) {
	family, err := GetFamilyFromRawAddr(addr)
	if err != nil {
		return "", err
	}

	var ip string
	var exists bool

	switch family {
	case "AF_INET":
		ip, exists = addr["sin_addr"]
		if !exists {
			return "", errors.New("ip not found in address")
		}
	case "AF_INET6":
		ip, exists = addr["sin6_addr"]
		if !exists {
			return "", errors.New("ip not found in address")
		}
	default:
		return "", errors.New("address family not supported")
	}

	return ip, nil
}

// GetPortFromRawAddr extracts the port number from a raw address map.
func GetPortFromRawAddr(addr map[string]string) (string, error) {
	family, err := GetFamilyFromRawAddr(addr)
	if err != nil {
		return "", err
	}

	var port string
	var exists bool

	switch family {
	case "AF_INET":
		port, exists = addr["sin_port"]
		if !exists {
			return "", errors.New("port not found in address")
		}
	case "AF_INET6":
		port, exists = addr["sin6_port"]
		if !exists {
			return "", errors.New("port not found in address")
		}
	default:
		return "", errors.New("address family not supported")
	}

	return port, nil
}

// GetPathFromRawAddr extracts the path from a Unix domain socket address map.
func GetPathFromRawAddr(addr map[string]string) (string, error) {
	family, err := GetFamilyFromRawAddr(addr)
	if err != nil {
		return "", err
	}

	switch family {
	case "AF_UNIX":
		path, exists := addr["sun_path"]
		if !exists {
			return "", errors.New("path not found in address")
		}
		return path, nil
	default:
		return "", errors.New("address family not supported")
	}
}
