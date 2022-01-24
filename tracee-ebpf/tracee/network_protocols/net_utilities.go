package network_protocols

import "bytes"

// check if a given Ip as byte array is Ipv6 or Ipv4
func IsIpv6(ip [16]byte) bool {
	zeroedPattern := make([]byte, 9, 9)
	if bytes.Compare(ip[:9], zeroedPattern) == 0 {
		return false
	}
	return true
}

func AssginIpV4(ip [16]byte) [4]byte {
	var ipV4 [4]byte
	copy(ipV4[:], ip[12:16])
	return ipV4
}
