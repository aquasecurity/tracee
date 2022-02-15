package tracee

import (
	"bytes"
	"inet.af/netaddr"
)

func parseIP(ip []byte) string {
	if IsIpv6(ip) {
		return netaddr.IPFrom16(ip).String()
	} else {
		ipv4 := AssginIpV4(ip)
		return netaddr.IPFrom4(ipv4).String()
	}
}

// check if a given Ip as byte array is Ipv6 or Ipv4
func IsIpv6(ip []byte) bool {
	var zeroedPattern []byte
	if bytes.Compare(ip[:9], zeroedPattern) == 0 {
		return false
	}
	return true
}

// convert a ipV4 to samller byte array
func AssginIpV4(ip []byte) [4]byte {
	var ipV4 [4]byte
	copy(ipV4[:], ip[12:16])
	return ipV4
}

// convert a ipV4 to samller byte array
func AssginIpV6(ip []byte) [4]byte {
	var ipV4 [16]byte
	copy(ipV4[:], ip[12:16])
	return ipV4
}
