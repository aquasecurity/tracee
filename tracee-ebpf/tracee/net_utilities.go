package tracee

import (
	"bytes"
	"inet.af/netaddr"
)

func parseIP(ip [16]byte) string {
	if IsIpv6(ip) {
		return netaddr.IPFrom16(ip).String()
	} else {
		ipv4 := AssginIpV4(ip)
		return netaddr.IPFrom4(ipv4).String()
	}
}

// check if a given Ip as byte array is Ipv6 or Ipv4
func IsIpv6(ip [16]byte) bool {
	var zeroedPattern []byte
	if bytes.Compare(ip[:9], zeroedPattern) == 0 {
		return false
	}
	return true
}

// convert a ipV4 to samller byte array
func AssginIpV4(ip [16]byte) [4]byte {
	var ipV4 [4]byte
	copy(ipV4[:], ip[12:16])
	return ipV4
}
