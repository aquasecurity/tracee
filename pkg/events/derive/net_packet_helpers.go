package derive

import "strings"

// helpers for all supported protocol derivations

const AF_INET = 2
const AF_INET6 = 10

func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func convertArrayOfBytes(given [][]byte) []string {
	var res []string

	for _, i := range given {
		res = append(res, string(i))
	}

	return res
}

func strToLower(given string) string {
	return strings.ToLower(given)
}
