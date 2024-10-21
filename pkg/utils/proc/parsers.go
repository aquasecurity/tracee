package proc

import (
	"strconv"
	"strings"
)

//
// proc status/stat fields type parsers
//

func parseInt(value string) int {
	val, _ := strconv.Atoi(value)
	return val
}

func parseUint64(value string) uint64 {
	val, _ := strconv.ParseUint(value, 10, 64)
	return val
}

func parseString(value string) string {
	return strings.Clone(value) // clone it to avoid memory leak
}
