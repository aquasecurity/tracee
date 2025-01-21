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

func ParseInt64(value string) (int64, error) {
	return strconv.ParseInt(value, 10, 64)
}

func ParseUint64(value string) (uint64, error) {
	return strconv.ParseUint(value, 10, 64)
}

func parseString(value string) string {
	return strings.Clone(value) // clone it to avoid memory leak
}
