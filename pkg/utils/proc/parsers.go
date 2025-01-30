package proc

import (
	"strconv"
	"strings"
)

//
// proc status/stat fields type parsers
// TODO: move to a more appropriate package (e.g. pkg/utils/parsers.go)
// TODO: consider using them in argument parsing
//

func ParseInt32(value string) (int32, error) {
	val, err := strconv.ParseInt(value, 10, 32)
	return int32(val), err
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
