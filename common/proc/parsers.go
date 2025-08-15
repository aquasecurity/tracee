package proc

import (
	"strconv"
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

func ParseUint32(value string) (uint32, error) {
	val, err := strconv.ParseUint(value, 10, 32)
	return uint32(val), err
}

func ParseUint64(value string) (uint64, error) {
	return strconv.ParseUint(value, 10, 64)
}
