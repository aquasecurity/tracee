package helpers

import (
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
