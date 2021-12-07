package helpers

import (
	"fmt"
	"strings"

	tracee "github.com/aquasecurity/tracee/pkg/external"
)

// GetTraceeArgumentByName fetches the argument in event with `Name` that matches argName
func GetTraceeArgumentByName(event tracee.Event, argName string) (tracee.Argument, error) {
	for _, arg := range event.Args {
		if arg.Name == argName {
			return arg, nil
		}
	}
	return tracee.Argument{}, fmt.Errorf("argument %s not found", argName)
}

// IsFileWrite returns whether or not the passed file permissions string contains
// o_wronly or o_rdwr
func IsFileWrite(flags string) bool {
	flagsLow := strings.ToLower(flags)
	if strings.Contains(flagsLow, "o_wronly") || strings.Contains(flagsLow, "o_rdwr") {
		return true
	}
	return false
}
