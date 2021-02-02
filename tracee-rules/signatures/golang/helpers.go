package main

import (
	"fmt"
	"strings"

	tracee "github.com/aquasecurity/tracee/tracee/external"
)

func GetTraceeArgumentByName(event tracee.Event, argName string) (tracee.Argument, error) {
	for _, arg := range event.Args {
		if arg.Name == argName {
			return arg, nil
		}
	}
	return tracee.Argument{}, fmt.Errorf("argument %s not found", argName)
}

func IsFileWrite(flags string) bool {
	flagsLow := strings.ToLower(flags)
	if strings.Contains(flagsLow, "o_wronly") || strings.Contains(flagsLow, "o_rdwr") {
		return true
	}
	return false
}
