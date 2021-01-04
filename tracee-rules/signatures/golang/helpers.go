package main

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/tracee-rules/types"
)

func GetTraceeArgumentByName(event types.TraceeEvent, argName string) (types.TraceeEventArgument, error) {
	for _, arg := range event.Args {
		if arg.Name == argName {
			return arg, nil
		}
	}
	return types.TraceeEventArgument{}, fmt.Errorf("argument %s not found", argName)
}

func IsFileWrite(flags string) bool {
	flagsLow := strings.ToLower(flags)
	if strings.Contains(flagsLow, "o_wronly") || strings.Contains(flagsLow, "o_rdwr") {
		return true
	}
	return false
}
