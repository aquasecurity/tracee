package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/types/trace"
)

func GetTraceeArgumentByName(event trace.Event, argName string) (trace.Argument, error) {
	for _, arg := range event.Args {
		if arg.Name == argName {
			return arg, nil
		}
	}
	return trace.Argument{}, fmt.Errorf("argument %s not found", argName)
}
