package main

import "github.com/aquasecurity/tracee/pkg/events/parsers"

func buildFlagArgValue(flags ...parsers.SystemFunctionArgument) int32 {
	var res int32
	for _, flagVal := range flags {
		res = res | int32(flagVal.Value())
	}
	return res
}
