package main

import (
	"github.com/aquasecurity/libbpfgo/helpers"
)

func buildFlagArgValue(flags ...helpers.SystemFunctionArgument) int32 {
	var res int32
	for _, flagVal := range flags {
		res = res | int32(flagVal.Value())
	}
	return res
}
