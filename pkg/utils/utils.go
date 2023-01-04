package utils

import (
	"strings"

	"github.com/aquasecurity/libbpfgo/helpers"
)

func ParseSymbol(address uint64, table helpers.KernelSymbolTable) *helpers.KernelSymbol {
	hookingFunction, err := table.GetSymbolByAddr(address)
	if err != nil {
		hookingFunction = &helpers.KernelSymbol{}
		hookingFunction.Owner = "hidden"
	}
	hookingFunction.Owner = strings.TrimPrefix(hookingFunction.Owner, "[")
	hookingFunction.Owner = strings.TrimSuffix(hookingFunction.Owner, "]")
	return hookingFunction
}
