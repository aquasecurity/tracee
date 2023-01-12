package utils

import (
	"fmt"
	"runtime"
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

// ErrorFuncName displays a given error prefixed by the current (caller) fn name
func ErrorFuncName(e error) error {

	if e != nil {
		pc, _, _, _ := runtime.Caller(1)
		funcName := runtime.FuncForPC(pc).Name()
		index := strings.LastIndex(funcName, "/") + 1

		return fmt.Errorf("%v: %v", funcName[index:], e)
	}

	return nil
}

func HasBit(n uint64, offset uint) bool {
	return (n & (1 << offset)) > 0
}

func ClearBit(n *uint64, offset uint) {
	*n &= ^(1 << offset)
}

func SetBit(n *uint64, offset uint) {
	*n |= (1 << offset)
}

func Min(x, y uint64) uint64 {
	if x < y {
		return x
	}
	return y
}

func Max(x, y uint64) uint64 {
	if x > y {
		return x
	}
	return y
}
