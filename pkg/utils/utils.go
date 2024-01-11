package utils

import (
	"math/rand"
	"strings"
	"time"

	"github.com/aquasecurity/libbpfgo/helpers"
)

// Cloner is an interface for objects that can be cloned
type Cloner interface {
	Clone() Cloner
}

func ParseSymbol(address uint64, table *helpers.KernelSymbolTable) helpers.KernelSymbol {
	var hookingFunction helpers.KernelSymbol

	symbols, err := table.GetSymbolByAddr(address)
	if err != nil {
		hookingFunction = helpers.KernelSymbol{}
		hookingFunction.Owner = "hidden"
	} else {
		hookingFunction = symbols[0]
	}

	hookingFunction.Owner = strings.TrimPrefix(hookingFunction.Owner, "[")
	hookingFunction.Owner = strings.TrimSuffix(hookingFunction.Owner, "]")

	return hookingFunction
}

func HasBit(n uint64, offset uint) bool {
	return (n & (1 << offset)) > 0
}

func ClearBit(n *uint64, offset uint) {
	*n &= ^(1 << offset)
}

func ClearBits(n *uint64, mask uint64) {
	*n &= ^mask
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

// GenerateRandomDuration returns a random duration between min and max, inclusive
func GenerateRandomDuration(min, max int) time.Duration {
	return time.Duration(rand.Intn(max-min+1)+min) * time.Second
}
