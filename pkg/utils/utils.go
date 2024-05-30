package utils

import (
	"math/rand"
	"strings"
	"time"

	"github.com/aquasecurity/tracee/pkg/utils/environment"
)

// Cloner is a generic interface for objects that can clone themselves.
type Cloner[T any] interface {
	Clone() T
}

// Iterator is a generic interface for iterators.
type Iterator[T any] interface {
	// HasNext returns true if there are more elements to iterate.
	HasNext() bool

	// Next returns the next element in the iteration.
	Next() T
}

func ParseSymbol(address uint64, table *environment.KernelSymbolTable) environment.KernelSymbol {
	var hookingFunction environment.KernelSymbol

	symbols, err := table.GetSymbolByAddr(address)
	if err != nil {
		hookingFunction = environment.KernelSymbol{}
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
