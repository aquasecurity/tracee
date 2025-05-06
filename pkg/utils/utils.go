package utils

import (
	"math/rand"
	"time"
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

func ReverseString(s string) string {
	n := len(s)
	bytes := make([]byte, n)

	for i := 0; i < n; i++ {
		bytes[n-i-1] = s[i]
	}
	return string(bytes)
}

// TrimTrailingNUL returns a subslice of the input with all trailing NUL bytes (0x00) removed.
// It performs a reverse scan and returns b[:end], avoiding any allocations.
//
// This function is optimized for fixed-size, ASCII-compatible C-style buffers where padding
// with trailing NULs may occur.
//
// Note:
//   - The returned slice shares memory with the original input.
//   - If you need an independent string or slice, copy it manually.
//   - This function is not safe for UTF-8 or multibyte character data; it assumes ASCII content only.
func TrimTrailingNUL(b []byte) []byte {
	end := len(b)

	for end > 0 && b[end-1] == 0 {
		end--
	}

	return b[:end]
}
