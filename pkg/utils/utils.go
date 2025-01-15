package utils

import (
	"fmt"
	"io"
	"math/rand"
	"reflect"
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

// PrintStructSizes prints the size of a struct and the size of its fields
func PrintStructSizes(w io.Writer, structure interface{}) {
	typ := reflect.TypeOf(structure)

	// if the type is a pointer to a struct, dereference it
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}

	if typ.Kind() != reflect.Struct {
		fmt.Fprintf(w, "Type %s is not a struct\n", typ.Kind())
		return
	}

	totalSize := typ.Size()
	expectedSize := uintptr(0)
	fieldsInfo := "["

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		fieldSize := field.Type.Size()
		fieldOffset := field.Offset
		fieldsInfo += fmt.Sprintf(
			"%s:%s %d bytes (offset=%d), ",
			field.Name, field.Type.String(), fieldSize, fieldOffset,
		)
		expectedSize += fieldSize
	}

	padding := totalSize - expectedSize
	paddingInfo := ""
	if padding > 0 {
		paddingInfo = "(has padding)"
	}

	// remove trailing comma and space
	if len(fieldsInfo) > 2 {
		fieldsInfo = fieldsInfo[:len(fieldsInfo)-2]
	}
	fieldsInfo += "]"

	fmt.Fprintf(w, "%s: %d bytes %s %s\n", typ.Name(), totalSize, fieldsInfo, paddingInfo)
}
