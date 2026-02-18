// Package intern provides string interning using Go's unique package (Go 1.23+).
//
// String interning ensures that identical strings share the same underlying memory,
// reducing RSS usage for programs that process many events containing repetitive
// string fields (e.g., process names, hostnames, container IDs, event names).
//
// The unique package uses weak references internally, so interned strings that are
// no longer referenced anywhere in the program are automatically cleaned up by the GC.
package intern

import "unique"

// String returns a canonical (interned) version of s.
//
// If an identical string has already been interned, the returned string shares
// its underlying memory with the previously interned copy. This eliminates
// duplicate backing arrays for strings that appear frequently.
//
// The interning table uses weak references, so unused entries are automatically
// garbage collected.
//
// This function is safe for concurrent use.
func String(s string) string {
	if len(s) == 0 {
		return ""
	}
	return unique.Make(s).Value()
}
