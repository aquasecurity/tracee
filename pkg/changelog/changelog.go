package changelog

import (
	"time"

	"github.com/aquasecurity/tracee/pkg/logger"
)

//
// Entries, entryList and entry structures are used to manage a list of changes.
//

// MemberKind represents the unique identifier for each kind of entry in the Entries.
// It is used to categorize different kinds of changes tracked by the Entries.
//
// NOTE: Declare your own MemberKind constants sequentially starting from 0,
// since they are used as the indexes in the flags slice passed to NewEntries and
// other methods. For example:
//
//	const MyKind1 MemberKind = 0
//	const MyKind2 MemberKind = 1
//
//	var flags = []MaxEntries{
//	    MyKind1: 3,
//	    MyKind2: 5,
//	}
type MemberKind uint8

// MaxEntries represents the maximum number of entries that can be stored for a given kind of entry.
type MaxEntries uint8

// Entries is the main structure that manages a list of changes (entries).
// It keeps track of specifically configured members indicated by MemberKind identifiers.
// When instantiating an Entries struct, one must supply a relevant mapping between the desired
// unique members and the maximum amount of changes that member can track.
//
// ATTENTION: You should use Entries within a struct and provide methods to access it,
// coordinating access through your struct mutexes. DO NOT EXPOSE the Entries object directly to
// the outside world as it is not thread-safe.
type Entries[T comparable] struct {
	kindLists []entryList[T] // slice of entryList for each kind of entry.
}

// entryList is an internal structure that manages a list of changes (entries) for a specific kind of entry.
type entryList[T comparable] struct {
	maxEntries MaxEntries // maximum number of entries.
	entries    []entry[T] // list of entries.
}

// entry is an internal structure representing a single change in the entryList.
// It includes the timestamp and the value of the change.
type entry[T comparable] struct {
	timestamp time.Time // timestamp of the change
	value     T         // value of the change
}

// Public

// NewEntries initializes a new `Entries` structure using the provided `MaxEntries` slice.
func NewEntries[T comparable](maxEntries []MaxEntries) *Entries[T] {
	newKindList := make([]entryList[T], 0, len(maxEntries))

	for _, max := range maxEntries {
		if max == 0 {
			logger.Fatalw("maxEntries must be greater than 0")
		}

		newEntryList := entryList[T]{
			maxEntries: max,
			entries:    make([]entry[T], 0),
		}
		newKindList = append(newKindList, newEntryList)
	}

	return &Entries[T]{
		kindLists: newKindList,
	}
}

// Set adds or updates an entry in the Entries for the specified `MemberKind` ordered by timestamp.
// If the new entry has the same value as the latest one, only the timestamp is updated.
// If there are already the maximum number of entries for this kind, it reuses or replaces an existing entry.
//
// ATTENTION: Make sure to pass a value of the correct type for the specified `MemberKind`.
func (e *Entries[T]) Set(kind MemberKind, value T, timestamp time.Time) {
	if int(kind) >= len(e.kindLists) {
		logger.Errorw("kind is not present in the entries", "kind", kind)
		return
	}

	entries := e.kindLists[kind].entries

	// if there are entries for kind check if the last entry has the same value
	if len(entries) > 0 {
		lastIdx := len(entries) - 1
		if entries[lastIdx].value == value && timestamp.After(entries[lastIdx].timestamp) {
			// only update timestamp and return
			entries[lastIdx].timestamp = timestamp
			return
		}
	}

	newEntry := entry[T]{
		timestamp: timestamp,
		value:     value,
	}

	// if there is space, insert the new entry at the correct position

	maxEntries := int(e.kindLists[kind].maxEntries)
	if len(entries) < maxEntries {
		insertPos := findInsertIdx(entries, timestamp)
		if insertPos == len(entries) {
			entries = append(entries, newEntry)
		} else {
			entries = insertAt(insertPos, entries, newEntry)
		}
		e.kindLists[kind].entries = entries // update kindLists
		return
	}

	// as there is no space, replace an entry

	replaceIdx := len(entries) - 1 // default index to replace
	if timestamp.After(entries[replaceIdx].timestamp) {
		// reallocate values to the left
		shiftLeft(entries)
	} else {
		// find the correct position to store the entry
		replaceIdx = findInsertIdx(entries, timestamp) - 1
		if replaceIdx == -1 {
			replaceIdx = 0
		}
	}
	entries[replaceIdx] = newEntry
}

// Get retrieves the value of the entry for the specified `MemberKind` at or before the given timestamp.
// If no matching entry is found, it returns the default value for the entry type.
func (e *Entries[T]) Get(kind MemberKind, timestamp time.Time) T {
	if e.noEntries(kind) {
		return getZero[T]()
	}

	entries := e.kindLists[kind].entries
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].timestamp.Before(timestamp) || entries[i].timestamp.Equal(timestamp) {
			return entries[i].value
		}
	}

	return getZero[T]()
}

// GetCurrent retrieves the most recent value for the specified `MemberKind`.
// If no entry is found, it returns the default value for the entry type.
func (e *Entries[T]) GetCurrent(kind MemberKind) T {
	if e.noEntries(kind) {
		return getZero[T]()
	}

	entries := e.kindLists[kind].entries
	return entries[len(entries)-1].value
}

// // GetAll retrieves all values for the specified `MemberKind`, from the newest to the oldest.
func (e *Entries[T]) GetAll(kind MemberKind) []T {
	if e.noEntries(kind) {
		return nil
	}

	entries := e.kindLists[kind].entries
	values := make([]T, 0, len(entries))
	for i := len(entries) - 1; i >= 0; i-- {
		values = append(values, entries[i].value)
	}

	return values
}

// Count returns the number of entries recorded for the specified `MemberKind`.
func (e *Entries[T]) Count(kind MemberKind) int {
	if e.noEntries(kind) {
		return 0
	}

	return len(e.kindLists[kind].entries)
}

// private

// noEntries checks if there are no entries for the specified `MemberKind`.
func (e *Entries[T]) noEntries(kind MemberKind) bool {
	return int(kind) >= len(e.kindLists) || len(e.kindLists[kind].entries) == 0
}

// utility

// insertAt inserts a new entry at the specified index in the entries list.
func insertAt[T comparable](idx int, entries []entry[T], newEntry entry[T]) []entry[T] {
	return append(entries[:idx], append([]entry[T]{newEntry}, entries[idx:]...)...)
}

// findInsertIdx finds the correct index to insert a new entry based on its timestamp.
func findInsertIdx[T comparable](entries []entry[T], timestamp time.Time) int {
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].timestamp.Before(timestamp) {
			return i + 1
		}
	}

	return len(entries)
}

// shiftLeft shifts entries within the given indexes to the left, discarding the oldest entry.
func shiftLeft[T comparable](entries []entry[T]) {
	for i := 0; i < len(entries)-1; i++ {
		entries[i] = entries[i+1]
	}
}

// getZero returns the zero value for the type `T`.
func getZero[T comparable]() T {
	var zero T
	return zero
}
