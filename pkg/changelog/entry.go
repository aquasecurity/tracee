package changelog

import (
	"time"
)

// MaxEntries represents the maximum number of changes that can be tracked.
type MaxEntries uint8

// entry is an internal structure representing a single change in the entryList.
// It includes the timestamp and the value of the change.
type entry[T comparable] struct {
	tsUnixNano int64 // timestamp of the change (nanoseconds since epoch)
	value      T     // value of the change
}

func newEntry[T comparable](value T, timestamp time.Time) entry[T] {
	return entry[T]{
		tsUnixNano: timestamp.UnixNano(),
		value:      value,
	}
}

// entryList is an internal structure that stores a list of changes (entries).
type entryList[T comparable] struct {
	maxEntries MaxEntries // maximum number of entries
	entries    []entry[T] // list of entries
}

func newEntryList[T comparable](maxEntries MaxEntries) entryList[T] {
	return entryList[T]{
		maxEntries: maxEntries,
		entries:    make([]entry[T], 0), // don't pre-allocate full capacity
	}
}

func (el *entryList[T]) set(value T, timestamp time.Time) entryList[T] {
	tsUnixNano := timestamp.UnixNano()
	entries := el.entries
	length := len(entries)

	// if there are entries, check if the last entry has the same value

	if length > 0 {
		lastIdx := length - 1
		if entries[lastIdx].value == value && tsUnixNano > entries[lastIdx].tsUnixNano {
			// only update timestamp and return
			entries[lastIdx].tsUnixNano = tsUnixNano
			return *el
		}
	}

	entry := newEntry[T](value, timestamp)

	// if there is space, insert the new entry at the correct position

	if length < int(el.maxEntries) {
		insertPos := findInsertIdx(entries, tsUnixNano)
		if insertPos == length {
			entries = append(entries, entry)
		} else {
			entries = insertAt(insertPos, entries, entry)
		}
		el.entries = entries // replace entries with the new list
		return *el
	}

	// as there is no space, replace an entry

	replaceIdx := length - 1 // default index to replace
	if tsUnixNano > entries[replaceIdx].tsUnixNano {
		// reallocate values to the left
		shiftLeft(entries)
	} else {
		// find the correct position to store the entry
		replaceIdx = findInsertIdx(entries, tsUnixNano) - 1
		if replaceIdx == -1 {
			replaceIdx = 0
		}
	}
	entries[replaceIdx] = entry

	return *el
}

func (el *entryList[T]) get(timestamp time.Time) T {
	tsUnixNano := timestamp.UnixNano()
	entries := el.entries
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].tsUnixNano <= tsUnixNano {
			return entries[i].value
		}
	}

	return getZero[T]()
}

func (el *entryList[T]) getCurrent() T {
	entries := el.entries
	length := len(entries)
	if length == 0 {
		return getZero[T]()
	}

	return entries[length-1].value
}

func (el *entryList[T]) getAll() []T {
	entries := el.entries
	values := make([]T, 0, len(entries))
	for i := len(entries) - 1; i >= 0; i-- {
		values = append(values, entries[i].value)
	}

	return values
}

func (el *entryList[T]) noEntries() bool {
	return len(el.entries) == 0
}

// populateEntries fills the entries list with zeroed entries up to the maximum number of entries.
// This is useful to measure the memory usage.
func (el *entryList[T]) populateEntries() {
	maxEntries := int(el.maxEntries)
	newEntries := make([]entry[T], 0, maxEntries)

	for i := 0; i < maxEntries; i++ {
		newEntries = append(newEntries, entry[T]{
			// futuristic timestamp to make sure it will be replaced
			tsUnixNano: time.Now().AddDate(0, 0, 1).UnixNano(),
			// be aware that for variable-length types like strings,
			// zero value will not reflect the actual memory usage of the type.
			value: getZero[T](),
		})
	}

	el.entries = newEntries
}

// utility

// insertAt inserts a new entry at the specified index in the entries list.
func insertAt[T comparable](idx int, entries []entry[T], newEntry entry[T]) []entry[T] {
	return append(entries[:idx], append([]entry[T]{newEntry}, entries[idx:]...)...)
}

// findInsertIdx finds the correct index to insert a new entry based on its timestamp.
func findInsertIdx[T comparable](entries []entry[T], tsUnixNano int64) int {
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].tsUnixNano < tsUnixNano {
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
