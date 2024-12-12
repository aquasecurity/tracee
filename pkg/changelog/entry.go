package changelog

import "time"

// entry is an internal structure representing a single change in the entryList.
// It includes the timestamp and the value of the change.
type entry[T comparable] struct {
	timestamp time.Time // timestamp of the change
	value     T         // value of the change
}

func newEntry[T comparable](value T, timestamp time.Time) entry[T] {
	return entry[T]{
		timestamp: timestamp,
		value:     value,
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
		entries:    make([]entry[T], 0), // don't pre-allocate
	}
}

func (el *entryList[T]) set(value T, timestamp time.Time) entryList[T] {
	entries := el.entries
	length := len(entries)

	// if there are entries, check if the last entry has the same value

	if length > 0 {
		lastIdx := length - 1
		if entries[lastIdx].value == value && timestamp.After(entries[lastIdx].timestamp) {
			// Only update timestamp and return
			entries[lastIdx].timestamp = timestamp
			return *el
		}
	}

	entry := newEntry[T](value, timestamp)

	// if there is space, insert the new entry at the correct position

	if length < int(el.maxEntries) {
		insertPos := findInsertIdx(entries, timestamp)
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
	entries[replaceIdx] = entry

	return *el
}

func (el *entryList[T]) get(timestamp time.Time) T {
	entries := el.entries
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].timestamp.Before(timestamp) || entries[i].timestamp.Equal(timestamp) {
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
