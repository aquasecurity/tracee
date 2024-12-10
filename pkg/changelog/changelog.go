package changelog

import (
	"time"

	"github.com/aquasecurity/tracee/pkg/logger"
)

//
// Entries, entry, and entryList structures are used to manage a list of changes.
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
	kindList []entryList[T] // slice of entryList for each kind of entry.
}

// entry is an internal structure representing a single change in the entryList.
// It includes the kind of the entry, the timestamp of the change, and the value of the change.
type entry[T comparable] struct {
	timestamp time.Time // Timestamp of the change.
	value     T         // Value of the change.
	prev      *entry[T] // Pointer to the previous entry in the linked list.
}

// entryList is an internal structure that manages a list of changes (entries) for a specific kind of entry.
type entryList[T comparable] struct {
	maxEntries MaxEntries // Maximum number of entries.
	size       uint8      // Current number of entries.
	tail       *entry[T]  // Tail pointer for the linked list of entries.
}

// Public

// NewEntries initializes a new `Entries` structure using the provided flags.
func NewEntries[T comparable](flags []MaxEntries) *Entries[T] {
	newKindList := make([]entryList[T], 0, len(flags))

	for _, max := range flags {
		if max == 0 {
			logger.Fatalw("maxEntries must be greater than 0")
		}

		newEntryList := entryList[T]{
			maxEntries: max,
			tail:       nil,
		}
		newKindList = append(newKindList, newEntryList)
	}

	return &Entries[T]{
		kindList: newKindList,
	}
}

// Set adds or updates an entry in the Entries for the specified `MemberKind` ordered by timestamp.
// If the new entry has the same value as the latest one, only the timestamp is updated.
// If there are already the maximum number of entries for this kind, it reuses or replaces an existing entry.
//
// ATTENTION: Make sure to pass a value of the correct type for the specified `MemberKind`.
func (e *Entries[T]) Set(kind MemberKind, value T, timestamp time.Time) {
	if int(kind) >= len(e.kindList) {
		logger.Errorw("kind is not present in the entries", "kind", kind)
		return
	}

	entryList := &e.kindList[kind]

	newEntry := &entry[T]{
		timestamp: timestamp,
		value:     value,
	}

	// if the list is empty, set the new entry as the tail
	if entryList.tail == nil {
		entryList.tail = newEntry
		entryList.size++
		return
	}

	// traverse the list to find the correct position or match
	current := entryList.tail
	var previous *entry[T]
	for current != nil {
		// if the value matches, update the timestamp if newer
		if current.value == value {
			if timestamp.After(current.timestamp) {
				current.timestamp = timestamp
			}
			return
		}

		// stop traversal when reaching the right position for insertion
		if timestamp.After(current.timestamp) {
			break
		}

		previous = current
		current = current.prev
	}

	// insert the new entry

	newEntry.prev = current
	if previous == nil {
		// new entry becomes the new tail
		entryList.tail = newEntry
	} else {
		// insert the new entry between the previous and current entries
		previous.prev = newEntry
	}

	entryList.size++
	entryList.enforceMax()
}

// Get retrieves the value of the entry for the specified `MemberKind` at or before the given timestamp.
// If no matching entry is found, it returns the default value for the entry type.
func (e *Entries[T]) Get(kind MemberKind, timestamp time.Time) T {
	if e.noEntries(kind) {
		return getZero[T]()
	}

	// traverse the list to find the most recent entry at or before the given timestamp
	current := e.kindList[kind].tail
	for current != nil {
		if current.timestamp.Before(timestamp) || current.timestamp.Equal(timestamp) {
			return current.value
		}

		current = current.prev
	}

	return getZero[T]()
}

// GetCurrent retrieves the most recent value for the specified `MemberKind`.
// If no entry is found, it returns the default value for the entry type.
func (e *Entries[T]) GetCurrent(kind MemberKind) T {
	if e.noEntries(kind) {
		return getZero[T]()
	}

	return e.kindList[kind].tail.value
}

// GetAll retrieves all values for the specified `MemberKind`, from the newest to the oldest.
func (e *Entries[T]) GetAll(kind MemberKind) []T {
	if e.noEntries(kind) {
		return nil
	}

	values := make([]T, 0, e.kindList[kind].size)
	current := e.kindList[kind].tail
	for current != nil {
		values = append(values, current.value)
		current = current.prev
	}

	return values
}

// Count returns the number of entries recorded for the specified `MemberKind`.
func (e *Entries[T]) Count(kind MemberKind) int {
	if e.noEntries(kind) {
		return 0
	}

	return int(e.kindList[kind].size)
}

// private

// noEntries checks if there are no entries for the specified `MemberKind`.
func (e *Entries[T]) noEntries(kind MemberKind) bool {
	return int(kind) >= len(e.kindList) || e.kindList[kind].size == 0
}

// enforceMax ensures that the number of entries does not exceed the maximum limit.
func (el *entryList[T]) enforceMax() {
	if el.isUnderLimit() {
		return
	}

	// traverse the list to find the second-to-last node
	current := el.tail
	secondToLast := int(el.maxEntries) - 1
	for i := 0; i <= secondToLast; i++ {
		current = current.prev
	}

	// sever the link to the oldest node
	current.prev = nil
	el.size--
}

// isUnderLimit checks if the number of entries in the list is under the maximum limit.
func (el *entryList[T]) isUnderLimit() bool {
	return el.size <= uint8(el.maxEntries)
}

// utility

// getZero returns the zero value for the type `T`.
func getZero[T comparable]() T {
	var zero T
	return zero
}
