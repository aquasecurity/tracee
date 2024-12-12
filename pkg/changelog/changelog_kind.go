package changelog

import (
	"time"

	"github.com/aquasecurity/tracee/pkg/logger"
)

// MemberKind represents the unique identifier for each kind of entry in the ChangelogKind.
// It is used to categorize different kinds of changes tracked by the ChangelogKind.
//
// NOTE: Declare your own MemberKind constants sequentially starting from 0,
// since they are used as the indexes in the flags slice passed to NewChangelog and
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

// ChangelogKind is the main structure that manages a list of changes (entries).
// It keeps track of specifically configured members indicated by MemberKind identifiers.
// When instantiating an ChangelogKind struct, one must supply a relevant mapping between the desired
// unique members and the maximum amount of changes that member can track.
//
// ATTENTION: You should use ChangelogKind within a struct and provide methods to access it,
// coordinating access through your struct mutexes. DO NOT EXPOSE the ChangelogKind object directly to
// the outside world as it is not thread-safe.
type ChangelogKind[T comparable] struct {
	kindLists []entryList[T] // list of entries for each kind
}

// NewChangelogKind initializes a new `ChangelogKind` structure using the provided `MaxEntries` slice.
func NewChangelogKind[T comparable](maxEntries []MaxEntries) *ChangelogKind[T] {
	newKindList := make([]entryList[T], 0, len(maxEntries))

	for _, max := range maxEntries {
		if max == 0 {
			logger.Fatalw("maxEntries must be greater than 0")
		}

		newKindList = append(newKindList, newEntryList[T](max))
	}

	return &ChangelogKind[T]{
		kindLists: newKindList,
	}
}

// Set adds or updates an entry in the ChangelogKind for the specified `MemberKind` ordered by timestamp.
// If the new entry has the same value as the latest one, only the timestamp is updated.
// If there are already the maximum number of entries for this kind, it reuses or replaces an existing entry.
//
// ATTENTION: Make sure to pass a value of the correct type for the specified `MemberKind`.
func (e *ChangelogKind[T]) Set(kind MemberKind, value T, timestamp time.Time) {
	if int(kind) >= len(e.kindLists) {
		logger.Errorw("kind is not present in the entries", "kind", kind)
		return
	}

	kindList := e.kindLists[kind]
	e.kindLists[kind] = kindList.set(value, timestamp)
}

// Get retrieves the value of the entry for the specified `MemberKind` at or before the given timestamp.
// If no matching entry is found, it returns the default value for the entry type.
func (e *ChangelogKind[T]) Get(kind MemberKind, timestamp time.Time) T {
	if e.invalidKind(kind) {
		return getZero[T]()
	}

	return e.kindLists[kind].get(timestamp)
}

// GetCurrent retrieves the most recent value for the specified `MemberKind`.
// If no entry is found, it returns the default value for the entry type.
func (e *ChangelogKind[T]) GetCurrent(kind MemberKind) T {
	if e.invalidKind(kind) {
		return getZero[T]()
	}

	return e.kindLists[kind].getCurrent()
}

// // GetAll retrieves all values for the specified `MemberKind`, from the newest to the oldest.
func (e *ChangelogKind[T]) GetAll(kind MemberKind) []T {
	if e.invalidKind(kind) {
		return nil
	}

	return e.kindLists[kind].getAll()
}

// Count returns the number of entries recorded for the specified `MemberKind`.
func (e *ChangelogKind[T]) Count(kind MemberKind) int {
	if e.invalidKind(kind) {
		return 0
	}

	return len(e.kindLists[kind].entries)
}

// private

// invalidKind checks if the specified `MemberKind` is invalid.
func (e *ChangelogKind[T]) invalidKind(kind MemberKind) bool {
	return int(kind) >= len(e.kindLists)
}
