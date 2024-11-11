package changelog

import (
	"time"

	"github.com/aquasecurity/tracee/pkg/logger"
)

// Changelog manages a list of changes (entries) for a single type.
// When instantiating a Changelog struct, one must supply the maximum amount of changes
// that can be tracked.
//
// ATTENTION: You should use Changelog within a struct and provide methods to access it,
// coordinating access through your struct mutexes. DO NOT EXPOSE the Changelog object directly to
// the outside world as it is not thread-safe.
type Changelog[T comparable] struct {
	list entryList[T]
}

// NewChangelog initializes a new `Changelog` with the specified maximum number of entries.
func NewChangelog[T comparable](maxEntries MaxEntries) *Changelog[T] {
	if maxEntries <= 0 {
		logger.Fatalw("maxEntries must be greater than 0")
	}

	newList := newEntryList[T](maxEntries)
	// DEBUG: uncomment this to populate entries to measure memory footprint.
	// newList.populateEntries()
	return &Changelog[T]{
		list: newList,
	}
}

// Set adds or updates an entry in the Changelog, ordered by timestamp.
// If the new entry has the same value as the latest one, only the timestamp is updated.
// If there are already the maximum number of entries, it reuses or replaces an existing entry.
func (c *Changelog[T]) Set(value T, timestamp time.Time) {
	c.list = c.list.set(value, timestamp)
}

// Get retrieves the value of the entry at or before the given timestamp.
// If no matching entry is found, it returns the default value for the entry type.
func (c *Changelog[T]) Get(timestamp time.Time) T {
	return c.list.get(timestamp)
}

// GetCurrent retrieves the most recent value.
// If no entry is found, it returns the default value for the entry type.
func (c *Changelog[T]) GetCurrent() T {
	return c.list.getCurrent()
}

// GetAll retrieves all values, from the newest to the oldest.
func (c *Changelog[T]) GetAll() []T {
	return c.list.getAll()
}

// Count returns the number of entries recorded.
func (c *Changelog[T]) Count() int {
	return len(c.list.entries)
}
