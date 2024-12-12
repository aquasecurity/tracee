package changelog

import (
	"time"

	"github.com/aquasecurity/tracee/pkg/logger"
)

// Changelog manages a list of changes (entries) for a single type.
type Changelog[T comparable] struct {
	list entryList[T]
}

// NewChangelog initializes a new `Changelog` with the specified maximum number of entries.
func NewChangelog[T comparable](maxEntries MaxEntries) *Changelog[T] {
	if maxEntries <= 0 {
		logger.Fatalw("maxEntries must be greater than 0")
	}

	return &Changelog[T]{
		list: newEntryList[T](maxEntries),
	}
}

// Set adds or updates an entry in the Changelog, ordered by timestamp.
// If the new entry has the same value as the latest one, only the timestamp is updated.
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
