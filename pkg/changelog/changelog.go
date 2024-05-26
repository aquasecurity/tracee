package changelog

import (
	"slices"
	"time"

	"github.com/aquasecurity/tracee/pkg/logger"
)

type comparable interface {
	~int | ~float64 | ~string
}

type item[T comparable] struct {
	timestamp time.Time // timestamp of the change
	value     T         // value of the change
}

// The changelog package provides a changelog data structure. It is a list of changes, each with a
// timestamp. The changelog can be queried for the value at a given time.

// ATTENTION: You should use Changelog within a struct and provide methods to access it,
// coordinating access through your struct mutexes. DO NOT EXPOSE the changelog object directly to
// the outside world as it is not thread-safe.

type Changelog[T comparable] struct {
	changes    []item[T]              // list of changes
	timestamps map[time.Time]struct{} // set of timestamps (used to avoid duplicates)
	maxSize    int                    // maximum amount of changes to keep track of
}

// NewChangelog creates a new changelog.
func NewChangelog[T comparable](maxSize int) *Changelog[T] {
	return &Changelog[T]{
		changes:    []item[T]{},
		timestamps: map[time.Time]struct{}{},
		maxSize:    maxSize,
	}
}

// Getters

// GetCurrent: Observation on single element changelog.
//
// If there's one element in the changelog, after the loop, left would be set to 1 if the single
// timestamp is before the targetTime, and 0 if it's equal or after.
//
// BEFORE: If the single timestamp is before the targetTime, when we return
// clv.changes[left-1].value, returns clv.changes[0].value, which is the expected behavior.
//
// AFTER: If the single timestamp is equal to, or after the targetTime, the current logic would
// return a "zero" value because of the condition if left == 0.
//
// We need to find the last change that occurred before or exactly at the targetTime. The binary
// search loop finds the position where a new entry with the targetTime timestamp would be inserted
// to maintain chronological order:
//
// This position is stored in "left".
//
// So, to get the last entry that occurred before the targetTime, we need to access the previous
// position, which is left-1.
//
// GetCurrent returns the latest value of the changelog.
func (clv *Changelog[T]) GetCurrent() T {
	if len(clv.changes) == 0 {
		return returnZero[T]()
	}

	return clv.changes[len(clv.changes)-1].value
}

// Get returns the value of the changelog at the given time.
func (clv *Changelog[T]) Get(targetTime time.Time) T {
	if len(clv.changes) == 0 {
		return returnZero[T]()
	}

	idx := clv.findIndex(targetTime)
	if idx == 0 {
		var zero T
		return zero
	}

	return clv.changes[idx-1].value
}

// GetAll returns all the values of the changelog.
func (clv *Changelog[T]) GetAll() []T {
	values := make([]T, len(clv.changes))
	for i := range clv.changes {
		values[i] = clv.changes[i].value
	}
	return values
}

// Setters

// SetCurrent sets the latest value of the changelog.
func (clv *Changelog[T]) SetCurrent(value T) {
	clv.setAt(value, time.Now())
}

// Set sets the value of the changelog at the given time.
func (clv *Changelog[T]) Set(value T, targetTime time.Time) {
	clv.setAt(value, targetTime)
}

// private

// setAt sets the value of the changelog at the given time.
func (clv *Changelog[T]) setAt(value T, targetTime time.Time) {
	// If the timestamp is already set, update that value only.
	_, ok := clv.timestamps[targetTime]
	if ok {
		index := clv.findIndex(targetTime)
		if !clv.changes[index].timestamp.Equal(targetTime) { // sanity check only (time exists already)
			logger.Debugw("changelog internal error: timestamp mismatch")
			return
		}
		if clv.changes[index].value != value {
			logger.Debugw("changelog error: value mismatch for same timestamp")
		}
		clv.changes[index].value = value
		return
	}

	entry := item[T]{
		timestamp: targetTime,
		value:     value,
	}

	idx := clv.findIndex(entry.timestamp)
	// If the changelog has reached its maximum size and the new change would be inserted as the oldest,
	// there is no need to add the new change. We can simply return without making any modifications.
	if len(clv.changes) >= clv.maxSize && idx == 0 {
		return
	}
	// Insert the new entry in the changelog, keeping the list sorted by timestamp.
	clv.changes = append(clv.changes, item[T]{})
	copy(clv.changes[idx+1:], clv.changes[idx:])
	clv.changes[idx] = entry
	// Mark the timestamp as set.
	clv.timestamps[targetTime] = struct{}{}

	clv.enforceSizeBoundary()
}

// findIndex returns the index of the first item in the changelog that is after the given time.
func (clv *Changelog[T]) findIndex(target time.Time) int {
	left, right := 0, len(clv.changes)

	for left < right {
		middle := (left + right) / 2
		if clv.changes[middle].timestamp.Before(target) {
			left = middle + 1
		} else {
			right = middle
		}
	}

	return left
}

// enforceSizeBoundary ensures that the size of the inner array doesn't exceed the limit.
// It applies two methods to reduce the log size to the maximum allowed:
// 1. Unite duplicate values that are trailing one another.
// 2. Remove the oldest logs as they are likely less important.

func (clv *Changelog[T]) enforceSizeBoundary() {
	if len(clv.changes) > clv.maxSize {
		// Get rid of oldest changes to keep max size boundary
		boundaryDiff := len(clv.changes) - clv.maxSize

		// First try to unite states
		clv.changes = slices.CompactFunc(clv.changes, func(i item[T], i2 item[T]) bool {
			if i.value == i2.value && boundaryDiff > 0 {
				delete(clv.timestamps, i2.timestamp)
				boundaryDiff--
				return true
			}
			return false
		})

		if boundaryDiff == 0 {
			return
		}
		removedChanges := clv.changes[:boundaryDiff]
		clv.changes = clv.changes[boundaryDiff:]
		for _, removedChange := range removedChanges {
			delete(clv.timestamps, removedChange.timestamp)
		}
	}
}

// returnZero returns the zero value of the type T.
func returnZero[T any]() T {
	var zero T
	return zero
}
