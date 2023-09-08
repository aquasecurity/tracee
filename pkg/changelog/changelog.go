package changelog

import "time"

type item[T any] struct {
	stamp time.Time // timestamp of the change
	value T         // value of the change
}

type Changelog[T any] struct {
	changes []item[T] // list of changes
}

// Getters

// GetCurrent returns the latest value of the changelog.
func (clv *Changelog[T]) GetCurrent() T {
	if len(clv.changes) == 0 {
		var zero T
		return zero
	}
	return clv.changes[len(clv.changes)-1].value
}

// Get returns the value of the changelog at the given time.
func (clv *Changelog[T]) Get(targetTime time.Time) T {
	left, right := 0, len(clv.changes)

	for left < right {
		middle := (left + right) / 2
		if clv.changes[middle].stamp.Before(targetTime) {
			left = middle + 1
		} else {
			right = middle
		}
	}
	if left == 0 {
		var zero T
		return zero
	}

	return clv.changes[left-1].value
}

// GetAll returns all the values of the changelog.
func (clv *Changelog[T]) GetAll() []T {
	values := make([]T, len(clv.changes))
	for i, entry := range clv.changes {
		values[i] = entry.value
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
	entry := item[T]{
		stamp: targetTime,
		value: value,
	}

	idx := clv.findIndex(entry.stamp)
	clv.changes = append(clv.changes, item[T]{})
	copy(clv.changes[idx+1:], clv.changes[idx:])
	clv.changes[idx] = entry
}

// findIndex returns the index of the first item in the changelog that is after the given time.
func (clv *Changelog[T]) findIndex(target time.Time) int {
	left, right := 0, len(clv.changes)

	for left < right {
		middle := (left + right) / 2
		if clv.changes[middle].stamp.Before(target) {
			left = middle + 1
		} else {
			right = middle
		}
	}

	return left
}
