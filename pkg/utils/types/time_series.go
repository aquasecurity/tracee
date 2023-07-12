package types

import (
	"sync"
	"time"
)

// State represent a change of value - the new value and the time of the change
type State[T any] struct {
	StartTime time.Time
	Val       T
}

// TimeSeries represents a value that changes over time.
// It exposes the value at a given time, assuming that between two changes the value is constant.
// The object is designed to be thread-safe.
// TODO: change implementation to use AVL tree to improve performance in large amount of states
// cases
type TimeSeries[T any] struct {
	states []State[T]
	mu     sync.RWMutex
}

func NewTimeSeries[T any](defaultVal T) *TimeSeries[T] {
	defaultState := State[T]{
		StartTime: time.Unix(0, 0),
		Val:       defaultVal,
	}
	return &TimeSeries[T]{
		states: []State[T]{defaultState},
	}
}

// AddState add a change in the value - from given time until next change, the value is the new one.
func (ts *TimeSeries[T]) AddState(newState State[T]) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	insertIndex := ts.getRelevantStateIndex(newState.StartTime) + 1
	stateList := make([]State[T], len(ts.states)+1)
	copy(stateList[:insertIndex], ts.states[:insertIndex])
	copy(stateList[insertIndex+1:], ts.states[insertIndex:])
	stateList[insertIndex] = newState
	ts.states = stateList
}

// Get return the value at a given time
func (ts *TimeSeries[T]) Get(queryTime time.Time) T {
	relevantState := ts.GetState(queryTime)
	return relevantState.Val
}

// GetState return the value at a given time, and the time it was changed to this value
func (ts *TimeSeries[T]) GetState(queryTime time.Time) State[T] {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	relevantStateIndex := ts.getRelevantStateIndex(queryTime)
	return ts.states[relevantStateIndex]
}

// ChangeDefault change the value assumed before first recorded change
func (ts *TimeSeries[T]) ChangeDefault(defaultVal T) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.states[0].Val = defaultVal
}

// getRelevantStateIndex searches for the index of the state in the states slice of the TimeSeries
// object that has the closest start time to the given time parameter.
// It uses binary search to find the index.
func (ts *TimeSeries[T]) getRelevantStateIndex(queryTime time.Time) int {
	low := 0
	high := len(ts.states) - 1
	closestIndex := 0

	for low <= high {
		mid := low + (high-low)/2

		if queryTime.Before(ts.states[mid].StartTime) {
			high = mid - 1 // Target is in the left half
		} else {
			closestIndex = mid
			low = mid + 1 // Target is in the right half
		}
	}
	return closestIndex
}
