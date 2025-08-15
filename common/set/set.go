package set

import (
	"sync"
)

// Set is a generic thread-safe data structure representing a unique collection of items,
// with synchronized access.
type Set[T, H comparable] struct {
	*SimpleSet[T, H]
	l *sync.RWMutex
}

func New[T comparable](items ...T) *Set[T, T] {
	s := NewSimpleSet(items...)
	return &Set[T, T]{
		s,
		new(sync.RWMutex),
	}
}

func NewWithHash[T, H comparable](hashFunc func(T) H, items ...T) *Set[T, H] {
	s := NewSimpleSetWithHash(hashFunc, items...)
	return &Set[T, H]{
		s,
		new(sync.RWMutex),
	}
}

// Empty checks if the set's content is 0
func (s *Set[T, H]) Empty() bool {
	s.l.RLock()
	defer s.l.RUnlock()
	return len(s.items) == 0
}

// Clear resets the set
func (s *Set[T, H]) Clear() {
	s.uniqueSet = make(map[H]T)
	s.items = make([]T, 0)
}

// Length returns the amount of items in the set
func (s *Set[T, H]) Length() int {
	s.l.RLock()
	defer s.l.RUnlock()
	return s.SimpleSet.Length()
}

// Has checks the existance of an item in the set
func (s *Set[T, H]) Has(item T) bool {
	s.l.RLock()
	defer s.l.RUnlock()
	return s.SimpleSet.Has(item)
}

// Items returns a copy of the underlying item array
func (s *Set[T, H]) Items() []T {
	s.l.RLock()
	defer s.l.RUnlock()
	return s.SimpleSet.Items()
}

// ItemsMutable returns a direct reference to the underlying item array.
// Use and modify at your own risk.
func (s *Set[T, H]) ItemsMutable() []T {
	s.l.RLock()
	defer s.l.RUnlock()
	return s.SimpleSet.ItemsMutable()
}

// Append adds unique items in order to the end of the set
func (s *Set[T, H]) Append(items ...T) {
	s.l.Lock()
	defer s.l.Unlock()
	s.SimpleSet.Append(items...)
}

// Prepend adds unique items in order to the start of the set
func (s *Set[T, H]) Prepend(items ...T) {
	s.l.Lock()
	defer s.l.Unlock()
	s.SimpleSet.Prepend(items...)
}

func (s *Set[T, H]) String() string {
	s.l.RLock()
	defer s.l.RUnlock()
	return s.SimpleSet.String()
}
