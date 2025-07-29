package set

import (
	"fmt"
)

// SimpleSet is a generic data structure representing a unique collection of items.
// It is not thread safe, concurrent reads and writes will cause a panic. Use this
// version only if this is not a concern.
type SimpleSet[T, HashType comparable] struct {
	items     []T
	uniqueSet map[HashType]T
	hashFunc  func(T) HashType
}

// New builds a new set object
func NewSimpleSet[T comparable](items ...T) *SimpleSet[T, T] {
	set := SimpleSet[T, T]{
		items:     make([]T, 0, len(items)),
		uniqueSet: make(map[T]T, len(items)),
		hashFunc: func(t T) T {
			return t
		},
	}
	for _, item := range items {
		set.uniqueSet[item] = item
	}
	for item := range set.uniqueSet {
		set.items = append(set.items, item)
	}
	return &set
}

// New builds a new set object
func NewSimpleSetWithHash[T comparable, HashType comparable](hashFunc func(T) HashType, items ...T) *SimpleSet[T, HashType] {
	set := SimpleSet[T, HashType]{
		items:     make([]T, 0, len(items)),
		uniqueSet: make(map[HashType]T, len(items)),
		hashFunc:  hashFunc,
	}
	for _, item := range items {
		set.uniqueSet[hashFunc(item)] = item
	}
	for _, item := range set.uniqueSet {
		set.items = append(set.items, item)
	}
	return &set
}

// Empty checks if the set's content is 0
func (s *SimpleSet[T, H]) Empty() bool {
	return len(s.items) == 0
}

// Clear resets the set
func (s *SimpleSet[T, H]) Clear() {
	s.uniqueSet = make(map[H]T)
	s.items = make([]T, 0)
}

// Length returns the amount of items in the set
func (s *SimpleSet[T, H]) Length() int {
	return len(s.items)
}

// Has checks the existance of an item in the set
func (s *SimpleSet[T, H]) Has(item T) bool {
	_, ok := s.uniqueSet[s.hashFunc(item)]
	return ok
}

// Items returns a copy of the underlying item array
func (s *SimpleSet[T, H]) Items() []T {
	copyArr := make([]T, len(s.items))
	copy(copyArr, s.items)
	return copyArr
}

// ItemsMutable returns a direct reference to the underlying item array.
// Use and modify at your own risk.
func (s *SimpleSet[T, H]) ItemsMutable() []T {
	return s.items
}

// Append adds unique items in order to the end of the set
func (s *SimpleSet[T, H]) Append(items ...T) {
	toInsert := make([]T, 0, len(items))
	for _, item := range items {
		hashed := s.hashFunc(item)
		_, ok := s.uniqueSet[hashed]
		if ok {
			continue
		}
		s.uniqueSet[hashed] = item
		toInsert = append(toInsert, item)
	}
	s.items = append(s.items, toInsert...)
}

// Prepend adds unique items in order to the start of the set
func (s *SimpleSet[T, H]) Prepend(items ...T) {
	toInsert := make([]T, 0, len(items))
	for _, item := range items {
		hashed := s.hashFunc(item)
		_, ok := s.uniqueSet[hashed]
		if ok {
			continue
		}
		s.uniqueSet[hashed] = item
		toInsert = append(toInsert, item)
	}
	s.items = append(toInsert, s.items...)
}

func (s *SimpleSet[T, H]) String() string {
	if s != nil && s.items != nil {
		return fmt.Sprintf("%v", s.Items())
	}
	return ""
}
