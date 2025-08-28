package interfaces

// Cloner is a generic interface for objects that can clone themselves.
type Cloner[T any] interface {
	Clone() T
}

// Iterator is a generic interface for iterators.
type Iterator[T any] interface {
	// HasNext returns true if there are more elements to iterate.
	HasNext() bool

	// Next returns the next element in the iteration.
	Next() T
}
