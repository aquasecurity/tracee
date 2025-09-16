package set

import (
	"reflect"
	"strings"
	"testing"
)

// Test SimpleSet basic functionality
func TestNewSimpleSet(t *testing.T) {
	t.Run("empty set", func(t *testing.T) {
		s := NewSimpleSet[int]()
		if !s.Empty() {
			t.Errorf("Expected empty set")
		}
		if s.Length() != 0 {
			t.Errorf("Expected length 0, got %d", s.Length())
		}
	})

	t.Run("set with initial items", func(t *testing.T) {
		s := NewSimpleSet(1, 2, 3)
		if s.Empty() {
			t.Errorf("Expected non-empty set")
		}
		if s.Length() != 3 {
			t.Errorf("Expected length 3, got %d", s.Length())
		}

		items := s.Items()
		if len(items) != 3 {
			t.Errorf("Expected 3 items, got %d", len(items))
		}

		// Check all items are present (order doesn't matter for sets)
		for _, expected := range []int{1, 2, 3} {
			if !s.Has(expected) {
				t.Errorf("Expected set to contain %d", expected)
			}
		}
	})

	t.Run("set with duplicate items", func(t *testing.T) {
		s := NewSimpleSet(1, 2, 2, 3, 1)
		if s.Length() != 3 {
			t.Errorf("Expected length 3 (duplicates removed), got %d", s.Length())
		}

		// Check all unique items are present
		for _, expected := range []int{1, 2, 3} {
			if !s.Has(expected) {
				t.Errorf("Expected set to contain %d", expected)
			}
		}
	})

	t.Run("string set", func(t *testing.T) {
		s := NewSimpleSet("hello", "world", "hello")
		if s.Length() != 2 {
			t.Errorf("Expected length 2, got %d", s.Length())
		}

		if !s.Has("hello") || !s.Has("world") {
			t.Errorf("Expected set to contain 'hello' and 'world'")
		}
	})
}

// Test SimpleSet with custom hash function
func TestNewSimpleSetWithHash(t *testing.T) {
	// Custom struct for testing
	type Person struct {
		Name string
		Age  int
	}

	// Hash function that uses only the name (ignoring age)
	nameHash := func(p Person) string {
		return p.Name
	}

	t.Run("custom hash function", func(t *testing.T) {
		s := NewSimpleSetWithHash(nameHash,
			Person{"Alice", 25},
			Person{"Bob", 30},
			Person{"Alice", 26}) // Different age, same name

		if s.Length() != 2 {
			t.Errorf("Expected length 2 (Alice with different ages should be same), got %d", s.Length())
		}

		if !s.Has(Person{"Alice", 99}) { // Any age should work for Alice
			t.Errorf("Expected set to contain Alice (regardless of age)")
		}
		if !s.Has(Person{"Bob", 99}) { // Any age should work for Bob
			t.Errorf("Expected set to contain Bob (regardless of age)")
		}
	})

	t.Run("string length hash", func(t *testing.T) {
		lengthHash := func(s string) int {
			return len(s)
		}

		set := NewSimpleSetWithHash(lengthHash, "hello", "world", "hi", "test", "go")
		// "hello" and "world" both have length 5, so only one should remain
		// "test" has length 4
		// "hi" has length 2
		// "go" has length 2, so should be same as "hi"
		if set.Length() != 3 {
			t.Errorf("Expected length 3 (lengths 2, 4, 5), got %d", set.Length())
		}
	})
}

// Test basic set operations
func TestSimpleSet_BasicOperations(t *testing.T) {
	s := NewSimpleSet[int]()

	t.Run("empty set operations", func(t *testing.T) {
		if !s.Empty() {
			t.Errorf("New set should be empty")
		}
		if s.Length() != 0 {
			t.Errorf("Empty set length should be 0")
		}
		if s.Has(42) {
			t.Errorf("Empty set should not contain any items")
		}
		if len(s.Items()) != 0 {
			t.Errorf("Empty set items should be empty slice")
		}
	})

	t.Run("append items", func(t *testing.T) {
		s.Append(1, 2, 3)
		if s.Empty() {
			t.Errorf("Set should not be empty after append")
		}
		if s.Length() != 3 {
			t.Errorf("Expected length 3, got %d", s.Length())
		}

		items := s.Items()
		if !reflect.DeepEqual(items, []int{1, 2, 3}) {
			t.Errorf("Expected items [1, 2, 3], got %v", items)
		}
	})

	t.Run("append duplicates", func(t *testing.T) {
		s.Append(2, 3, 4) // 2 and 3 already exist
		if s.Length() != 4 {
			t.Errorf("Expected length 4, got %d", s.Length())
		}

		items := s.Items()
		if !reflect.DeepEqual(items, []int{1, 2, 3, 4}) {
			t.Errorf("Expected items [1, 2, 3, 4], got %v", items)
		}
	})

	t.Run("clear set", func(t *testing.T) {
		s.Clear()
		if !s.Empty() {
			t.Errorf("Set should be empty after clear")
		}
		if s.Length() != 0 {
			t.Errorf("Cleared set length should be 0")
		}
	})
}

// Test prepend functionality
func TestSimpleSet_Prepend(t *testing.T) {
	s := NewSimpleSet[int]()

	t.Run("prepend to empty set", func(t *testing.T) {
		s.Prepend(3, 2, 1)
		items := s.Items()
		if !reflect.DeepEqual(items, []int{3, 2, 1}) {
			t.Errorf("Expected items [3, 2, 1], got %v", items)
		}
	})

	t.Run("prepend to existing set", func(t *testing.T) {
		s.Prepend(5, 4) // Should go to the beginning
		items := s.Items()
		if !reflect.DeepEqual(items, []int{5, 4, 3, 2, 1}) {
			t.Errorf("Expected items [5, 4, 3, 2, 1], got %v", items)
		}
	})

	t.Run("prepend duplicates", func(t *testing.T) {
		s.Prepend(1, 2, 6) // 1 and 2 already exist, only 6 should be added
		items := s.Items()
		if !reflect.DeepEqual(items, []int{6, 5, 4, 3, 2, 1}) {
			t.Errorf("Expected items [6, 5, 4, 3, 2, 1], got %v", items)
		}
	})
}

// Test Items vs ItemsMutable
func TestSimpleSet_ItemsVsMutable(t *testing.T) {
	s := NewSimpleSet(1, 2, 3)

	t.Run("Items returns copy", func(t *testing.T) {
		items := s.Items()
		items[0] = 999 // Modify the returned slice

		// Original set should be unchanged
		if s.Items()[0] == 999 {
			t.Errorf("Items() should return a copy, not reference")
		}
	})

	t.Run("ItemsMutable returns reference", func(t *testing.T) {
		mutable := s.ItemsMutable()
		original := s.ItemsMutable()

		// They should be the same slice
		if &mutable[0] != &original[0] {
			t.Errorf("ItemsMutable() should return same reference")
		}

		// Modifying one affects the other
		mutable[0] = 999
		if original[0] != 999 {
			t.Errorf("ItemsMutable() should return mutable reference")
		}
	})
}

// Test String method
func TestSimpleSet_String(t *testing.T) {
	t.Run("empty set string", func(t *testing.T) {
		s := NewSimpleSet[int]()
		str := s.String()
		if str != "[]" {
			t.Errorf("Expected empty set string to be '[]', got '%s'", str)
		}
	})

	t.Run("set with items", func(t *testing.T) {
		s := NewSimpleSet(1, 2, 3)
		str := s.String()
		// The exact format depends on the Items() order, but should contain the elements
		if !contains(str, "1") || !contains(str, "2") || !contains(str, "3") {
			t.Errorf("String representation should contain all elements, got '%s'", str)
		}
	})

	t.Run("nil set string", func(t *testing.T) {
		var s *SimpleSet[int, int]
		str := s.String()
		if str != "" {
			t.Errorf("Expected nil set string to be empty, got '%s'", str)
		}
	})
}

// Test thread-safe Set wrapper
func TestSet_ThreadSafe(t *testing.T) {
	t.Run("basic operations", func(t *testing.T) {
		s := New(1, 2, 3)

		if s.Empty() {
			t.Errorf("Set with items should not be empty")
		}
		if s.Length() != 3 {
			t.Errorf("Expected length 3, got %d", s.Length())
		}
		if !s.Has(2) {
			t.Errorf("Set should contain 2")
		}

		items := s.Items()
		if len(items) != 3 {
			t.Errorf("Expected 3 items, got %d", len(items))
		}
	})

	t.Run("append and prepend", func(t *testing.T) {
		s := New[int]()
		s.Append(1, 2)
		s.Prepend(0)

		if s.Length() != 3 {
			t.Errorf("Expected length 3, got %d", s.Length())
		}

		items := s.Items()
		if !reflect.DeepEqual(items, []int{0, 1, 2}) {
			t.Errorf("Expected items [0, 1, 2], got %v", items)
		}
	})

	t.Run("clear", func(t *testing.T) {
		s := New(1, 2, 3)
		s.Clear()

		if !s.Empty() {
			t.Errorf("Set should be empty after clear")
		}
	})

	t.Run("mutable items", func(t *testing.T) {
		s := New(1, 2, 3)
		mutable := s.ItemsMutable()

		if len(mutable) != 3 {
			t.Errorf("Expected 3 mutable items, got %d", len(mutable))
		}
	})

	t.Run("string representation", func(t *testing.T) {
		s := New(1, 2, 3)
		str := s.String()

		if !contains(str, "1") || !contains(str, "2") || !contains(str, "3") {
			t.Errorf("String should contain all elements, got '%s'", str)
		}
	})
}

// Test Set with custom hash function
func TestSet_WithHash(t *testing.T) {
	// Test with custom hash function
	lengthHash := func(s string) int {
		return len(s)
	}

	t.Run("custom hash function", func(t *testing.T) {
		s := NewWithHash(lengthHash, "hello", "world", "hi")

		// "hello" and "world" both have length 5, so only one should remain
		if s.Length() != 2 {
			t.Errorf("Expected length 2, got %d", s.Length())
		}

		// Test with the exact strings that should be in the set
		// We can't predict which of "hello"/"world" will be kept, so check both possibilities
		hasLength5 := s.Has("hello") || s.Has("world")
		if !hasLength5 {
			t.Errorf("Should contain either 'hello' or 'world' (length 5)")
		}
		if !s.Has("hi") {
			t.Errorf("Should contain 'hi' (length 2)")
		}

		// Test that any other string with same length is recognized
		if !s.Has("abcde") { // Any 5-char string should match "hello"/"world"
			t.Errorf("Should contain string of length 5")
		}
		if !s.Has("xy") { // Any 2-char string should match "hi"
			t.Errorf("Should contain string of length 2")
		}
	})
}

// Edge cases and error conditions
func TestSimpleSet_EdgeCases(t *testing.T) {
	t.Run("large dataset", func(t *testing.T) {
		s := NewSimpleSet[int]()

		// Add many items
		items := make([]int, 1000)
		for i := 0; i < 1000; i++ {
			items[i] = i
		}
		s.Append(items...)

		if s.Length() != 1000 {
			t.Errorf("Expected length 1000, got %d", s.Length())
		}

		// Check some random items
		if !s.Has(500) || !s.Has(999) || !s.Has(0) {
			t.Errorf("Large set should contain test items")
		}
	})

	t.Run("empty operations", func(t *testing.T) {
		s := NewSimpleSet[int]()

		// Operations on empty set should not panic
		s.Append()
		s.Prepend()
		s.Clear()

		if !s.Empty() {
			t.Errorf("Set should remain empty")
		}
	})

	t.Run("nil items in constructor", func(t *testing.T) {
		// Test with pointer types that can be nil
		s := NewSimpleSet[*int]()
		var nilPtr *int
		s.Append(nilPtr)

		if s.Length() != 1 {
			t.Errorf("Should be able to store nil pointers")
		}
		if !s.Has(nilPtr) {
			t.Errorf("Should find nil pointer")
		}
	})
}

// Benchmark tests
func BenchmarkSimpleSet_Append(b *testing.B) {
	s := NewSimpleSet[int]()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		s.Append(i)
	}
}

func BenchmarkSimpleSet_Has(b *testing.B) {
	s := NewSimpleSet[int]()
	for i := 0; i < 1000; i++ {
		s.Append(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Has(i % 1000)
	}
}

func BenchmarkSet_ThreadSafe(b *testing.B) {
	s := New[int]()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Append(i)
		s.Has(i)
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 &&
		(s == substr || len(s) > len(substr) &&
			(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
				strings.Contains(s, substr)))
}

// Test with different types to ensure generics work
func TestSet_DifferentTypes(t *testing.T) {
	t.Run("string set", func(t *testing.T) {
		s := New("apple", "banana", "cherry", "apple")
		if s.Length() != 3 {
			t.Errorf("Expected 3 unique strings, got %d", s.Length())
		}
	})

	t.Run("float set", func(t *testing.T) {
		s := New(1.1, 2.2, 3.3, 1.1)
		if s.Length() != 3 {
			t.Errorf("Expected 3 unique floats, got %d", s.Length())
		}
	})

	t.Run("custom struct set", func(t *testing.T) {
		type Point struct{ X, Y int }

		s := New(Point{1, 2}, Point{3, 4}, Point{1, 2})
		if s.Length() != 2 {
			t.Errorf("Expected 2 unique points, got %d", s.Length())
		}

		if !s.Has(Point{1, 2}) {
			t.Errorf("Should contain Point{1, 2}")
		}
	})
}
