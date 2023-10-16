package counter

import (
	"testing"
)

// Increment

func BenchmarkIncrement(b *testing.B) {
	c := NewCounter(0)

	for i := 0; i < b.N; i++ {
		err := c.Increment()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIncrementWithValue(b *testing.B) {
	c := NewCounter(0)

	for i := 0; i < b.N; i++ {
		err := c.Increment(1)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIncrementWithMultipleValue(b *testing.B) {
	c := NewCounter(0)

	for i := 0; i < b.N; i += 3 {
		err := c.Increment(1, 1, 1)
		if err != nil {
			b.Fatal(err)
		}
	}

	// Note: Looping 1/3 of times in this case
}

func BenchmarkZeroedIncrementWithValue(b *testing.B) {
	c := NewCounter(0)

	for i := 0; i < b.N; i++ {
		err := c.Increment(0)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkZeroedIncrementWithMultipleValue(b *testing.B) {
	c := NewCounter(0)

	for i := 0; i < b.N; i++ {
		err := c.Increment(0, 0, 0)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Decrement

func BenchmarkDecrement(b *testing.B) {
	c := NewCounter(uint64(b.N))

	for i := b.N; i > 0; i-- {
		err := c.Decrement()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrementWithValue(b *testing.B) {
	c := NewCounter(uint64(b.N))

	for i := b.N; i > 0; i-- {
		err := c.Decrement(1)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrementWithMultipleValue(b *testing.B) {
	c := NewCounter(uint64(b.N))

	for i := b.N; i > 3; i -= 3 {
		err := c.Decrement(1, 1, 1)
		if err != nil {
			b.Fatal(err)
		}
	}

	// Note: Looping 1/3 of times in this case
}

func BenchmarkZeroedDecrementWithValue(b *testing.B) {
	c := NewCounter(uint64(b.N))

	for i := b.N; i > 0; i-- {
		err := c.Decrement(0)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkZeroedDecrementWithMultipleValue(b *testing.B) {
	c := NewCounter(uint64(b.N))

	for i := b.N; i > 0; i-- {
		err := c.Decrement(0, 0, 0)
		if err != nil {
			b.Fatal(err)
		}
	}
}
