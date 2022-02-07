package counter

import "testing"

func TestIncrement(t *testing.T) {
	var c Counter = 0

	c.Increment()

	if c.Read() != 1 {
		t.Errorf("Increment was incorrect, got %d, expected %d", c.Read(), 1)
	}
}

func TestIncrementMultiple(t *testing.T) {
	var c Counter = 0

	c.Increment(1, 2, 3)
	expected := 1 + 2 + 3

	if c.Read() != int32(expected) {
		t.Errorf("Increment was incorrect, got %d, expected %d", c.Read(), expected)
	}
}

func TestDecrement(t *testing.T) {
	var c Counter = 1

	c.Decrement()

	if c.Read() != 0 {
		t.Errorf("Increment was incorrect, got %d, expected %d", c.Read(), 0)
	}
}

func TestDecrementMultiple(t *testing.T) {
	var c Counter = 1 + 2 + 3

	c.Decrement(1, 2, 3)

	if c.Read() != 0 {
		t.Errorf("Increment was incorrect, got %d, expected %d", c.Read(), 0)
	}
}
