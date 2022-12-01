package counter

import (
	"math"
	"testing"
)

func TestIncrement(t *testing.T) {
	expected := uint64(1)
	c := NewCounter(0)

	err := c.Increment()

	if err != nil {
		t.Error(err)
	}

	if c.Read() != expected {
		t.Errorf("Increment was incorrect, got %d, expected %d", c.Read(), expected)
	}
}

func TestZeroedIncrement(t *testing.T) {
	expected := uint64(1)
	c := NewCounter(1)

	err := c.Increment(0)

	if err != nil {
		t.Error(err)
	}

	if c.Read() != expected {
		t.Errorf("Increment was incorrect, got %d, expected %d", c.Read(), expected)
	}
}

func TestIncrementWrapErr(t *testing.T) {
	expected := uint64(math.MaxUint64)
	c := NewCounter(expected)

	err := c.Increment()
	if err == nil {
		t.Errorf("Increment was incorrect, got no error, expected %v", errorCounterWrapAround())
	}

	if c.Read() != expected {
		t.Errorf("Increment was incorrect, got %d, expected %d", c.Read(), expected)
	}
}

func TestIncrementMultiple(t *testing.T) {
	expected := uint64(1 + 2 + 3)
	c := NewCounter(0)

	err := c.Increment(1, 2, 3)
	if err != nil {
		t.Error(err)
	}

	if c.Read() != expected {
		t.Errorf("Increment was incorrect, got %d, expected %d", c.Read(), expected)
	}
}

func TestIncrementMultipleSumWrapErr(t *testing.T) {
	expected := uint64(0)
	c := NewCounter(expected)

	err := c.Increment(1, math.MaxUint64)
	if err == nil {
		t.Errorf("Increment was incorrect, got no error, expected %v", errorCounterSumWrapAround())
	}

	if c.Read() != expected {
		t.Errorf("Increment was incorrect, got %d, expected %d", c.Read(), expected)
	}
}

func TestIncrementMultipleWrapErr(t *testing.T) {
	expected := uint64(math.MaxUint64)
	c := NewCounter(expected)

	err := c.Increment(1)
	if err == nil {
		t.Errorf("Increment was incorrect, got no error, expected %v", errorCounterWrapAround())
	}

	if c.Read() != expected {
		t.Errorf("Increment was incorrect, got %d, expected %d", c.Read(), expected)
	}
}

func TestDecrement(t *testing.T) {
	expected := uint64(0)
	c := NewCounter(1)

	err := c.Decrement()
	if err != nil {
		t.Error(err)
	}

	if c.Read() != expected {
		t.Errorf("Decrement was incorrect, got %d, expected %d", c.Read(), expected)
	}
}

func TestZeroedDecrement(t *testing.T) {
	expected := uint64(1)
	c := NewCounter(1)

	err := c.Decrement(0)

	if err != nil {
		t.Error(err)
	}

	if c.Read() != expected {
		t.Errorf("Decrement was incorrect, got %d, expected %d", c.Read(), expected)
	}
}

func TestDecrementWrapErr(t *testing.T) {
	expected := uint64(0)
	c := NewCounter(expected)

	err := c.Decrement()
	if err == nil {
		t.Errorf("Decrement was incorrect, got no error, expected %v", errorCounterWrapAround())
	}

	if c.Read() != expected {
		t.Errorf("Decrement was incorrect, got %d, expected %d", c.Read(), expected)
	}
}

func TestDecrementMultiple(t *testing.T) {
	expected := uint64(0)
	c := NewCounter(1 + 2 + 3)

	err := c.Decrement(1, 2, 3)
	if err != nil {
		t.Error(err)
	}

	if c.Read() != expected {
		t.Errorf("Decrement was incorrect, got %d, expected %d", c.Read(), expected)
	}
}

func TestDecrementMultipleSumWrapErr(t *testing.T) {
	expected := uint64(math.MaxUint64)
	c := NewCounter(math.MaxUint64)

	err := c.Decrement(1, math.MaxUint64)
	if err == nil {
		t.Errorf("Decrement was incorrect, got no error, expected %v", errorCounterSumWrapAround())
	}

	if c.Read() != expected {
		t.Errorf("Decrement was incorrect, got %d, expected %d", c.Read(), expected)
	}
}

func TestDecrementMultipleWrapErr(t *testing.T) {
	expected := uint64(3)
	c := NewCounter(expected)

	err := c.Decrement(1, 2, 1)
	if err == nil {
		t.Errorf("Decrement was incorrect, got no error, expected %v", errorCounterWrapAround())
	}

	if c.Read() != expected {
		t.Errorf("Decrement was incorrect, got %d, expected %d", c.Read(), expected)
	}
}
