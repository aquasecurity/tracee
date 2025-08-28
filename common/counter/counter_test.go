package counter

import (
	"math"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// Increment

func TestIncrement(t *testing.T) {
	t.Parallel()

	expected := uint64(1)
	c := NewCounter(0)

	err := c.Increment()

	require.NoError(t, err)
	require.Equal(t, expected, c.Get())
}

func TestIncrementWithValue(t *testing.T) {
	t.Parallel()

	expected := uint64(9)
	c := NewCounter(0)

	err := c.Increment(9)

	require.NoError(t, err)
	require.Equal(t, expected, c.Get())
}

func TestIncrementWithMultipleValue(t *testing.T) {
	t.Parallel()

	expected := uint64(9)
	c := NewCounter(0)

	err := c.Increment(3, 3, 3)

	require.NoError(t, err)
	require.Equal(t, expected, c.Get())
}

func TestIncrementAndRead(t *testing.T) {
	t.Parallel()

	expected := uint64(9)
	c := NewCounter(0)

	n, err := c.IncrementValueAndRead(9)

	require.NoError(t, err)
	require.Equal(t, expected, n)
	require.Equal(t, expected, c.Get())
}

func TestZeroedIncrementWithValue(t *testing.T) {
	t.Parallel()

	expected := uint64(9)
	c := NewCounter(9)

	err := c.Increment(0)

	require.NoError(t, err)
	require.Equal(t, expected, c.Get())
}

func TestZeroedIncrementWithMultipleValue(t *testing.T) {
	t.Parallel()

	expected := uint64(9)
	c := NewCounter(9)

	err := c.Increment(0, 0, 0)

	require.NoError(t, err)
	require.Equal(t, expected, c.Get())
}

func TestIncrementOverflow(t *testing.T) {
	t.Parallel()

	expected := uint64(0)
	c := NewCounter(uint64(math.MaxUint64) - 1)

	err := c.Increment() // uint64 max value
	require.NoError(t, err)

	err = c.Increment() // overflow
	require.Error(t, err)

	require.Equal(t, expected, c.Get())
}

func TestIncrementWithValueOverflow(t *testing.T) {
	t.Parallel()

	expected := uint64(0)
	c := NewCounter(0)

	err := c.Increment(uint64(math.MaxUint64 / 2))
	require.NoError(t, err)

	err = c.Increment(uint64(math.MaxUint64/2) + 2)
	require.Error(t, err)

	require.Equal(t, expected, c.Get())
}

func TestIncrement_MultipleThreads(t *testing.T) {
	t.Parallel()

	expected := uint64(100000)
	c := NewCounter(0)

	wg := sync.WaitGroup{}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			for j := 0; j < 500; j++ {
				err := c.Increment(1, 1) // test with multiple values
				require.NoError(t, err)
			}
			wg.Done()
		}()
	}

	wg.Wait()

	require.Equal(t, expected, c.Get())
}

// Decrement

func TestDecrement(t *testing.T) {
	t.Parallel()

	expected := uint64(0)
	c := NewCounter(1)

	err := c.Decrement()

	require.NoError(t, err)
	require.Equal(t, expected, c.Get())
}

func TestDecrementWithValue(t *testing.T) {
	t.Parallel()

	expected := uint64(1)
	c := NewCounter(10)

	err := c.Decrement(9)

	require.NoError(t, err)
	require.Equal(t, expected, c.Get())
}

func TestDecrementWithMultipleValue(t *testing.T) {
	t.Parallel()

	expected := uint64(1)
	c := NewCounter(10)

	err := c.Decrement(3, 3, 3)

	require.NoError(t, err)
	require.Equal(t, expected, c.Get())
}

func TestDecrementAndRead(t *testing.T) {
	t.Parallel()

	expected := uint64(1)
	c := NewCounter(10)

	n, err := c.DecrementValueAndRead(9)

	require.NoError(t, err)
	require.Equal(t, expected, n)
	require.Equal(t, expected, c.Get())
}

func TestZeroedDecrementWithValue(t *testing.T) {
	t.Parallel()

	expected := uint64(9)
	c := NewCounter(9)

	err := c.Decrement(0)

	require.NoError(t, err)
	require.Equal(t, expected, c.Get())
}

func TestZeroedDecrementWithMultipleValue(t *testing.T) {
	t.Parallel()

	expected := uint64(9)
	c := NewCounter(9)

	err := c.Decrement(0, 0, 0)

	require.NoError(t, err)
	require.Equal(t, expected, c.Get())
}

func TestDecrementOverflow(t *testing.T) {
	t.Parallel()

	expected := uint64(math.MaxUint64)
	c := NewCounter(0)

	err := c.Decrement() // uint64 max value
	require.Error(t, err)
	require.Equal(t, expected, c.Get())

	expected = uint64(math.MaxUint64 - 1)

	err = c.Decrement() // uint64 max value
	require.NoError(t, err)
	require.Equal(t, expected, c.Get())
}

func TestDecrementWithValueOverflow(t *testing.T) {
	t.Parallel()

	expected := uint64(math.MaxUint64 - 8)
	c := NewCounter(0)

	err := c.Decrement(9)
	require.Error(t, err)
	require.Equal(t, expected, c.Get())
}

func TestDecrement_MultipleThreads(t *testing.T) {
	t.Parallel()

	expected := uint64(0)
	c := NewCounter(100000)

	wg := sync.WaitGroup{}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			for j := 0; j < 500; j++ {
				err := c.Decrement(1, 1) // test with multiple values
				require.NoError(t, err)
			}
			wg.Done()
		}()
	}

	wg.Wait()

	require.Equal(t, expected, c.Get())
}

// Increment + Decrement

func TestIncrementDecrement(t *testing.T) {
	t.Parallel()

	expected := uint64(0)
	c := NewCounter(0)

	err := c.Increment()
	require.NoError(t, err)

	err = c.Decrement()
	require.NoError(t, err)

	require.Equal(t, expected, c.Get())
}

func TestIncrementDecrement_MultipleThreads(t *testing.T) {
	t.Parallel()

	expected := uint64(0)
	c := NewCounter(0)

	wg := sync.WaitGroup{}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			for j := 0; j < 1000; j++ {
				err := c.Increment()
				require.NoError(t, err)
				err = c.Decrement()
				require.NoError(t, err)
			}
			wg.Done()
		}()
	}

	wg.Wait()

	require.Equal(t, expected, c.Get())
}
