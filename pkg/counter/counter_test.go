package counter

import (
	"math"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

//
// Increase
//

// TestZeroedIncrease tests that the counter is not increased when 0 is given.
func TestZeroedIncrease(t *testing.T) {
	expected := uint64(1)
	c := NewCounter(1)

	err := c.Increase(0)

	require.NoError(t, err)
	require.Equal(t, expected, c.Read())
}

// TestIncreaseAndRead tests that the counter is increased by 1 and returns the new value.
func TestIncreaseAndRead(t *testing.T) {
	expected := uint64(1)
	c := NewCounter(0)

	n, err := c.IncreaseAndRead()

	require.NoError(t, err)
	require.Equal(t, expected, n)
	require.Equal(t, expected, c.Read())
}

// TestIncrease tests that the counter is increased by 1.
func TestIncrease(t *testing.T) {
	expected := uint64(1)
	c := NewCounter(0)

	err := c.Increase()

	require.NoError(t, err)
	require.Equal(t, expected, c.Read())
}

// TestIncrease_MultipleThreads is a stress test to check thread safety for increased.
func TestIncrease_MultipleThreads(t *testing.T) {
	expected := uint64(100000)
	c := NewCounter(0)

	wg := sync.WaitGroup{}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			for j := 0; j < 1000; j++ {
				err := c.Increase()
				require.NoError(t, err)
			}
			wg.Done()
		}()
	}

	wg.Wait()

	require.Equal(t, expected, c.Read())
}

// TestIncreaseWrapErr tests that the counter wraps when it reaches the maximum value.
func TestIncreaseWrapErr(t *testing.T) {
	expected := uint64(0)
	c := NewCounter(uint64(math.MaxUint64))

	err := c.Increase()

	require.Error(t, err) // requires wrapped error
	require.Equal(t, expected, c.Read())
}

// TestIncreaseMultiple tests that the counter is increased by the given values.
func TestIncreaseMultiple(t *testing.T) {
	expected := uint64(1 + 2 + 3)
	c := NewCounter(0)

	err := c.Increase(1, 2, 3)

	require.NoError(t, err)
	require.Equal(t, expected, c.Read())
}

// TestIncreaseMultipleSumWrapErr tests that the counter wraps when it reaches the maximum value.
func TestIncreaseMultipleSumWrapErr(t *testing.T) {
	expected := uint64(0)
	c := NewCounter(expected)

	err := c.Increase(1, math.MaxUint64)

	require.Error(t, err) // requires wrapped error
	require.Equal(t, expected, c.Read())
}

//
// Decrease
//

// TestZeroedDecrease tests that the counter is not decreased when 0 is given.
func TestZeroedDecrease(t *testing.T) {
	expected := uint64(1)
	c := NewCounter(1)

	err := c.Decrease(0)

	require.NoError(t, err)
	require.Equal(t, expected, c.Read())
}

// TestDecreaseAndRead tests that the counter is decreased by 1 and returns the new value.
func TestDecreaseAndRead(t *testing.T) {
	expected := uint64(0)
	c := NewCounter(1)

	n, err := c.DecreaseAndRead()

	require.NoError(t, err)
	require.Equal(t, expected, n)
	require.Equal(t, expected, c.Read())
}

// TestDecrease tests that the counter is decreased by 1.
func TestDecrease(t *testing.T) {
	expected := uint64(0)
	c := NewCounter(1)

	err := c.Decrease()

	require.NoError(t, err)
	require.Equal(t, expected, c.Read())
}

// TestDecrease_MultipleThreads is a stress test to check thread safety for decreasing.
func TestDecrease_MultipleThreads(t *testing.T) {
	expected := uint64(1)
	c := NewCounter(100001)

	wg := sync.WaitGroup{}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			for j := 0; j < 1000; j++ {
				err := c.Decrease()
				if err != nil {
					wg.Done()
				}
				require.NoError(t, err)
			}
			wg.Done()
		}()
	}

	wg.Wait()

	require.Equal(t, expected, c.Read())
}

// TestDecreaseWrapErr tests that the counter wraps when it reaches the minimum value.
func TestDecreaseWrapErr(t *testing.T) {
	expected := uint64(math.MaxUint64)
	c := NewCounter(0)

	err := c.Decrease()

	require.Error(t, err) // requires wrapped error
	require.Equal(t, expected, c.Read())
}

// TestDecreaseMultiple tests that the counter is decreased by the given values.
func TestDecreaseMultiple(t *testing.T) {
	expected := uint64(0)
	c := NewCounter(1 + 2 + 3)

	err := c.Decrease(1, 2, 3)

	require.NoError(t, err)
	require.Equal(t, expected, c.Read())
}

// TestDecreaseMultipleSumWrapErr tests that the counter wraps when it reaches the minimum value.
func TestDecreaseMultipleSumWrapErr(t *testing.T) {
	expected := uint64(math.MaxUint64)
	c := NewCounter(math.MaxUint64)

	err := c.Decrease(1, math.MaxUint64)

	require.Error(t, err) // requires wrapped error
	require.Equal(t, expected, c.Read())
}

//
// Increase + Decrease
//

// TestIncreaseDecrease tests that the counter is increased and decreased by 1.
func TestIncreaseDecrease(t *testing.T) {
	expected := uint64(0)
	c := NewCounter(0)

	err := c.Increase()
	require.NoError(t, err)
	err = c.Decrease()
	require.NoError(t, err)

	require.Equal(t, expected, c.Read())
}

// TestIncreaseDecrease_MultipleThreads is a stress test to check thread safety.
func TestIncreaseDecrease_MultipleThreads(t *testing.T) {
	expected := uint64(0)
	c := NewCounter(0)

	wg := sync.WaitGroup{}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			for j := 0; j < 1000; j++ {
				err := c.Increase()
				require.NoError(t, err)
				err = c.Decrease()
				require.NoError(t, err)
			}
			wg.Done()
		}()
	}

	wg.Wait()

	require.Equal(t, expected, c.Read())
}
