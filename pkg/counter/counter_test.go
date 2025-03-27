package counter

import (
	"math"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCounter_Basic(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		initialValue  uint64
		increment     uint64
		decrement     uint64
		expectedValue uint64
		expectError   bool
	}{
		{
			name:          "basic increment and decrement",
			initialValue:  0,
			increment:     5,
			decrement:     2,
			expectedValue: 3,
			expectError:   false,
		},
		{
			name:          "increment only",
			initialValue:  10,
			increment:     5,
			decrement:     0,
			expectedValue: 15,
			expectError:   false,
		},
		{
			name:          "decrement only",
			initialValue:  10,
			increment:     0,
			decrement:     5,
			expectedValue: 5,
			expectError:   false,
		},
		{
			name:          "overflow test",
			initialValue:  math.MaxUint64 - 5,
			increment:     10,
			decrement:     0,
			expectedValue: 4,
			expectError:   true,
		},
		{
			name:          "underflow test",
			initialValue:  5,
			increment:     0,
			decrement:     10,
			expectedValue: math.MaxUint64 - 4,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := NewCounter(tt.initialValue)

			var err error
			if tt.increment > 0 {
				err = c.Increment(tt.increment)
				if tt.expectError {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
			}

			if tt.decrement > 0 {
				err = c.Decrement(tt.decrement)
				if tt.expectError {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
			}

			assert.Equal(t, tt.expectedValue, c.Get())
		})
	}
}

func TestCounter_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	c := NewCounter(0)
	var wg sync.WaitGroup
	numGoroutines := 100
	incrementsPerGoroutine := uint64(1000)

	// Test concurrent increments
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := uint64(0); j < incrementsPerGoroutine; j++ {
				err := c.Increment(1)
				assert.NoError(t, err)
			}
		}()
	}
	wg.Wait()

	expectedValue := uint64(numGoroutines) * incrementsPerGoroutine
	assert.Equal(t, expectedValue, c.Get())

	// Test concurrent decrements
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := uint64(0); j < incrementsPerGoroutine; j++ {
				err := c.Decrement(1)
				assert.NoError(t, err)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, uint64(0), c.Get())
}

func TestCounter_SetAndGet(t *testing.T) {
	t.Parallel()

	c := NewCounter(0)
	testValue := uint64(42)

	c.Set(testValue)
	assert.Equal(t, testValue, c.Get())
}

func TestCounter_MultipleIncrements(t *testing.T) {
	t.Parallel()

	c := NewCounter(0)
	err := c.Increment(1, 2, 3, 4, 5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(15), c.Get())
}

func TestCounter_MultipleDecrements(t *testing.T) {
	t.Parallel()

	c := NewCounter(20)
	err := c.Decrement(1, 2, 3, 4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(10), c.Get())
}
