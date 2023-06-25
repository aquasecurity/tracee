package counter

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"sync/atomic"
)

type Counter struct {
	value uint64
}

// NewCounter creates a new counter with the given initial value.
func NewCounter(initialValue uint64) Counter {
	return Counter{value: initialValue}
}

// Increase increases the counter by the given value (thread-safe).
func (c *Counter) Increase(values ...uint64) error {
	if len(values) == 0 {
		values = append(values, 1)
	}

	for _, value := range values {
		if atomic.AddUint64(&c.value, value) < value {
			return errors.New("counter overflow")
		}
	}

	return nil
}

// Decrease decreases the counter by the given value (thread-safe).
func (c *Counter) Decrease(values ...uint64) error {
	if len(values) == 0 {
		values = append(values, 1)
	}

	for _, value := range values {
		if value == 0 {
			continue
		}
		if atomic.AddUint64(&c.value, ^uint64(value-1)) == math.MaxUint64 {
			return errors.New("counter underflow")
		}
	}

	return nil
}

// Read returns the current value of the counter (thread-safe).
func (c *Counter) Read() uint64 {
	return atomic.LoadUint64(&c.value)
}

// Set sets the counter to the given value (thread-safe).
func (c *Counter) Set(value uint64) {
	atomic.StoreUint64(&c.value, value)
}

// Format implements fmt.Formatter (thread-safe).
func (c *Counter) Format(f fmt.State, r rune) {
	f.Write([]byte(strconv.FormatUint(c.Read(), 10)))
}
