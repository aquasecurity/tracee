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

func NewCounter(initialValue uint64) Counter {
	return Counter{value: initialValue}
}

// Increment

// Increment increments counter by given value (default: 1, thread-safe).
func (c *Counter) Increment(x ...uint64) error {
	var err error

	val := uint64(1)
	if len(x) != 0 {
		for _, v := range x {
			val += v
		}
		val-- // initial 1
	}

	// NOTE: checking if val > 0 adds ~200ns/op in benchmarking: not worth if
	//       not proved that amount of times Increment(0) is called makes it
	//       worth it.
	_, err = c.IncrementValueAndRead(val)

	return err
}

// IncrementValueAndRead increments counter by given value and returns the new value (thread-safe).
func (c *Counter) IncrementValueAndRead(x uint64) (uint64, error) {
	var err error

	n := atomic.AddUint64(&c.value, x)
	if n < x {
		err = errors.New("counter overflow")
	}

	return n, err
}

// Decrement

// Decrement decrements counter by given value (default: 1, thread-safe).
func (c *Counter) Decrement(x ...uint64) error {
	val := uint64(1)
	if len(x) != 0 {
		for _, v := range x {
			val += v
		}
		val-- // initial 1
	}

	// NOTE: checking if val > 0 adds ~200ns/op in benchmarking: not worth if
	//       not proved that amount of times Decrement(0) is called makes it
	//       worth it.
	_, err := c.DecrementValueAndRead(val)

	return err
}

// DecrementValueAndRead decrements counter by given value and returns the new value (thread-safe).
func (c *Counter) DecrementValueAndRead(x uint64) (uint64, error) {
	var err error

	n := atomic.AddUint64(&c.value, ^uint64(x-1))
	if n > math.MaxUint64-x {
		err = errors.New("counter underflow")
	}

	return n, err
}

// Setters and Getters

func (c *Counter) Set(value uint64) {
	atomic.StoreUint64(&c.value, value)
}

func (c *Counter) Get() uint64 {
	return atomic.LoadUint64(&c.value)
}

func (c *Counter) Format(f fmt.State, r rune) {
	f.Write([]byte(strconv.FormatUint(c.Get(), 10)))
}
