package counter

import (
	"fmt"
	"strconv"
	"sync/atomic"

	"github.com/aquasecurity/tracee/pkg/errfmt"
)

type Counter struct {
	count uint64
}

func NewCounter(v uint64) Counter {
	return Counter{
		count: v,
	}
}

func (c *Counter) Increment(amount ...uint64) error {
	if len(amount) == 0 {
		return c.incAtomic(1)
	}

	sum, err := sumUint64(amount...)
	if err != nil {
		return errfmt.WrapError(err)
	}

	return c.incAtomic(sum)
}

func (c *Counter) Decrement(amount ...uint64) error {
	if len(amount) == 0 {
		return c.decAtomic(1)
	}

	sum, err := sumUint64(amount...)
	if err != nil {
		return errfmt.WrapError(err)
	}

	return c.decAtomic(sum)
}

func (c *Counter) Read() uint64 {
	return atomic.LoadUint64(&c.count)
}

func (c *Counter) Set(val uint64) {
	atomic.StoreUint64(&c.count, val)
}

func (c Counter) Format(f fmt.State, r rune) {
	f.Write([]byte(strconv.FormatUint(c.count, 10)))
}

func (c *Counter) incAtomic(v uint64) error {
	if (v + c.count) < c.count {
		return errorCounterWrapAround()
	}
	atomic.AddUint64(&c.count, v)

	return nil
}

func (c *Counter) decAtomic(v uint64) error {
	v = ^uint64(v - 1)
	if (v + c.count) > c.count {
		return errorCounterWrapAround()
	}
	atomic.AddUint64(&c.count, v)

	return nil
}

func sumUint64(values ...uint64) (uint64, error) {
	sum := uint64(0)
	for _, v := range values {
		sum += v
		if sum < v {
			return 0, errorCounterSumWrapAround()
		}
	}

	return sum, nil
}

func errorCounterWrapAround() error {
	return errfmt.Errorf("counter: wrap around")
}

func errorCounterSumWrapAround() error {
	return errfmt.Errorf("counter sum: wrap around")
}
