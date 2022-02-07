package counter

import "sync/atomic"

type Counter int32

func (c *Counter) Increment(amount ...int) {
	sum := 1
	if len(amount) > 0 {
		sum = 0
		for _, a := range amount {
			sum = sum + a
		}
	}
	atomic.AddInt32((*int32)(c), int32(sum))
}

func (c *Counter) Decrement(amount ...int) {
	sum := -1
	if len(amount) > 0 {
		sum = 0
		for _, a := range amount {
			sum = sum - a
		}
	}
	atomic.AddInt32((*int32)(c), int32(sum))
}

func (c *Counter) Read() int32 {
	return atomic.LoadInt32((*int32)(c))
}
