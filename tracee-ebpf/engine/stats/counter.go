package stats

import "sync/atomic"

type Store struct {
	EventCounter  counter
	ErrorCounter  counter
	LostEvCounter counter
	LostWrCounter counter
}

type counter int32

func (c *counter) Increment(amount ...int) {
	sum := 1
	if len(amount) > 0 {
		sum = 0
		for _, a := range amount {
			sum = sum + a
		}
	}
	atomic.AddInt32((*int32)(c), int32(sum))
}
