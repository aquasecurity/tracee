package counter

import (
	"fmt"
	"sync"
)

type Average struct {
	sum Counter
	c   Counter
	m   *sync.RWMutex
}

func NewAverage() Average {
	return Average{
		sum: NewCounter(0),
		c:   NewCounter(0),
		m:   new(sync.RWMutex),
	}
}

func (avg *Average) Read() float64 {
	avg.m.RLock()
	defer avg.m.RUnlock()

	sum := float64(avg.sum.Get())
	count := float64(avg.c.Get())

	return sum / count
}

func (avg *Average) Add(val uint64) error {
	_, err := avg.AddAndRead(val)
	return err
}

func (avg *Average) AddAndRead(val uint64) (float64, error) {
	avg.m.Lock()
	defer avg.m.Unlock()

	sum, err := avg.sum.IncrementValueAndRead(val)
	if err != nil {
		return 0, fmt.Errorf("failed to increment average sum: %v", err)
	}
	count, err := avg.c.IncrementValueAndRead(1)
	if err != nil {
		return 0, fmt.Errorf("failed to increment average count: %v", err)
	}

	return float64(sum) / float64(count), nil
}

func (avg Average) String() string {
	return fmt.Sprintf("%f", avg.Read())
}
