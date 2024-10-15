package metrics

import (
	"maps"
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/aquasecurity/tracee/pkg/counter"
	"github.com/aquasecurity/tracee/pkg/logger"
)

type Collector[K comparable] struct {
	m           sync.RWMutex
	description string
	values      map[K]uint64
	gaugeVec    *prometheus.GaugeVec
}

func NewCollector[K comparable](description string, gv *prometheus.GaugeVec) *Collector[K] {
	return &Collector[K]{
		m:           sync.RWMutex{},
		description: description,
		values:      make(map[K]uint64),
		gaugeVec:    gv,
	}
}

func (c *Collector[K]) Get(k K) (uint64, bool) {
	c.m.RLock()
	defer c.m.RUnlock()

	v, ok := c.values[k]
	return v, ok
}

func (c *Collector[K]) Set(k K, v uint64) {
	c.m.Lock()
	defer c.m.Unlock()

	c.values[k] = v
}

func (c *Collector[K]) Total() uint64 {
	c.m.RLock()
	defer c.m.RUnlock()

	total := counter.NewCounter(0)
	for _, v := range c.values {
		err := total.Increment(v)
		if err != nil {
			logger.Errorw("Failed to increment total counter", "error", err)
		}
	}

	return total.Get()
}

func (c *Collector[K]) Reset() {
	c.m.Lock()
	defer c.m.Unlock()

	c.values = make(map[K]uint64)
}

func (c *Collector[K]) Description() string {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.description
}

func (c *Collector[K]) GaugeVec() *prometheus.GaugeVec {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.gaugeVec
}

func (c *Collector[K]) Values() map[K]uint64 {
	c.m.RLock()
	defer c.m.RUnlock()

	return maps.Clone(c.values)
}
