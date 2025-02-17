package metrics

import (
	"encoding/json"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/aquasecurity/tracee/pkg/counter"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
)

type EventCollector struct {
	c *Collector[events.ID]
}

func NewEventCollector(description string, gv *prometheus.GaugeVec) *EventCollector {
	return &EventCollector{
		c: NewCollector[events.ID](description, gv),
	}
}

func (ec *EventCollector) Get(id events.ID) uint64 {
	v, ok := ec.c.Get(id)
	if !ok {
		logger.Errorw("Failed to get value from event collector", "event_id", id)
	}
	return v
}

func (ec *EventCollector) Set(id events.ID, v uint64) {
	ec.c.Set(id, v)
}

func (ec *EventCollector) Total() uint64 {
	return ec.c.Total()
}

func (ec *EventCollector) Reset() {
	ec.c.Reset()
}

func (ec *EventCollector) Description() string {
	return ec.c.Description()
}

func (ec *EventCollector) GaugeVec() *prometheus.GaugeVec {
	return ec.c.GaugeVec()
}

func (ec *EventCollector) Values() map[events.ID]uint64 {
	return ec.c.Values()
}

func (ec *EventCollector) Log() {
	values := ec.c.Values()
	description := ec.c.Description()

	keyVals := make([]interface{}, 0, len(values)*2+1)
	total := counter.NewCounter(0)
	for k, v := range values {
		keyVals = append(keyVals,
			events.Core.GetDefinitionByID(events.ID(k)).GetName(),
			v,
		)

		err := total.Increment(v)
		if err != nil {
			logger.Errorw("Failed to increment total counter", "error", err)
		}
	}

	// Log the counts
	keyVals = append(keyVals, "total", total.Get())
	logger.Infow(description, keyVals...)
}

// JSON marshaler interface

func (ec *EventCollector) MarshalJSON() ([]byte, error) {
	return json.Marshal(ec.Total())
}
