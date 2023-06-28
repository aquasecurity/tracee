package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/aquasecurity/tracee/pkg/counter"
)

// When updating this struct, please make sure to update the relevant exporting functions
type Stats struct {
	Events     counter.Counter
	Signatures counter.Counter
	Detections counter.Counter
}

// Register Stats to prometheus metrics exporter
func (stats *Stats) RegisterPrometheus() error {
	err := prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_rules",
		Name:      "events_total",
		Help:      "events ingested by tracee-rules",
	}, func() float64 { return float64(stats.Events.Get()) }))

	if err != nil {
		return err
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_rules",
		Name:      "detections_total",
		Help:      "detections made by tracee-rules",
	}, func() float64 { return float64(stats.Detections.Get()) }))

	if err != nil {
		return err
	}

	err = prometheus.Register(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: "tracee_rules",
		Name:      "signatures_total",
		Help:      "signatures loaded",
	}, func() float64 { return float64(stats.Signatures.Get()) }))

	if err != nil {
		return err
	}

	return nil
}
