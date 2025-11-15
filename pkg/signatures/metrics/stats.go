package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/aquasecurity/tracee/common/counter"
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
		Namespace: "tracee",
		Name:      "signatures_events_total",
		Help:      "events ingested by signature engine",
	}, func() float64 { return float64(stats.Events.Get()) }))

	if err != nil {
		return err
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee",
		Name:      "signatures_detections_total",
		Help:      "detections made by signatures",
	}, func() float64 { return float64(stats.Detections.Get()) }))

	if err != nil {
		return err
	}

	err = prometheus.Register(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: "tracee",
		Name:      "signatures_total",
		Help:      "signatures loaded",
	}, func() float64 { return float64(stats.Signatures.Get()) }))

	if err != nil {
		return err
	}

	return nil
}
