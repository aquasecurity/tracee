package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

//This function takes a pointer to a stats struct, it can be exported through the relevant .Stats() method
func RegisterPrometheus(stats *Stats) error {
	err := prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_rules",
		Name:      "events_total",
		Help:      "events ingested by tracee-rules",
	}, func() float64 { return float64(stats.Events.Read()) }))

	if err != nil {
		return err
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_rules",
		Name:      "detections_total",
		Help:      "detections made by tracee-rules",
	}, func() float64 { return float64(stats.Detections.Read()) }))

	if err != nil {
		return err
	}

	err = prometheus.Register(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: "tracee_rules",
		Name:      "signatures_total",
		Help:      "signatures loaded",
	}, func() float64 { return float64(stats.Signatures.Read()) }))

	if err != nil {
		return err
	}

	return nil
}
