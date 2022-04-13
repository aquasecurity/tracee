package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

//This function takes a pointer to a stats struct, it can be exported through the relevant .Stats() method
func RegisterPrometheus(stats *Stats) error {
	err := prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "events_total",
		Help:      "events collected by tracee-ebpf",
	}, func() float64 { return float64(stats.EventCount.Read()) }))

	if err != nil {
		return err
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "lostevents_total",
		Help:      "events lost in the submission buffer",
	}, func() float64 { return float64(stats.LostEvCount.Read()) }))

	if err != nil {
		return err
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "write_lostevents_total",
		Help:      "events lost in the write buffer",
	}, func() float64 { return float64(stats.LostWrCount.Read()) }))

	if err != nil {
		return err
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "network_lostevents_total",
		Help:      "events lost in the network buffer",
	}, func() float64 { return float64(stats.LostNtCount.Read()) }))

	if err != nil {
		return err
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "errors_total",
		Help:      "errors accumulated by tracee-ebpf",
	}, func() float64 { return float64(stats.ErrorCount.Read()) }))

	if err != nil {
		return err
	}

	return nil
}
