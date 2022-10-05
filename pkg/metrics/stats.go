package metrics

import (
	"github.com/aquasecurity/tracee/pkg/counter"
	"github.com/prometheus/client_golang/prometheus"
)

// When updating this struct, please make sure to update the relevant exporting functions
type Stats struct {
	EventCount     counter.Counter
	EventsFiltered counter.Counter
	NetEvCount     counter.Counter
	ErrorCount     counter.Counter
	LostEvCount    counter.Counter
	LostWrCount    counter.Counter
	LostNtCount    counter.Counter
}

// Register Stats to prometheus metrics exporter
func (stats *Stats) RegisterPrometheus() error {
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
		Name:      "events_filtered",
		Help:      "events filtered by tracee-ebpf in userspace",
	}, func() float64 { return float64(stats.EventsFiltered.Read()) }))

	if err != nil {
		return err
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "netevents_total",
		Help:      "net events collected by tracee-ebpf",
	}, func() float64 { return float64(stats.NetEvCount.Read()) }))

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

	return err
}
