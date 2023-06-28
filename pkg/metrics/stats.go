package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/aquasecurity/tracee/pkg/counter"
	"github.com/aquasecurity/tracee/pkg/errfmt"
)

// When updating this struct, please make sure to update the relevant exporting functions
type Stats struct {
	EventCount       counter.Counter
	EventsFiltered   counter.Counter
	NetCapCount      counter.Counter // network capture events
	BPFLogsCount     counter.Counter
	ErrorCount       counter.Counter
	LostEvCount      counter.Counter
	LostWrCount      counter.Counter
	LostNtCapCount   counter.Counter // lost network capture events
	LostBPFLogsCount counter.Counter
}

// Register Stats to prometheus metrics exporter
func (stats *Stats) RegisterPrometheus() error {
	err := prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "events_total",
		Help:      "events collected by tracee-ebpf",
	}, func() float64 { return float64(stats.EventCount.Get()) }))

	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "events_filtered",
		Help:      "events filtered by tracee-ebpf in userspace",
	}, func() float64 { return float64(stats.EventsFiltered.Get()) }))

	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "network_capture_events_total",
		Help:      "network capture events collected by tracee-ebpf",
	}, func() float64 { return float64(stats.NetCapCount.Get()) }))

	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "lostevents_total",
		Help:      "events lost in the submission buffer",
	}, func() float64 { return float64(stats.LostEvCount.Get()) }))

	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "write_lostevents_total",
		Help:      "events lost in the write buffer",
	}, func() float64 { return float64(stats.LostWrCount.Get()) }))

	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "network_capture_lostevents_total",
		Help:      "network capture lost events in network capture buffer",
	}, func() float64 { return float64(stats.LostNtCapCount.Get()) }))

	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "bpf_logs_total",
		Help:      "logs collected by tracee-ebpf during ebpf execution",
	}, func() float64 { return float64(stats.BPFLogsCount.Get()) }))

	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "errors_total",
		Help:      "errors accumulated by tracee-ebpf",
	}, func() float64 { return float64(stats.ErrorCount.Get()) }))

	return errfmt.WrapError(err)
}
