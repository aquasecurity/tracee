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

	// NOTE: BPFPerfEventSubmit* metrics are periodically collected from the 'events_stats'
	// BPF map, while userspace metrics are continuously updated within the application
	// based on varying logic. Due to differences in data sources and collection timing,
	// the two sets of metrics are not directly synchronized. As a result, the total event
	// counts fetched from 'events_stats' may not align with those reported by userspace metrics.
	// Each metric set is designed to provide distinct insights and should be analyzed
	// independently, without direct comparison.
	BPFPerfEventSubmitAttemptsCount *EventCollector
	BPFPerfEventSubmitFailuresCount *EventCollector
}

func NewStats() *Stats {
	return &Stats{
		EventCount:       counter.NewCounter(0),
		EventsFiltered:   counter.NewCounter(0),
		NetCapCount:      counter.NewCounter(0),
		BPFLogsCount:     counter.NewCounter(0),
		ErrorCount:       counter.NewCounter(0),
		LostEvCount:      counter.NewCounter(0),
		LostWrCount:      counter.NewCounter(0),
		LostNtCapCount:   counter.NewCounter(0),
		LostBPFLogsCount: counter.NewCounter(0),
		BPFPerfEventSubmitAttemptsCount: NewEventCollector(
			"Event submit attempts",
			prometheus.NewGaugeVec(
				prometheus.GaugeOpts{
					Namespace: "tracee_ebpf",
					Name:      "bpf_perf_event_submit_attempts",
					Help:      "calls to submit to the event perf buffer",
				},
				[]string{"event_name"},
			),
		),
		BPFPerfEventSubmitFailuresCount: NewEventCollector(
			"Event submit failures",
			prometheus.NewGaugeVec(
				prometheus.GaugeOpts{
					Namespace: "tracee_ebpf",
					Name:      "bpf_perf_event_submit_failures",
					Help:      "failed calls to submit to the event perf buffer",
				},
				[]string{"event_name"},
			),
		),
	}
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
		Name:      "bpf_logs_total",
		Help:      "logs collected by tracee-ebpf during ebpf execution",
	}, func() float64 { return float64(stats.BPFLogsCount.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Updated by countPerfEventSubmissions() goroutine
	err = prometheus.Register(stats.BPFPerfEventSubmitAttemptsCount.GaugeVec())
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Updated by countPerfEventSubmissions() goroutine
	err = prometheus.Register(stats.BPFPerfEventSubmitFailuresCount.GaugeVec())
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "errors_total",
		Help:      "errors accumulated by tracee-ebpf",
	}, func() float64 { return float64(stats.ErrorCount.Get()) }))
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

	return errfmt.WrapError(err)
}
