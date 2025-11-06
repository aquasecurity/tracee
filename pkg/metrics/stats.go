package metrics

import (
	"encoding/binary"
	"encoding/json"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/common/counter"
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/version"
	"github.com/aquasecurity/tracee/types/trace"
)

// BPFPerfEventCollector is a custom Prometheus collector that reads from BPF maps on-demand
type BPFPerfEventCollector struct {
	attemptsDesc      *prometheus.Desc
	failuresDesc      *prometheus.Desc
	perfEventStatsMap *bpf.BPFMap
}

// NewBPFPerfEventCollector creates a new on-demand BPF perf event collector
func NewBPFPerfEventCollector(perfEventStatsMap *bpf.BPFMap) *BPFPerfEventCollector {
	return &BPFPerfEventCollector{
		attemptsDesc: prometheus.NewDesc(
			"tracee_bpf_perf_event_submit_attempts",
			"calls to submit to the event perf buffer",
			[]string{"event_name", "internal"},
			nil,
		),
		failuresDesc: prometheus.NewDesc(
			"tracee_bpf_perf_event_submit_failures",
			"failed calls to submit to the event perf buffer",
			[]string{"event_name", "internal"},
			nil,
		),
		perfEventStatsMap: perfEventStatsMap,
	}
}

// Describe implements prometheus.Collector
func (c *BPFPerfEventCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.attemptsDesc
	ch <- c.failuresDesc
}

// Collect implements prometheus.Collector - this is called when Prometheus scrapes
func (c *BPFPerfEventCollector) Collect(ch chan<- prometheus.Metric) {
	if c.perfEventStatsMap == nil {
		return // No metrics if map unavailable
	}

	// Iterate through the BPF map and collect metrics
	iter := c.perfEventStatsMap.Iterator()
	for iter.Next() {
		key := binary.LittleEndian.Uint32(iter.Key())
		value, err := c.perfEventStatsMap.GetValue(unsafe.Pointer(&key))
		if err != nil {
			continue
		}

		id := events.ID(key)
		attempts := binary.LittleEndian.Uint64(value[0:8])
		failures := binary.LittleEndian.Uint64(value[8:16])

		evtDef := events.Core.GetDefinitionByID(id)
		evtName := evtDef.GetName()
		isInternal := "false"
		if evtDef.IsInternal() {
			isInternal = "true"
		}

		// Create and send metrics
		ch <- prometheus.MustNewConstMetric(
			c.attemptsDesc,
			prometheus.GaugeValue,
			float64(attempts),
			evtName, isInternal,
		)
		ch <- prometheus.MustNewConstMetric(
			c.failuresDesc,
			prometheus.GaugeValue,
			float64(failures),
			evtName, isInternal,
		)
	}
}

// When updating this struct, please make sure to update the relevant exporting functions
type Stats struct {
	EventCount       *counter.Counter `json:"EventCount"`
	EventsFiltered   *counter.Counter `json:"EventsFiltered"`
	NetCapCount      *counter.Counter `json:"NetCapCount"` // network capture events
	BPFLogsCount     *counter.Counter `json:"BPFLogsCount"`
	ErrorCount       *counter.Counter `json:"ErrorCount"`
	LostEvCount      *counter.Counter `json:"LostEvCount"`
	LostWrCount      *counter.Counter `json:"LostWrCount"`
	LostNtCapCount   *counter.Counter `json:"LostNtCapCount"` // lost network capture events
	LostBPFLogsCount *counter.Counter `json:"LostBPFLogsCount"`

	// BPF map for on-demand perf event stats collection (METRICS build only)
	perfEventStatsMap *bpf.BPFMap

	Channels ChannelMetrics[*trace.Event] `json:"ChannelMetrics"`
}

func NewStats() *Stats {
	stats := &Stats{
		EventCount:       counter.NewCounter(0),
		EventsFiltered:   counter.NewCounter(0),
		NetCapCount:      counter.NewCounter(0),
		BPFLogsCount:     counter.NewCounter(0),
		ErrorCount:       counter.NewCounter(0),
		LostEvCount:      counter.NewCounter(0),
		LostWrCount:      counter.NewCounter(0),
		LostNtCapCount:   counter.NewCounter(0),
		LostBPFLogsCount: counter.NewCounter(0),
		Channels:         make(ChannelMetrics[*trace.Event]),
	}

	return stats
}

// SetPerfEventStatsMap sets the BPF map for on-demand perf event stats collection
func (s *Stats) SetPerfEventStatsMap(perfEventStatsMap *bpf.BPFMap) {
	s.perfEventStatsMap = perfEventStatsMap
}

// BPFPerfEventStats holds the BPF perf event stats
type BPFPerfEventStats struct {
	Attempts map[events.ID]uint64
	Failures map[events.ID]uint64
}

// GetBPFPerfEventStats returns the BPF perf event stats
func (s *Stats) GetBPFPerfEventStats() BPFPerfEventStats {
	result := BPFPerfEventStats{
		Attempts: make(map[events.ID]uint64),
		Failures: make(map[events.ID]uint64),
	}

	if s.perfEventStatsMap == nil {
		return result // needed for grpc server
	}

	iter := s.perfEventStatsMap.Iterator()
	for iter.Next() {
		key := binary.LittleEndian.Uint32(iter.Key())
		value, err := s.perfEventStatsMap.GetValue(unsafe.Pointer(&key))
		if err != nil {
			logger.Errorw("failed to get value from perf event stats map", "error", err)
			continue
		}

		id := events.ID(key)
		result.Attempts[id] = binary.LittleEndian.Uint64(value[0:8])  // attempts
		result.Failures[id] = binary.LittleEndian.Uint64(value[8:16]) // failures
	}

	return result
}

// Register Stats to prometheus metrics exporter
func (s *Stats) RegisterPrometheus() error {
	err := prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee",
		Name:      "events_total",
		Help:      "events collected by tracee",
	}, func() float64 { return float64(s.EventCount.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee",
		Name:      "events_filtered",
		Help:      "events filtered by tracee in userspace",
	}, func() float64 { return float64(s.EventsFiltered.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee",
		Name:      "network_capture_events_total",
		Help:      "network capture events collected by tracee",
	}, func() float64 { return float64(s.NetCapCount.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee",
		Name:      "bpf_logs_total",
		Help:      "logs collected by tracee during ebpf execution",
	}, func() float64 { return float64(s.BPFLogsCount.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	if version.MetricsBuild() && s.perfEventStatsMap != nil {
		// Register custom collector for on-demand BPF perf event metrics
		collector := NewBPFPerfEventCollector(s.perfEventStatsMap)
		err = prometheus.Register(collector)
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee",
		Name:      "errors_total",
		Help:      "errors accumulated by tracee",
	}, func() float64 { return float64(s.ErrorCount.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee",
		Name:      "lostevents_total",
		Help:      "events lost in the submission buffer",
	}, func() float64 { return float64(s.LostEvCount.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee",
		Name:      "write_lostevents_total",
		Help:      "events lost in the write buffer",
	}, func() float64 { return float64(s.LostWrCount.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee",
		Name:      "network_capture_lostevents_total",
		Help:      "network capture lost events in network capture buffer",
	}, func() float64 { return float64(s.LostNtCapCount.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = s.Channels.RegisterChannels()
	if err != nil {
		return errfmt.WrapError(err)
	}

	return nil
}

// ShouldTrackEventForBPFStats determines if an event should be tracked for BPF stats collection.
func (s *Stats) ShouldTrackEventForBPFStats(id events.ID) bool {
	// Track common events (core and extended)
	if id >= events.StartCommonID && id <= events.MaxCommonExtendedID {
		return true
	}
	// Track signal events (core and extended)
	if id >= events.StartSignalID && id <= events.MaxSignalExtendedID {
		return true
	}
	// Track test events
	if id >= events.StartTestID && id <= events.MaxTestID {
		return true
	}

	// Exclude everything else:
	// - Userspace-derived events (core and extended)
	// - Capture events
	// - Signature events (core and extended)
	return false
}

// JSON marshaler interface

func (s *Stats) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Stats Stats `json:"Stats"`
	}{Stats: *s})
}
