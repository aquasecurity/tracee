package detectors

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics tracks detector performance and activity
type Metrics struct {
	// EventsProcessed counts events dispatched to detectors (per-detector)
	EventsProcessed *prometheus.CounterVec

	// EventsProduced counts events produced by detectors (per-detector)
	EventsProduced *prometheus.CounterVec

	// Errors counts errors during detector execution (per-detector)
	Errors *prometheus.CounterVec

	// ExecutionDuration tracks detector execution time distribution (per-detector)
	ExecutionDuration *prometheus.HistogramVec

	// ChainDepthExceeded counts when max chain depth is exceeded (should be 0)
	ChainDepthExceeded prometheus.Counter
}

// NewMetrics creates a new Metrics instance
func NewMetrics() *Metrics {
	return &Metrics{
		EventsProcessed: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "tracee_detectors",
				Name:      "events_processed_total",
				Help:      "Total number of events processed by detectors",
			},
			[]string{"detector_id"},
		),
		EventsProduced: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "tracee_detectors",
				Name:      "events_produced_total",
				Help:      "Total number of events produced by detectors",
			},
			[]string{"detector_id"},
		),
		Errors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "tracee_detectors",
				Name:      "errors_total",
				Help:      "Total number of errors during detector execution",
			},
			[]string{"detector_id"},
		),
		ExecutionDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "tracee_detectors",
				Name:      "execution_duration_seconds",
				Help:      "Time spent executing detectors in seconds",
				// Fast (<50μs), Normal (<100μs), Slow (<1ms), Critical (>1ms)
				Buckets: []float64{0.00005, 0.0001, 0.001},
			},
			[]string{"detector_id"},
		),
		ChainDepthExceeded: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "tracee_detectors",
				Name:      "chain_depth_exceeded_total",
				Help:      "Number of times max detector chain depth was exceeded (should always be 0)",
			},
		),
	}
}

// RegisterPrometheus registers detector metrics with Prometheus
func (m *Metrics) RegisterPrometheus() error {
	// Per-detector metrics
	if err := prometheus.Register(m.EventsProcessed); err != nil {
		return err
	}

	if err := prometheus.Register(m.EventsProduced); err != nil {
		return err
	}

	if err := prometheus.Register(m.Errors); err != nil {
		return err
	}

	if err := prometheus.Register(m.ExecutionDuration); err != nil {
		return err
	}

	// Chain depth safety counter
	return prometheus.Register(m.ChainDepthExceeded)
}
