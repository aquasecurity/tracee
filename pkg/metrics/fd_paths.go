package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/aquasecurity/tracee/common/counter"
	"github.com/aquasecurity/tracee/pkg/events"
)

// FDPathStats counts capture outcomes in decoded records, before event filtering.
// It does not account for records lost in the perf buffer.
type FDPathStats struct {
	Resolved     *counter.Counter `json:"Resolved"`
	Unavailable  *counter.Counter `json:"Unavailable"`
	ReadError    *counter.Counter `json:"ReadError"`
	StorageError *counter.Counter `json:"StorageError"`
	Truncated    *counter.Counter `json:"Truncated"`
}

func newFDPathStats() FDPathStats {
	return FDPathStats{
		Resolved: counter.NewCounter(0), Unavailable: counter.NewCounter(0),
		ReadError: counter.NewCounter(0), StorageError: counter.NewCounter(0),
		Truncated: counter.NewCounter(0),
	}
}

// Observe records expected misses separately from capture failures, without
// emitting one error log for every invalid descriptor or AT_FDCWD sentinel.
func (s *FDPathStats) Observe(status events.FDPathStatus) {
	var count *counter.Counter
	switch status {
	case events.FDPathResolved:
		count = s.Resolved
	case events.FDPathUnavailable:
		count = s.Unavailable
	case events.FDPathReadError:
		count = s.ReadError
	case events.FDPathStorageError:
		count = s.StorageError
	case events.FDPathTruncated:
		count = s.Truncated
	default:
		return
	}
	_ = count.Increment()
}

func (s *FDPathStats) registerPrometheus() error {
	for status, count := range map[string]*counter.Counter{
		"resolved": s.Resolved, "unavailable": s.Unavailable,
		"read_error": s.ReadError, "storage_error": s.StorageError,
		"truncated": s.Truncated,
	} {
		if err := prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
			Namespace: "tracee", Name: "fd_path_captures_total",
			Help:        "FD path capture outcomes in decoded events, before filtering",
			ConstLabels: prometheus.Labels{"status": status},
		}, func() float64 { return float64(count.Get()) })); err != nil {
			return err
		}
	}
	return nil
}
