package metrics

import "github.com/aquasecurity/tracee/pkg/counter"

type Stats struct {
	EventCount  counter.Counter
	NetEvCount  counter.Counter
	ErrorCount  counter.Counter
	LostEvCount counter.Counter
	LostWrCount counter.Counter
	LostNtCount counter.Counter
}
