package metrics

import "github.com/aquasecurity/tracee/pkg/counter"

type Stats struct {
	Events     counter.Counter
	Signatures counter.Counter
	Detections counter.Counter
}
