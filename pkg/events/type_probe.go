package events

import (
	"sync/atomic"

	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
)

type Probe struct {
	handle   *atomic.Uint32
	required *atomic.Bool // should tracee fail if probe fails to attach
}

// NewProbe creates a new ProbeDependency with default values.
func NewProbe(handle probes.Handle, required bool) *Probe {
	h := &atomic.Uint32{}
	r := &atomic.Bool{}

	h.Store(uint32(handle))
	r.Store(required)

	return &Probe{
		handle:   h,
		required: r,
	}
}

// GetHandle returns the handle of the probe (thread-safe).
func (p *Probe) GetHandle() probes.Handle {
	return probes.Handle(p.handle.Load())
}

// IsRequired returns true if the dependency is required (thread-safe).
func (p *Probe) IsRequired() bool {
	return p.required.Load()
}

// SetRequired sets the dependency as required (thread-safe).
func (p *Probe) SetRequired() {
	p.required.Store(true)
}

// SetNotRequired sets the dependency as not required (thread-safe).
func (p *Probe) SetNotRequired() {
	p.required.Store(false)
}
