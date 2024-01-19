package probes

import (
	"sync"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/errfmt"
)

var kernelSymbolTable *helpers.KernelSymbolTable

type Probes struct {
	mutex  *sync.RWMutex
	module *bpf.Module
	probes map[ProbeHandle]Probe // Probe is an interface, thus a reference type
}

// NewProbes creates a new Probes object.
func NewProbes(m *bpf.Module, p map[ProbeHandle]Probe) *Probes {
	return &Probes{
		mutex:  &sync.RWMutex{},
		probes: p,
		module: m,
	}
}

// AddProbe adds a probe to the Probes object.
func (p *Probes) AddProbe(handle ProbeHandle, probe Probe) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.probes[handle] = probe
}

// RemoveProbe removes a probe from the Probes object.
func (p *Probes) RemoveProbe(handle ProbeHandle) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	delete(p.probes, handle)
}

// GetProbeByHandle returns a probe by its handle.
func (p *Probes) GetProbeByHandle(handle ProbeHandle) Probe {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.probes[handle]
}

// GetProbes returns a map of all probes.
func (p *Probes) GetProbes() map[ProbeHandle]Probe {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	newMap := make(map[ProbeHandle]Probe)
	for k, v := range p.probes {
		newMap[k] = v
	}
	return newMap
}

// AttachProbeByHandle attaches a probe by its handle.
func (p *Probes) AttachProbeByHandle(handle ProbeHandle, args ...interface{}) error {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	if _, ok := p.probes[handle]; !ok {
		return errfmt.Errorf("probe handle (%d) does not exist", handle)
	}

	return p.probes[handle].Attach(p.module, args...)
}

// DetachProbeByHandle detaches a probe by its handle.
func (p *Probes) DetachProbeByHandle(handle ProbeHandle, args ...interface{}) error {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	if _, ok := p.probes[handle]; !ok {
		return errfmt.Errorf("probe handle (%d) does not exist", handle)
	}

	return p.probes[handle].Detach(args...)
}

// AttachAll attaches all probes.
func (p *Probes) AttachAll() error {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	for _, pr := range p.probes {
		err := pr.Attach(p.module)
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}

// DetachAll detaches all probes.
func (p *Probes) DetachAll() error {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	for _, pr := range p.probes {
		err := pr.Detach()
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}

// SetAutoloadByHandle sets the autoload flag of a probe by its handle.
func (p *Probes) SetAutoloadByHandle(handle ProbeHandle, autoload bool) error {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.probes[handle].SetAutoload(p.module, autoload)
}
