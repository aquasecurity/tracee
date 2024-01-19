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
	probes map[Handle]Probe
}

func NewProbes(m *bpf.Module, p map[Handle]Probe) *Probes {
	return &Probes{
		mutex:  &sync.RWMutex{},
		probes: p,
		module: m,
	}
}

func (p *Probes) GetProbeType(handle Handle) string {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	if r, ok := p.probes[handle]; ok {
		if probe, ok := r.(*TraceProbe); ok {
			switch probe.probeType {
			case KProbe:
				return "kprobe"
			case KretProbe:
				return "kretprobe"
			case Tracepoint:
				return "tracepoint"
			case RawTracepoint:
				return "raw_tracepoint"
			}
		}
	}

	return ""
}

func (p *Probes) Attach(handle Handle, args ...interface{}) error {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	if _, ok := p.probes[handle]; !ok {
		return errfmt.Errorf("probe handle (%d) does not exist", handle)
	}

	return p.probes[handle].attach(p.module, args...)
}

func (p *Probes) Detach(handle Handle, args ...interface{}) error {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	if _, ok := p.probes[handle]; !ok {
		return errfmt.Errorf("probe handle (%d) does not exist", handle)
	}

	return p.probes[handle].detach(args...)
}

func (p *Probes) DetachAll() error {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	for _, pr := range p.probes {
		err := pr.detach()
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}

func (p *Probes) Autoload(handle Handle, autoload bool) error {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	return p.probes[handle].autoload(p.module, autoload)
}

func (p *Probes) GetProbeByHandle(handle Handle) Probe {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	return p.probes[handle]
}
