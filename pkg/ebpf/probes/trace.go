package probes

import (
	"strings"
	"sync"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/extensions"
	"github.com/aquasecurity/tracee/pkg/logger"
)

// When attaching a traceProbe, by handle, to its eBPF program:
//
//   Handle == traceProbe (types: rawTracepoint, kprobe, kretprobe)
//
//     Attach(EventHandle)
//     Detach(EventHandle)
//
// to detach all probes:
//
//     DetachAll()

type ProbeType uint8

const (
	KProbe        = iota // github.com/iovisor/bcc/blob/master/docs/reference_guide.md#1-kp
	KretProbe            // github.com/iovisor/bcc/blob/master/docs/reference_guide.md#1-kp
	Tracepoint           // github.com/iovisor/bcc/blob/master/docs/reference_guide.md#3-tracep
	RawTracepoint        // github.com/iovisor/bcc/blob/master/docs/reference_guide.md#7-raw-tracep
)

func (p ProbeType) String() string {
	switch p {
	case KProbe:
		return "kprobe"
	case KretProbe:
		return "kretprobe"
	case Tracepoint:
		return "tracepoint"
	case RawTracepoint:
		return "raw_tracepoint"
	default:
		return "unknown"
	}
}

type TraceProbe struct {
	eventName   string
	programName string
	probeType   ProbeType
	bpfLink     []*bpf.BPFLink // same symbol might have multiple addresses
	attached    bool
	mutex       *sync.RWMutex
}

func NewTraceProbe(t ProbeType, evtName string, progName string) *TraceProbe {
	return &TraceProbe{
		programName: progName,
		eventName:   evtName,
		probeType:   t,
		mutex:       &sync.RWMutex{},
	}
}

func (p *TraceProbe) GetEventName() string {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.eventName
}

func (p *TraceProbe) GetProgramName() string {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.programName
}

func (p *TraceProbe) GetProbeType() ProbeType {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.probeType
}

func (p *TraceProbe) Attach(args ...interface{}) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.attached {
		return nil // already attached, it is ok to call attach again
	}

	prog, err := extensions.Modules.Get("core").GetProgram(p.programName)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// KProbe and KretProbe

	switch p.probeType {
	case KProbe, KretProbe:
		var err error
		var link *bpf.BPFLink
		var attachFunc func(uint64) (*bpf.BPFLink, error)
		// https://github.com/aquasecurity/tracee/issues/3653#issuecomment-1832642225
		//
		// After commit b022f0c7e404 ('tracing/kprobes: Return EADDRNOTAVAIL
		// when func matches several symbols') it is better to attach kprobes
		// using the address of the symbol instead of the name. This way in
		// older kernels tracee can be sure that the attachment wasn't made just
		// to the first address (if symbols has multiple addresses) and in newer
		// kernels it won't fail when trying to attach to a symbol that has
		// multiple addresses.
		//
		syms, err := kernelSymbolTable.GetSymbolByName(p.eventName)
		if err != nil {
			goto rollback
		}
		switch len(syms) {
		case 0:
			err = errfmt.Errorf("failed to get symbol address: %s (%v)", p.eventName, err)
			goto rollback
		case 1: // single address, attach kprobe using symbol name
			switch p.probeType {
			case KProbe:
				link, err = prog.AttachKprobe(syms[0].Name)
			case KretProbe:
				link, err = prog.AttachKretprobe(syms[0].Name)
			}
			if err != nil {
				goto rollback
			}
			p.bpfLink = append(p.bpfLink, link)
		default: // multiple addresses, attach kprobe using symbol addresses
			switch p.probeType {
			case KProbe:
				attachFunc = prog.AttachKprobeOffset
			case KretProbe:
				attachFunc = prog.AttachKretprobeOnOffset
			}
			for _, sym := range syms {
				link, err := attachFunc(sym.Address)
				if err != nil {
					goto rollback
				}
				p.bpfLink = append(p.bpfLink, link)
			}
		}
		goto success

	rollback: // rollback any successful attachments before the error
		if err != nil {
			logger.Debugw("failed to attach event", "event", p.eventName, "error", err)
			for _, link := range p.bpfLink {
				err = link.Destroy()
				if err != nil {
					logger.Debugw("failed to destroy link while detaching", "error", err)
				}
			}
			return errfmt.WrapError(err) // return original error
		}
	success:
		p.attached = true
		return nil
	}

	// Tracepoint and RawTracepoint

	var link *bpf.BPFLink
	switch p.probeType {
	case Tracepoint:
		tp := strings.Split(p.eventName, ":")
		tpClass := tp[0]
		tpEvent := tp[1]
		link, err = prog.AttachTracepoint(tpClass, tpEvent)
	case RawTracepoint:
		tpEvent := strings.Split(p.eventName, ":")[1]
		link, err = prog.AttachRawTracepoint(tpEvent)
	}
	if err != nil {
		return errfmt.Errorf("failed to attach event: %s (%v)", p.eventName, err)
	}
	p.bpfLink = append(p.bpfLink, link)
	p.attached = true
	return nil
}

func (p *TraceProbe) Detach(args ...interface{}) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if !p.attached {
		return nil
	}
	for _, link := range p.bpfLink {
		err := link.Destroy()
		if err != nil {
			return errfmt.Errorf("failed to detach event: %s (%v)", p.eventName, err)
		}
	}
	p.attached = false
	return nil
}

func (p *TraceProbe) SetAutoload(autoload bool) error {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return enableDisableAutoload(p.programName, autoload)
}
