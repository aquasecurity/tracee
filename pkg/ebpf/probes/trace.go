package probes

import (
	"strings"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils/environment"
)

// NOTE: thread-safety guaranteed by the ProbeGroup big lock.

//
// traceProbe
//

type ProbeType uint8

const (
	KProbe        = iota // github.com/iovisor/bcc/blob/master/docs/reference_guide.md#1-kp
	KretProbe            // github.com/iovisor/bcc/blob/master/docs/reference_guide.md#1-kp
	Tracepoint           // github.com/iovisor/bcc/blob/master/docs/reference_guide.md#3-tracep
	RawTracepoint        // github.com/iovisor/bcc/blob/master/docs/reference_guide.md#7-raw-tracep
	SyscallEnter
	SyscallExit
	InvalidProbeType
)

func (t ProbeType) String() string {
	switch t {
	case KProbe:
		return "kprobe"
	case KretProbe:
		return "kretprobe"
	case Tracepoint:
		return "tracepoint"
	case RawTracepoint:
		return "raw_tracepoint"
	case SyscallEnter:
		return "syscall_enter"
	case SyscallExit:
		return "syscall_exit"
	}

	return "invalid"
}

// When attaching a traceProbe, by handle, to its eBPF program:
//
//   Handle == traceProbe (types: rawTracepoint, kprobe, kretprobe, syscallEnter, syscallExit)
//
//     Attach(EventHandle)
//     Detach(EventHandle)
//
// to detach all probes:
//
//     DetachAll()

type TraceProbe struct {
	eventName   string
	programName string
	probeType   ProbeType
	bpfLink     []*bpf.BPFLink // same symbol might have multiple addresses
	attached    bool
}

// NewTraceProbe creates a new tracing probe (kprobe, kretprobe, tracepoint, raw_tracepoint).
func NewTraceProbe(t ProbeType, evtName string, progName string) *TraceProbe {
	return &TraceProbe{
		programName: progName,
		eventName:   evtName,
		probeType:   t,
	}
}

func (p *TraceProbe) GetEventName() string {
	return p.eventName
}

func (p *TraceProbe) GetProgramName() string {
	return p.programName
}

func (p *TraceProbe) GetProbeType() ProbeType {
	return p.probeType
}

func (p *TraceProbe) IsAttached() bool {
	return p.attached
}

func (p *TraceProbe) attach(module *bpf.Module, args ...interface{}) error {
	if p.attached {
		return nil // already attached, it is ok to call attach again
	}
	if module == nil {
		return errfmt.Errorf("incorrect arguments for event: %s", p.eventName)
	}

	prog, err := module.GetProgram(p.programName)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// KProbe and KretProbe

	switch p.probeType {
	case KProbe, KretProbe, SyscallEnter, SyscallExit:
		var err error
		var link *bpf.BPFLink
		var attachFunc func(uint64) (*bpf.BPFLink, error)
		var syms []*environment.KernelSymbol
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

		var ksyms *environment.KernelSymbolTable

		for _, arg := range args {
			switch a := arg.(type) {
			case *environment.KernelSymbolTable:
				ksyms = a
			}
		}
		if ksyms == nil {
			return errfmt.Errorf("trace probes needs kernel symbols table argument")
		}

		if p.probeType == SyscallEnter || p.probeType == SyscallExit {
			syms, err = ksyms.GetSymbolByName(SyscallPrefix + p.eventName)
			if err != nil {
				goto rollback
			}
			if p.probeType == SyscallEnter {
				link, err = prog.AttachKprobe(syms[0].Name)
			}
			if p.probeType == SyscallExit {
				link, err = prog.AttachKretprobe(syms[0].Name)
			}
			if err != nil {
				goto rollback
			}
			p.bpfLink = append(p.bpfLink, link)

			// Try to attach compat syscall. Don't return error if we failed to attach.
			symsCompat, _ := ksyms.GetSymbolByName(SyscallPrefixCompat + p.eventName)
			if len(symsCompat) > 0 {
				if p.probeType == SyscallEnter {
					link, _ = prog.AttachKprobe(symsCompat[0].Name)
				}
				if p.probeType == SyscallExit {
					link, _ = prog.AttachKretprobe(symsCompat[0].Name)
				}
				p.bpfLink = append(p.bpfLink, link)
			}
			// In x86, there are 2 possible compat prefixes - we handle it here
			symsCompat, _ = ksyms.GetSymbolByName(SyscallPrefixCompat2 + p.eventName)
			if len(symsCompat) > 0 {
				if p.probeType == SyscallEnter {
					link, _ = prog.AttachKprobe(symsCompat[0].Name)
				}
				if p.probeType == SyscallExit {
					link, _ = prog.AttachKretprobe(symsCompat[0].Name)
				}
				p.bpfLink = append(p.bpfLink, link)
			}

			goto success
		}

		syms, err = ksyms.GetSymbolByName(p.eventName)
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

func (p *TraceProbe) detach(args ...interface{}) error {
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

func (p *TraceProbe) autoload(module *bpf.Module, autoload bool) error {
	return enableDisableAutoload(module, p.programName, autoload)
}
