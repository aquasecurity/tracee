package probes

import (
	"strings"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/errfmt"
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

type TraceProbe struct {
	eventName   string
	programName string
	probeType   ProbeType
	bpfLink     *bpf.BPFLink
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

func (p *TraceProbe) attach(module *bpf.Module, args ...interface{}) error {
	var link *bpf.BPFLink

	if p.bpfLink != nil {
		return nil // already attached, it is ok to call attach again
	}

	if module == nil {
		return errfmt.Errorf("incorrect arguments for event: %s", p.eventName)
	}

	prog, err := module.GetProgram(p.programName)
	if err != nil {
		return errfmt.WrapError(err)
	}

	switch p.probeType {
	case KProbe:
		link, err = prog.AttachKprobe(p.eventName)
	case KretProbe:
		link, err = prog.AttachKretprobe(p.eventName)
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

	p.bpfLink = link

	return nil
}

func (p *TraceProbe) detach(args ...interface{}) error {
	var err error

	if p.bpfLink == nil {
		return nil // already detached, it is ok to call detach again
	}

	err = p.bpfLink.Destroy()
	if err != nil {
		return errfmt.Errorf("failed to detach event: %s (%v)", p.eventName, err)
	}

	p.bpfLink = nil // NOTE: needed so a new call to bpf_link__destroy() works

	return nil
}

func (p *TraceProbe) autoload(module *bpf.Module, autoload bool) error {
	return enableDisableAutoload(module, p.programName, autoload)
}
