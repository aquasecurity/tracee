package probes

import (
	"strings"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/errfmt"
)

//
// traceProbe
//

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

type traceProbe struct {
	probeType   probeType
	eventName   string
	programName string
	bpfLink     *bpf.BPFLink
}

// attach attaches an eBPF program to its probe
func (p *traceProbe) attach(module *bpf.Module, args ...interface{}) error {
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
	case kprobe:
		link, err = prog.AttachKprobe(p.eventName)
	case kretprobe:
		link, err = prog.AttachKretprobe(p.eventName)
	case tracepoint:
		tp := strings.Split(p.eventName, ":")
		tpClass := tp[0]
		tpEvent := tp[1]
		link, err = prog.AttachTracepoint(tpClass, tpEvent)
	case rawTracepoint:
		tpEvent := strings.Split(p.eventName, ":")[1]
		link, err = prog.AttachRawTracepoint(tpEvent)
	}

	if err != nil {
		return errfmt.Errorf("failed to attach event: %s (%v)", p.eventName, err)
	}

	p.bpfLink = link

	return nil
}

// detach detaches an eBPF program from its probe
func (p *traceProbe) detach(args ...interface{}) error {
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

// autoload sets an eBPF program to autoload (true|false)
func (p *traceProbe) autoload(module *bpf.Module, autoload bool) error {
	return enableDisableAutoload(module, p.programName, autoload)
}
