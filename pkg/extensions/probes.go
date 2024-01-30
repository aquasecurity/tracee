package extensions

import (
	"strings"
	"sync"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/cgroup"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/global"
	"github.com/aquasecurity/tracee/pkg/logger"
)

//
// Probes
//

type ProbesPerExtension struct {
	mutex  *sync.RWMutex
	probes map[string]map[int]Probe // [extension_name][handle]probe
}

func (p *ProbesPerExtension) Get(ext string, id int) Probe {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	if _, ok := p.probes[ext]; !ok {
		return nil
	}
	return p.probes[ext][id]
}

func (p *ProbesPerExtension) GetOk(ext string, id int) (Probe, bool) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	if _, ok := p.probes[ext]; !ok {
		return nil, false
	}
	probe, ok := p.probes[ext][id]
	return probe, ok
}

func (p *ProbesPerExtension) Add(ext string, id int, probe Probe) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if _, ok := p.probes[ext]; !ok {
		p.probes[ext] = make(map[int]Probe)
	}
	p.probes[ext][id] = probe
}

func (p *ProbesPerExtension) AddBatch(ext string, probes map[int]Probe) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if _, ok := p.probes[ext]; !ok {
		p.probes[ext] = make(map[int]Probe)
	}
	for id, probe := range probes {
		p.probes[ext][id] = probe
	}
}

func (p *ProbesPerExtension) AttachAll(ext string) error {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	if _, ok := p.probes[ext]; !ok {
		return errfmt.Errorf("extension (%s) does not exist", ext)
	}
	for _, pr := range p.probes[ext] {
		err := pr.Attach()
		if err != nil {
			return errfmt.WrapError(err)
		}
	}
	return nil
}

func (p *ProbesPerExtension) AutoloadAll(ext string, cond bool) error {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	if _, ok := p.probes[ext]; !ok {
		return errfmt.Errorf("extension (%s) does not exist", ext)
	}
	for _, pr := range p.probes[ext] {
		err := pr.SetAutoload(cond)
		if err != nil {
			return errfmt.WrapError(err)
		}
	}
	return nil
}

func (p *ProbesPerExtension) DetachAll(ext string) error {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	if _, ok := p.probes[ext]; !ok {
		return errfmt.Errorf("extension (%s) does not exist", ext)
	}
	for _, pr := range p.probes[ext] {
		err := pr.Detach()
		if err != nil {
			return errfmt.WrapError(err)
		}
	}
	return nil
}

//
// Probe
//

type Probe interface {
	// Attach attaches the probe's program to its hook.
	Attach(args ...interface{}) error
	// Detach detaches the probe's program from its hook.
	Detach(...interface{}) error
	// SetAutoload sets the probe's ebpf program automatic attaching to its hook.
	SetAutoload(autoload bool) error
}

func enableDisableAutoload(programName string, autoload bool) error {
	prog, err := Modules.Get("core").GetProgram(programName)
	if err != nil {
		return errfmt.WrapError(err)
	}
	return prog.SetAutoload(autoload)
}

//
// Tracing Probes
//

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

	prog, err := Modules.Get("core").GetProgram(p.programName)
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
		syms, err := global.KSymbols.GetSymbolByName(p.eventName)
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
	prog, err := Modules.Get("core").GetProgram(p.programName)
	if err != nil {
		return errfmt.WrapError(err)
	}
	return prog.SetAutoload(autoload)
}

//
// Uprobe
//

type Uprobe struct {
	eventName   string
	programName string // eBPF program to execute when uprobe triggered
	binaryPath  string // ELF file path to attach uprobe to
	symbolName  string // ELF binary symbol to attach uprobe to
	bpfLink     *bpf.BPFLink
	mutex       *sync.RWMutex
}

func NewUprobe(evtName string, progName string, binPath string, symName string) *Uprobe {
	return &Uprobe{
		programName: progName,
		eventName:   evtName,
		binaryPath:  binPath,
		symbolName:  symName,
		mutex:       &sync.RWMutex{},
	}
}

func (p *Uprobe) GetEventName() string {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.eventName
}

func (p *Uprobe) GetProgramName() string {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.programName
}

func (p *Uprobe) GetBinaryPath() string {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.binaryPath
}

func (p *Uprobe) GetSymbolName() string {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.symbolName
}

func (p *Uprobe) Attach(args ...interface{}) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	var link *bpf.BPFLink

	if p.bpfLink != nil {
		return nil // already attached, it is ok to call attach again
	}

	prog, err := Modules.Get("core").GetProgram(p.programName)
	if err != nil {
		return errfmt.WrapError(err)
	}

	offset, err := helpers.SymbolToOffset(p.binaryPath, p.symbolName)
	if err != nil {
		return errfmt.Errorf("error finding %s function offset: %v", p.symbolName, err)
	}

	link, err = prog.AttachUprobe(-1, p.binaryPath, offset)
	if err != nil {
		return errfmt.Errorf("error attaching uprobe on %s: %v", p.symbolName, err)
	}

	p.bpfLink = link

	return nil
}

func (p *Uprobe) Detach(args ...interface{}) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

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

func (p *Uprobe) SetAutoload(autoload bool) error {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	prog, err := Modules.Get("core").GetProgram(p.programName)
	if err != nil {
		return errfmt.WrapError(err)
	}
	return prog.SetAutoload(autoload)
}

//
// Cgroup Probes
//

type CgroupProbe struct {
	programName string
	attachType  bpf.BPFAttachType
	bpfLink     *bpf.BPFLink
	mutex       *sync.RWMutex
}

func NewCgroupProbe(a bpf.BPFAttachType, progName string) *CgroupProbe {
	return &CgroupProbe{
		programName: progName,
		attachType:  a,
		mutex:       &sync.RWMutex{},
	}
}

func (p *CgroupProbe) GetProgramName() string {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.programName
}

func (p *CgroupProbe) GetAttachType() bpf.BPFAttachType {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.attachType
}

func (p *CgroupProbe) Attach(args ...interface{}) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	var cgroups *cgroup.AllCGroups

	for _, arg := range args {
		switch a := arg.(type) {
		case *cgroup.AllCGroups:
			cgroups = a
		}
	}
	if cgroups == nil {
		return errfmt.Errorf("cgroup probes needs control groups argument")
	}
	cgroupV2 := cgroups.GetCgroup(cgroup.CgroupVersion2)
	if cgroupV2 == nil {
		return errfmt.Errorf("cgroup probes needs cgroup v2 support")
	}

	cgroupV2MountPoint := cgroupV2.GetMountPoint()

	var link *bpf.BPFLink

	if p.bpfLink != nil {
		return nil // already attached, it is ok to call attach again
	}

	// attach

	prog, err := Modules.Get("core").GetProgram(p.programName)
	if err != nil {
		return errfmt.WrapError(err)
	}

	link, err = prog.AttachCgroupLegacy(cgroupV2MountPoint, p.attachType)
	if err != nil {
		return errfmt.Errorf("failed to attach program %s to cgroup %s (error: %v)", p.programName, cgroupV2MountPoint, err)
	}

	p.bpfLink = link

	return nil
}

func (p *CgroupProbe) Detach(args ...interface{}) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	var err error

	if p.bpfLink == nil {
		return nil // already detached, it is ok to call detach again
	}

	// Legacy attachments (for now cgroupv2 prog attachments under older
	// kernels) might not be done using BpfLink logic. Without a file
	// descriptor for the link, tracee needs to raise its capabilities
	// in order to call bpf() syscall for the legacy detachment.
	err = capabilities.GetInstance().EBPF(
		func() error {
			return p.bpfLink.Destroy()
		},
	)
	if err != nil {
		return errfmt.Errorf("failed to detach program: %s (%v)", p.programName, err)
	}

	p.bpfLink = nil // NOTE: needed so a new call to bpf_link__destroy() works

	return nil
}

func (p *CgroupProbe) SetAutoload(autoload bool) error {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	prog, err := Modules.Get("core").GetProgram(p.programName)
	if err != nil {
		return errfmt.WrapError(err)
	}
	return prog.SetAutoload(autoload)
}
