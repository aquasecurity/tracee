package probes

import (
	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/errfmt"
)

//
// uProbe
//

type uProbe struct {
	eventName   string
	programName string // eBPF program to execute when uprobe triggered
	binaryPath  string // ELF file path to attach uprobe to
	symbolName  string // ELF binary symbol to attach uprobe to
	bpfLink     *bpf.BPFLink
}

// attach attaches an eBPF program to its probe
func (p *uProbe) attach(module *bpf.Module, args ...interface{}) error {
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

// detach detaches an eBPF program from its probe
func (p *uProbe) detach(args ...interface{}) error {
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
func (p *uProbe) autoload(module *bpf.Module, autoload bool) error {
	return enableDisableAutoload(module, p.programName, autoload)
}
