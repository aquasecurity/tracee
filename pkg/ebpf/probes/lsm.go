package probes

import (
	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/common/errfmt"
)

//
// LsmProgramProbe
//

// LsmProgramProbe represents an LSM (Linux Security Module) eBPF program probe.
// It automatically includes compatibility checking for the BPF_PROG_TYPE_LSM program type.
type LsmProgramProbe struct {
	ProbeCompatibility
	hookName    string
	programName string
	bpfLink     *bpf.BPFLink
	attached    bool
}

// NewLsmProgramProbe creates a new LSM program probe with automatic BPF_PROG_TYPE_LSM compatibility checking.
func NewLsmProgramProbe(hookName string, progName string) *LsmProgramProbe {
	// Create compatibility requirements with automatic BPF_PROG_TYPE_LSM support check
	compatibility := NewProbeCompatibility(
		NewBpfProgramRequirement(bpf.BPFProgTypeLsm),
	)

	return &LsmProgramProbe{
		ProbeCompatibility: *compatibility,
		hookName:           hookName,
		programName:        progName,
	}
}

// NewLsmProgramProbeWithCompatibility creates a new LSM program probe with custom compatibility requirements.
// Note: BPF_PROG_TYPE_LSM compatibility is automatically added to the provided requirements.
func NewLsmProgramProbeWithCompatibility(hookName string, progName string, compatibility *ProbeCompatibility) *LsmProgramProbe {
	// Add BPF_PROG_TYPE_LSM requirement to existing compatibility requirements
	lsmRequirement := NewBpfProgramRequirement(bpf.BPFProgTypeLsm)
	compatibility.requirements = append(compatibility.requirements, lsmRequirement)

	return &LsmProgramProbe{
		ProbeCompatibility: *compatibility,
		hookName:           hookName,
		programName:        progName,
	}
}

func (p *LsmProgramProbe) GetEventName() string {
	return p.hookName
}

func (p *LsmProgramProbe) GetProgramName() string {
	return p.programName
}

func (p *LsmProgramProbe) GetProbeType() ProbeType {
	return LSM
}

func (p *LsmProgramProbe) IsAttached() bool {
	return p.attached
}

func (p *LsmProgramProbe) attach(module *bpf.Module, args ...interface{}) error {
	if p.attached {
		return nil // already attached, it is ok to call attach again
	}
	if module == nil {
		return errfmt.Errorf("incorrect arguments for LSM hook: %s", p.hookName)
	}

	prog, err := module.GetProgram(p.programName)
	if err != nil {
		return errfmt.WrapError(err)
	}

	link, err := prog.AttachLSM()
	if err != nil {
		return errfmt.Errorf("failed to attach LSM hook: %s (%v)", p.hookName, err)
	}

	p.bpfLink = link
	p.attached = true
	return nil
}

func (p *LsmProgramProbe) detach(args ...interface{}) error {
	if !p.attached {
		return nil
	}
	if p.bpfLink != nil {
		err := p.bpfLink.Destroy()
		if err != nil {
			return errfmt.Errorf("failed to detach LSM hook: %s (%v)", p.hookName, err)
		}
	}
	p.attached = false
	return nil
}

func (p *LsmProgramProbe) autoload(module *bpf.Module, autoload bool) error {
	return enableDisableAutoload(module, p.programName, autoload)
}
