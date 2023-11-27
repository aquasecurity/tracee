package probes

import (
	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/cgroup"
	"github.com/aquasecurity/tracee/pkg/errfmt"
)

// NOTE: thread-safety guaranteed by the ProbeGroup big lock.

//
// Cgroup
//

// When attaching a cgroupProbe, by handle, to its eBPF program:
//
//   Handle == cgroupProbe
//
//     Attach(EventHandle, *cgroup.Cgroup)
//     Detach(EventHandle, *cgroup.Cgroup)
//
// to detach all probes:
//
//     DetachAll()

type CgroupProbe struct {
	programName string
	attachType  bpf.BPFAttachType
	bpfLink     *bpf.BPFLink
}

// NewCgroupProbe creates a new cgroup probe.
func NewCgroupProbe(a bpf.BPFAttachType, progName string) *CgroupProbe {
	return &CgroupProbe{
		programName: progName,
		attachType:  a,
	}
}

func (p *CgroupProbe) GetProgramName() string {
	return p.programName
}

func (p *CgroupProbe) attach(module *bpf.Module, args ...interface{}) error {
	var cgroups *cgroup.Cgroups

	for _, arg := range args {
		switch a := arg.(type) {
		case *cgroup.Cgroups:
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

	// sanity checks

	if module == nil {
		return errfmt.Errorf("incorrect arguments for program: %s", p.programName)
	}

	// attach

	prog, err := module.GetProgram(p.programName)
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

func (p *CgroupProbe) detach(args ...interface{}) error {
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

func (p *CgroupProbe) autoload(module *bpf.Module, autoload bool) error {
	return enableDisableAutoload(module, p.programName, autoload)
}
