package probes

import (
	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/cgroup"
	"github.com/aquasecurity/tracee/pkg/errfmt"
)

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

type cgroupProbe struct {
	programName string
	attachType  bpf.BPFAttachType
	bpfLink     *bpf.BPFLink
}

// attach attaches an eBPF program to a cgroup
func (p *cgroupProbe) attach(module *bpf.Module, args ...interface{}) error {
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

// detach detaches an eBPF program from a cgroup
func (p *cgroupProbe) detach(args ...interface{}) error {
	var err error

	if p.bpfLink == nil {
		return nil // already detached, it is ok to call detach again
	}

	err = p.bpfLink.Destroy()
	if err != nil {
		return errfmt.Errorf("failed to detach program: %s (%v)", p.programName, err)
	}

	p.bpfLink = nil // NOTE: needed so a new call to bpf_link__destroy() works

	return nil
}

// autoload sets an eBPF program to autoload (true|false)
func (p *cgroupProbe) autoload(module *bpf.Module, autoload bool) error {
	return enableDisableAutoload(module, p.programName, autoload)
}
