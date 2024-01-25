package probes

import (
	"sync"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/cgroup"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/extensions"
)

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

	// attach

	prog, err := extensions.Modules.Get("core").GetProgram(p.programName)
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
	return enableDisableAutoload(p.programName, autoload)
}
