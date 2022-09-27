package probes

import (
	"fmt"
	"os"

	bpf "github.com/aquasecurity/libbpfgo"
)

//
// Cgroup
//

type cgroupProbe struct {
	programName string
	attachType  bpf.BPFAttachType
	bpfLink     *bpf.BPFLink
}

// attach attaches an eBPF program to a cgroup
func (p *cgroupProbe) attach(module *bpf.Module, args ...interface{}) error {
	var link *bpf.BPFLink

	if p.bpfLink != nil {
		return nil // already attached, it is ok to call attach again
	}

	var cgroupDir string
	for _, arg := range args {
		switch a := arg.(type) {
		case string:
			cgroupDir = a
		}
	}

	// sanity checks

	if module == nil {
		return fmt.Errorf("incorrect arguments for program: %s", p.programName)
	}
	if cgroupDir == "" {
		return fmt.Errorf("program %s needs a cgroup to attach to", p.programName)
	}

	if _, err := os.Stat(cgroupDir); os.IsNotExist(err) {
		return fmt.Errorf("program %s could not attach to cgroup directory: %s", p.programName, cgroupDir)
	}

	// attach

	prog, err := module.GetProgram(p.programName)
	if err != nil {
		return err
	}

	link, err = prog.AttachCgroupLegacy(cgroupDir, p.attachType)
	if err != nil {
		return fmt.Errorf("failed to attach program %s to cgroup %s", p.programName, cgroupDir)
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
		return fmt.Errorf("failed to detach program: %s (%v)", p.programName, err)
	}

	p.bpfLink = nil // NOTE: needed so a new call to bpf_link__destroy() works

	return nil
}

// autoload sets an eBPF program to autoload (true|false)
func (p *cgroupProbe) autoload(module *bpf.Module, autoload bool) error {
	return enableDisableAutoload(module, p.programName, autoload)
}
