package probes

import (
	"fmt"
	"net"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
)

//
// tcProbe
//

// When attaching a tcProbe, by handle, to its eBPF program:
//
//   Handle == tcProbe
//
//     Attach(EventHandle, *net.Interface)
//     Detach(EventHandle, *net.Interface)
//
// to detach all probes:
//
//     DetachAll()

type tcProbe struct {
	programName   string
	tcHooks       map[*net.Interface]*bpf.TcHook
	tcAttachPoint bpf.TcAttachPoint
	skipLoopback  bool
}

// attach attaches an eBPF program to its probe
func (p *tcProbe) attach(module *bpf.Module, args ...interface{}) error {

	return p.attachOrDetach(module, args...)
}

// detach detaches an eBPF program from its probe
func (p *tcProbe) detach(args ...interface{}) error {
	return p.attachOrDetach(nil, args...)
}

// attachOrDetach resolves variadic argument and calls appropriate function
func (p *tcProbe) attachOrDetach(module *bpf.Module, args ...interface{}) error {
	var netIface *net.Interface

	for _, arg := range args {
		switch a := arg.(type) {
		case *net.Interface:
			netIface = a
		}
	}

	if module != nil {
		return p.attachTc(module, netIface)
	}

	if netIface == nil { // detach from all if no interface given
		return p.detachTcAll(module)
	}

	return p.detachTc(module, netIface)
}

// attachTc attaches a tc program to a given interface
func (p *tcProbe) attachTc(module *bpf.Module, netIface *net.Interface) error {
	var err error

	if netIface == nil {
		return fmt.Errorf("missing interface to attach to: %s", p.programName)
	}

	// loopback devices are special, some tc probes should be skipped
	isNetIfaceLo := netIface.Flags&net.FlagLoopback == net.FlagLoopback
	if isNetIfaceLo && p.skipLoopback {
		return nil
	}

	if _, ok := p.tcHooks[netIface]; ok {
		return fmt.Errorf("%s already attached to %s", p.programName, netIface.Name)
	}

	hook := module.TcHookInit()
	if hook == nil {
		return fmt.Errorf("could not initialize TcHook %s", p.programName)
	}

	err = hook.SetInterfaceByName(netIface.Name)
	if err != nil {
		return fmt.Errorf("failed to set tc hook interface: %v", err)
	}

	hook.SetAttachPoint(p.tcAttachPoint)

	err = hook.Create()
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno != syscall.EEXIST {
			return fmt.Errorf("tc hook create: %v", err)
		}
	}

	prog, _ := module.GetProgram(p.programName)
	if prog == nil {
		return fmt.Errorf("could not find tc program %s", p.programName)
	}

	tcOpts := bpf.TcOpts{ProgFd: int(prog.FileDescriptor())}

	err = hook.Attach(&tcOpts)
	if err != nil {
		return fmt.Errorf("tc attach: %v", err)
	}

	if p.tcHooks == nil {
		p.tcHooks = make(map[*net.Interface]*bpf.TcHook)
	}

	p.tcHooks[netIface] = hook

	return err
}

// detachTc detaches a tc program from a given interface it is attached to
func (p *tcProbe) detachTc(module *bpf.Module, netIface *net.Interface) error {
	var err error

	if _, ok := p.tcHooks[netIface]; !ok {
		return fmt.Errorf("%s not attached to %s", p.programName, netIface.Name)
	}

	hook := p.tcHooks[netIface]

	// TODO: https://github.com/aquasecurity/tracee/issues/1828
	//
	// 1. Entire clsact qdisc is purged when tc hook is destroyed:
	//    it might destroy existing filters (other eBPF programs)
	//    unrelated to tracee.
	//
	// 2. eBPF TC detach does not work (destroy needs to be used)

	if hook != nil {
		err = hook.Destroy()
		if err != nil {
			return err
		}
	}

	delete(p.tcHooks, netIface)

	return err
}

// detachTcAll detaches a tc program from all interfaces it is attached to
func (p *tcProbe) detachTcAll(module *bpf.Module) error {
	var err error

	for netIface := range p.tcHooks {
		err = p.detachTc(module, netIface)
		if err != nil {
			return err
		}
	}

	return err
}

// autoload sets an eBPF program to autoload (true|false)
func (p *tcProbe) autoload(module *bpf.Module, autoload bool) error {
	return enableDisableAutoload(module, p.programName, autoload)
}
