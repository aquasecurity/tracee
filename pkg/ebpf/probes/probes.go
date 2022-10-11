package probes

import (
	"fmt"
	"net"
	"strings"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
)

//
// Probes:
//

// when attaching a traceProbe, by handle, to its eBPF program:
//
//   Handle == traceProbe (types: rawTracepoint, kprobe, kretprobe)
//
//     Attach(EventHandle)
//     Detach(EventHandle)
//
// when attaching a tcProbe, by handle, to its eBPF program:
//
//   Handle == tcProbe
//
//     Attach(EventHandle, *net.Interface)
//     Detach(EventHandle, *net.Interface)
//
// to detach all probes:
//
//     DetachAll()
//
// NOTE: keeping both interfaces with variadic args on **purpose** until we
//       define real use cases, by extending supported "probes" types (trace,
//       tc, socket, xdp, tunnel, cgroup, ...) **
//

type Probes interface {
	Attach(handle Handle, args ...interface{}) error
	Detach(handle Handle, args ...interface{}) error
	DetachAll() error
}

type probes struct {
	module *bpf.Module
	probes map[Handle]Probe
}

// Init initializes a Probes interface
func Init(module *bpf.Module, netEnabled bool) (Probes, error) {

	binaryPath := "/proc/self/exe"

	allProbes := map[Handle]Probe{
		SysEnter:                   &traceProbe{eventName: "raw_syscalls:sys_enter", probeType: rawTracepoint, programName: "trace_sys_enter"},
		SyscallEnter__Internal:     &traceProbe{eventName: "raw_syscalls:sys_enter", probeType: rawTracepoint, programName: "tracepoint__raw_syscalls__sys_enter"},
		SysExit:                    &traceProbe{eventName: "raw_syscalls:sys_exit", probeType: rawTracepoint, programName: "trace_sys_exit"},
		SyscallExit__Internal:      &traceProbe{eventName: "raw_syscalls:sys_exit", probeType: rawTracepoint, programName: "tracepoint__raw_syscalls__sys_exit"},
		SchedProcessFork:           &traceProbe{eventName: "sched:sched_process_fork", probeType: rawTracepoint, programName: "tracepoint__sched__sched_process_fork"},
		SchedProcessExec:           &traceProbe{eventName: "sched:sched_process_exec", probeType: rawTracepoint, programName: "tracepoint__sched__sched_process_exec"},
		SchedProcessExit:           &traceProbe{eventName: "sched:sched_process_exit", probeType: rawTracepoint, programName: "tracepoint__sched__sched_process_exit"},
		SchedSwitch:                &traceProbe{eventName: "sched:sched_switch", probeType: rawTracepoint, programName: "tracepoint__sched__sched_switch"},
		DoExit:                     &traceProbe{eventName: "do_exit", probeType: kprobe, programName: "trace_do_exit"},
		CapCapable:                 &traceProbe{eventName: "cap_capable", probeType: kprobe, programName: "trace_cap_capable"},
		VfsWrite:                   &traceProbe{eventName: "vfs_write", probeType: kprobe, programName: "trace_vfs_write"},
		VfsWriteRet:                &traceProbe{eventName: "vfs_write", probeType: kretprobe, programName: "trace_ret_vfs_write"},
		VfsWriteV:                  &traceProbe{eventName: "vfs_writev", probeType: kprobe, programName: "trace_vfs_writev"},
		VfsWriteVRet:               &traceProbe{eventName: "vfs_writev", probeType: kretprobe, programName: "trace_ret_vfs_writev"},
		KernelWrite:                &traceProbe{eventName: "__kernel_write", probeType: kprobe, programName: "trace_kernel_write"},
		KernelWriteRet:             &traceProbe{eventName: "__kernel_write", probeType: kretprobe, programName: "trace_ret_kernel_write"},
		CgroupAttachTask:           &traceProbe{eventName: "cgroup:cgroup_attach_task", probeType: rawTracepoint, programName: "tracepoint__cgroup__cgroup_attach_task"},
		CgroupMkdir:                &traceProbe{eventName: "cgroup:cgroup_mkdir", probeType: rawTracepoint, programName: "tracepoint__cgroup__cgroup_mkdir"},
		CgroupRmdir:                &traceProbe{eventName: "cgroup:cgroup_rmdir", probeType: rawTracepoint, programName: "tracepoint__cgroup__cgroup_rmdir"},
		SecurityBPRMCheck:          &traceProbe{eventName: "security_bprm_check", probeType: kprobe, programName: "trace_security_bprm_check"},
		SecurityFileOpen:           &traceProbe{eventName: "security_file_open", probeType: kprobe, programName: "trace_security_file_open"},
		SecurityFilePermission:     &traceProbe{eventName: "security_file_permission", probeType: kprobe, programName: "trace_security_file_permission"},
		SecuritySocketCreate:       &traceProbe{eventName: "security_socket_create", probeType: kprobe, programName: "trace_security_socket_create"},
		SecuritySocketListen:       &traceProbe{eventName: "security_socket_listen", probeType: kprobe, programName: "trace_security_socket_listen"},
		SecuritySocketConnect:      &traceProbe{eventName: "security_socket_connect", probeType: kprobe, programName: "trace_security_socket_connect"},
		SecuritySocketAccept:       &traceProbe{eventName: "security_socket_accept", probeType: kprobe, programName: "trace_security_socket_accept"},
		SecuritySocketBind:         &traceProbe{eventName: "security_socket_bind", probeType: kprobe, programName: "trace_security_socket_bind"},
		SecuritySocketSetsockopt:   &traceProbe{eventName: "security_socket_setsockopt", probeType: kprobe, programName: "trace_security_socket_setsockopt"},
		SecuritySbMount:            &traceProbe{eventName: "security_sb_mount", probeType: kprobe, programName: "trace_security_sb_mount"},
		SecurityBPF:                &traceProbe{eventName: "security_bpf", probeType: kprobe, programName: "trace_security_bpf"},
		SecurityBPFMap:             &traceProbe{eventName: "security_bpf_map", probeType: kprobe, programName: "trace_security_bpf_map"},
		SecurityKernelReadFile:     &traceProbe{eventName: "security_kernel_read_file", probeType: kprobe, programName: "trace_security_kernel_read_file"},
		SecurityKernelPostReadFile: &traceProbe{eventName: "security_kernel_post_read_file", probeType: kprobe, programName: "trace_security_kernel_post_read_file"},
		SecurityInodeMknod:         &traceProbe{eventName: "security_inode_mknod", probeType: kprobe, programName: "trace_security_inode_mknod"},
		SecurityInodeSymlink:       &traceProbe{eventName: "security_inode_symlink", probeType: kprobe, programName: "trace_security_inode_symlink"},
		SecurityInodeUnlink:        &traceProbe{eventName: "security_inode_unlink", probeType: kprobe, programName: "trace_security_inode_unlink"},
		SecurityMmapAddr:           &traceProbe{eventName: "security_mmap_addr", probeType: kprobe, programName: "trace_mmap_alert"},
		SecurityMmapFile:           &traceProbe{eventName: "security_mmap_file", probeType: kprobe, programName: "trace_security_mmap_file"},
		DoSplice:                   &traceProbe{eventName: "do_splice", probeType: kprobe, programName: "trace_do_splice"},
		DoSpliceRet:                &traceProbe{eventName: "do_splice", probeType: kretprobe, programName: "trace_ret_do_splice"},
		ProcCreate:                 &traceProbe{eventName: "proc_create", probeType: kprobe, programName: "trace_proc_create"},
		SecurityFileMProtect:       &traceProbe{eventName: "security_file_mprotect", probeType: kprobe, programName: "trace_security_file_mprotect"},
		CommitCreds:                &traceProbe{eventName: "commit_creds", probeType: kprobe, programName: "trace_commit_creds"},
		SwitchTaskNS:               &traceProbe{eventName: "switch_task_namespaces", probeType: kprobe, programName: "trace_switch_task_namespaces"},
		RegisterKprobe:             &traceProbe{eventName: "register_kprobe", probeType: kprobe, programName: "trace_register_kprobe"},
		RegisterKprobeRet:          &traceProbe{eventName: "register_kprobe", probeType: kretprobe, programName: "trace_ret_register_kprobe"},
		CallUsermodeHelper:         &traceProbe{eventName: "call_usermodehelper", probeType: kprobe, programName: "trace_call_usermodehelper"},
		DebugfsCreateFile:          &traceProbe{eventName: "debugfs_create_file", probeType: kprobe, programName: "trace_debugfs_create_file"},
		DebugfsCreateDir:           &traceProbe{eventName: "debugfs_create_dir", probeType: kprobe, programName: "trace_debugfs_create_dir"},
		DeviceAdd:                  &traceProbe{eventName: "device_add", probeType: kprobe, programName: "trace_device_add"},
		RegisterChrdev:             &traceProbe{eventName: "__register_chrdev", probeType: kprobe, programName: "trace___register_chrdev"},
		RegisterChrdevRet:          &traceProbe{eventName: "__register_chrdev", probeType: kretprobe, programName: "trace_ret__register_chrdev"},
		DoInitModule:               &traceProbe{eventName: "do_init_module", probeType: kprobe, programName: "trace_do_init_module"},
		DoInitModuleRet:            &traceProbe{eventName: "do_init_module", probeType: kretprobe, programName: "trace_ret_do_init_module"},
		LoadElfPhdrs:               &traceProbe{eventName: "load_elf_phdrs", probeType: kprobe, programName: "trace_load_elf_phdrs"},
		Filldir64:                  &traceProbe{eventName: "filldir64", probeType: kprobe, programName: "trace_filldir64"},
		TaskRename:                 &traceProbe{eventName: "task:task_rename", probeType: rawTracepoint, programName: "tracepoint__task__task_rename"},
		UDPSendmsg:                 &traceProbe{eventName: "udp_sendmsg", probeType: kprobe, programName: "trace_udp_sendmsg"},
		UDPDisconnect:              &traceProbe{eventName: "__udp_disconnect", probeType: kprobe, programName: "trace_udp_disconnect"},
		UDPDestroySock:             &traceProbe{eventName: "udp_destroy_sock", probeType: kprobe, programName: "trace_udp_destroy_sock"},
		UDPv6DestroySock:           &traceProbe{eventName: "udpv6_destroy_sock", probeType: kprobe, programName: "trace_udpv6_destroy_sock"},
		InetSockSetState:           &traceProbe{eventName: "sock:inet_sock_set_state", probeType: rawTracepoint, programName: "tracepoint__inet_sock_set_state"},
		TCPConnect:                 &traceProbe{eventName: "tcp_connect", probeType: kprobe, programName: "trace_tcp_connect"},
		ICMPRecv:                   &traceProbe{eventName: "icmp_rcv", probeType: kprobe, programName: "trace_icmp_rcv"},
		ICMPSend:                   &traceProbe{eventName: "__icmp_send", probeType: kprobe, programName: "trace_icmp_send"},
		ICMPv6Recv:                 &traceProbe{eventName: "icmpv6_rcv", probeType: kprobe, programName: "trace_icmpv6_rcv"},
		ICMPv6Send:                 &traceProbe{eventName: "icmp6_send", probeType: kprobe, programName: "trace_icmp6_send"},
		Pingv4Sendmsg:              &traceProbe{eventName: "ping_v4_sendmsg", probeType: kprobe, programName: "trace_ping_v4_sendmsg"},
		Pingv6Sendmsg:              &traceProbe{eventName: "ping_v6_sendmsg", probeType: kprobe, programName: "trace_ping_v6_sendmsg"},
		DefaultTcIngress:           &tcProbe{programName: "tc_ingress", tcAttachPoint: bpf.BPFTcIngress},
		DefaultTcEgress:            &tcProbe{programName: "tc_egress", tcAttachPoint: bpf.BPFTcEgress, skipLoopback: true},
		PrintSyscallTable:          &uProbe{eventName: "print_syscall_table", binaryPath: binaryPath, symbolName: "github.com/aquasecurity/tracee/pkg/ebpf.(*Tracee).triggerSyscallsIntegrityCheckCall", programName: "uprobe_syscall_trigger"},
		PrintNetSeqOps:             &uProbe{eventName: "print_net_seq_ops", binaryPath: binaryPath, symbolName: "github.com/aquasecurity/tracee/pkg/ebpf.(*Tracee).triggerSeqOpsIntegrityCheckCall", programName: "uprobe_seq_ops_trigger"},
		SecurityInodeRename:        &traceProbe{eventName: "security_inode_rename", probeType: kprobe, programName: "trace_security_inode_rename"},
	}

	// disable autoload for network related eBPF programs in network is disabled
	if !netEnabled {
		for _, p := range allProbes {
			if tc, ok := p.(*tcProbe); ok {
				tc.autoload(module, false)
			}
		}
	}

	return &probes{
		probes: allProbes,
		module: module,
	}, nil
}

// Attach attaches given handle's program to its hook
func (p *probes) Attach(handle Handle, args ...interface{}) error {
	if _, ok := p.probes[handle]; !ok {
		return fmt.Errorf("probe handle (%d) does not exist", handle)
	}

	return p.probes[handle].attach(p.module, args...)
}

// Detach detaches given handle's program from its hook
func (p *probes) Detach(handle Handle, args ...interface{}) error {
	if _, ok := p.probes[handle]; !ok {
		return fmt.Errorf("probe handle (%d) does not exist", handle)
	}

	return p.probes[handle].detach(args...)
}

// DetachAll detaches all existing probes (programs from their hooks)
func (p *probes) DetachAll() error {
	for _, pr := range p.probes {
		err := pr.detach()
		if err != nil {
			return err
		}
	}

	return nil
}

// Autoload disables autoload feature for a given handle's program
func (p *probes) Autoload(handle Handle, autoload bool) error {
	return p.probes[handle].autoload(p.module, autoload)
}

//
// probe
//

type probeType uint8

const (
	kprobe        = iota // github.com/iovisor/bcc/blob/master/docs/reference_guide.md#1-kp
	kretprobe            // github.com/iovisor/bcc/blob/master/docs/reference_guide.md#1-kp
	tracepoint           // github.com/iovisor/bcc/blob/master/docs/reference_guide.md#3-tracep
	rawTracepoint        // github.com/iovisor/bcc/blob/master/docs/reference_guide.md#7-raw-tracep
)

type Probe interface {
	attach(module *bpf.Module, args ...interface{}) error
	detach(...interface{}) error
	autoload(module *bpf.Module, autoload bool) error
}

//
// traceProbe
//

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
		return fmt.Errorf("incorrect arguments for event: %s", p.eventName)
	}

	prog, err := module.GetProgram(p.programName)
	if err != nil {
		return err
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
		return fmt.Errorf("failed to attach event: %s (%v)", p.eventName, err)
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
		return fmt.Errorf("failed to detach event: %s (%v)", p.eventName, err)
	}

	p.bpfLink = nil // NOTE: needed so a new call to bpf_link__destroy() works

	return nil
}

// autoload sets an eBPF program to autoload (true|false)
func (p *traceProbe) autoload(module *bpf.Module, autoload bool) error {
	return enableDisableAutoload(module, p.programName, autoload)
}

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
		return fmt.Errorf("incorrect arguments for event: %s", p.eventName)
	}

	prog, err := module.GetProgram(p.programName)
	if err != nil {
		return err
	}

	offset, err := helpers.SymbolToOffset(p.binaryPath, p.symbolName)
	if err != nil {
		return fmt.Errorf("error finding %s function offset: %v", p.symbolName, err)
	}

	link, err = prog.AttachUprobe(-1, p.binaryPath, offset)
	if err != nil {
		return fmt.Errorf("error attaching uprobe on %s: %v", p.symbolName, err)
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
		return fmt.Errorf("failed to detach event: %s (%v)", p.eventName, err)
	}

	p.bpfLink = nil // NOTE: needed so a new call to bpf_link__destroy() works

	return nil
}

// autoload sets an eBPF program to autoload (true|false)
func (p *uProbe) autoload(module *bpf.Module, autoload bool) error {
	return enableDisableAutoload(module, p.programName, autoload)
}

//
// tcProbe
//

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

//
// common function(s) to Probe implementations
//

// enableDisableAutoload enables or disables an eBPF program autoload setting
func enableDisableAutoload(module *bpf.Module, programName string, autoload bool) error {
	var err error

	if module == nil || programName == "" {
		return fmt.Errorf("incorrect arguments (program: %s)", programName)
	}

	prog, err := module.GetProgram(programName)
	if err != nil {
		return err
	}

	return prog.SetAutoload(autoload)
}

// event handles

type Handle int32

const (
	SysEnter Handle = iota
	SysExit
	SyscallEnter__Internal
	SyscallExit__Internal
	SchedProcessFork
	SchedProcessExec
	SchedProcessExit
	SchedSwitch
	DoExit
	CapCapable
	VfsWrite
	VfsWriteRet
	VfsWriteV
	VfsWriteVRet
	SecurityMmapAddr
	SecurityMmapFile
	SecurityFileMProtect
	CommitCreds
	SwitchTaskNS
	KernelWrite
	KernelWriteRet
	CgroupAttachTask
	CgroupMkdir
	CgroupRmdir
	SecurityBPRMCheck
	SecurityFileOpen
	SecurityInodeUnlink
	SecurityInodeMknod
	SecurityInodeSymlink
	SecuritySocketCreate
	SecuritySocketListen
	SecuritySocketConnect
	SecuritySocketAccept
	SecuritySocketBind
	SecuritySocketSetsockopt
	SecuritySbMount
	SecurityBPF
	SecurityBPFMap
	SecurityKernelReadFile
	SecurityKernelPostReadFile
	DoSplice
	DoSpliceRet
	ProcCreate
	RegisterKprobe
	RegisterKprobeRet
	CallUsermodeHelper
	DebugfsCreateFile
	DebugfsCreateDir
	DeviceAdd
	RegisterChrdev
	RegisterChrdevRet
	DoInitModule
	DoInitModuleRet
	LoadElfPhdrs
	Filldir64
	SecurityFilePermission
	TaskRename
	UDPSendmsg
	UDPDisconnect
	UDPDestroySock
	UDPv6DestroySock
	InetSockSetState
	TCPConnect
	ICMPRecv
	ICMPSend
	ICMPv6Recv
	ICMPv6Send
	Pingv4Sendmsg
	Pingv6Sendmsg
	DefaultTcIngress
	DefaultTcEgress
	PrintSyscallTable
	PrintNetSeqOps
	SecurityInodeRename
)
