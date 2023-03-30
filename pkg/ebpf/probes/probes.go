package probes

import (
	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
)

//
// Probes:
//
// NOTE: keeping both (Probes and Probe) interfaces with variadic args on
//       **purpose** until we define real use cases, by extending supported
//       "probes" types (trace, tc, socket, xdp, tunnel, cgroup, ...) **
//

type Probes interface {
	Attach(handle Handle, args ...interface{}) error
	Detach(handle Handle, args ...interface{}) error
	DetachAll() error
	GetProbeType(handle Handle) string
	GetEventName(handle Handle) (string, string)
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
		SchedProcessFree:           &traceProbe{eventName: "sched:sched_process_free", probeType: rawTracepoint, programName: "tracepoint__sched__sched_process_free"},
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
		PrintSyscallTable:          &uProbe{eventName: "print_syscall_table", binaryPath: binaryPath, symbolName: "github.com/aquasecurity/tracee/pkg/ebpf.(*Tracee).triggerSyscallsIntegrityCheckCall", programName: "uprobe_syscall_trigger"},
		HiddenKernelModuleSeeker:   &uProbe{eventName: "hidden_kernel_module", binaryPath: binaryPath, symbolName: "github.com/aquasecurity/tracee/pkg/ebpf.(*Tracee).triggerKernelModuleSeeker", programName: "uprobe_lkm_seeker"},
		PrintNetSeqOps:             &uProbe{eventName: "print_net_seq_ops", binaryPath: binaryPath, symbolName: "github.com/aquasecurity/tracee/pkg/ebpf.(*Tracee).triggerSeqOpsIntegrityCheckCall", programName: "uprobe_seq_ops_trigger"},
		PrintMemDump:               &uProbe{eventName: "print_mem_dump", binaryPath: binaryPath, symbolName: "github.com/aquasecurity/tracee/pkg/ebpf.(*Tracee).triggerMemDumpCall", programName: "uprobe_mem_dump_trigger"},
		SecurityInodeRename:        &traceProbe{eventName: "security_inode_rename", probeType: kprobe, programName: "trace_security_inode_rename"},
		DoSigaction:                &traceProbe{eventName: "do_sigaction", probeType: kprobe, programName: "trace_do_sigaction"},
		SecurityBpfProg:            &traceProbe{eventName: "security_bpf_prog", probeType: kprobe, programName: "trace_security_bpf_prog"},
		SecurityFileIoctl:          &traceProbe{eventName: "security_file_ioctl", probeType: kprobe, programName: "trace_security_file_ioctl"},
		CheckHelperCall:            &traceProbe{eventName: "check_helper_call", probeType: kprobe, programName: "trace_check_helper_call"},
		CheckMapFuncCompatibility:  &traceProbe{eventName: "check_map_func_compatibility", probeType: kprobe, programName: "trace_check_map_func_compatibility"},
		KallsymsLookupName:         &traceProbe{eventName: "kallsyms_lookup_name", probeType: kprobe, programName: "trace_kallsyms_lookup_name"},
		KallsymsLookupNameRet:      &traceProbe{eventName: "kallsyms_lookup_name", probeType: kretprobe, programName: "trace_ret_kallsyms_lookup_name"},
		SockAllocFile:              &traceProbe{eventName: "sock_alloc_file", probeType: kprobe, programName: "trace_sock_alloc_file"},
		SockAllocFileRet:           &traceProbe{eventName: "sock_alloc_file", probeType: kretprobe, programName: "trace_ret_sock_alloc_file"},
		SecuritySocketSendmsg:      &traceProbe{eventName: "security_socket_sendmsg", probeType: kprobe, programName: "trace_security_socket_sendmsg"},
		SecuritySocketRecvmsg:      &traceProbe{eventName: "security_socket_recvmsg", probeType: kprobe, programName: "trace_security_socket_recvmsg"},
		CgroupBPFRunFilterSKB:      &traceProbe{eventName: "__cgroup_bpf_run_filter_skb", probeType: kprobe, programName: "cgroup_bpf_run_filter_skb"},
		CgroupSKBIngress:           &cgroupProbe{programName: "cgroup_skb_ingress", attachType: bpf.BPFAttachTypeCgroupInetIngress},
		CgroupSKBEgress:            &cgroupProbe{programName: "cgroup_skb_egress", attachType: bpf.BPFAttachTypeCgroupInetEgress},
		DoMmap:                     &traceProbe{eventName: "do_mmap", probeType: kprobe, programName: "trace_do_mmap"},
		DoMmapRet:                  &traceProbe{eventName: "do_mmap", probeType: kretprobe, programName: "trace_ret_do_mmap"},
		VfsRead:                    &traceProbe{eventName: "vfs_read", probeType: kprobe, programName: "trace_vfs_read"},
		VfsReadRet:                 &traceProbe{eventName: "vfs_read", probeType: kretprobe, programName: "trace_ret_vfs_read"},
		VfsReadV:                   &traceProbe{eventName: "vfs_readv", probeType: kprobe, programName: "trace_vfs_readv"},
		VfsReadVRet:                &traceProbe{eventName: "vfs_readv", probeType: kretprobe, programName: "trace_ret_vfs_readv"},
		VfsUtimes:                  &traceProbe{eventName: "vfs_utimes", probeType: kprobe, programName: "trace_vfs_utimes"},
		UtimesCommon:               &traceProbe{eventName: "utimes_common", probeType: kprobe, programName: "trace_utimes_common"},
		DoTruncate:                 &traceProbe{eventName: "do_truncate", probeType: kprobe, programName: "trace_do_truncate"},
		FileUpdateTime:             &traceProbe{eventName: "file_update_time", probeType: kprobe, programName: "trace_file_update_time"},
		FileUpdateTimeRet:          &traceProbe{eventName: "file_update_time", probeType: kretprobe, programName: "trace_ret_file_update_time"},
		FileModified:               &traceProbe{eventName: "file_modified", probeType: kprobe, programName: "trace_file_modified"},
		FileModifiedRet:            &traceProbe{eventName: "file_modified", probeType: kretprobe, programName: "trace_ret_file_modified"},
		FdInstall:                  &traceProbe{eventName: "fd_install", probeType: kprobe, programName: "trace_fd_install"},
		FilpClose:                  &traceProbe{eventName: "filp_close", probeType: kprobe, programName: "trace_filp_close"},
		InotifyFindInode:           &traceProbe{eventName: "inotify_find_inode", probeType: kprobe, programName: "trace_inotify_find_inode"},
		InotifyFindInodeRet:        &traceProbe{eventName: "inotify_find_inode", probeType: kretprobe, programName: "trace_ret_inotify_find_inode"},
		BpfCheck:                   &traceProbe{eventName: "bpf_check", probeType: kprobe, programName: "trace_bpf_check"},
		ExecBinprm:                 &traceProbe{eventName: "exec_binprm", probeType: kprobe, programName: "trace_exec_binprm"},
		ExecBinprmRet:              &traceProbe{eventName: "exec_binprm", probeType: kretprobe, programName: "trace_ret_exec_binprm"},
	}

	if !netEnabled {
		// disable network cgroup probes (avoid effective CAP_NET_ADMIN if not needed)
		if err := allProbes[CgroupSKBIngress].autoload(module, false); err != nil {
			logger.Errorw("CgroupSKBIngress probe autoload", "error", err)
		}
		if err := allProbes[CgroupSKBEgress].autoload(module, false); err != nil {
			logger.Errorw("CgroupSKBEgress probe autoload", "error", err)
		}
	}

	return &probes{
		probes: allProbes,
		module: module,
	}, nil
}

func (p *probes) GetEventName(handle Handle) (string, string) {
	if r, ok := p.probes[handle]; ok {
		if probe, ok := r.(*traceProbe); ok {
			return probe.eventName, probe.programName
		}
	}
	return "", ""
}

func (p *probes) GetProbeType(handle Handle) string {
	if r, ok := p.probes[handle]; ok {
		if probe, ok := r.(*traceProbe); ok {
			switch probe.probeType {
			case kprobe:
				return "kprobe"
			case kretprobe:
				return "kretprobe"
			case tracepoint:
				return "tracepoint"
			case rawTracepoint:
				return "raw_tracepoint"
			}
		}
	}
	return ""
}

// Attach attaches given handle's program to its hook
func (p *probes) Attach(handle Handle, args ...interface{}) error {
	if _, ok := p.probes[handle]; !ok {
		return errfmt.Errorf("probe handle (%d) does not exist", handle)
	}

	return p.probes[handle].attach(p.module, args...)
}

// Detach detaches given handle's program from its hook
func (p *probes) Detach(handle Handle, args ...interface{}) error {
	if _, ok := p.probes[handle]; !ok {
		return errfmt.Errorf("probe handle (%d) does not exist", handle)
	}

	return p.probes[handle].detach(args...)
}

// DetachAll detaches all existing probes (programs from their hooks)
func (p *probes) DetachAll() error {
	for _, pr := range p.probes {
		err := pr.detach()
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}

// Autoload disables autoload feature for a given handle's program
func (p *probes) Autoload(handle Handle, autoload bool) error {
	return p.probes[handle].autoload(p.module, autoload)
}

//
// Probe
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
// Event Handles
//

type Handle int32

const (
	SysEnter Handle = iota
	SysExit
	SyscallEnter__Internal
	SyscallExit__Internal
	SchedProcessFork
	SchedProcessExec
	SchedProcessExit
	SchedProcessFree
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
	PrintSyscallTable
	PrintNetSeqOps
	SecurityInodeRename
	DoSigaction
	SecurityBpfProg
	SecurityFileIoctl
	CheckHelperCall
	CheckMapFuncCompatibility
	KallsymsLookupName
	KallsymsLookupNameRet
	SockAllocFile
	SockAllocFileRet
	SecuritySocketRecvmsg
	SecuritySocketSendmsg
	CgroupBPFRunFilterSKB
	CgroupSKBIngress
	CgroupSKBEgress
	DoMmap
	DoMmapRet
	PrintMemDump
	VfsRead
	VfsReadRet
	VfsReadV
	VfsReadVRet
	VfsUtimes
	UtimesCommon
	DoTruncate
	FileUpdateTime
	FileUpdateTimeRet
	FileModified
	FileModifiedRet
	FdInstall
	FilpClose
	InotifyFindInode
	InotifyFindInodeRet
	BpfCheck
	ExecBinprm
	ExecBinprmRet
	HiddenKernelModuleSeeker
)
