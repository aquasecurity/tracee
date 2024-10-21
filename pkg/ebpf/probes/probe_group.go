package probes

import (
	"sync"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
)

//
// ProbeGroup
//

// ProbeGroup is a collection of probes.
type ProbeGroup struct {
	probesLock *sync.Mutex // disallow concurrent access to the probe group
	module     *bpf.Module
	probes     map[Handle]Probe
}

// NewProbeGroup creates a new ProbeGroup.
func NewProbeGroup(m *bpf.Module, p map[Handle]Probe) *ProbeGroup {
	return &ProbeGroup{
		probesLock: &sync.Mutex{}, // no parallel attaching/detaching of probes
		probes:     p,
		module:     m,
	}
}

func (p *ProbeGroup) HandleExists(handle Handle) bool {
	p.probesLock.Lock()
	defer p.probesLock.Unlock()

	_, ok := p.probes[handle]
	return ok
}

func (p *ProbeGroup) AddProbe(handle Handle, probe Probe) error {
	if p.HandleExists(handle) {
		return errfmt.Errorf("probe handle (%d) already exists", handle)
	}

	p.probesLock.Lock()
	defer p.probesLock.Unlock()

	p.probes[handle] = probe

	return nil
}

// GetProbe returns a probe type by its handle.
func (p *ProbeGroup) GetProbeType(handle Handle) ProbeType {
	p.probesLock.Lock()
	defer p.probesLock.Unlock()

	if r, ok := p.probes[handle]; ok {
		if probe, ok := r.(*TraceProbe); ok {
			return probe.probeType
		}
	}

	return InvalidProbeType
}

// Attach attaches a probe's program to its hook, by given handle.
func (p *ProbeGroup) Attach(handle Handle, args ...interface{}) error {
	p.probesLock.Lock()
	defer p.probesLock.Unlock()

	if _, ok := p.probes[handle]; !ok {
		return errfmt.Errorf("probe handle (%d) does not exist", handle)
	}

	return p.probes[handle].attach(p.module, args...)
}

// Detach detaches a probe's program from its hook, by given handle.
func (p *ProbeGroup) Detach(handle Handle, args ...interface{}) error {
	p.probesLock.Lock()
	defer p.probesLock.Unlock()

	if _, ok := p.probes[handle]; !ok {
		return errfmt.Errorf("probe handle (%d) does not exist", handle)
	}

	return p.probes[handle].detach(args...)
}

// DetachAll detaches all existing probes programs from their hooks.
func (p *ProbeGroup) DetachAll() error {
	p.probesLock.Lock()
	defer p.probesLock.Unlock()

	for _, pr := range p.probes {
		err := pr.detach()
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}

// Autoload disables autoload feature for a given handle's program.
func (p *ProbeGroup) Autoload(handle Handle, autoload bool) error {
	p.probesLock.Lock()
	defer p.probesLock.Unlock()
	return p.probes[handle].autoload(p.module, autoload)
}

func (p *ProbeGroup) GetProbeByHandle(handle Handle) Probe {
	return p.probes[handle]
}

// NewDefaultProbeGroup initializes the default ProbeGroup (TODO: extensions will use probe groups)
func NewDefaultProbeGroup(module *bpf.Module, netEnabled bool) (*ProbeGroup, error) {
	binaryPath := "/proc/self/exe"

	allProbes := map[Handle]Probe{
		SysEnter:                   NewTraceProbe(RawTracepoint, "raw_syscalls:sys_enter", "trace_sys_enter"),
		SyscallEnter__Internal:     NewTraceProbe(RawTracepoint, "raw_syscalls:sys_enter", "tracepoint__raw_syscalls__sys_enter"),
		SysExit:                    NewTraceProbe(RawTracepoint, "raw_syscalls:sys_exit", "trace_sys_exit"),
		SyscallExit__Internal:      NewTraceProbe(RawTracepoint, "raw_syscalls:sys_exit", "tracepoint__raw_syscalls__sys_exit"),
		SchedProcessFork:           NewTraceProbe(RawTracepoint, "sched:sched_process_fork", "tracepoint__sched__sched_process_fork"),
		SchedProcessExec:           NewTraceProbe(RawTracepoint, "sched:sched_process_exec", "tracepoint__sched__sched_process_exec"),
		SchedProcessExit:           NewTraceProbe(RawTracepoint, "sched:sched_process_exit", "tracepoint__sched__sched_process_exit"),
		SchedProcessFree:           NewTraceProbe(RawTracepoint, "sched:sched_process_free", "tracepoint__sched__sched_process_free"),
		SchedSwitch:                NewTraceProbe(RawTracepoint, "sched:sched_switch", "tracepoint__sched__sched_switch"),
		DoExit:                     NewTraceProbe(KProbe, "do_exit", "trace_do_exit"),
		CapCapable:                 NewTraceProbe(KProbe, "cap_capable", "trace_cap_capable"),
		VfsWrite:                   NewTraceProbe(KProbe, "vfs_write", "trace_vfs_write"),
		VfsWriteRet:                NewTraceProbe(KretProbe, "vfs_write", "trace_ret_vfs_write"),
		VfsWriteV:                  NewTraceProbe(KProbe, "vfs_writev", "trace_vfs_writev"),
		VfsWriteVRet:               NewTraceProbe(KretProbe, "vfs_writev", "trace_ret_vfs_writev"),
		KernelWrite:                NewTraceProbe(KProbe, "__kernel_write", "trace_kernel_write"),
		KernelWriteRet:             NewTraceProbe(KretProbe, "__kernel_write", "trace_ret_kernel_write"),
		VfsWriteMagic:              NewTraceProbe(KProbe, "vfs_write", "vfs_write_magic_enter"),
		VfsWriteMagicRet:           NewTraceProbe(KretProbe, "vfs_write", "vfs_write_magic_return"),
		VfsWriteVMagic:             NewTraceProbe(KProbe, "vfs_writev", "vfs_writev_magic_enter"),
		VfsWriteVMagicRet:          NewTraceProbe(KretProbe, "vfs_writev", "vfs_writev_magic_return"),
		KernelWriteMagic:           NewTraceProbe(KProbe, "__kernel_write", "kernel_write_magic_enter"),
		KernelWriteMagicRet:        NewTraceProbe(KretProbe, "__kernel_write", "kernel_write_magic_return"),
		CgroupAttachTask:           NewTraceProbe(RawTracepoint, "cgroup:cgroup_attach_task", "tracepoint__cgroup__cgroup_attach_task"),
		CgroupMkdir:                NewTraceProbe(RawTracepoint, "cgroup:cgroup_mkdir", "tracepoint__cgroup__cgroup_mkdir"),
		CgroupRmdir:                NewTraceProbe(RawTracepoint, "cgroup:cgroup_rmdir", "tracepoint__cgroup__cgroup_rmdir"),
		SecurityBPRMCheck:          NewTraceProbe(KProbe, "security_bprm_check", "trace_security_bprm_check"),
		SecurityFileOpen:           NewTraceProbe(KProbe, "security_file_open", "trace_security_file_open"),
		SecurityFilePermission:     NewTraceProbe(KProbe, "security_file_permission", "trace_security_file_permission"),
		SecuritySocketCreate:       NewTraceProbe(KProbe, "security_socket_create", "trace_security_socket_create"),
		SecuritySocketListen:       NewTraceProbe(KProbe, "security_socket_listen", "trace_security_socket_listen"),
		SecuritySocketConnect:      NewTraceProbe(KProbe, "security_socket_connect", "trace_security_socket_connect"),
		SecuritySocketAccept:       NewTraceProbe(KProbe, "security_socket_accept", "trace_security_socket_accept"),
		SecuritySocketBind:         NewTraceProbe(KProbe, "security_socket_bind", "trace_security_socket_bind"),
		SecuritySocketSetsockopt:   NewTraceProbe(KProbe, "security_socket_setsockopt", "trace_security_socket_setsockopt"),
		SecuritySbMount:            NewTraceProbe(KProbe, "security_sb_mount", "trace_security_sb_mount"),
		SecurityBPF:                NewTraceProbe(KProbe, "security_bpf", "trace_security_bpf"),
		SecurityBPFMap:             NewTraceProbe(KProbe, "security_bpf_map", "trace_security_bpf_map"),
		SecurityKernelReadFile:     NewTraceProbe(KProbe, "security_kernel_read_file", "trace_security_kernel_read_file"),
		SecurityKernelPostReadFile: NewTraceProbe(KProbe, "security_kernel_post_read_file", "trace_security_kernel_post_read_file"),
		SecurityInodeMknod:         NewTraceProbe(KProbe, "security_inode_mknod", "trace_security_inode_mknod"),
		SecurityInodeSymlink:       NewTraceProbe(KProbe, "security_inode_symlink", "trace_security_inode_symlink"),
		SecurityInodeUnlink:        NewTraceProbe(KProbe, "security_inode_unlink", "trace_security_inode_unlink"),
		SecurityMmapAddr:           NewTraceProbe(KProbe, "security_mmap_addr", "trace_mmap_alert"),
		SecurityMmapFile:           NewTraceProbe(KProbe, "security_mmap_file", "trace_security_mmap_file"),
		DoSplice:                   NewTraceProbe(KProbe, "do_splice", "trace_do_splice"),
		DoSpliceRet:                NewTraceProbe(KretProbe, "do_splice", "trace_ret_do_splice"),
		ProcCreate:                 NewTraceProbe(KProbe, "proc_create", "trace_proc_create"),
		SecurityFileMProtect:       NewTraceProbe(KProbe, "security_file_mprotect", "trace_security_file_mprotect"),
		CommitCreds:                NewTraceProbe(KProbe, "commit_creds", "trace_commit_creds"),
		SwitchTaskNS:               NewTraceProbe(KProbe, "switch_task_namespaces", "trace_switch_task_namespaces"),
		RegisterKprobe:             NewTraceProbe(KProbe, "register_kprobe", "trace_register_kprobe"),
		RegisterKprobeRet:          NewTraceProbe(KretProbe, "register_kprobe", "trace_ret_register_kprobe"),
		CallUsermodeHelper:         NewTraceProbe(KProbe, "call_usermodehelper", "trace_call_usermodehelper"),
		DebugfsCreateFile:          NewTraceProbe(KProbe, "debugfs_create_file", "trace_debugfs_create_file"),
		DebugfsCreateDir:           NewTraceProbe(KProbe, "debugfs_create_dir", "trace_debugfs_create_dir"),
		DeviceAdd:                  NewTraceProbe(KProbe, "device_add", "trace_device_add"),
		RegisterChrdev:             NewTraceProbe(KProbe, "__register_chrdev", "trace___register_chrdev"),
		RegisterChrdevRet:          NewTraceProbe(KretProbe, "__register_chrdev", "trace_ret__register_chrdev"),
		DoInitModule:               NewTraceProbe(KProbe, "do_init_module", "trace_do_init_module"),
		DoInitModuleRet:            NewTraceProbe(KretProbe, "do_init_module", "trace_ret_do_init_module"),
		LoadElfPhdrs:               NewTraceProbe(KProbe, "load_elf_phdrs", "trace_load_elf_phdrs"),
		Filldir64:                  NewTraceProbe(KProbe, "filldir64", "trace_filldir64"),
		TaskRename:                 NewTraceProbe(RawTracepoint, "task:task_rename", "tracepoint__task__task_rename"),
		SyscallTableCheck:          NewUprobe("syscall_table_check", "uprobe_syscall_table_check", binaryPath, "github.com/aquasecurity/tracee/pkg/ebpf.(*Tracee).triggerSyscallTableIntegrityCheckCall"),
		HiddenKernelModuleSeeker:   NewUprobe("hidden_kernel_module", "uprobe_lkm_seeker", binaryPath, "github.com/aquasecurity/tracee/pkg/ebpf.(*Tracee).triggerKernelModuleSeeker"),
		HiddenKernelModuleVerifier: NewUprobe("hidden_kernel_module", "uprobe_lkm_seeker_submitter", binaryPath, "github.com/aquasecurity/tracee/pkg/ebpf.(*Tracee).triggerKernelModuleSubmitter"),
		PrintNetSeqOps:             NewUprobe("print_net_seq_ops", "uprobe_seq_ops_trigger", binaryPath, "github.com/aquasecurity/tracee/pkg/ebpf.(*Tracee).triggerSeqOpsIntegrityCheckCall"),
		PrintMemDump:               NewUprobe("print_mem_dump", "uprobe_mem_dump_trigger", binaryPath, "github.com/aquasecurity/tracee/pkg/ebpf.(*Tracee).triggerMemDumpCall"),
		SecurityInodeRename:        NewTraceProbe(KProbe, "security_inode_rename", "trace_security_inode_rename"),
		DoSigaction:                NewTraceProbe(KProbe, "do_sigaction", "trace_do_sigaction"),
		SecurityBpfProg:            NewTraceProbe(KProbe, "security_bpf_prog", "trace_security_bpf_prog"),
		SecurityFileIoctl:          NewTraceProbe(KProbe, "security_file_ioctl", "trace_security_file_ioctl"),
		CheckHelperCall:            NewTraceProbe(KProbe, "check_helper_call", "trace_check_helper_call"),
		CheckMapFuncCompatibility:  NewTraceProbe(KProbe, "check_map_func_compatibility", "trace_check_map_func_compatibility"),
		KallsymsLookupName:         NewTraceProbe(KProbe, "kallsyms_lookup_name", "trace_kallsyms_lookup_name"),
		KallsymsLookupNameRet:      NewTraceProbe(KretProbe, "kallsyms_lookup_name", "trace_ret_kallsyms_lookup_name"),
		SockAllocFile:              NewTraceProbe(KProbe, "sock_alloc_file", "trace_sock_alloc_file"),
		SockAllocFileRet:           NewTraceProbe(KretProbe, "sock_alloc_file", "trace_ret_sock_alloc_file"),
		SecuritySkClone:            NewTraceProbe(KProbe, "security_sk_clone", "trace_security_sk_clone"),
		SecuritySocketSendmsg:      NewTraceProbe(KProbe, "security_socket_sendmsg", "trace_security_socket_sendmsg"),
		SecuritySocketRecvmsg:      NewTraceProbe(KProbe, "security_socket_recvmsg", "trace_security_socket_recvmsg"),
		CgroupBPFRunFilterSKB:      NewTraceProbe(KProbe, "__cgroup_bpf_run_filter_skb", "cgroup_bpf_run_filter_skb"),
		CgroupSKBIngress:           NewCgroupProbe(bpf.BPFAttachTypeCgroupInetIngress, "cgroup_skb_ingress"),
		CgroupSKBEgress:            NewCgroupProbe(bpf.BPFAttachTypeCgroupInetEgress, "cgroup_skb_egress"),
		DoMmap:                     NewTraceProbe(KProbe, "do_mmap", "trace_do_mmap"),
		DoMmapRet:                  NewTraceProbe(KretProbe, "do_mmap", "trace_ret_do_mmap"),
		VfsRead:                    NewTraceProbe(KProbe, "vfs_read", "trace_vfs_read"),
		VfsReadRet:                 NewTraceProbe(KretProbe, "vfs_read", "trace_ret_vfs_read"),
		VfsReadV:                   NewTraceProbe(KProbe, "vfs_readv", "trace_vfs_readv"),
		VfsReadVRet:                NewTraceProbe(KretProbe, "vfs_readv", "trace_ret_vfs_readv"),
		VfsUtimes:                  NewTraceProbe(KProbe, "vfs_utimes", "trace_vfs_utimes"),
		UtimesCommon:               NewTraceProbe(KProbe, "utimes_common", "trace_utimes_common"),
		DoTruncate:                 NewTraceProbe(KProbe, "do_truncate", "trace_do_truncate"),
		FileUpdateTime:             NewTraceProbe(KProbe, "file_update_time", "trace_file_update_time"),
		FileUpdateTimeRet:          NewTraceProbe(KretProbe, "file_update_time", "trace_ret_file_update_time"),
		FileModified:               NewTraceProbe(KProbe, "file_modified", "trace_file_modified"),
		FileModifiedRet:            NewTraceProbe(KretProbe, "file_modified", "trace_ret_file_modified"),
		FdInstall:                  NewTraceProbe(KProbe, "fd_install", "trace_fd_install"),
		FilpClose:                  NewTraceProbe(KProbe, "filp_close", "trace_filp_close"),
		InotifyFindInode:           NewTraceProbe(KProbe, "inotify_find_inode", "trace_inotify_find_inode"),
		InotifyFindInodeRet:        NewTraceProbe(KretProbe, "inotify_find_inode", "trace_ret_inotify_find_inode"),
		BpfCheck:                   NewTraceProbe(KProbe, "bpf_check", "trace_bpf_check"),
		ExecBinprm:                 NewTraceProbe(KProbe, "exec_binprm", "trace_exec_binprm"),
		SecurityPathNotify:         NewTraceProbe(KProbe, "security_path_notify", "trace_security_path_notify"),
		SecurityBprmCredsForExec:   NewTraceProbe(KProbe, "security_bprm_creds_for_exec", "trace_security_bprm_creds_for_exec"),
		SetFsPwd:                   NewTraceProbe(KProbe, "set_fs_pwd", "trace_set_fs_pwd"),
		TpProbeRegPrioMayExist:     NewTraceProbe(KProbe, "tracepoint_probe_register_prio_may_exist", "trace_tracepoint_probe_register_prio_may_exist"),
		ModuleLoad:                 NewTraceProbe(RawTracepoint, "module:module_load", "tracepoint__module__module_load"),
		ModuleFree:                 NewTraceProbe(RawTracepoint, "module:module_free", "tracepoint__module__module_free"),
		SignalCgroupMkdir:          NewTraceProbe(RawTracepoint, "cgroup:cgroup_mkdir", "cgroup_mkdir_signal"),
		SignalCgroupRmdir:          NewTraceProbe(RawTracepoint, "cgroup:cgroup_rmdir", "cgroup_rmdir_signal"),
		SignalSchedProcessFork:     NewTraceProbe(RawTracepoint, "sched:sched_process_fork", "sched_process_fork_signal"),
		SignalSchedProcessExec:     NewTraceProbe(RawTracepoint, "sched:sched_process_exec", "sched_process_exec_signal"),
		SignalSchedProcessExit:     NewTraceProbe(RawTracepoint, "sched:sched_process_exit", "sched_process_exit_signal"),
		ExecuteFinishedX86:         NewTraceProbe(KretProbe, "__x64_sys_execve", "trace_execute_finished"),
		ExecuteAtFinishedX86:       NewTraceProbe(KretProbe, "__x64_sys_execveat", "trace_execute_finished"),
		ExecuteFinishedCompatX86:   NewTraceProbe(KretProbe, "__ia32_compat_sys_execve", "trace_execute_finished"),
		ExecuteAtFinishedCompatX86: NewTraceProbe(KretProbe, "__ia32_compat_sys_execveat", "trace_execute_finished"),
		ExecuteFinishedARM:         NewTraceProbe(KretProbe, "__arm64_sys_execve", "trace_execute_finished"),
		ExecuteAtFinishedARM:       NewTraceProbe(KretProbe, "__arm64_sys_execveat", "trace_execute_finished"),
		ExecuteFinishedCompatARM:   NewTraceProbe(KretProbe, "__arm64_compat_sys_execve", "trace_execute_finished"),
		ExecuteAtFinishedCompatARM: NewTraceProbe(KretProbe, "__arm64_compat_sys_execveat", "trace_execute_finished"),
		SecurityTaskSetrlimit:      NewTraceProbe(KProbe, "security_task_setrlimit", "trace_security_task_setrlimit"),
		SecuritySettime64:          NewTraceProbe(KProbe, "security_settime64", "trace_security_settime64"),
		Ptrace:                     NewTraceProbe(SyscallEnter, "ptrace", "trace_ptrace"),
		PtraceRet:                  NewTraceProbe(SyscallExit, "ptrace", "trace_ret_ptrace"),
		ProcessVmWritev:            NewTraceProbe(SyscallEnter, "process_vm_writev", "trace_process_vm_writev"),
		ProcessVmWritevRet:         NewTraceProbe(SyscallExit, "process_vm_writev", "trace_ret_process_vm_writev"),
		ArchPrctl:                  NewTraceProbe(SyscallEnter, "arch_prctl", "trace_arch_prctl"),
		ArchPrctlRet:               NewTraceProbe(SyscallExit, "arch_prctl", "trace_ret_arch_prctl"),
		Dup:                        NewTraceProbe(SyscallEnter, "dup", "trace_dup"),
		DupRet:                     NewTraceProbe(SyscallExit, "dup", "trace_ret_dup"),
		Dup2:                       NewTraceProbe(SyscallEnter, "dup2", "trace_dup2"),
		Dup2Ret:                    NewTraceProbe(SyscallExit, "dup2", "trace_ret_dup2"),
		Dup3:                       NewTraceProbe(SyscallEnter, "dup3", "trace_dup3"),
		Dup3Ret:                    NewTraceProbe(SyscallExit, "dup3", "trace_ret_dup3"),
		ChmodCommon:                NewTraceProbe(KProbe, "chmod_common", "trace_chmod_common"),

		TestUnavailableHook: NewTraceProbe(KProbe, "non_existing_func", "empty_kprobe"),
		ExecTest:            NewTraceProbe(RawTracepoint, "raw_syscalls:sched_process_exec", "tracepoint__exec_test"),
		EmptyKprobe:         NewTraceProbe(KProbe, "security_bprm_check", "empty_kprobe"),
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

	return NewProbeGroup(module, allProbes), nil
}
