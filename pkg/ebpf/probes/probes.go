package probes

import (
	"fmt"
	"strings"

	bpf "github.com/aquasecurity/libbpfgo"
)

type Probes interface {
	Attach(probe Handle) error
	Detach(probe Handle) error
}

type probes struct {
	probes map[Handle]*probe
	module *bpf.Module
}

type probe struct {
	event     string
	probeType probeType
	functions []string
	link      *bpf.BPFLink
}

// Initialize tracee's probe map
func Init(module *bpf.Module) (Probes, error) {
	return &probes{
		module: module,
		probes: map[Handle]*probe{
			SysEnter:                   {event: "raw_syscalls:sys_enter", probeType: rawTracepoint, functions: []string{"tracepoint__raw_syscalls__sys_enter"}},
			SysExit:                    {event: "raw_syscalls:sys_exit", probeType: rawTracepoint, functions: []string{"tracepoint__raw_syscalls__sys_exit"}},
			SchedProcessFork:           {event: "sched:sched_process_fork", probeType: rawTracepoint, functions: []string{"tracepoint__sched__sched_process_fork"}},
			SchedProcessExec:           {event: "sched:sched_process_exec", probeType: rawTracepoint, functions: []string{"tracepoint__sched__sched_process_exec"}},
			SchedProcessExit:           {event: "sched:sched_process_exit", probeType: rawTracepoint, functions: []string{"tracepoint__sched__sched_process_exit"}},
			SchedSwitch:                {event: "sched:sched_switch", probeType: rawTracepoint, functions: []string{"tracepoint__sched__sched_switch"}},
			DoExit:                     {event: "do_exit", probeType: kprobe, functions: []string{"trace_do_exit"}},
			CapCapable:                 {event: "cap_capable", probeType: kprobe, functions: []string{"trace_cap_capable"}},
			VfsWrite:                   {event: "vfs_write", probeType: kprobe, functions: []string{"trace_vfs_write"}},
			VfsWriteRet:                {event: "vfs_write", probeType: kretprobe, functions: []string{"trace_ret_vfs_write"}},
			VfsWriteV:                  {event: "vfs_writev", probeType: kprobe, functions: []string{"trace_vfs_writev"}},
			VfsWriteVRet:               {event: "vfs_writev", probeType: kretprobe, functions: []string{"trace_ret_vfs_writev"}},
			KernelWrite:                {event: "__kernel_write", probeType: kprobe, functions: []string{"trace_kernel_write"}},
			KernelWriteRet:             {event: "__kernel_write", probeType: kretprobe, functions: []string{"trace_ret_kernel_write"}},
			CgroupAttachTask:           {event: "cgroup:cgroup_attach_task", probeType: rawTracepoint, functions: []string{"tracepoint__cgroup__cgroup_attach_task"}},
			CgroupMkdir:                {event: "cgroup:cgroup_mkdir", probeType: rawTracepoint, functions: []string{"tracepoint__cgroup__cgroup_mkdir"}},
			CgroupRmdir:                {event: "cgroup:cgroup_rmdir", probeType: rawTracepoint, functions: []string{"tracepoint__cgroup__cgroup_rmdir"}},
			SecurityBPRMCheck:          {event: "security_bprm_check", probeType: kprobe, functions: []string{"fentry_security_bprm_check", "trace_security_bprm_check"}},
			SecurityFileOpen:           {event: "security_file_open", probeType: kprobe, functions: []string{"trace_security_file_open"}},
			SecurityFileIoctl:          {event: "security_file_ioctl", probeType: kprobe, functions: []string{"trace_tracee_trigger_event"}},
			SecurityFilePermission:     {event: "security_file_permission", probeType: kprobe, functions: []string{"trace_security_file_permission"}},
			SecuritySocketCreate:       {event: "security_socket_create", probeType: kprobe, functions: []string{"trace_security_socket_create"}},
			SecuritySocketListen:       {event: "security_socket_listen", probeType: kprobe, functions: []string{"trace_security_socket_listen"}},
			SecuritySocketConnect:      {event: "security_socket_connect", probeType: kprobe, functions: []string{"trace_security_socket_connect"}},
			SecuritySocketAccept:       {event: "security_socket_accept", probeType: kprobe, functions: []string{"trace_security_socket_accept"}},
			SecuritySocketBind:         {event: "security_socket_bind", probeType: kprobe, functions: []string{"trace_security_socket_bind"}},
			SecuritySocketSetsockopt:   {event: "security_socket_setsockopt", probeType: kprobe, functions: []string{"trace_security_socket_setsockopt"}},
			SecuritySbMount:            {event: "security_sb_mount", probeType: kprobe, functions: []string{"trace_security_sb_mount"}},
			SecurityBPF:                {event: "security_bpf", probeType: kprobe, functions: []string{"trace_security_bpf"}},
			SecurityBPFMap:             {event: "security_bpf_map", probeType: kprobe, functions: []string{"trace_security_bpf_map"}},
			SecurityKernelReadFile:     {event: "security_kernel_read_file", probeType: kprobe, functions: []string{"trace_security_kernel_read_file"}},
			SecurityKernelPostReadFile: {event: "security_kernel_post_read_file", probeType: kprobe, functions: []string{"trace_security_kernel_post_read_file"}},
			SecurityInodeMknod:         {event: "security_inode_mknod", probeType: kprobe, functions: []string{"trace_security_inode_mknod"}},
			SecurityInodeSymlink:       {event: "security_inode_symlink", probeType: kprobe, functions: []string{"trace_security_inode_symlink"}},
			SecurityInodeUnlink:        {event: "security_inode_unlink", probeType: kprobe, functions: []string{"trace_security_inode_unlink"}},
			SecurityMmapAddr:           {event: "security_mmap_addr", probeType: kprobe, functions: []string{"trace_mmap_alert"}},
			SecurityMmapFile:           {event: "security_mmap_file", probeType: kprobe, functions: []string{"trace_security_mmap_file"}},
			DoSplice:                   {event: "do_splice", probeType: kprobe, functions: []string{"trace_do_splice"}},
			DoSpliceRet:                {event: "do_splice", probeType: kretprobe, functions: []string{"trace_ret_do_splice"}},
			ProcCreate:                 {event: "proc_create", probeType: kprobe, functions: []string{"trace_proc_create"}},
			SecurityFileMProtect:       {event: "security_file_mprotect", probeType: kprobe, functions: []string{"trace_security_file_mprotect"}},
			CommitCreds:                {event: "commit_creds", probeType: kprobe, functions: []string{"trace_commit_creds"}},
			SwitchTaskNS:               {event: "switch_task_namespaces", probeType: kprobe, functions: []string{"trace_switch_task_namespaces"}},
			ARMKprobe:                  {event: "arm_kprobe", probeType: kprobe, functions: []string{"trace_arm_kprobe"}},
			CallUsermodeHelper:         {event: "call_usermodehelper", probeType: kprobe, functions: []string{"trace_call_usermodehelper"}},
			DebugfsCreateFile:          {event: "debugfs_create_file", probeType: kprobe, functions: []string{"trace_debugfs_create_file"}},
			DebugfsCreateDir:           {event: "debugfs_create_dir", probeType: kprobe, functions: []string{"trace_debugfs_create_dir"}},
			DeviceAdd:                  {event: "device_add", probeType: kprobe, functions: []string{"trace_device_add"}},
			RegisterChrdev:             {event: "__register_chrdev", probeType: kprobe, functions: []string{"trace___register_chrdev"}},
			RegisterChrdevRet:          {event: "__register_chrdev", probeType: kretprobe, functions: []string{"trace_ret__register_chrdev"}},
			DoInitModule:               {event: "do_init_module", probeType: kprobe, functions: []string{"trace_do_init_module"}},
			DoInitModuleRet:            {event: "do_init_module", probeType: kretprobe, functions: []string{"trace_ret_do_init_module"}},
			LoadElfPhdrs:               {event: "load_elf_phdrs", probeType: kprobe, functions: []string{"trace_load_elf_phdrs"}},
			Filldir64:                  {event: "filldir64", probeType: kprobe, functions: []string{"trace_filldir64"}},
			TaskRename:                 {event: "task:task_rename", probeType: rawTracepoint, functions: []string{"tracepoint__task__task_rename"}},
		},
	}, nil
}

//Attach the probe corresponding to the probe's handle
func (p *probes) Attach(probe Handle) error {
	if p.probes[probe] == nil {
		return fmt.Errorf("failed to attach probe: doesn't exist")
	}

	return p.probes[probe].attach(p.module)
}

//Detach the probe corresponding to the probe's handle
func (p *probes) Detach(probe Handle) error {
	if p.probes[probe] == nil {
		return fmt.Errorf("failed to detach probe: doesn't exist")
	}

	return p.probes[probe].detach()
}

// ProbeType is an enum that describes the mechanism used to attach the event
// Kprobes are explained here: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#1-kp
// Tracepoints are explained here: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#3-tracep
// Raw tracepoints are explained here: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#7-raw-tracep
type probeType uint8

const (
	kprobe = iota
	kretprobe
	tracepoint
	rawTracepoint
)

//internal attach function - takes *bpf.Module the from the owning probes struct as a parameter
func (p *probe) attach(module *bpf.Module) error {
	if p.link != nil {
		return nil
	}

	var (
		err         error
		prog        *bpf.BPFProg
		isSupported bool
	)

	for i := range p.functions {
		prog, err = module.GetProgram(p.functions[i])
		if err != nil {
			return err
		}
		isSupported, err = bpf.BPFProgramTypeIsSupported(prog.GetType())
		if err != nil {
			return err
		}
		if isSupported {
			continue
		}
	}
	if !isSupported {
		return fmt.Errorf("no supported program for chosen event: %s", p.event)
	}

	probeType := prog.GetType()
	var link *bpf.BPFLink
	switch probeType {
	case bpf.BPFProgTypeKprobe:
		if strings.HasPrefix(prog.GetSectionName(), "kretprobe/") {
			link, err = prog.AttachKretprobe(p.event)
		}
		link, err = prog.AttachKprobe(p.event)
	case bpf.BPFProgTypeTracepoint:
		tpEvent := strings.Split(p.event, ":")
		if len(tpEvent) != 2 {
			err = fmt.Errorf("tracepoint must be in 'category:name' format")
		} else {
			link, err = prog.AttachTracepoint(p.event, p.event)
		}
	case bpf.BPFProgTypeRawTracepoint:
		tpEvent := strings.Split(p.event, ":")[1]
		link, err = prog.AttachRawTracepoint(tpEvent)
	default:
		link, err = prog.AttachGeneric()
	}
	if err != nil {
		return fmt.Errorf("error attaching probe %s: %v", p.event, err)
	}

	//we store the bpf link so we can detach the probe later
	p.link = link
	return nil
}

//internal detach function
func (p *probe) detach() error {
	//probes is unattached so just return nil early
	if p.link == nil {
		return nil
	}

	err := p.link.Destroy()

	if err != nil {
		return fmt.Errorf("error detaching probe %s: %v", p.event, err)
	}

	p.link = nil
	return err
}

type Handle int32

const (
	SysEnter Handle = iota
	SysExit
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
	ARMKprobe
	CallUsermodeHelper
	DebugfsCreateFile
	DebugfsCreateDir
	SecurityFileIoctl
	DeviceAdd
	RegisterChrdev
	RegisterChrdevRet
	DoInitModule
	DoInitModuleRet
	LoadElfPhdrs
	Filldir64
	SecurityFilePermission
	TaskRename
)
