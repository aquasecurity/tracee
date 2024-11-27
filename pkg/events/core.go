package events

import (
	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
	"github.com/aquasecurity/tracee/pkg/events/trigger"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

const (
	// use (0xfffffff - x) as most overflows behavior is undefined
	All            ID = 0xfffffff - 1
	Undefined      ID = 0xfffffff - 2
	Sys32Undefined ID = 0xfffffff - 3
	Unsupported    ID = 9000
	MaxBuiltinID   ID = 10000 - 1
)

type ID int32

// NOTE: Events should match defined values in ebpf code.

// Common events (used by all architectures).
const (
	NetPacketBase ID = iota + 700
	NetPacketRaw
	NetPacketIPBase
	NetPacketTCPBase
	NetPacketUDPBase
	NetPacketICMPBase
	NetPacketICMPv6Base
	NetPacketDNSBase
	NetPacketHTTPBase
	NetPacketCapture
	NetPacketFlow
	MaxNetID // network base events go ABOVE this item
	SysEnter
	SysExit
	SchedProcessFork
	SchedProcessExec
	SchedProcessExit
	SchedSwitch
	DoExit
	CapCapable
	VfsWrite
	VfsWritev
	VfsRead
	VfsReadv
	MemProtAlert
	CommitCreds
	SwitchTaskNS
	MagicWrite
	CgroupAttachTask
	CgroupMkdir
	CgroupRmdir
	SecurityBprmCheck
	SecurityFileOpen
	SecurityInodeUnlink
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
	SecurityInodeMknod
	SecurityPostReadFile
	SecurityInodeSymlinkEventId
	SecurityMmapFile
	SecurityFileMprotect
	SocketDup
	HiddenInodes
	KernelWrite
	ProcCreate
	KprobeAttach
	CallUsermodeHelper
	DirtyPipeSplice
	DebugfsCreateFile
	SyscallTableCheck
	DebugfsCreateDir
	DeviceAdd
	RegisterChrdev
	SharedObjectLoaded
	DoInitModule
	SocketAccept
	LoadElfPhdrs
	HookedProcFops
	PrintNetSeqOps
	TaskRename
	SecurityInodeRename
	DoSigaction
	BpfAttach
	KallsymsLookupName
	DoMmap
	PrintMemDump
	VfsUtimes
	DoTruncate
	FileModification
	InotifyWatch
	SecurityBpfProg
	ProcessExecuteFailed
	SecurityPathNotify
	SetFsPwd
	SuspiciousSyscallSource
	StackPivot
	HiddenKernelModuleSeeker
	ModuleLoad
	ModuleFree
	ExecuteFinished
	ProcessExecuteFailedInternal
	SecurityTaskSetrlimit
	SecuritySettime64
	ChmodCommon
	MaxCommonID
)

// Events originated from user-space
const (
	NetPacketIPv4 ID = iota + 2000
	NetPacketIPv6
	NetPacketTCP
	NetPacketUDP
	NetPacketICMP
	NetPacketICMPv6
	NetPacketDNS
	NetPacketDNSRequest
	NetPacketDNSResponse
	NetPacketHTTP
	NetPacketHTTPRequest
	NetPacketHTTPResponse
	NetFlowEnd
	NetFlowTCPBegin
	NetFlowTCPEnd
	MaxUserNetID
	NetTCPConnect
	InitNamespaces
	ContainerCreate
	ContainerRemove
	ExistingContainer
	HookedSyscall
	HookedSeqOps
	SymbolsLoaded
	SymbolsCollision
	HiddenKernelModule
	FtraceHook
	TraceeInfo
	MaxUserSpace
)

// Capture meta-events
const (
	CaptureFileWrite ID = iota + 4000
	CaptureExec
	CaptureModule
	CaptureMem
	CapturePcap
	CaptureNetPacket
	CaptureBpf
	CaptureFileRead
)

// Signal meta-events

const (
	SignalCgroupMkdir ID = iota + 5000
	SignalCgroupRmdir
	SignalSchedProcessFork
	SignalSchedProcessExec
	SignalSchedProcessExit
)

// Signature events
const (
	StartSignatureID ID = 6000
	MaxSignatureID   ID = 6999
)

// Test events
const (
	ExecTest ID = 8000 + iota
	MissingKsymbol
	FailedAttach
)

//
// All Events
//

var Core *DefinitionGroup

func init() {
	Core = NewDefinitionGroup()
	err := Core.AddBatch(CoreEvents)
	if err != nil {
		logger.Errorw("failed to initialize event definitions", "err", err)
	}
}

var CoreEvents = map[ID]Definition{
	//
	// Begin of Syscalls
	//
	Read: {
		id:      Read,
		id32Bit: Sys32read,
		name:    "read",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_read_write"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "void*", Name: "buf"},
			{Type: "size_t", Name: "count"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Read)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Read)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Read)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Read)}},
			},
		},
	},
	Write: {
		id:      Write,
		id32Bit: Sys32write,
		name:    "write",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_read_write"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "void*", Name: "buf"},
			{Type: "size_t", Name: "count"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Write)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Write)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Write)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Write)}},
			},
		},
	},
	Open: {
		id:      Open,
		id32Bit: Sys32open,
		name:    "open",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_ops"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "int", Name: "flags"},
			{Type: "umode_t", Name: "mode"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Open)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Open)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Open)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Open)}},
			},
		},
	},
	Close: {
		id:      Close,
		id32Bit: Sys32close,
		name:    "close",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_ops"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Close)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Close)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Close)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Close)}},
			},
		},
	},
	Stat: {
		id:      Stat,
		id32Bit: Sys32stat,
		name:    "stat",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "struct stat*", Name: "statbuf"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Stat)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Stat)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Stat)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Stat)}},
			},
		},
	},
	Fstat: {
		id:      Fstat,
		id32Bit: Sys32fstat,
		name:    "fstat",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "struct stat*", Name: "statbuf"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Fstat)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Fstat)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Fstat)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Fstat)}},
			},
		},
	},
	Lstat: {
		id:      Lstat,
		id32Bit: Sys32lstat,
		name:    "lstat",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "struct stat*", Name: "statbuf"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Lstat)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Lstat)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Lstat)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Lstat)}},
			},
		},
	},
	Poll: {
		id:      Poll,
		id32Bit: Sys32poll,
		name:    "poll",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_mux_io"},
		fields: []trace.ArgMeta{
			{Type: "struct pollfd*", Name: "fds"},
			{Type: "unsigned int", Name: "nfds"},
			{Type: "int", Name: "timeout"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Poll)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Poll)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Poll)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Poll)}},
			},
		},
	},
	Lseek: {
		id:      Lseek,
		id32Bit: Sys32lseek,
		name:    "lseek",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_read_write"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "off_t", Name: "offset"},
			{Type: "unsigned int", Name: "whence"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Lseek)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Lseek)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Lseek)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Lseek)}},
			},
		},
	},
	Mmap: {
		id:      Mmap,
		id32Bit: Sys32mmap,
		name:    "mmap",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_mem"},
		fields: []trace.ArgMeta{
			{Type: "void*", Name: "addr"},
			{Type: "size_t", Name: "length"},
			{Type: "int", Name: "prot"},
			{Type: "int", Name: "flags"},
			{Type: "int", Name: "fd"},
			{Type: "off_t", Name: "off"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Mmap)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Mmap)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Mmap)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Mmap)}},
			},
		},
	},
	Mprotect: {
		id:      Mprotect,
		id32Bit: Sys32mprotect,
		name:    "mprotect",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_mem"},
		fields: []trace.ArgMeta{
			{Type: "void*", Name: "addr"},
			{Type: "size_t", Name: "len"},
			{Type: "int", Name: "prot"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Mprotect)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Mprotect)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Mprotect)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Mprotect)}},
			},
		},
	},
	Munmap: {
		id:      Munmap,
		id32Bit: Sys32munmap,
		name:    "munmap",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_mem"},
		fields: []trace.ArgMeta{
			{Type: "void*", Name: "addr"},
			{Type: "size_t", Name: "length"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Munmap)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Munmap)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Munmap)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Munmap)}},
			},
		},
	},
	Brk: {
		id:      Brk,
		id32Bit: Sys32brk,
		name:    "brk",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_mem"},
		fields: []trace.ArgMeta{
			{Type: "void*", Name: "addr"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Brk)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Brk)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Brk)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Brk)}},
			},
		},
	},
	RtSigaction: {
		id:      RtSigaction,
		id32Bit: Sys32rt_sigaction,
		name:    "rt_sigaction",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "signals"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "signum"},
			{Type: "const struct sigaction*", Name: "act"},
			{Type: "struct sigaction*", Name: "oldact"},
			{Type: "size_t", Name: "sigsetsize"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(RtSigaction)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(RtSigaction)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(RtSigaction)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(RtSigaction)}},
			},
		},
	},
	RtSigprocmask: {
		id:      RtSigprocmask,
		id32Bit: Sys32rt_sigprocmask,
		name:    "rt_sigprocmask",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "signals"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "how"},
			{Type: "sigset_t*", Name: "set"},
			{Type: "sigset_t*", Name: "oldset"},
			{Type: "size_t", Name: "sigsetsize"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(RtSigprocmask)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(RtSigprocmask)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(RtSigprocmask)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(RtSigprocmask)}},
			},
		},
	},
	RtSigreturn: {
		id:      RtSigreturn,
		id32Bit: Sys32rt_sigreturn,
		name:    "rt_sigreturn",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "signals"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(RtSigreturn)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(RtSigreturn)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(RtSigreturn)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(RtSigreturn)}},
			},
		},
	},
	Ioctl: {
		id:      Ioctl,
		id32Bit: Sys32ioctl,
		name:    "ioctl",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_fd_ops"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "unsigned long", Name: "request"},
			{Type: "unsigned long", Name: "arg"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Ioctl)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Ioctl)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Ioctl)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Ioctl)}},
			},
		},
	},
	Pread64: {
		id:      Pread64,
		id32Bit: Sys32pread64,
		name:    "pread64",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_read_write"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "void*", Name: "buf"},
			{Type: "size_t", Name: "count"},
			{Type: "off_t", Name: "offset"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Pread64)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Pread64)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Pread64)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Pread64)}},
			},
		},
	},
	Pwrite64: {
		id:      Pwrite64,
		id32Bit: Sys32pwrite64,
		name:    "pwrite64",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_read_write"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const void*", Name: "buf"},
			{Type: "size_t", Name: "count"},
			{Type: "off_t", Name: "offset"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Pwrite64)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Pwrite64)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Pwrite64)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Pwrite64)}},
			},
		},
	},
	Readv: {
		id:      Readv,
		id32Bit: Sys32readv,
		name:    "readv",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_read_write"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const struct iovec*", Name: "iov"},
			{Type: "int", Name: "iovcnt"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Readv)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Readv)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Readv)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Readv)}},
			},
		},
	},
	Writev: {
		id:      Writev,
		id32Bit: Sys32writev,
		name:    "writev",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_read_write"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const struct iovec*", Name: "iov"},
			{Type: "int", Name: "iovcnt"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Writev)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Writev)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Writev)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Writev)}},
			},
		},
	},
	Access: {
		id:      Access,
		id32Bit: Sys32access,
		name:    "access",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "int", Name: "mode"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Access)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Access)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Access)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Access)}},
			},
		},
	},
	Pipe: {
		id:      Pipe,
		id32Bit: Sys32pipe,
		name:    "pipe",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "ipc", "ipc_pipe"},
		fields: []trace.ArgMeta{
			{Type: "int[2]", Name: "pipefd"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Pipe)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Pipe)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Pipe)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Pipe)}},
			},
		},
	},
	Select: {
		id:      Select,
		id32Bit: Sys32_newselect,
		name:    "select",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_mux_io"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "nfds"},
			{Type: "fd_set*", Name: "readfds"},
			{Type: "fd_set*", Name: "writefds"},
			{Type: "fd_set*", Name: "exceptfds"},
			{Type: "struct timeval*", Name: "timeout"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Select)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Select)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Select)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Select)}},
			},
		},
	},
	SchedYield: {
		id:      SchedYield,
		id32Bit: Sys32sched_yield,
		name:    "sched_yield",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_sched"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(SchedYield)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(SchedYield)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(SchedYield)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(SchedYield)}},
			},
		},
	},
	Mremap: {
		id:      Mremap,
		id32Bit: Sys32mremap,
		name:    "mremap",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_mem"},
		fields: []trace.ArgMeta{
			{Type: "void*", Name: "old_address"},
			{Type: "size_t", Name: "old_size"},
			{Type: "size_t", Name: "new_size"},
			{Type: "int", Name: "flags"},
			{Type: "void*", Name: "new_address"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Mremap)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Mremap)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Mremap)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Mremap)}},
			},
		},
	},
	Msync: {
		id:      Msync,
		id32Bit: Sys32msync,
		name:    "msync",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_sync"},
		fields: []trace.ArgMeta{
			{Type: "void*", Name: "addr"},
			{Type: "size_t", Name: "length"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Msync)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Msync)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Msync)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Msync)}},
			},
		},
	},
	Mincore: {
		id:      Mincore,
		id32Bit: Sys32mincore,
		name:    "mincore",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_mem"},
		fields: []trace.ArgMeta{
			{Type: "void*", Name: "addr"},
			{Type: "size_t", Name: "length"},
			{Type: "unsigned char*", Name: "vec"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Mincore)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Mincore)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Mincore)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Mincore)}},
			},
		},
	},
	Madvise: {
		id:      Madvise,
		id32Bit: Sys32madvise,
		name:    "madvise",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_mem"},
		fields: []trace.ArgMeta{
			{Type: "void*", Name: "addr"},
			{Type: "size_t", Name: "length"},
			{Type: "int", Name: "advice"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Madvise)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Madvise)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Madvise)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Madvise)}},
			},
		},
	},
	Shmget: {
		id:      Shmget,
		id32Bit: Sys32shmget,
		name:    "shmget",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "ipc", "ipc_shm"},
		fields: []trace.ArgMeta{
			{Type: "key_t", Name: "key"},
			{Type: "size_t", Name: "size"},
			{Type: "int", Name: "shmflg"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Shmget)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Shmget)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Shmget)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Shmget)}},
			},
		},
	},
	Shmat: {
		id:      Shmat,
		id32Bit: Sys32shmat,
		name:    "shmat",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "ipc", "ipc_shm"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "shmid"},
			{Type: "const void*", Name: "shmaddr"},
			{Type: "int", Name: "shmflg"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Shmat)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Shmat)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Shmat)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Shmat)}},
			},
		},
	},
	Shmctl: {
		id:      Shmctl,
		id32Bit: Sys32shmctl,
		name:    "shmctl",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "ipc", "ipc_shm"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "shmid"},
			{Type: "int", Name: "cmd"},
			{Type: "struct shmid_ds*", Name: "buf"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Shmctl)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Shmctl)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Shmctl)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Shmctl)}},
			},
		},
	},
	Dup: {
		id:      Dup,
		id32Bit: Sys32dup,
		name:    "dup",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_fd_ops"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "oldfd"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.Dup, required: true},
				{handle: probes.DupRet, required: true},
			},
		},
	},
	Dup2: {
		id:      Dup2,
		id32Bit: Sys32dup2,
		name:    "dup2",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_fd_ops"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "oldfd"},
			{Type: "int", Name: "newfd"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.Dup2, required: true},
				{handle: probes.Dup2Ret, required: true},
			},
		},
	},
	Pause: {
		id:      Pause,
		id32Bit: Sys32pause,
		name:    "pause",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "signals"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Pause)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Pause)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Pause)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Pause)}},
			},
		},
	},
	Nanosleep: {
		id:      Nanosleep,
		id32Bit: Sys32nanosleep,
		name:    "nanosleep",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "time", "time_timer"},
		fields: []trace.ArgMeta{
			{Type: "const struct timespec*", Name: "req"},
			{Type: "struct timespec*", Name: "rem"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Nanosleep)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Nanosleep)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Nanosleep)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Nanosleep)}},
			},
		},
	},
	Getitimer: {
		id:      Getitimer,
		id32Bit: Sys32getitimer,
		name:    "getitimer",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "time", "time_timer"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "which"},
			{Type: "struct itimerval*", Name: "curr_value"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getitimer)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getitimer)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getitimer)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getitimer)}},
			},
		},
	},
	Alarm: {
		id:      Alarm,
		id32Bit: Sys32alarm,
		name:    "alarm",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "time", "time_timer"},
		fields: []trace.ArgMeta{
			{Type: "unsigned int", Name: "seconds"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Alarm)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Alarm)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Alarm)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Alarm)}},
			},
		},
	},
	Setitimer: {
		id:      Setitimer,
		id32Bit: Sys32setitimer,
		name:    "setitimer",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "time", "time_timer"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "which"},
			{Type: "struct itimerval*", Name: "new_value"},
			{Type: "struct itimerval*", Name: "old_value"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setitimer)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setitimer)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setitimer)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setitimer)}},
			},
		},
	},
	Getpid: {
		id:      Getpid,
		id32Bit: Sys32getpid,
		name:    "getpid",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_ids"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getpid)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getpid)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getpid)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getpid)}},
			},
		},
	},
	Sendfile: {
		id:      Sendfile,
		id32Bit: Sys32sendfile64,
		name:    "sendfile",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_read_write"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "out_fd"},
			{Type: "int", Name: "in_fd"},
			{Type: "off_t*", Name: "offset"},
			{Type: "size_t", Name: "count"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Sendfile)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Sendfile)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Sendfile)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Sendfile)}},
			},
		},
	},
	Socket: {
		id:      Socket,
		id32Bit: Sys32socket,
		name:    "socket",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "net", "net_sock"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "domain"},
			{Type: "int", Name: "type"},
			{Type: "int", Name: "protocol"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Socket)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Socket)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Socket)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Socket)}},
			},
		},
	},
	Connect: {
		id:      Connect,
		id32Bit: Sys32connect,
		name:    "connect",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "net", "net_sock"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct sockaddr*", Name: "addr"},
			{Type: "int", Name: "addrlen"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Connect)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Connect)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Connect)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Connect)}},
			},
		},
	},
	Accept: {
		id:      Accept,
		id32Bit: Sys32Undefined,
		name:    "accept",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "net", "net_sock"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct sockaddr*", Name: "addr"},
			{Type: "int*", Name: "addrlen"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Accept)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Accept)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Accept)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Accept)}},
			},
		},
	},
	Sendto: {
		id:      Sendto,
		id32Bit: Sys32sendto,
		name:    "sendto",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "net", "net_snd_rcv"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "void*", Name: "buf"},
			{Type: "size_t", Name: "len"},
			{Type: "int", Name: "flags"},
			{Type: "struct sockaddr*", Name: "dest_addr"},
			{Type: "int", Name: "addrlen"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Sendto)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Sendto)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Sendto)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Sendto)}},
			},
		},
	},
	Recvfrom: {
		id:      Recvfrom,
		id32Bit: Sys32recvfrom,
		name:    "recvfrom",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "net", "net_snd_rcv"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "void*", Name: "buf"},
			{Type: "size_t", Name: "len"},
			{Type: "int", Name: "flags"},
			{Type: "struct sockaddr*", Name: "src_addr"},
			{Type: "int*", Name: "addrlen"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Recvfrom)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Recvfrom)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Recvfrom)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Recvfrom)}},
			},
		},
	},
	Sendmsg: {
		id:      Sendmsg,
		id32Bit: Sys32sendmsg,
		name:    "sendmsg",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "net", "net_snd_rcv"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct msghdr*", Name: "msg"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Sendmsg)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Sendmsg)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Sendmsg)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Sendmsg)}},
			},
		},
	},
	Recvmsg: {
		id:      Recvmsg,
		id32Bit: Sys32recvmsg,
		name:    "recvmsg",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "net", "net_snd_rcv"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct msghdr*", Name: "msg"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Recvmsg)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Recvmsg)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Recvmsg)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Recvmsg)}},
			},
		},
	},
	Shutdown: {
		id:      Shutdown,
		id32Bit: Sys32shutdown,
		name:    "shutdown",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "net", "net_sock"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "int", Name: "how"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Shutdown)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Shutdown)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Shutdown)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Shutdown)}},
			},
		},
	},
	Bind: {
		id:      Bind,
		id32Bit: Sys32bind,
		name:    "bind",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "net", "net_sock"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct sockaddr*", Name: "addr"},
			{Type: "int", Name: "addrlen"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Bind)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Bind)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Bind)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Bind)}},
			},
		},
	},
	Listen: {
		id:      Listen,
		id32Bit: Sys32listen,
		name:    "listen",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "net", "net_sock"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "int", Name: "backlog"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Listen)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Listen)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Listen)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Listen)}},
			},
		},
	},
	Getsockname: {
		id:      Getsockname,
		id32Bit: Sys32getsockname,
		name:    "getsockname",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "net", "net_sock"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct sockaddr*", Name: "addr"},
			{Type: "int*", Name: "addrlen"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getsockname)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getsockname)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getsockname)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getsockname)}},
			},
		},
	},
	Getpeername: {
		id:      Getpeername,
		id32Bit: Sys32getpeername,
		name:    "getpeername",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "net", "net_sock"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct sockaddr*", Name: "addr"},
			{Type: "int*", Name: "addrlen"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getpeername)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getpeername)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getpeername)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getpeername)}},
			},
		},
	},
	Socketpair: {
		id:      Socketpair,
		id32Bit: Sys32socketpair,
		name:    "socketpair",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "net", "net_sock"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "domain"},
			{Type: "int", Name: "type"},
			{Type: "int", Name: "protocol"},
			{Type: "int[2]", Name: "sv"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Socketpair)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Socketpair)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Socketpair)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Socketpair)}},
			},
		},
	},
	Setsockopt: {
		id:      Setsockopt,
		id32Bit: Sys32setsockopt,
		name:    "setsockopt",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "net", "net_sock"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "int", Name: "level"},
			{Type: "int", Name: "optname"},
			{Type: "const void*", Name: "optval"},
			{Type: "int", Name: "optlen"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setsockopt)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setsockopt)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setsockopt)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setsockopt)}},
			},
		},
	},
	Getsockopt: {
		id:      Getsockopt,
		id32Bit: Sys32getsockopt,
		name:    "getsockopt",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "net", "net_sock"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "int", Name: "level"},
			{Type: "int", Name: "optname"},
			{Type: "void*", Name: "optval"},
			{Type: "int*", Name: "optlen"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getsockopt)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getsockopt)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getsockopt)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getsockopt)}},
			},
		},
	},
	Clone: {
		id:      Clone,
		id32Bit: Sys32clone,
		name:    "clone",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_life"},
		fields: []trace.ArgMeta{
			{Type: "unsigned long", Name: "flags"},
			{Type: "void*", Name: "stack"},
			{Type: "int*", Name: "parent_tid"},
			{Type: "int*", Name: "child_tid"},
			{Type: "unsigned long", Name: "tls"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Clone)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Clone)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Clone)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Clone)}},
			},
		},
	},
	Fork: {
		id:      Fork,
		id32Bit: Sys32fork,
		name:    "fork",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_life"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Fork)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Fork)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Fork)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Fork)}},
			},
		},
	},
	Vfork: {
		id:      Vfork,
		id32Bit: Sys32vfork,
		name:    "vfork",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_life"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Vfork)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Vfork)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Vfork)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Vfork)}},
			},
		},
	},
	Execve: {
		id:      Execve,
		id32Bit: Sys32execve,
		name:    "execve",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_life"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "const char*const*", Name: "argv"},
			{Type: "const char*const*", Name: "envp"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Execve)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Execve)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Execve)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Execve)}},
				{"sys_enter_tails", "syscall__execve_enter", []uint32{uint32(Execve)}},
				{"sys_exit_tails", "syscall__execve_exit", []uint32{uint32(Execve)}},
			},
		},
	},
	Exit: {
		id:      Exit,
		id32Bit: Sys32exit,
		name:    "exit",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_life"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "status"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Exit)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Exit)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Exit)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Exit)}},
			},
		},
	},
	Wait4: {
		id:      Wait4,
		id32Bit: Sys32wait4,
		name:    "wait4",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_life"},
		fields: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "int*", Name: "wstatus"},
			{Type: "int", Name: "options"},
			{Type: "struct rusage*", Name: "rusage"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Wait4)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Wait4)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Wait4)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Wait4)}},
			},
		},
	},
	Kill: {
		id:      Kill,
		id32Bit: Sys32kill,
		name:    "kill",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "signals"},
		fields: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "int", Name: "sig"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Kill)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Kill)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Kill)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Kill)}},
			},
		},
	},
	Uname: {
		id:      Uname,
		id32Bit: Sys32uname,
		name:    "uname",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system"},
		fields: []trace.ArgMeta{
			{Type: "struct utsname*", Name: "buf"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Uname)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Uname)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Uname)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Uname)}},
			},
		},
	},
	Semget: {
		id:      Semget,
		id32Bit: Sys32semget,
		name:    "semget",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "ipc", "ipc_sem"},
		fields: []trace.ArgMeta{
			{Type: "key_t", Name: "key"},
			{Type: "int", Name: "nsems"},
			{Type: "int", Name: "semflg"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Semget)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Semget)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Semget)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Semget)}},
			},
		},
	},
	Semop: {
		id:      Semop,
		id32Bit: Sys32Undefined,
		name:    "semop",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "ipc", "ipc_sem"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "semid"},
			{Type: "struct sembuf*", Name: "sops"},
			{Type: "size_t", Name: "nsops"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Semop)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Semop)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Semop)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Semop)}},
			},
		},
	},
	Semctl: {
		id:      Semctl,
		id32Bit: Sys32semctl,
		name:    "semctl",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "ipc", "ipc_sem"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "semid"},
			{Type: "int", Name: "semnum"},
			{Type: "int", Name: "cmd"},
			{Type: "unsigned long", Name: "arg"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Semctl)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Semctl)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Semctl)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Semctl)}},
			},
		},
	},
	Shmdt: {
		id:      Shmdt,
		id32Bit: Sys32shmdt,
		name:    "shmdt",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "ipc", "ipc_shm"},
		fields: []trace.ArgMeta{
			{Type: "const void*", Name: "shmaddr"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Shmdt)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Shmdt)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Shmdt)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Shmdt)}},
			},
		},
	},
	Msgget: {
		id:      Msgget,
		id32Bit: Sys32msgget,
		name:    "msgget",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "ipc", "ipc_msgq"},
		fields: []trace.ArgMeta{
			{Type: "key_t", Name: "key"},
			{Type: "int", Name: "msgflg"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Msgget)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Msgget)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Msgget)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Msgget)}},
			},
		},
	},
	Msgsnd: {
		id:      Msgsnd,
		id32Bit: Sys32msgsnd,
		name:    "msgsnd",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "ipc", "ipc_msgq"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "msqid"},
			{Type: "struct msgbuf*", Name: "msgp"},
			{Type: "size_t", Name: "msgsz"},
			{Type: "int", Name: "msgflg"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Msgsnd)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Msgsnd)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Msgsnd)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Msgsnd)}},
			},
		},
	},
	Msgrcv: {
		id:      Msgrcv,
		id32Bit: Sys32msgrcv,
		name:    "msgrcv",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "ipc", "ipc_msgq"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "msqid"},
			{Type: "struct msgbuf*", Name: "msgp"},
			{Type: "size_t", Name: "msgsz"},
			{Type: "long", Name: "msgtyp"},
			{Type: "int", Name: "msgflg"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Msgrcv)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Msgrcv)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Msgrcv)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Msgrcv)}},
			},
		},
	},
	Msgctl: {
		id:      Msgctl,
		id32Bit: Sys32msgctl,
		name:    "msgctl",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "ipc", "ipc_msgq"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "msqid"},
			{Type: "int", Name: "cmd"},
			{Type: "struct msqid_ds*", Name: "buf"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Msgctl)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Msgctl)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Msgctl)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Msgctl)}},
			},
		},
	},
	Fcntl: {
		id:      Fcntl,
		id32Bit: Sys32fcntl,
		name:    "fcntl",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_fd_ops"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "int", Name: "cmd"},
			{Type: "unsigned long", Name: "arg"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Fcntl)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Fcntl)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Fcntl)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Fcntl)}},
			},
		},
	},
	Flock: {
		id:      Flock,
		id32Bit: Sys32flock,
		name:    "flock",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_fd_ops"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "int", Name: "operation"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Flock)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Flock)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Flock)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Flock)}},
			},
		},
	},
	Fsync: {
		id:      Fsync,
		id32Bit: Sys32fsync,
		name:    "fsync",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_sync"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Fsync)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Fsync)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Fsync)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Fsync)}},
			},
		},
	},
	Fdatasync: {
		id:      Fdatasync,
		id32Bit: Sys32fdatasync,
		name:    "fdatasync",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_sync"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Fdatasync)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Fdatasync)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Fdatasync)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Fdatasync)}},
			},
		},
	},
	Truncate: {
		id:      Truncate,
		id32Bit: Sys32truncate,
		name:    "truncate",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_ops"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "off_t", Name: "length"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Truncate)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Truncate)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Truncate)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Truncate)}},
			},
		},
	},
	Ftruncate: {
		id:      Ftruncate,
		id32Bit: Sys32ftruncate,
		name:    "ftruncate",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_ops"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "off_t", Name: "length"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Ftruncate)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Ftruncate)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Ftruncate)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Ftruncate)}},
			},
		},
	},
	Getdents: {
		id:      Getdents,
		id32Bit: Sys32getdents,
		name:    "getdents",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_dir_ops"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "struct linux_dirent*", Name: "dirp"},
			{Type: "unsigned int", Name: "count"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getdents)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getdents)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getdents)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getdents)}},
			},
		},
	},
	Getcwd: {
		id:      Getcwd,
		id32Bit: Sys32getcwd,
		name:    "getcwd",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_dir_ops"},
		fields: []trace.ArgMeta{
			{Type: "char*", Name: "buf"},
			{Type: "size_t", Name: "size"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getcwd)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getcwd)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getcwd)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getcwd)}},
			},
		},
	},
	Chdir: {
		id:      Chdir,
		id32Bit: Sys32chdir,
		name:    "chdir",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_dir_ops"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "path"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Chdir)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Chdir)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Chdir)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Chdir)}},
			},
		},
	},
	Fchdir: {
		id:      Fchdir,
		id32Bit: Sys32fchdir,
		name:    "fchdir",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_dir_ops"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Fchdir)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Fchdir)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Fchdir)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Fchdir)}},
			},
		},
	},
	Rename: {
		id:      Rename,
		id32Bit: Sys32rename,
		name:    "rename",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_ops"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "oldpath"},
			{Type: "const char*", Name: "newpath"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Rename)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Rename)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Rename)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Rename)}},
			},
		},
	},
	Mkdir: {
		id:      Mkdir,
		id32Bit: Sys32mkdir,
		name:    "mkdir",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_dir_ops"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "umode_t", Name: "mode"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Mkdir)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Mkdir)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Mkdir)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Mkdir)}},
			},
		},
	},
	Rmdir: {
		id:      Rmdir,
		id32Bit: Sys32rmdir,
		name:    "rmdir",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_dir_ops"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Rmdir)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Rmdir)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Rmdir)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Rmdir)}},
			},
		},
	},
	Creat: {
		id:      Creat,
		id32Bit: Sys32creat,
		name:    "creat",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_ops"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "umode_t", Name: "mode"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Creat)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Creat)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Creat)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Creat)}},
			},
		},
	},
	Link: {
		id:      Link,
		id32Bit: Sys32link,
		name:    "link",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_link_ops"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "oldpath"},
			{Type: "const char*", Name: "newpath"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Link)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Link)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Link)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Link)}},
			},
		},
	},
	Unlink: {
		id:      Unlink,
		id32Bit: Sys32unlink,
		name:    "unlink",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_link_ops"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Unlink)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Unlink)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Unlink)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Unlink)}},
			},
		},
	},
	Symlink: {
		id:      Symlink,
		id32Bit: Sys32symlink,
		name:    "symlink",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_link_ops"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "target"},
			{Type: "const char*", Name: "linkpath"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Symlink)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Symlink)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Symlink)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Symlink)}},
			},
		},
	},
	Readlink: {
		id:      Readlink,
		id32Bit: Sys32readlink,
		name:    "readlink",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_link_ops"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "char*", Name: "buf"},
			{Type: "size_t", Name: "bufsiz"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Readlink)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Readlink)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Readlink)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Readlink)}},
			},
		},
	},
	Chmod: {
		id:      Chmod,
		id32Bit: Sys32chmod,
		name:    "chmod",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "umode_t", Name: "mode"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Chmod)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Chmod)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Chmod)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Chmod)}},
			},
		},
	},
	Fchmod: {
		id:      Fchmod,
		id32Bit: Sys32fchmod,
		name:    "fchmod",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "umode_t", Name: "mode"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Fchmod)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Fchmod)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Fchmod)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Fchmod)}},
			},
		},
	},
	Chown: {
		id:      Chown,
		id32Bit: Sys32chown32,
		name:    "chown",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "uid_t", Name: "owner"},
			{Type: "gid_t", Name: "group"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Chown)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Chown)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Chown)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Chown)}},
			},
		},
	},
	Fchown: {
		id:      Fchown,
		id32Bit: Sys32fchown32,
		name:    "fchown",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "uid_t", Name: "owner"},
			{Type: "gid_t", Name: "group"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Fchown)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Fchown)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Fchown)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Fchown)}},
			},
		},
	},
	Lchown: {
		id:      Lchown,
		id32Bit: Sys32lchown32,
		name:    "lchown",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "uid_t", Name: "owner"},
			{Type: "gid_t", Name: "group"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Lchown)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Lchown)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Lchown)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Lchown)}},
			},
		},
	},
	Umask: {
		id:      Umask,
		id32Bit: Sys32umask,
		name:    "umask",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "mode_t", Name: "mask"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Umask)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Umask)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Umask)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Umask)}},
			},
		},
	},
	Gettimeofday: {
		id:      Gettimeofday,
		id32Bit: Sys32gettimeofday,
		name:    "gettimeofday",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "time", "time_tod"},
		fields: []trace.ArgMeta{
			{Type: "struct timeval*", Name: "tv"},
			{Type: "struct timezone*", Name: "tz"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Gettimeofday)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Gettimeofday)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Gettimeofday)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Gettimeofday)}},
			},
		},
	},
	Getrlimit: {
		id:      Getrlimit,
		id32Bit: Sys32ugetrlimit,
		name:    "getrlimit",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "resource"},
			{Type: "struct rlimit*", Name: "rlim"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getrlimit)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getrlimit)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getrlimit)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getrlimit)}},
			},
		},
	},
	Getrusage: {
		id:      Getrusage,
		id32Bit: Sys32getrusage,
		name:    "getrusage",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "who"},
			{Type: "struct rusage*", Name: "usage"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getrusage)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getrusage)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getrusage)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getrusage)}},
			},
		},
	},
	Sysinfo: {
		id:      Sysinfo,
		id32Bit: Sys32sysinfo,
		name:    "sysinfo",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system"},
		fields: []trace.ArgMeta{
			{Type: "struct sysinfo*", Name: "info"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Sysinfo)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Sysinfo)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Sysinfo)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Sysinfo)}},
			},
		},
	},
	Times: {
		id:      Times,
		id32Bit: Sys32times,
		name:    "times",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc"},
		fields: []trace.ArgMeta{
			{Type: "struct tms*", Name: "buf"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Times)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Times)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Times)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Times)}},
			},
		},
	},
	Ptrace: {
		id:      Ptrace,
		id32Bit: Sys32ptrace,
		name:    "ptrace",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"default", "syscalls", "proc"},
		fields: []trace.ArgMeta{
			{Type: "long", Name: "request"},
			{Type: "pid_t", Name: "pid"},
			{Type: "void*", Name: "addr"},
			{Type: "void*", Name: "data"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.Ptrace, required: true},
				{handle: probes.PtraceRet, required: true},
			},
		},
	},
	Getuid: {
		id:      Getuid,
		id32Bit: Sys32getuid32,
		name:    "getuid",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_ids"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getuid)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getuid)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getuid)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getuid)}},
			},
		},
	},
	Syslog: {
		id:      Syslog,
		id32Bit: Sys32syslog,
		name:    "syslog",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "type"},
			{Type: "char*", Name: "bufp"},
			{Type: "int", Name: "len"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Syslog)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Syslog)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Syslog)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Syslog)}},
			},
		},
	},
	Getgid: {
		id:      Getgid,
		id32Bit: Sys32getgid32,
		name:    "getgid",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_ids"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getgid)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getgid)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getgid)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getgid)}},
			},
		},
	},
	Setuid: {
		id:      Setuid,
		id32Bit: Sys32setuid32,
		name:    "setuid",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_ids"},
		fields: []trace.ArgMeta{
			{Type: "uid_t", Name: "uid"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setuid)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setuid)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setuid)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setuid)}},
			},
		},
	},
	Setgid: {
		id:      Setgid,
		id32Bit: Sys32setgid32,
		name:    "setgid",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_ids"},
		fields: []trace.ArgMeta{
			{Type: "gid_t", Name: "gid"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setgid)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setgid)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setgid)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setgid)}},
			},
		},
	},
	Geteuid: {
		id:      Geteuid,
		id32Bit: Sys32geteuid32,
		name:    "geteuid",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_ids"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Geteuid)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Geteuid)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Geteuid)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Geteuid)}},
			},
		},
	},
	Getegid: {
		id:      Getegid,
		id32Bit: Sys32getegid32,
		name:    "getegid",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_ids"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getegid)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getegid)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getegid)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getegid)}},
			},
		},
	},
	Setpgid: {
		id:      Setpgid,
		id32Bit: Sys32setpgid,
		name:    "setpgid",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_ids"},
		fields: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "pid_t", Name: "pgid"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setpgid)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setpgid)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setpgid)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setpgid)}},
			},
		},
	},
	Getppid: {
		id:      Getppid,
		id32Bit: Sys32getppid,
		name:    "getppid",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_ids"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getppid)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getppid)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getppid)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getppid)}},
			},
		},
	},
	Getpgrp: {
		id:      Getpgrp,
		id32Bit: Sys32getpgrp,
		name:    "getpgrp",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_ids"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getpgrp)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getpgrp)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getpgrp)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getpgrp)}},
			},
		},
	},
	Setsid: {
		id:      Setsid,
		id32Bit: Sys32setsid,
		name:    "setsid",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_ids"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setsid)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setsid)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setsid)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setsid)}},
			},
		},
	},
	Setreuid: {
		id:      Setreuid,
		id32Bit: Sys32setreuid32,
		name:    "setreuid",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_ids"},
		fields: []trace.ArgMeta{
			{Type: "uid_t", Name: "ruid"},
			{Type: "uid_t", Name: "euid"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setreuid)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setreuid)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setreuid)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setreuid)}},
			},
		},
	},
	Setregid: {
		id:      Setregid,
		id32Bit: Sys32setregid32,
		name:    "setregid",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_ids"},
		fields: []trace.ArgMeta{
			{Type: "gid_t", Name: "rgid"},
			{Type: "gid_t", Name: "egid"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setregid)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setregid)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setregid)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setregid)}},
			},
		},
	},
	Getgroups: {
		id:      Getgroups,
		id32Bit: Sys32getgroups32,
		name:    "getgroups",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_ids"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "size"},
			{Type: "gid_t*", Name: "list"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getgroups)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getgroups)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getgroups)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getgroups)}},
			},
		},
	},
	Setgroups: {
		id:      Setgroups,
		id32Bit: Sys32setgroups32,
		name:    "setgroups",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_ids"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "size"},
			{Type: "gid_t*", Name: "list"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setgroups)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setgroups)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setgroups)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setgroups)}},
			},
		},
	},
	Setresuid: {
		id:      Setresuid,
		id32Bit: Sys32setresuid32,
		name:    "setresuid",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_ids"},
		fields: []trace.ArgMeta{
			{Type: "uid_t", Name: "ruid"},
			{Type: "uid_t", Name: "euid"},
			{Type: "uid_t", Name: "suid"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setresuid)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setresuid)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setresuid)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setresuid)}},
			},
		},
	},
	Getresuid: {
		id:      Getresuid,
		id32Bit: Sys32getresuid32,
		name:    "getresuid",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_ids"},
		fields: []trace.ArgMeta{
			{Type: "uid_t*", Name: "ruid"},
			{Type: "uid_t*", Name: "euid"},
			{Type: "uid_t*", Name: "suid"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getresuid)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getresuid)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getresuid)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getresuid)}},
			},
		},
	},
	Setresgid: {
		id:      Setresgid,
		id32Bit: Sys32setresgid32,
		name:    "setresgid",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_ids"},
		fields: []trace.ArgMeta{
			{Type: "gid_t", Name: "rgid"},
			{Type: "gid_t", Name: "egid"},
			{Type: "gid_t", Name: "sgid"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setresgid)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setresgid)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setresgid)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setresgid)}},
			},
		},
	},
	Getresgid: {
		id:      Getresgid,
		id32Bit: Sys32getresgid32,
		name:    "getresgid",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_ids"},
		fields: []trace.ArgMeta{
			{Type: "gid_t*", Name: "rgid"},
			{Type: "gid_t*", Name: "egid"},
			{Type: "gid_t*", Name: "sgid"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getresgid)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getresgid)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getresgid)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getresgid)}},
			},
		},
	},
	Getpgid: {
		id:      Getpgid,
		id32Bit: Sys32getpgid,
		name:    "getpgid",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_ids"},
		fields: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getpgid)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getpgid)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getpgid)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getpgid)}},
			},
		},
	},
	Setfsuid: {
		id:      Setfsuid,
		id32Bit: Sys32setfsuid32,
		name:    "setfsuid",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_ids"},
		fields: []trace.ArgMeta{
			{Type: "uid_t", Name: "fsuid"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setfsuid)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setfsuid)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setfsuid)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setfsuid)}},
			},
		},
	},
	Setfsgid: {
		id:      Setfsgid,
		id32Bit: Sys32setfsgid32,
		name:    "setfsgid",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_ids"},
		fields: []trace.ArgMeta{
			{Type: "gid_t", Name: "fsgid"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setfsgid)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setfsgid)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setfsgid)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setfsgid)}},
			},
		},
	},
	Getsid: {
		id:      Getsid,
		id32Bit: Sys32getsid,
		name:    "getsid",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_ids"},
		fields: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getsid)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getsid)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getsid)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getsid)}},
			},
		},
	},
	Capget: {
		id:      Capget,
		id32Bit: Sys32capget,
		name:    "capget",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc"},
		fields: []trace.ArgMeta{
			{Type: "cap_user_header_t", Name: "hdrp"},
			{Type: "cap_user_data_t", Name: "datap"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Capget)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Capget)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Capget)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Capget)}},
			},
		},
	},
	Capset: {
		id:      Capset,
		id32Bit: Sys32capset,
		name:    "capset",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc"},
		fields: []trace.ArgMeta{
			{Type: "cap_user_header_t", Name: "hdrp"},
			{Type: "const cap_user_data_t", Name: "datap"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Capset)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Capset)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Capset)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Capset)}},
			},
		},
	},
	RtSigpending: {
		id:      RtSigpending,
		id32Bit: Sys32rt_sigpending,
		name:    "rt_sigpending",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "signals"},
		fields: []trace.ArgMeta{
			{Type: "sigset_t*", Name: "set"},
			{Type: "size_t", Name: "sigsetsize"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(RtSigpending)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(RtSigpending)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(RtSigpending)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(RtSigpending)}},
			},
		},
	},
	RtSigtimedwait: {
		id:      RtSigtimedwait,
		id32Bit: Sys32rt_sigtimedwait_time64,
		name:    "rt_sigtimedwait",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "signals"},
		fields: []trace.ArgMeta{
			{Type: "const sigset_t*", Name: "set"},
			{Type: "siginfo_t*", Name: "info"},
			{Type: "const struct timespec*", Name: "timeout"},
			{Type: "size_t", Name: "sigsetsize"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(RtSigtimedwait)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(RtSigtimedwait)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(RtSigtimedwait)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(RtSigtimedwait)}},
			},
		},
	},
	RtSigqueueinfo: {
		id:      RtSigqueueinfo,
		id32Bit: Sys32rt_sigqueueinfo,
		name:    "rt_sigqueueinfo",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "signals"},
		fields: []trace.ArgMeta{
			{Type: "pid_t", Name: "tgid"},
			{Type: "int", Name: "sig"},
			{Type: "siginfo_t*", Name: "info"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(RtSigqueueinfo)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(RtSigqueueinfo)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(RtSigqueueinfo)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(RtSigqueueinfo)}},
			},
		},
	},
	RtSigsuspend: {
		id:      RtSigsuspend,
		id32Bit: Sys32rt_sigsuspend,
		name:    "rt_sigsuspend",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "signals"},
		fields: []trace.ArgMeta{
			{Type: "sigset_t*", Name: "mask"},
			{Type: "size_t", Name: "sigsetsize"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(RtSigsuspend)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(RtSigsuspend)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(RtSigsuspend)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(RtSigsuspend)}},
			},
		},
	},
	Sigaltstack: {
		id:      Sigaltstack,
		id32Bit: Sys32sigaltstack,
		name:    "sigaltstack",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "signals"},
		fields: []trace.ArgMeta{
			{Type: "const stack_t*", Name: "ss"},
			{Type: "stack_t*", Name: "old_ss"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Sigaltstack)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Sigaltstack)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Sigaltstack)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Sigaltstack)}},
			},
		},
	},
	Utime: {
		id:      Utime,
		id32Bit: Sys32utime,
		name:    "utime",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "filename"},
			{Type: "const struct utimbuf*", Name: "times"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Utime)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Utime)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Utime)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Utime)}},
			},
		},
	},
	Mknod: {
		id:      Mknod,
		id32Bit: Sys32mknod,
		name:    "mknod",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_ops"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "umode_t", Name: "mode"},
			{Type: "dev_t", Name: "dev"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Mknod)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Mknod)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Mknod)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Mknod)}},
			},
		},
	},
	Uselib: {
		id:      Uselib,
		id32Bit: Sys32uselib,
		name:    "uselib",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "library"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Uselib)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Uselib)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Uselib)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Uselib)}},
			},
		},
	},
	Personality: {
		id:      Personality,
		id32Bit: Sys32personality,
		name:    "personality",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system"},
		fields: []trace.ArgMeta{
			{Type: "unsigned long", Name: "persona"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Personality)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Personality)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Personality)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Personality)}},
			},
		},
	},
	Ustat: {
		id:      Ustat,
		id32Bit: Sys32ustat,
		name:    "ustat",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_info"},
		fields: []trace.ArgMeta{
			{Type: "dev_t", Name: "dev"},
			{Type: "struct ustat*", Name: "ubuf"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Ustat)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Ustat)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Ustat)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Ustat)}},
			},
		},
	},
	Statfs: {
		id:      Statfs,
		id32Bit: Sys32statfs,
		name:    "statfs",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_info"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "struct statfs*", Name: "buf"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Statfs)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Statfs)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Statfs)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Statfs)}},
			},
		},
	},
	Fstatfs: {
		id:      Fstatfs,
		id32Bit: Sys32fstatfs,
		name:    "fstatfs",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_info"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "struct statfs*", Name: "buf"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Fstatfs)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Fstatfs)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Fstatfs)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Fstatfs)}},
			},
		},
	},
	Sysfs: {
		id:      Sysfs,
		id32Bit: Sys32sysfs,
		name:    "sysfs",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_info"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "option"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Sysfs)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Sysfs)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Sysfs)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Sysfs)}},
			},
		},
	},
	Getpriority: {
		id:      Getpriority,
		id32Bit: Sys32getpriority,
		name:    "getpriority",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_sched"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "which"},
			{Type: "int", Name: "who"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getpriority)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getpriority)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getpriority)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getpriority)}},
			},
		},
	},
	Setpriority: {
		id:      Setpriority,
		id32Bit: Sys32setpriority,
		name:    "setpriority",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_sched"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "which"},
			{Type: "int", Name: "who"},
			{Type: "int", Name: "prio"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setpriority)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setpriority)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setpriority)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setpriority)}},
			},
		},
	},
	SchedSetparam: {
		id:      SchedSetparam,
		id32Bit: Sys32sched_setparam,
		name:    "sched_setparam",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_sched"},
		fields: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "struct sched_param*", Name: "param"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(SchedSetparam)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(SchedSetparam)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(SchedSetparam)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(SchedSetparam)}},
			},
		},
	},
	SchedGetparam: {
		id:      SchedGetparam,
		id32Bit: Sys32sched_getparam,
		name:    "sched_getparam",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_sched"},
		fields: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "struct sched_param*", Name: "param"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(SchedGetparam)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(SchedGetparam)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(SchedGetparam)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(SchedGetparam)}},
			},
		},
	},
	SchedSetscheduler: {
		id:      SchedSetscheduler,
		id32Bit: Sys32sched_setscheduler,
		name:    "sched_setscheduler",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_sched"},
		fields: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "int", Name: "policy"},
			{Type: "struct sched_param*", Name: "param"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(SchedSetscheduler)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(SchedSetscheduler)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(SchedSetscheduler)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(SchedSetscheduler)}},
			},
		},
	},
	SchedGetscheduler: {
		id:      SchedGetscheduler,
		id32Bit: Sys32sched_getscheduler,
		name:    "sched_getscheduler",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_sched"},
		fields: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(SchedGetscheduler)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(SchedGetscheduler)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(SchedGetscheduler)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(SchedGetscheduler)}},
			},
		},
	},
	SchedGetPriorityMax: {
		id:      SchedGetPriorityMax,
		id32Bit: Sys32sched_get_priority_max,
		name:    "sched_get_priority_max",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_sched"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "policy"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(SchedGetPriorityMax)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(SchedGetPriorityMax)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(SchedGetPriorityMax)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(SchedGetPriorityMax)}},
			},
		},
	},
	SchedGetPriorityMin: {
		id:      SchedGetPriorityMin,
		id32Bit: Sys32sched_get_priority_min,
		name:    "sched_get_priority_min",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_sched"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "policy"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(SchedGetPriorityMin)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(SchedGetPriorityMin)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(SchedGetPriorityMin)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(SchedGetPriorityMin)}},
			},
		},
	},
	SchedRrGetInterval: {
		id:      SchedRrGetInterval,
		id32Bit: Sys32sched_rr_get_interval_time64,
		name:    "sched_rr_get_interval",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_sched"},
		fields: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "struct timespec*", Name: "tp"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(SchedRrGetInterval)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(SchedRrGetInterval)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(SchedRrGetInterval)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(SchedRrGetInterval)}},
			},
		},
	},
	Mlock: {
		id:      Mlock,
		id32Bit: Sys32mlock,
		name:    "mlock",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_mem"},
		fields: []trace.ArgMeta{
			{Type: "const void*", Name: "addr"},
			{Type: "size_t", Name: "len"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Mlock)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Mlock)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Mlock)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Mlock)}},
			},
		},
	},
	Munlock: {
		id:      Munlock,
		id32Bit: Sys32munlock,
		name:    "munlock",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_mem"},
		fields: []trace.ArgMeta{
			{Type: "const void*", Name: "addr"},
			{Type: "size_t", Name: "len"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Munlock)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Munlock)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Munlock)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Munlock)}},
			},
		},
	},
	Mlockall: {
		id:      Mlockall,
		id32Bit: Sys32mlockall,
		name:    "mlockall",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_mem"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Mlockall)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Mlockall)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Mlockall)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Mlockall)}},
			},
		},
	},
	Munlockall: {
		id:      Munlockall,
		id32Bit: Sys32munlockall,
		name:    "munlockall",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_mem"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Munlockall)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Munlockall)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Munlockall)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Munlockall)}},
			},
		},
	},
	Vhangup: {
		id:      Vhangup,
		id32Bit: Sys32vhangup,
		name:    "vhangup",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Vhangup)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Vhangup)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Vhangup)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Vhangup)}},
			},
		},
	},
	ModifyLdt: {
		id:      ModifyLdt,
		id32Bit: Sys32modify_ldt,
		name:    "modify_ldt",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_mem"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "func"},
			{Type: "void*", Name: "ptr"},
			{Type: "unsigned long", Name: "bytecount"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(ModifyLdt)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(ModifyLdt)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(ModifyLdt)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(ModifyLdt)}},
			},
		},
	},
	PivotRoot: {
		id:      PivotRoot,
		id32Bit: Sys32pivot_root,
		name:    "pivot_root",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "new_root"},
			{Type: "const char*", Name: "put_old"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(PivotRoot)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(PivotRoot)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(PivotRoot)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(PivotRoot)}},
			},
		},
	},
	Sysctl: {
		id:      Sysctl,
		id32Bit: Sys32_sysctl,
		name:    "sysctl",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system"},
		fields: []trace.ArgMeta{
			{Type: "struct __sysctl_args*", Name: "args"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Sysctl)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Sysctl)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Sysctl)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Sysctl)}},
			},
		},
	},
	Prctl: {
		id:      Prctl,
		id32Bit: Sys32prctl,
		name:    "prctl",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "option"},
			{Type: "unsigned long", Name: "arg2"},
			{Type: "unsigned long", Name: "arg3"},
			{Type: "unsigned long", Name: "arg4"},
			{Type: "unsigned long", Name: "arg5"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Prctl)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Prctl)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Prctl)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Prctl)}},
			},
		},
	},
	ArchPrctl: {
		id:      ArchPrctl,
		id32Bit: Sys32arch_prctl,
		name:    "arch_prctl",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "option"},
			{Type: "unsigned long", Name: "addr"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.ArchPrctl, required: true},
				{handle: probes.ArchPrctlRet, required: true},
			},
		},
	},
	Adjtimex: {
		id:      Adjtimex,
		id32Bit: Sys32adjtimex,
		name:    "adjtimex",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "time", "time_clock"},
		fields: []trace.ArgMeta{
			{Type: "struct timex*", Name: "buf"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Adjtimex)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Adjtimex)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Adjtimex)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Adjtimex)}},
			},
		},
	},
	Setrlimit: {
		id:      Setrlimit,
		id32Bit: Sys32setrlimit,
		name:    "setrlimit",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "resource"},
			{Type: "const struct rlimit*", Name: "rlim"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setrlimit)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setrlimit)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setrlimit)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setrlimit)}},
			},
		},
	},
	Chroot: {
		id:      Chroot,
		id32Bit: Sys32chroot,
		name:    "chroot",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_dir_ops"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "path"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Chroot)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Chroot)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Chroot)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Chroot)}},
			},
		},
	},
	Sync: {
		id:      Sync,
		id32Bit: Sys32sync,
		name:    "sync",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_sync"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Sync)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Sync)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Sync)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Sync)}},
			},
		},
	},
	Acct: {
		id:      Acct,
		id32Bit: Sys32acct,
		name:    "acct",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "filename"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Acct)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Acct)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Acct)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Acct)}},
			},
		},
	},
	Settimeofday: {
		id:      Settimeofday,
		id32Bit: Sys32settimeofday,
		name:    "settimeofday",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "time", "time_tod"},
		fields: []trace.ArgMeta{
			{Type: "const struct timeval*", Name: "tv"},
			{Type: "const struct timezone*", Name: "tz"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Settimeofday)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Settimeofday)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Settimeofday)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Settimeofday)}},
			},
		},
	},
	Mount: {
		id:      Mount,
		id32Bit: Sys32mount,
		name:    "mount",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "source"},
			{Type: "const char*", Name: "target"},
			{Type: "const char*", Name: "filesystemtype"},
			{Type: "unsigned long", Name: "mountflags"},
			{Type: "const void*", Name: "data"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Mount)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Mount)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Mount)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Mount)}},
			},
		},
	},
	Umount2: {
		id:      Umount2,
		id32Bit: Sys32umount2,
		name:    "umount2",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "target"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Umount2)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Umount2)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Umount2)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Umount2)}},
			},
		},
	},
	Swapon: {
		id:      Swapon,
		id32Bit: Sys32swapon,
		name:    "swapon",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "int", Name: "swapflags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Swapon)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Swapon)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Swapon)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Swapon)}},
			},
		},
	},
	Swapoff: {
		id:      Swapoff,
		id32Bit: Sys32swapoff,
		name:    "swapoff",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "path"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Swapoff)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Swapoff)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Swapoff)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Swapoff)}},
			},
		},
	},
	Reboot: {
		id:      Reboot,
		id32Bit: Sys32reboot,
		name:    "reboot",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "magic"},
			{Type: "int", Name: "magic2"},
			{Type: "int", Name: "cmd"},
			{Type: "void*", Name: "arg"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Reboot)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Reboot)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Reboot)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Reboot)}},
			},
		},
	},
	Sethostname: {
		id:      Sethostname,
		id32Bit: Sys32sethostname,
		name:    "sethostname",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "net"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "name"},
			{Type: "size_t", Name: "len"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Sethostname)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Sethostname)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Sethostname)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Sethostname)}},
			},
		},
	},
	Setdomainname: {
		id:      Setdomainname,
		id32Bit: Sys32setdomainname,
		name:    "setdomainname",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "net"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "name"},
			{Type: "size_t", Name: "len"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setdomainname)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setdomainname)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setdomainname)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setdomainname)}},
			},
		},
	},
	Iopl: {
		id:      Iopl,
		id32Bit: Sys32iopl,
		name:    "iopl",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "level"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Iopl)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Iopl)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Iopl)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Iopl)}},
			},
		},
	},
	Ioperm: {
		id:      Ioperm,
		id32Bit: Sys32ioperm,
		name:    "ioperm",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system"},
		fields: []trace.ArgMeta{
			{Type: "unsigned long", Name: "from"},
			{Type: "unsigned long", Name: "num"},
			{Type: "int", Name: "turn_on"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Ioperm)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Ioperm)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Ioperm)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Ioperm)}},
			},
		},
	},
	CreateModule: {
		id:      CreateModule,
		id32Bit: Sys32create_module,
		name:    "create_module",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system", "system_module"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(CreateModule)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(CreateModule)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(CreateModule)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(CreateModule)}},
			},
		},
	},
	InitModule: {
		id:      InitModule,
		id32Bit: Sys32init_module,
		name:    "init_module",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system", "system_module"},
		fields: []trace.ArgMeta{
			{Type: "void*", Name: "module_image"},
			{Type: "unsigned long", Name: "len"},
			{Type: "const char*", Name: "param_values"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(InitModule)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(InitModule)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(InitModule)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(InitModule)}},
			},
		},
	},
	DeleteModule: {
		id:      DeleteModule,
		id32Bit: Sys32delete_module,
		name:    "delete_module",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system", "system_module"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "name"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(DeleteModule)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(DeleteModule)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(DeleteModule)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(DeleteModule)}},
			},
		},
	},
	GetKernelSyms: {
		id:      GetKernelSyms,
		id32Bit: Sys32get_kernel_syms,
		name:    "get_kernel_syms",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system", "system_module"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(GetKernelSyms)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(GetKernelSyms)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(GetKernelSyms)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(GetKernelSyms)}},
			},
		},
	},
	QueryModule: {
		id:      QueryModule,
		id32Bit: Sys32query_module,
		name:    "query_module",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system", "system_module"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(QueryModule)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(QueryModule)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(QueryModule)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(QueryModule)}},
			},
		},
	},
	Quotactl: {
		id:      Quotactl,
		id32Bit: Sys32quotactl,
		name:    "quotactl",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "cmd"},
			{Type: "const char*", Name: "special"},
			{Type: "int", Name: "id"},
			{Type: "void*", Name: "addr"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Quotactl)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Quotactl)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Quotactl)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Quotactl)}},
			},
		},
	},
	Nfsservctl: {
		id:      Nfsservctl,
		id32Bit: Sys32nfsservctl,
		name:    "nfsservctl",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Nfsservctl)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Nfsservctl)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Nfsservctl)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Nfsservctl)}},
			},
		},
	},
	Getpmsg: {
		id:      Getpmsg,
		id32Bit: Sys32getpmsg,
		name:    "getpmsg",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getpmsg)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getpmsg)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getpmsg)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getpmsg)}},
			},
		},
	},
	Putpmsg: {
		id:      Putpmsg,
		id32Bit: Sys32putpmsg,
		name:    "putpmsg",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Putpmsg)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Putpmsg)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Putpmsg)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Putpmsg)}},
			},
		},
	},
	Afs: {
		id:      Afs,
		id32Bit: Sys32Undefined,
		name:    "afs",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Afs)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Afs)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Afs)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Afs)}},
			},
		},
	},
	Tuxcall: {
		id:      Tuxcall,
		id32Bit: Sys32Undefined,
		name:    "tuxcall",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Tuxcall)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Tuxcall)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Tuxcall)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Tuxcall)}},
			},
		},
	},
	Security: {
		id:      Security,
		id32Bit: Sys32Undefined,
		name:    "security",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Security)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Security)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Security)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Security)}},
			},
		},
	},
	Gettid: {
		id:      Gettid,
		id32Bit: Sys32gettid,
		name:    "gettid",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_ids"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Gettid)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Gettid)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Gettid)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Gettid)}},
			},
		},
	},
	Readahead: {
		id:      Readahead,
		id32Bit: Sys32readahead,
		name:    "readahead",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "off_t", Name: "offset"},
			{Type: "size_t", Name: "count"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Readahead)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Readahead)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Readahead)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Readahead)}},
			},
		},
	},
	Setxattr: {
		id:      Setxattr,
		id32Bit: Sys32setxattr,
		name:    "setxattr",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "const char*", Name: "name"},
			{Type: "const void*", Name: "value"},
			{Type: "size_t", Name: "size"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setxattr)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setxattr)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setxattr)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setxattr)}},
			},
		},
	},
	Lsetxattr: {
		id:      Lsetxattr,
		id32Bit: Sys32lsetxattr,
		name:    "lsetxattr",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "const char*", Name: "name"},
			{Type: "const void*", Name: "value"},
			{Type: "size_t", Name: "size"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Lsetxattr)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Lsetxattr)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Lsetxattr)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Lsetxattr)}},
			},
		},
	},
	Fsetxattr: {
		id:      Fsetxattr,
		id32Bit: Sys32fsetxattr,
		name:    "fsetxattr",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const char*", Name: "name"},
			{Type: "const void*", Name: "value"},
			{Type: "size_t", Name: "size"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Fsetxattr)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Fsetxattr)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Fsetxattr)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Fsetxattr)}},
			},
		},
	},
	Getxattr: {
		id:      Getxattr,
		id32Bit: Sys32getxattr,
		name:    "getxattr",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "const char*", Name: "name"},
			{Type: "void*", Name: "value"},
			{Type: "size_t", Name: "size"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getxattr)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getxattr)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getxattr)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getxattr)}},
			},
		},
	},
	Lgetxattr: {
		id:      Lgetxattr,
		id32Bit: Sys32lgetxattr,
		name:    "lgetxattr",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "const char*", Name: "name"},
			{Type: "void*", Name: "value"},
			{Type: "size_t", Name: "size"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Lgetxattr)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Lgetxattr)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Lgetxattr)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Lgetxattr)}},
			},
		},
	},
	Fgetxattr: {
		id:      Fgetxattr,
		id32Bit: Sys32fgetxattr,
		name:    "fgetxattr",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const char*", Name: "name"},
			{Type: "void*", Name: "value"},
			{Type: "size_t", Name: "size"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Fgetxattr)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Fgetxattr)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Fgetxattr)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Fgetxattr)}},
			},
		},
	},
	Listxattr: {
		id:      Listxattr,
		id32Bit: Sys32listxattr,
		name:    "listxattr",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "char*", Name: "list"},
			{Type: "size_t", Name: "size"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Listxattr)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Listxattr)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Listxattr)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Listxattr)}},
			},
		},
	},
	Llistxattr: {
		id:      Llistxattr,
		id32Bit: Sys32llistxattr,
		name:    "llistxattr",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "char*", Name: "list"},
			{Type: "size_t", Name: "size"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Llistxattr)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Llistxattr)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Llistxattr)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Llistxattr)}},
			},
		},
	},
	Flistxattr: {
		id:      Flistxattr,
		id32Bit: Sys32flistxattr,
		name:    "flistxattr",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "char*", Name: "list"},
			{Type: "size_t", Name: "size"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Flistxattr)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Flistxattr)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Flistxattr)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Flistxattr)}},
			},
		},
	},
	Removexattr: {
		id:      Removexattr,
		id32Bit: Sys32removexattr,
		name:    "removexattr",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "const char*", Name: "name"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Removexattr)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Removexattr)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Removexattr)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Removexattr)}},
			},
		},
	},
	Lremovexattr: {
		id:      Lremovexattr,
		id32Bit: Sys32lremovexattr,
		name:    "lremovexattr",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "const char*", Name: "name"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Lremovexattr)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Lremovexattr)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Lremovexattr)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Lremovexattr)}},
			},
		},
	},
	Fremovexattr: {
		id:      Fremovexattr,
		id32Bit: Sys32fremovexattr,
		name:    "fremovexattr",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const char*", Name: "name"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Fremovexattr)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Fremovexattr)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Fremovexattr)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Fremovexattr)}},
			},
		},
	},
	Tkill: {
		id:      Tkill,
		id32Bit: Sys32tkill,
		name:    "tkill",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "signals"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "tid"},
			{Type: "int", Name: "sig"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Tkill)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Tkill)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Tkill)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Tkill)}},
			},
		},
	},
	Time: {
		id:      Time,
		id32Bit: Sys32time,
		name:    "time",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "time", "time_tod"},
		fields: []trace.ArgMeta{
			{Type: "time_t*", Name: "tloc"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Time)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Time)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Time)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Time)}},
			},
		},
	},
	Futex: {
		id:      Futex,
		id32Bit: Sys32futex_time64,
		name:    "futex",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "ipc", "ipc_futex"},
		fields: []trace.ArgMeta{
			{Type: "int*", Name: "uaddr"},
			{Type: "int", Name: "futex_op"},
			{Type: "int", Name: "val"},
			{Type: "const struct timespec*", Name: "timeout"},
			{Type: "int*", Name: "uaddr2"},
			{Type: "int", Name: "val3"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Futex)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Futex)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Futex)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Futex)}},
			},
		},
	},
	SchedSetaffinity: {
		id:      SchedSetaffinity,
		id32Bit: Sys32sched_setaffinity,
		name:    "sched_setaffinity",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_sched"},
		fields: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "size_t", Name: "cpusetsize"},
			{Type: "unsigned long*", Name: "mask"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(SchedSetaffinity)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(SchedSetaffinity)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(SchedSetaffinity)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(SchedSetaffinity)}},
			},
		},
	},
	SchedGetaffinity: {
		id:      SchedGetaffinity,
		id32Bit: Sys32sched_getaffinity,
		name:    "sched_getaffinity",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_sched"},
		fields: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "size_t", Name: "cpusetsize"},
			{Type: "unsigned long*", Name: "mask"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(SchedGetaffinity)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(SchedGetaffinity)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(SchedGetaffinity)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(SchedGetaffinity)}},
			},
		},
	},
	SetThreadArea: {
		id:      SetThreadArea,
		id32Bit: Sys32set_thread_area,
		name:    "set_thread_area",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc"},
		fields: []trace.ArgMeta{
			{Type: "struct user_desc*", Name: "u_info"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(SetThreadArea)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(SetThreadArea)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(SetThreadArea)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(SetThreadArea)}},
			},
		},
	},
	IoSetup: {
		id:      IoSetup,
		id32Bit: Sys32io_setup,
		name:    "io_setup",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_async_io"},
		fields: []trace.ArgMeta{
			{Type: "unsigned int", Name: "nr_events"},
			{Type: "aio_context_t*", Name: "ctx_idp"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(IoSetup)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(IoSetup)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(IoSetup)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(IoSetup)}},
			},
		},
	},
	IoDestroy: {
		id:      IoDestroy,
		id32Bit: Sys32io_destroy,
		name:    "io_destroy",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_async_io"},
		fields: []trace.ArgMeta{
			{Type: "aio_context_t", Name: "ctx_id"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(IoDestroy)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(IoDestroy)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(IoDestroy)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(IoDestroy)}},
			},
		},
	},
	IoGetevents: {
		id:      IoGetevents,
		id32Bit: Sys32io_getevents,
		name:    "io_getevents",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_async_io"},
		fields: []trace.ArgMeta{
			{Type: "aio_context_t", Name: "ctx_id"},
			{Type: "long", Name: "min_nr"},
			{Type: "long", Name: "nr"},
			{Type: "struct io_event*", Name: "events"},
			{Type: "struct timespec*", Name: "timeout"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(IoGetevents)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(IoGetevents)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(IoGetevents)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(IoGetevents)}},
			},
		},
	},
	IoSubmit: {
		id:      IoSubmit,
		id32Bit: Sys32io_submit,
		name:    "io_submit",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_async_io"},
		fields: []trace.ArgMeta{
			{Type: "aio_context_t", Name: "ctx_id"},
			{Type: "long", Name: "nr"},
			{Type: "struct iocb**", Name: "iocbpp"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(IoSubmit)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(IoSubmit)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(IoSubmit)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(IoSubmit)}},
			},
		},
	},
	IoCancel: {
		id:      IoCancel,
		id32Bit: Sys32io_cancel,
		name:    "io_cancel",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_async_io"},
		fields: []trace.ArgMeta{
			{Type: "aio_context_t", Name: "ctx_id"},
			{Type: "struct iocb*", Name: "iocb"},
			{Type: "struct io_event*", Name: "result"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(IoCancel)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(IoCancel)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(IoCancel)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(IoCancel)}},
			},
		},
	},
	GetThreadArea: {
		id:      GetThreadArea,
		id32Bit: Sys32get_thread_area,
		name:    "get_thread_area",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc"},
		fields: []trace.ArgMeta{
			{Type: "struct user_desc*", Name: "u_info"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(GetThreadArea)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(GetThreadArea)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(GetThreadArea)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(GetThreadArea)}},
			},
		},
	},
	LookupDcookie: {
		id:      LookupDcookie,
		id32Bit: Sys32lookup_dcookie,
		name:    "lookup_dcookie",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_dir_ops"},
		fields: []trace.ArgMeta{
			{Type: "u64", Name: "cookie"},
			{Type: "char*", Name: "buffer"},
			{Type: "size_t", Name: "len"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(LookupDcookie)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(LookupDcookie)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(LookupDcookie)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(LookupDcookie)}},
			},
		},
	},
	EpollCreate: {
		id:      EpollCreate,
		id32Bit: Sys32epoll_create,
		name:    "epoll_create",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_mux_io"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "size"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(EpollCreate)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(EpollCreate)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(EpollCreate)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(EpollCreate)}},
			},
		},
	},
	EpollCtlOld: {
		id:      EpollCtlOld,
		id32Bit: Sys32Undefined,
		name:    "epoll_ctl_old",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_mux_io"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(EpollCtlOld)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(EpollCtlOld)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(EpollCtlOld)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(EpollCtlOld)}},
			},
		},
	},
	EpollWaitOld: {
		id:      EpollWaitOld,
		id32Bit: Sys32Undefined,
		name:    "epoll_wait_old",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_mux_io"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(EpollWaitOld)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(EpollWaitOld)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(EpollWaitOld)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(EpollWaitOld)}},
			},
		},
	},
	RemapFilePages: {
		id:      RemapFilePages,
		id32Bit: Sys32remap_file_pages,
		name:    "remap_file_pages",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls"},
		fields: []trace.ArgMeta{
			{Type: "void*", Name: "addr"},
			{Type: "size_t", Name: "size"},
			{Type: "int", Name: "prot"},
			{Type: "size_t", Name: "pgoff"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(RemapFilePages)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(RemapFilePages)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(RemapFilePages)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(RemapFilePages)}},
			},
		},
	},
	Getdents64: {
		id:      Getdents64,
		id32Bit: Sys32getdents64,
		name:    "getdents64",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_dir_ops"},
		fields: []trace.ArgMeta{
			{Type: "unsigned int", Name: "fd"},
			{Type: "struct linux_dirent64*", Name: "dirp"},
			{Type: "unsigned int", Name: "count"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getdents64)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getdents64)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getdents64)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getdents64)}},
			},
		},
	},
	SetTidAddress: {
		id:      SetTidAddress,
		id32Bit: Sys32set_tid_address,
		name:    "set_tid_address",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc"},
		fields: []trace.ArgMeta{
			{Type: "int*", Name: "tidptr"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(SetTidAddress)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(SetTidAddress)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(SetTidAddress)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(SetTidAddress)}},
			},
		},
	},
	RestartSyscall: {
		id:      RestartSyscall,
		id32Bit: Sys32restart_syscall,
		name:    "restart_syscall",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "signals"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(RestartSyscall)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(RestartSyscall)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(RestartSyscall)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(RestartSyscall)}},
			},
		},
	},
	Semtimedop: {
		id:      Semtimedop,
		id32Bit: Sys32semtimedop_time64,
		name:    "semtimedop",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "ipc", "ipc_sem"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "semid"},
			{Type: "struct sembuf*", Name: "sops"},
			{Type: "size_t", Name: "nsops"},
			{Type: "const struct timespec*", Name: "timeout"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Semtimedop)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Semtimedop)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Semtimedop)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Semtimedop)}},
			},
		},
	},
	Fadvise64: {
		id:      Fadvise64,
		id32Bit: Sys32fadvise64,
		name:    "fadvise64",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "off_t", Name: "offset"},
			{Type: "size_t", Name: "len"},
			{Type: "int", Name: "advice"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Fadvise64)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Fadvise64)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Fadvise64)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Fadvise64)}},
			},
		},
	},
	TimerCreate: {
		id:      TimerCreate,
		id32Bit: Sys32timer_create,
		name:    "timer_create",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "time", "time_timer"},
		fields: []trace.ArgMeta{
			{Type: "const clockid_t", Name: "clockid"},
			{Type: "struct sigevent*", Name: "sevp"},
			{Type: "timer_t*", Name: "timer_id"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(TimerCreate)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(TimerCreate)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(TimerCreate)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(TimerCreate)}},
			},
		},
	},
	TimerSettime: {
		id:      TimerSettime,
		id32Bit: Sys32timer_settime64,
		name:    "timer_settime",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "time", "time_timer"},
		fields: []trace.ArgMeta{
			{Type: "timer_t", Name: "timer_id"},
			{Type: "int", Name: "flags"},
			{Type: "const struct itimerspec*", Name: "new_value"},
			{Type: "struct itimerspec*", Name: "old_value"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(TimerSettime)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(TimerSettime)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(TimerSettime)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(TimerSettime)}},
			},
		},
	},
	TimerGettime: {
		id:      TimerGettime,
		id32Bit: Sys32timer_gettime64,
		name:    "timer_gettime",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "time", "time_timer"},
		fields: []trace.ArgMeta{
			{Type: "timer_t", Name: "timer_id"},
			{Type: "struct itimerspec*", Name: "curr_value"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(TimerGettime)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(TimerGettime)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(TimerGettime)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(TimerGettime)}},
			},
		},
	},
	TimerGetoverrun: {
		id:      TimerGetoverrun,
		id32Bit: Sys32timer_getoverrun,
		name:    "timer_getoverrun",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "time", "time_timer"},
		fields: []trace.ArgMeta{
			{Type: "timer_t", Name: "timer_id"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(TimerGetoverrun)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(TimerGetoverrun)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(TimerGetoverrun)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(TimerGetoverrun)}},
			},
		},
	},
	TimerDelete: {
		id:      TimerDelete,
		id32Bit: Sys32timer_delete,
		name:    "timer_delete",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "time", "time_timer"},
		fields: []trace.ArgMeta{
			{Type: "timer_t", Name: "timer_id"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(TimerDelete)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(TimerDelete)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(TimerDelete)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(TimerDelete)}},
			},
		},
	},
	ClockSettime: {
		id:      ClockSettime,
		id32Bit: Sys32clock_settime64,
		name:    "clock_settime",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "time", "time_clock"},
		fields: []trace.ArgMeta{
			{Type: "const clockid_t", Name: "clockid"},
			{Type: "const struct timespec*", Name: "tp"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(ClockSettime)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(ClockSettime)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(ClockSettime)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(ClockSettime)}},
			},
		},
	},
	ClockGettime: {
		id:      ClockGettime,
		id32Bit: Sys32clock_gettime64,
		name:    "clock_gettime",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "time", "time_clock"},
		fields: []trace.ArgMeta{
			{Type: "const clockid_t", Name: "clockid"},
			{Type: "struct timespec*", Name: "tp"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(ClockGettime)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(ClockGettime)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(ClockGettime)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(ClockGettime)}},
			},
		},
	},
	ClockGetres: {
		id:      ClockGetres,
		id32Bit: Sys32clock_getres_time64,
		name:    "clock_getres",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "time", "time_clock"},
		fields: []trace.ArgMeta{
			{Type: "const clockid_t", Name: "clockid"},
			{Type: "struct timespec*", Name: "res"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(ClockGetres)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(ClockGetres)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(ClockGetres)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(ClockGetres)}},
			},
		},
	},
	ClockNanosleep: {
		id:      ClockNanosleep,
		id32Bit: Sys32clock_nanosleep_time64,
		name:    "clock_nanosleep",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "time", "time_clock"},
		fields: []trace.ArgMeta{
			{Type: "const clockid_t", Name: "clockid"},
			{Type: "int", Name: "flags"},
			{Type: "const struct timespec*", Name: "request"},
			{Type: "struct timespec*", Name: "remain"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(ClockNanosleep)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(ClockNanosleep)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(ClockNanosleep)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(ClockNanosleep)}},
			},
		},
	},
	ExitGroup: {
		id:      ExitGroup,
		id32Bit: Sys32exit_group,
		name:    "exit_group",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_life"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "status"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(ExitGroup)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(ExitGroup)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(ExitGroup)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(ExitGroup)}},
			},
		},
	},
	EpollWait: {
		id:      EpollWait,
		id32Bit: Sys32epoll_wait,
		name:    "epoll_wait",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_mux_io"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "epfd"},
			{Type: "struct epoll_event*", Name: "events"},
			{Type: "int", Name: "maxevents"},
			{Type: "int", Name: "timeout"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(EpollWait)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(EpollWait)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(EpollWait)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(EpollWait)}},
			},
		},
	},
	EpollCtl: {
		id:      EpollCtl,
		id32Bit: Sys32epoll_ctl,
		name:    "epoll_ctl",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_mux_io"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "epfd"},
			{Type: "int", Name: "op"},
			{Type: "int", Name: "fd"},
			{Type: "struct epoll_event*", Name: "event"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(EpollCtl)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(EpollCtl)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(EpollCtl)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(EpollCtl)}},
			},
		},
	},
	Tgkill: {
		id:      Tgkill,
		id32Bit: Sys32tgkill,
		name:    "tgkill",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "signals"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "tgid"},
			{Type: "int", Name: "tid"},
			{Type: "int", Name: "sig"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Tgkill)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Tgkill)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Tgkill)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Tgkill)}},
			},
		},
	},
	Utimes: {
		id:      Utimes,
		id32Bit: Sys32utimes,
		name:    "utimes",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "char*", Name: "filename"},
			{Type: "struct timeval*", Name: "times"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Utimes)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Utimes)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Utimes)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Utimes)}},
			},
		},
	},
	Vserver: {
		id:      Vserver,
		id32Bit: Sys32vserver,
		name:    "vserver",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Vserver)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Vserver)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Vserver)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Vserver)}},
			},
		},
	},
	Mbind: {
		id:      Mbind,
		id32Bit: Sys32mbind,
		name:    "mbind",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system", "system_numa"},
		fields: []trace.ArgMeta{
			{Type: "void*", Name: "addr"},
			{Type: "unsigned long", Name: "len"},
			{Type: "int", Name: "mode"},
			{Type: "const unsigned long*", Name: "nodemask"},
			{Type: "unsigned long", Name: "maxnode"},
			{Type: "unsigned int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Mbind)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Mbind)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Mbind)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Mbind)}},
			},
		},
	},
	SetMempolicy: {
		id:      SetMempolicy,
		id32Bit: Sys32set_mempolicy,
		name:    "set_mempolicy",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system", "system_numa"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "mode"},
			{Type: "const unsigned long*", Name: "nodemask"},
			{Type: "unsigned long", Name: "maxnode"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(SetMempolicy)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(SetMempolicy)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(SetMempolicy)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(SetMempolicy)}},
			},
		},
	},
	GetMempolicy: {
		id:      GetMempolicy,
		id32Bit: Sys32get_mempolicy,
		name:    "get_mempolicy",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system", "system_numa"},
		fields: []trace.ArgMeta{
			{Type: "int*", Name: "mode"},
			{Type: "unsigned long*", Name: "nodemask"},
			{Type: "unsigned long", Name: "maxnode"},
			{Type: "void*", Name: "addr"},
			{Type: "unsigned long", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(GetMempolicy)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(GetMempolicy)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(GetMempolicy)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(GetMempolicy)}},
			},
		},
	},
	MqOpen: {
		id:      MqOpen,
		id32Bit: Sys32mq_open,
		name:    "mq_open",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "ipc", "ipc_msgq"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "name"},
			{Type: "int", Name: "oflag"},
			{Type: "umode_t", Name: "mode"},
			{Type: "struct mq_attr*", Name: "attr"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(MqOpen)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(MqOpen)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(MqOpen)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(MqOpen)}},
			},
		},
	},
	MqUnlink: {
		id:      MqUnlink,
		id32Bit: Sys32mq_unlink,
		name:    "mq_unlink",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "ipc", "ipc_msgq"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "name"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(MqUnlink)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(MqUnlink)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(MqUnlink)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(MqUnlink)}},
			},
		},
	},
	MqTimedsend: {
		id:      MqTimedsend,
		id32Bit: Sys32mq_timedsend_time64,
		name:    "mq_timedsend",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "ipc", "ipc_msgq"},
		fields: []trace.ArgMeta{
			{Type: "mqd_t", Name: "mqdes"},
			{Type: "const char*", Name: "msg_ptr"},
			{Type: "size_t", Name: "msg_len"},
			{Type: "unsigned int", Name: "msg_prio"},
			{Type: "const struct timespec*", Name: "abs_timeout"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(MqTimedsend)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(MqTimedsend)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(MqTimedsend)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(MqTimedsend)}},
			},
		},
	},
	MqTimedreceive: {
		id:      MqTimedreceive,
		id32Bit: Sys32mq_timedreceive_time64,
		name:    "mq_timedreceive",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "ipc", "ipc_msgq"},
		fields: []trace.ArgMeta{
			{Type: "mqd_t", Name: "mqdes"},
			{Type: "char*", Name: "msg_ptr"},
			{Type: "size_t", Name: "msg_len"},
			{Type: "unsigned int*", Name: "msg_prio"},
			{Type: "const struct timespec*", Name: "abs_timeout"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(MqTimedreceive)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(MqTimedreceive)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(MqTimedreceive)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(MqTimedreceive)}},
			},
		},
	},
	MqNotify: {
		id:      MqNotify,
		id32Bit: Sys32mq_notify,
		name:    "mq_notify",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "ipc", "ipc_msgq"},
		fields: []trace.ArgMeta{
			{Type: "mqd_t", Name: "mqdes"},
			{Type: "const struct sigevent*", Name: "sevp"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(MqNotify)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(MqNotify)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(MqNotify)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(MqNotify)}},
			},
		},
	},
	MqGetsetattr: {
		id:      MqGetsetattr,
		id32Bit: Sys32mq_getsetattr,
		name:    "mq_getsetattr",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "ipc", "ipc_msgq"},
		fields: []trace.ArgMeta{
			{Type: "mqd_t", Name: "mqdes"},
			{Type: "const struct mq_attr*", Name: "newattr"},
			{Type: "struct mq_attr*", Name: "oldattr"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(MqGetsetattr)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(MqGetsetattr)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(MqGetsetattr)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(MqGetsetattr)}},
			},
		},
	},
	KexecLoad: {
		id:      KexecLoad,
		id32Bit: Sys32kexec_load,
		name:    "kexec_load",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system"},
		fields: []trace.ArgMeta{
			{Type: "unsigned long", Name: "entry"},
			{Type: "unsigned long", Name: "nr_segments"},
			{Type: "struct kexec_segment*", Name: "segments"},
			{Type: "unsigned long", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(KexecLoad)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(KexecLoad)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(KexecLoad)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(KexecLoad)}},
			},
		},
	},
	Waitid: {
		id:      Waitid,
		id32Bit: Sys32waitid,
		name:    "waitid",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_life"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "idtype"},
			{Type: "pid_t", Name: "id"},
			{Type: "struct siginfo*", Name: "infop"},
			{Type: "int", Name: "options"},
			{Type: "struct rusage*", Name: "rusage"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Waitid)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Waitid)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Waitid)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Waitid)}},
			},
		},
	},
	AddKey: {
		id:      AddKey,
		id32Bit: Sys32add_key,
		name:    "add_key",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system", "system_keys"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "type"},
			{Type: "const char*", Name: "description"},
			{Type: "const void*", Name: "payload"},
			{Type: "size_t", Name: "plen"},
			{Type: "key_serial_t", Name: "keyring"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(AddKey)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(AddKey)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(AddKey)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(AddKey)}},
			},
		},
	},
	RequestKey: {
		id:      RequestKey,
		id32Bit: Sys32request_key,
		name:    "request_key",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system", "system_keys"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "type"},
			{Type: "const char*", Name: "description"},
			{Type: "const char*", Name: "callout_info"},
			{Type: "key_serial_t", Name: "dest_keyring"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(RequestKey)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(RequestKey)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(RequestKey)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(RequestKey)}},
			},
		},
	},
	Keyctl: {
		id:      Keyctl,
		id32Bit: Sys32keyctl,
		name:    "keyctl",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system", "system_keys"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "operation"},
			{Type: "unsigned long", Name: "arg2"},
			{Type: "unsigned long", Name: "arg3"},
			{Type: "unsigned long", Name: "arg4"},
			{Type: "unsigned long", Name: "arg5"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Keyctl)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Keyctl)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Keyctl)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Keyctl)}},
			},
		},
	},
	IoprioSet: {
		id:      IoprioSet,
		id32Bit: Sys32ioprio_set,
		name:    "ioprio_set",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_sched"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "which"},
			{Type: "int", Name: "who"},
			{Type: "int", Name: "ioprio"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(IoprioSet)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(IoprioSet)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(IoprioSet)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(IoprioSet)}},
			},
		},
	},
	IoprioGet: {
		id:      IoprioGet,
		id32Bit: Sys32ioprio_get,
		name:    "ioprio_get",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_sched"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "which"},
			{Type: "int", Name: "who"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(IoprioGet)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(IoprioGet)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(IoprioGet)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(IoprioGet)}},
			},
		},
	},
	InotifyInit: {
		id:      InotifyInit,
		id32Bit: Sys32inotify_init,
		name:    "inotify_init",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_monitor"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(InotifyInit)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(InotifyInit)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(InotifyInit)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(InotifyInit)}},
			},
		},
	},
	InotifyAddWatch: {
		id:      InotifyAddWatch,
		id32Bit: Sys32inotify_add_watch,
		name:    "inotify_add_watch",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_monitor"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "u32", Name: "mask"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(InotifyAddWatch)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(InotifyAddWatch)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(InotifyAddWatch)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(InotifyAddWatch)}},
			},
		},
	},
	InotifyRmWatch: {
		id:      InotifyRmWatch,
		id32Bit: Sys32inotify_rm_watch,
		name:    "inotify_rm_watch",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_monitor"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "int", Name: "wd"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(InotifyRmWatch)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(InotifyRmWatch)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(InotifyRmWatch)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(InotifyRmWatch)}},
			},
		},
	},
	MigratePages: {
		id:      MigratePages,
		id32Bit: Sys32migrate_pages,
		name:    "migrate_pages",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system", "system_numa"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "pid"},
			{Type: "unsigned long", Name: "maxnode"},
			{Type: "const unsigned long*", Name: "old_nodes"},
			{Type: "const unsigned long*", Name: "new_nodes"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(MigratePages)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(MigratePages)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(MigratePages)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(MigratePages)}},
			},
		},
	},
	Openat: {
		id:      Openat,
		id32Bit: Sys32openat,
		name:    "openat",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_ops"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "int", Name: "flags"},
			{Type: "umode_t", Name: "mode"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Openat)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Openat)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Openat)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Openat)}},
			},
		},
	},
	Mkdirat: {
		id:      Mkdirat,
		id32Bit: Sys32mkdirat,
		name:    "mkdirat",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_dir_ops"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "umode_t", Name: "mode"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Mkdirat)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Mkdirat)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Mkdirat)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Mkdirat)}},
			},
		},
	},
	Mknodat: {
		id:      Mknodat,
		id32Bit: Sys32mknodat,
		name:    "mknodat",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_ops"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "umode_t", Name: "mode"},
			{Type: "dev_t", Name: "dev"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Mknodat)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Mknodat)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Mknodat)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Mknodat)}},
			},
		},
	},
	Fchownat: {
		id:      Fchownat,
		id32Bit: Sys32fchownat,
		name:    "fchownat",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "uid_t", Name: "owner"},
			{Type: "gid_t", Name: "group"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Fchownat)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Fchownat)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Fchownat)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Fchownat)}},
			},
		},
	},
	Futimesat: {
		id:      Futimesat,
		id32Bit: Sys32futimesat,
		name:    "futimesat",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "struct timeval*", Name: "times"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Futimesat)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Futimesat)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Futimesat)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Futimesat)}},
			},
		},
	},
	Newfstatat: {
		id:      Newfstatat,
		id32Bit: Sys32fstatat64,
		name:    "newfstatat",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "struct stat*", Name: "statbuf"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Newfstatat)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Newfstatat)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Newfstatat)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Newfstatat)}},
			},
		},
	},
	Unlinkat: {
		id:      Unlinkat,
		id32Bit: Sys32unlinkat,
		name:    "unlinkat",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_link_ops"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Unlinkat)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Unlinkat)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Unlinkat)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Unlinkat)}},
			},
		},
	},
	Renameat: {
		id:      Renameat,
		id32Bit: Sys32renameat,
		name:    "renameat",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_ops"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "olddirfd"},
			{Type: "const char*", Name: "oldpath"},
			{Type: "int", Name: "newdirfd"},
			{Type: "const char*", Name: "newpath"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Renameat)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Renameat)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Renameat)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Renameat)}},
			},
		},
	},
	Linkat: {
		id:      Linkat,
		id32Bit: Sys32linkat,
		name:    "linkat",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_link_ops"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "olddirfd"},
			{Type: "const char*", Name: "oldpath"},
			{Type: "int", Name: "newdirfd"},
			{Type: "const char*", Name: "newpath"},
			{Type: "unsigned int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Linkat)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Linkat)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Linkat)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Linkat)}},
			},
		},
	},
	Symlinkat: {
		id:      Symlinkat,
		id32Bit: Sys32symlinkat,
		name:    "symlinkat",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_link_ops"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "target"},
			{Type: "int", Name: "newdirfd"},
			{Type: "const char*", Name: "linkpath"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Symlinkat)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Symlinkat)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Symlinkat)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Symlinkat)}},
			},
		},
	},
	Readlinkat: {
		id:      Readlinkat,
		id32Bit: Sys32readlinkat,
		name:    "readlinkat",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_link_ops"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "char*", Name: "buf"},
			{Type: "int", Name: "bufsiz"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Readlinkat)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Readlinkat)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Readlinkat)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Readlinkat)}},
			},
		},
	},
	Fchmodat: {
		id:      Fchmodat,
		id32Bit: Sys32fchmodat,
		name:    "fchmodat",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "umode_t", Name: "mode"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Fchmodat)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Fchmodat)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Fchmodat)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Fchmodat)}},
			},
		},
	},
	Faccessat: {
		id:      Faccessat,
		id32Bit: Sys32faccessat,
		name:    "faccessat",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "int", Name: "mode"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Faccessat)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Faccessat)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Faccessat)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Faccessat)}},
			},
		},
	},
	Pselect6: {
		id:      Pselect6,
		id32Bit: Sys32pselect6_time64,
		name:    "pselect6",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_mux_io"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "nfds"},
			{Type: "fd_set*", Name: "readfds"},
			{Type: "fd_set*", Name: "writefds"},
			{Type: "fd_set*", Name: "exceptfds"},
			{Type: "struct timespec*", Name: "timeout"},
			{Type: "void*", Name: "sigmask"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Pselect6)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Pselect6)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Pselect6)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Pselect6)}},
			},
		},
	},
	Ppoll: {
		id:      Ppoll,
		id32Bit: Sys32ppoll_time64,
		name:    "ppoll",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_mux_io"},
		fields: []trace.ArgMeta{
			{Type: "struct pollfd*", Name: "fds"},
			{Type: "unsigned int", Name: "nfds"},
			{Type: "struct timespec*", Name: "tmo_p"},
			{Type: "const sigset_t*", Name: "sigmask"},
			{Type: "size_t", Name: "sigsetsize"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Ppoll)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Ppoll)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Ppoll)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Ppoll)}},
			},
		},
	},
	Unshare: {
		id:      Unshare,
		id32Bit: Sys32unshare,
		name:    "unshare",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Unshare)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Unshare)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Unshare)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Unshare)}},
			},
		},
	},
	SetRobustList: {
		id:      SetRobustList,
		id32Bit: Sys32set_robust_list,
		name:    "set_robust_list",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "ipc", "ipc_futex"},
		fields: []trace.ArgMeta{
			{Type: "struct robust_list_head*", Name: "head"},
			{Type: "size_t", Name: "len"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(SetRobustList)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(SetRobustList)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(SetRobustList)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(SetRobustList)}},
			},
		},
	},
	GetRobustList: {
		id:      GetRobustList,
		id32Bit: Sys32get_robust_list,
		name:    "get_robust_list",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "ipc", "ipc_futex"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "pid"},
			{Type: "struct robust_list_head**", Name: "head_ptr"},
			{Type: "size_t*", Name: "len_ptr"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(GetRobustList)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(GetRobustList)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(GetRobustList)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(GetRobustList)}},
			},
		},
	},
	Splice: {
		id:      Splice,
		id32Bit: Sys32splice,
		name:    "splice",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "ipc", "ipc_pipe"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd_in"},
			{Type: "off_t*", Name: "off_in"},
			{Type: "int", Name: "fd_out"},
			{Type: "off_t*", Name: "off_out"},
			{Type: "size_t", Name: "len"},
			{Type: "unsigned int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Splice)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Splice)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Splice)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Splice)}},
			},
		},
	},
	Tee: {
		id:      Tee,
		id32Bit: Sys32tee,
		name:    "tee",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "ipc", "ipc_pipe"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd_in"},
			{Type: "int", Name: "fd_out"},
			{Type: "size_t", Name: "len"},
			{Type: "unsigned int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Tee)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Tee)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Tee)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Tee)}},
			},
		},
	},
	SyncFileRange: {
		id:      SyncFileRange,
		id32Bit: Sys32sync_file_range,
		name:    "sync_file_range",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_sync"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "off_t", Name: "offset"},
			{Type: "off_t", Name: "nbytes"},
			{Type: "unsigned int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(SyncFileRange)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(SyncFileRange)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(SyncFileRange)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(SyncFileRange)}},
			},
		},
	},
	Vmsplice: {
		id:      Vmsplice,
		id32Bit: Sys32vmsplice,
		name:    "vmsplice",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "ipc", "ipc_pipe"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const struct iovec*", Name: "iov"},
			{Type: "unsigned long", Name: "nr_segs"},
			{Type: "unsigned int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Vmsplice)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Vmsplice)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Vmsplice)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Vmsplice)}},
			},
		},
	},
	MovePages: {
		id:      MovePages,
		id32Bit: Sys32move_pages,
		name:    "move_pages",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system", "system_numa"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "pid"},
			{Type: "unsigned long", Name: "count"},
			{Type: "const void**", Name: "pages"},
			{Type: "const int*", Name: "nodes"},
			{Type: "int*", Name: "status"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(MovePages)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(MovePages)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(MovePages)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(MovePages)}},
			},
		},
	},
	Utimensat: {
		id:      Utimensat,
		id32Bit: Sys32utimensat_time64,
		name:    "utimensat",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "struct timespec*", Name: "times"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Utimensat)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Utimensat)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Utimensat)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Utimensat)}},
			},
		},
	},
	EpollPwait: {
		id:      EpollPwait,
		id32Bit: Sys32epoll_pwait,
		name:    "epoll_pwait",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_mux_io"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "epfd"},
			{Type: "struct epoll_event*", Name: "events"},
			{Type: "int", Name: "maxevents"},
			{Type: "int", Name: "timeout"},
			{Type: "const sigset_t*", Name: "sigmask"},
			{Type: "size_t", Name: "sigsetsize"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(EpollPwait)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(EpollPwait)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(EpollPwait)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(EpollPwait)}},
			},
		},
	},
	Signalfd: {
		id:      Signalfd,
		id32Bit: Sys32signalfd,
		name:    "signalfd",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "signals"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "sigset_t*", Name: "mask"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Signalfd)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Signalfd)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Signalfd)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Signalfd)}},
			},
		},
	},
	TimerfdCreate: {
		id:      TimerfdCreate,
		id32Bit: Sys32timerfd_create,
		name:    "timerfd_create",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "time", "time_timer"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "clockid"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(TimerfdCreate)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(TimerfdCreate)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(TimerfdCreate)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(TimerfdCreate)}},
			},
		},
	},
	Eventfd: {
		id:      Eventfd,
		id32Bit: Sys32eventfd,
		name:    "eventfd",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "signals"},
		fields: []trace.ArgMeta{
			{Type: "unsigned int", Name: "initval"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Eventfd)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Eventfd)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Eventfd)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Eventfd)}},
			},
		},
	},
	Fallocate: {
		id:      Fallocate,
		id32Bit: Sys32fallocate,
		name:    "fallocate",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_ops"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "int", Name: "mode"},
			{Type: "off_t", Name: "offset"},
			{Type: "off_t", Name: "len"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Fallocate)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Fallocate)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Fallocate)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Fallocate)}},
			},
		},
	},
	TimerfdSettime: {
		id:      TimerfdSettime,
		id32Bit: Sys32timerfd_settime64,
		name:    "timerfd_settime",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "time", "time_timer"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "int", Name: "flags"},
			{Type: "const struct itimerspec*", Name: "new_value"},
			{Type: "struct itimerspec*", Name: "old_value"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(TimerfdSettime)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(TimerfdSettime)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(TimerfdSettime)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(TimerfdSettime)}},
			},
		},
	},
	TimerfdGettime: {
		id:      TimerfdGettime,
		id32Bit: Sys32timerfd_gettime64,
		name:    "timerfd_gettime",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "time", "time_timer"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "struct itimerspec*", Name: "curr_value"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(TimerfdGettime)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(TimerfdGettime)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(TimerfdGettime)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(TimerfdGettime)}},
			},
		},
	},
	Accept4: {
		id:      Accept4,
		id32Bit: Sys32accept4,
		name:    "accept4",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "net", "net_sock"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct sockaddr*", Name: "addr"},
			{Type: "int*", Name: "addrlen"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Accept4)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Accept4)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Accept4)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Accept4)}},
			},
		},
	},
	Signalfd4: {
		id:      Signalfd4,
		id32Bit: Sys32signalfd4,
		name:    "signalfd4",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "signals"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const sigset_t*", Name: "mask"},
			{Type: "size_t", Name: "sizemask"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Signalfd4)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Signalfd4)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Signalfd4)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Signalfd4)}},
			},
		},
	},
	Eventfd2: {
		id:      Eventfd2,
		id32Bit: Sys32eventfd2,
		name:    "eventfd2",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "signals"},
		fields: []trace.ArgMeta{
			{Type: "unsigned int", Name: "initval"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Eventfd2)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Eventfd2)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Eventfd2)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Eventfd2)}},
			},
		},
	},
	EpollCreate1: {
		id:      EpollCreate1,
		id32Bit: Sys32epoll_create1,
		name:    "epoll_create1",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_mux_io"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(EpollCreate1)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(EpollCreate1)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(EpollCreate1)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(EpollCreate1)}},
			},
		},
	},
	Dup3: {
		id:      Dup3,
		id32Bit: Sys32dup3,
		name:    "dup3",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_fd_ops"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "oldfd"},
			{Type: "int", Name: "newfd"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.Dup3, required: true},
				{handle: probes.Dup3Ret, required: true},
			},
		},
	},
	Pipe2: {
		id:      Pipe2,
		id32Bit: Sys32pipe2,
		name:    "pipe2",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "ipc", "ipc_pipe"},
		fields: []trace.ArgMeta{
			{Type: "int[2]", Name: "pipefd"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Pipe2)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Pipe2)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Pipe2)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Pipe2)}},
			},
		},
	},
	InotifyInit1: {
		id:      InotifyInit1,
		id32Bit: Sys32inotify_init1,
		name:    "inotify_init1",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_monitor"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(InotifyInit1)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(InotifyInit1)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(InotifyInit1)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(InotifyInit1)}},
			},
		},
	},
	Preadv: {
		id:      Preadv,
		id32Bit: Sys32preadv,
		name:    "preadv",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_read_write"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const struct iovec*", Name: "iov"},
			{Type: "unsigned long", Name: "iovcnt"},
			{Type: "unsigned long", Name: "pos_l"},
			{Type: "unsigned long", Name: "pos_h"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Preadv)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Preadv)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Preadv)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Preadv)}},
			},
		},
	},
	Pwritev: {
		id:      Pwritev,
		id32Bit: Sys32pwritev,
		name:    "pwritev",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_read_write"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const struct iovec*", Name: "iov"},
			{Type: "unsigned long", Name: "iovcnt"},
			{Type: "unsigned long", Name: "pos_l"},
			{Type: "unsigned long", Name: "pos_h"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Pwritev)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Pwritev)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Pwritev)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Pwritev)}},
			},
		},
	},
	RtTgsigqueueinfo: {
		id:      RtTgsigqueueinfo,
		id32Bit: Sys32rt_tgsigqueueinfo,
		name:    "rt_tgsigqueueinfo",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "signals"},
		fields: []trace.ArgMeta{
			{Type: "pid_t", Name: "tgid"},
			{Type: "pid_t", Name: "tid"},
			{Type: "int", Name: "sig"},
			{Type: "siginfo_t*", Name: "info"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(RtTgsigqueueinfo)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(RtTgsigqueueinfo)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(RtTgsigqueueinfo)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(RtTgsigqueueinfo)}},
			},
		},
	},
	PerfEventOpen: {
		id:      PerfEventOpen,
		id32Bit: Sys32perf_event_open,
		name:    "perf_event_open",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system"},
		fields: []trace.ArgMeta{
			{Type: "struct perf_event_attr*", Name: "attr"},
			{Type: "pid_t", Name: "pid"},
			{Type: "int", Name: "cpu"},
			{Type: "int", Name: "group_fd"},
			{Type: "unsigned long", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(PerfEventOpen)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(PerfEventOpen)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(PerfEventOpen)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(PerfEventOpen)}},
			},
		},
	},
	Recvmmsg: {
		id:      Recvmmsg,
		id32Bit: Sys32recvmmsg_time64,
		name:    "recvmmsg",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "net", "net_snd_rcv"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct mmsghdr*", Name: "msgvec"},
			{Type: "unsigned int", Name: "vlen"},
			{Type: "int", Name: "flags"},
			{Type: "struct timespec*", Name: "timeout"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Recvmmsg)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Recvmmsg)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Recvmmsg)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Recvmmsg)}},
			},
		},
	},
	FanotifyInit: {
		id:      FanotifyInit,
		id32Bit: Sys32fanotify_init,
		name:    "fanotify_init",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_monitor"},
		fields: []trace.ArgMeta{
			{Type: "unsigned int", Name: "flags"},
			{Type: "unsigned int", Name: "event_f_flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(FanotifyInit)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(FanotifyInit)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(FanotifyInit)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(FanotifyInit)}},
			},
		},
	},
	FanotifyMark: {
		id:      FanotifyMark,
		id32Bit: Sys32fanotify_mark,
		name:    "fanotify_mark",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_monitor"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fanotify_fd"},
			{Type: "unsigned int", Name: "flags"},
			{Type: "u64", Name: "mask"},
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(FanotifyMark)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(FanotifyMark)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(FanotifyMark)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(FanotifyMark)}},
			},
		},
	},
	Prlimit64: {
		id:      Prlimit64,
		id32Bit: Sys32prlimit64,
		name:    "prlimit64",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc"},
		fields: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "int", Name: "resource"},
			{Type: "const struct rlimit64*", Name: "new_limit"},
			{Type: "struct rlimit64*", Name: "old_limit"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Prlimit64)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Prlimit64)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Prlimit64)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Prlimit64)}},
			},
		},
	},
	NameToHandleAt: {
		id:      NameToHandleAt,
		id32Bit: Sys32name_to_handle_at,
		name:    "name_to_handle_at",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_ops"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "struct file_handle*", Name: "handle"},
			{Type: "int*", Name: "mount_id"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(NameToHandleAt)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(NameToHandleAt)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(NameToHandleAt)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(NameToHandleAt)}},
			},
		},
	},
	OpenByHandleAt: {
		id:      OpenByHandleAt,
		id32Bit: Sys32open_by_handle_at,
		name:    "open_by_handle_at",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_ops"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "mount_fd"},
			{Type: "struct file_handle*", Name: "handle"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(OpenByHandleAt)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(OpenByHandleAt)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(OpenByHandleAt)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(OpenByHandleAt)}},
			},
		},
	},
	ClockAdjtime: {
		id:      ClockAdjtime,
		id32Bit: Sys32clock_adjtime,
		name:    "clock_adjtime",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "time", "time_clock"},
		fields: []trace.ArgMeta{
			{Type: "const clockid_t", Name: "clk_id"},
			{Type: "struct timex*", Name: "buf"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(ClockAdjtime)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(ClockAdjtime)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(ClockAdjtime)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(ClockAdjtime)}},
			},
		},
	},
	Syncfs: {
		id:      Syncfs,
		id32Bit: Sys32syncfs,
		name:    "syncfs",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_sync"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Syncfs)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Syncfs)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Syncfs)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Syncfs)}},
			},
		},
	},
	Sendmmsg: {
		id:      Sendmmsg,
		id32Bit: Sys32sendmmsg,
		name:    "sendmmsg",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "net", "net_snd_rcv"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct mmsghdr*", Name: "msgvec"},
			{Type: "unsigned int", Name: "vlen"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Sendmmsg)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Sendmmsg)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Sendmmsg)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Sendmmsg)}},
			},
		},
	},
	Setns: {
		id:      Setns,
		id32Bit: Sys32setns,
		name:    "setns",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "int", Name: "nstype"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setns)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setns)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setns)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setns)}},
			},
		},
	},
	Getcpu: {
		id:      Getcpu,
		id32Bit: Sys32getcpu,
		name:    "getcpu",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system", "system_numa"},
		fields: []trace.ArgMeta{
			{Type: "unsigned int*", Name: "cpu"},
			{Type: "unsigned int*", Name: "node"},
			{Type: "struct getcpu_cache*", Name: "tcache"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getcpu)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getcpu)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getcpu)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getcpu)}},
			},
		},
	},
	ProcessVmReadv: {
		id:      ProcessVmReadv,
		id32Bit: Sys32process_vm_readv,
		name:    "process_vm_readv",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc"},
		fields: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "const struct iovec*", Name: "local_iov"},
			{Type: "unsigned long", Name: "liovcnt"},
			{Type: "const struct iovec*", Name: "remote_iov"},
			{Type: "unsigned long", Name: "riovcnt"},
			{Type: "unsigned long", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(ProcessVmReadv)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(ProcessVmReadv)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(ProcessVmReadv)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(ProcessVmReadv)}},
			},
		},
	},
	ProcessVmWritev: {
		id:      ProcessVmWritev,
		id32Bit: Sys32process_vm_writev,
		name:    "process_vm_writev",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"default", "syscalls", "proc"},
		fields: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "const struct iovec*", Name: "local_iov"},
			{Type: "unsigned long", Name: "liovcnt"},
			{Type: "const struct iovec*", Name: "remote_iov"},
			{Type: "unsigned long", Name: "riovcnt"},
			{Type: "unsigned long", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.ProcessVmWritev, required: true},
				{handle: probes.ProcessVmWritevRet, required: true},
			},
		},
	},
	Kcmp: {
		id:      Kcmp,
		id32Bit: Sys32kcmp,
		name:    "kcmp",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc"},
		fields: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid1"},
			{Type: "pid_t", Name: "pid2"},
			{Type: "int", Name: "type"},
			{Type: "unsigned long", Name: "idx1"},
			{Type: "unsigned long", Name: "idx2"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Kcmp)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Kcmp)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Kcmp)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Kcmp)}},
			},
		},
	},
	FinitModule: {
		id:      FinitModule,
		id32Bit: Sys32finit_module,
		name:    "finit_module",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system", "system_module"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const char*", Name: "param_values"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(FinitModule)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(FinitModule)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(FinitModule)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(FinitModule)}},
			},
		},
	},
	SchedSetattr: {
		id:      SchedSetattr,
		id32Bit: Sys32sched_setattr,
		name:    "sched_setattr",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_sched"},
		fields: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "struct sched_attr*", Name: "attr"},
			{Type: "unsigned int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(SchedSetattr)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(SchedSetattr)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(SchedSetattr)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(SchedSetattr)}},
			},
		},
	},
	SchedGetattr: {
		id:      SchedGetattr,
		id32Bit: Sys32sched_getattr,
		name:    "sched_getattr",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_sched"},
		fields: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "struct sched_attr*", Name: "attr"},
			{Type: "unsigned int", Name: "size"},
			{Type: "unsigned int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(SchedGetattr)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(SchedGetattr)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(SchedGetattr)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(SchedGetattr)}},
			},
		},
	},
	Renameat2: {
		id:      Renameat2,
		id32Bit: Sys32renameat2,
		name:    "renameat2",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_ops"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "olddirfd"},
			{Type: "const char*", Name: "oldpath"},
			{Type: "int", Name: "newdirfd"},
			{Type: "const char*", Name: "newpath"},
			{Type: "unsigned int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Renameat2)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Renameat2)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Renameat2)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Renameat2)}},
			},
		},
	},
	Seccomp: {
		id:      Seccomp,
		id32Bit: Sys32seccomp,
		name:    "seccomp",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc"},
		fields: []trace.ArgMeta{
			{Type: "unsigned int", Name: "operation"},
			{Type: "unsigned int", Name: "flags"},
			{Type: "const void*", Name: "args"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Seccomp)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Seccomp)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Seccomp)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Seccomp)}},
			},
		},
	},
	Getrandom: {
		id:      Getrandom,
		id32Bit: Sys32getrandom,
		name:    "getrandom",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs"},
		fields: []trace.ArgMeta{
			{Type: "void*", Name: "buf"},
			{Type: "size_t", Name: "buflen"},
			{Type: "unsigned int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getrandom)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getrandom)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getrandom)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getrandom)}},
			},
		},
	},
	MemfdCreate: {
		id:      MemfdCreate,
		id32Bit: Sys32memfd_create,
		name:    "memfd_create",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_ops"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "name"},
			{Type: "unsigned int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(MemfdCreate)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(MemfdCreate)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(MemfdCreate)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(MemfdCreate)}},
			},
		},
	},
	KexecFileLoad: {
		id:      KexecFileLoad,
		id32Bit: Sys32Undefined,
		name:    "kexec_file_load",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "kernel_fd"},
			{Type: "int", Name: "initrd_fd"},
			{Type: "unsigned long", Name: "cmdline_len"},
			{Type: "const char*", Name: "cmdline"},
			{Type: "unsigned long", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(KexecFileLoad)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(KexecFileLoad)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(KexecFileLoad)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(KexecFileLoad)}},
			},
		},
	},
	Bpf: {
		id:      Bpf,
		id32Bit: Sys32bpf,
		name:    "bpf",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "cmd"},
			{Type: "union bpf_attr*", Name: "attr"},
			{Type: "unsigned int", Name: "size"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Bpf)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Bpf)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Bpf)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Bpf)}},
			},
		},
	},
	Execveat: {
		id:      Execveat,
		id32Bit: Sys32execveat,
		name:    "execveat",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_life"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "const char*const*", Name: "argv"},
			{Type: "const char*const*", Name: "envp"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Execveat)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Execveat)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Execveat)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Execveat)}},
				{"sys_enter_tails", "syscall__execveat_enter", []uint32{uint32(Execveat)}},
				{"sys_exit_tails", "syscall__execveat_exit", []uint32{uint32(Execveat)}},
			},
		},
	},
	Userfaultfd: {
		id:      Userfaultfd,
		id32Bit: Sys32userfaultfd,
		name:    "userfaultfd",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "system"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Userfaultfd)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Userfaultfd)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Userfaultfd)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Userfaultfd)}},
			},
		},
	},
	Membarrier: {
		id:      Membarrier,
		id32Bit: Sys32membarrier,
		name:    "membarrier",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_mem"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "cmd"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Membarrier)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Membarrier)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Membarrier)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Membarrier)}},
			},
		},
	},
	Mlock2: {
		id:      Mlock2,
		id32Bit: Sys32mlock2,
		name:    "mlock2",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_mem"},
		fields: []trace.ArgMeta{
			{Type: "const void*", Name: "addr"},
			{Type: "size_t", Name: "len"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Mlock2)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Mlock2)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Mlock2)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Mlock2)}},
			},
		},
	},
	CopyFileRange: {
		id:      CopyFileRange,
		id32Bit: Sys32copy_file_range,
		name:    "copy_file_range",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_read_write"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd_in"},
			{Type: "off_t*", Name: "off_in"},
			{Type: "int", Name: "fd_out"},
			{Type: "off_t*", Name: "off_out"},
			{Type: "size_t", Name: "len"},
			{Type: "unsigned int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(CopyFileRange)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(CopyFileRange)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(CopyFileRange)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(CopyFileRange)}},
			},
		},
	},
	Preadv2: {
		id:      Preadv2,
		id32Bit: Sys32preadv2,
		name:    "preadv2",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_read_write"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const struct iovec*", Name: "iov"},
			{Type: "unsigned long", Name: "iovcnt"},
			{Type: "unsigned long", Name: "pos_l"},
			{Type: "unsigned long", Name: "pos_h"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Preadv2)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Preadv2)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Preadv2)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Preadv2)}},
			},
		},
	},
	Pwritev2: {
		id:      Pwritev2,
		id32Bit: Sys32pwritev2,
		name:    "pwritev2",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_read_write"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const struct iovec*", Name: "iov"},
			{Type: "unsigned long", Name: "iovcnt"},
			{Type: "unsigned long", Name: "pos_l"},
			{Type: "unsigned long", Name: "pos_h"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Pwritev2)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Pwritev2)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Pwritev2)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Pwritev2)}},
			},
		},
	},
	PkeyMprotect: {
		id:      PkeyMprotect,
		id32Bit: Sys32pkey_mprotect,
		name:    "pkey_mprotect",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_mem"},
		fields: []trace.ArgMeta{
			{Type: "void*", Name: "addr"},
			{Type: "size_t", Name: "len"},
			{Type: "int", Name: "prot"},
			{Type: "int", Name: "pkey"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(PkeyMprotect)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(PkeyMprotect)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(PkeyMprotect)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(PkeyMprotect)}},
			},
		},
	},
	PkeyAlloc: {
		id:      PkeyAlloc,
		id32Bit: Sys32pkey_alloc,
		name:    "pkey_alloc",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_mem"},
		fields: []trace.ArgMeta{
			{Type: "unsigned int", Name: "flags"},
			{Type: "unsigned long", Name: "access_rights"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(PkeyAlloc)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(PkeyAlloc)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(PkeyAlloc)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(PkeyAlloc)}},
			},
		},
	},
	PkeyFree: {
		id:      PkeyFree,
		id32Bit: Sys32pkey_free,
		name:    "pkey_free",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_mem"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "pkey"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(PkeyFree)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(PkeyFree)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(PkeyFree)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(PkeyFree)}},
			},
		},
	},
	Statx: {
		id:      Statx,
		id32Bit: Sys32statx,
		name:    "statx",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "int", Name: "flags"},
			{Type: "unsigned int", Name: "mask"},
			{Type: "struct statx*", Name: "statxbuf"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Statx)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Statx)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Statx)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Statx)}},
			},
		},
	},
	IoPgetevents: {
		id:      IoPgetevents,
		id32Bit: Sys32io_pgetevents_time64,
		name:    "io_pgetevents",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_async_io"},
		fields: []trace.ArgMeta{
			{Type: "aio_context_t", Name: "ctx_id"},
			{Type: "long", Name: "min_nr"},
			{Type: "long", Name: "nr"},
			{Type: "struct io_event*", Name: "events"},
			{Type: "struct timespec*", Name: "timeout"},
			{Type: "const struct __aio_sigset*", Name: "usig"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(IoPgetevents)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(IoPgetevents)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(IoPgetevents)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(IoPgetevents)}},
			},
		},
	},
	Rseq: {
		id:      Rseq,
		id32Bit: Sys32rseq,
		name:    "rseq",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls"},
		fields: []trace.ArgMeta{
			{Type: "struct rseq*", Name: "rseq"},
			{Type: "u32", Name: "rseq_len"},
			{Type: "int", Name: "flags"},
			{Type: "u32", Name: "sig"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Rseq)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Rseq)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Rseq)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Rseq)}},
			},
		},
	},
	PidfdSendSignal: {
		id:      PidfdSendSignal,
		id32Bit: Sys32pidfd_send_signal,
		name:    "pidfd_send_signal",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "signals"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "pidfd"},
			{Type: "int", Name: "sig"},
			{Type: "siginfo_t*", Name: "info"},
			{Type: "unsigned int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(PidfdSendSignal)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(PidfdSendSignal)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(PidfdSendSignal)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(PidfdSendSignal)}},
			},
		},
	},
	IoUringSetup: {
		id:      IoUringSetup,
		id32Bit: Sys32io_uring_setup,
		name:    "io_uring_setup",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls"},
		fields: []trace.ArgMeta{
			{Type: "unsigned int", Name: "entries"},
			{Type: "struct io_uring_params*", Name: "p"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(IoUringSetup)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(IoUringSetup)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(IoUringSetup)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(IoUringSetup)}},
			},
		},
	},
	IoUringEnter: {
		id:      IoUringEnter,
		id32Bit: Sys32io_uring_enter,
		name:    "io_uring_enter",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls"},
		fields: []trace.ArgMeta{
			{Type: "unsigned int", Name: "fd"},
			{Type: "unsigned int", Name: "to_submit"},
			{Type: "unsigned int", Name: "min_complete"},
			{Type: "unsigned int", Name: "flags"},
			{Type: "sigset_t*", Name: "sig"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(IoUringEnter)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(IoUringEnter)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(IoUringEnter)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(IoUringEnter)}},
			},
		},
	},
	IoUringRegister: {
		id:      IoUringRegister,
		id32Bit: Sys32io_uring_register,
		name:    "io_uring_register",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls"},
		fields: []trace.ArgMeta{
			{Type: "unsigned int", Name: "fd"},
			{Type: "unsigned int", Name: "opcode"},
			{Type: "void*", Name: "arg"},
			{Type: "unsigned int", Name: "nr_args"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(IoUringRegister)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(IoUringRegister)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(IoUringRegister)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(IoUringRegister)}},
			},
		},
	},
	OpenTree: {
		id:      OpenTree,
		id32Bit: Sys32open_tree,
		name:    "open_tree",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "dfd"},
			{Type: "const char*", Name: "filename"},
			{Type: "unsigned int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(OpenTree)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(OpenTree)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(OpenTree)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(OpenTree)}},
			},
		},
	},
	MoveMount: {
		id:      MoveMount,
		id32Bit: Sys32move_mount,
		name:    "move_mount",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "from_dfd"},
			{Type: "const char*", Name: "from_path"},
			{Type: "int", Name: "to_dfd"},
			{Type: "const char*", Name: "to_path"},
			{Type: "unsigned int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(MoveMount)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(MoveMount)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(MoveMount)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(MoveMount)}},
			},
		},
	},
	Fsopen: {
		id:      Fsopen,
		id32Bit: Sys32fsopen,
		name:    "fsopen",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "fsname"},
			{Type: "unsigned int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Fsopen)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Fsopen)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Fsopen)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Fsopen)}},
			},
		},
	},
	Fsconfig: {
		id:      Fsconfig,
		id32Bit: Sys32fsconfig,
		name:    "fsconfig",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs"},
		fields: []trace.ArgMeta{
			{Type: "int*", Name: "fs_fd"},
			{Type: "unsigned int", Name: "cmd"},
			{Type: "const char*", Name: "key"},
			{Type: "const void*", Name: "value"},
			{Type: "int", Name: "aux"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Fsconfig)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Fsconfig)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Fsconfig)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Fsconfig)}},
			},
		},
	},
	Fsmount: {
		id:      Fsmount,
		id32Bit: Sys32fsmount,
		name:    "fsmount",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fsfd"},
			{Type: "unsigned int", Name: "flags"},
			{Type: "unsigned int", Name: "ms_flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Fsmount)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Fsmount)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Fsmount)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Fsmount)}},
			},
		},
	},
	Fspick: {
		id:      Fspick,
		id32Bit: Sys32fspick,
		name:    "fspick",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "unsigned int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Fspick)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Fspick)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Fspick)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Fspick)}},
			},
		},
	},
	PidfdOpen: {
		id:      PidfdOpen,
		id32Bit: Sys32pidfd_open,
		name:    "pidfd_open",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls"},
		fields: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "unsigned int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(PidfdOpen)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(PidfdOpen)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(PidfdOpen)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(PidfdOpen)}},
			},
		},
	},
	Clone3: {
		id:      Clone3,
		id32Bit: Sys32clone3,
		name:    "clone3",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "proc_life"},
		fields: []trace.ArgMeta{
			{Type: "struct clone_args*", Name: "cl_args"},
			{Type: "size_t", Name: "size"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Clone3)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Clone3)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Clone3)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Clone3)}},
			},
		},
	},
	CloseRange: {
		id:      CloseRange,
		id32Bit: Sys32close_range,
		name:    "close_range",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_ops"},
		fields: []trace.ArgMeta{
			{Type: "unsigned int", Name: "first"},
			{Type: "unsigned int", Name: "last"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(CloseRange)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(CloseRange)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(CloseRange)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(CloseRange)}},
			},
		},
	},
	Openat2: {
		id:      Openat2,
		id32Bit: Sys32openat2,
		name:    "openat2",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_ops"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "struct open_how*", Name: "how"},
			{Type: "size_t", Name: "size"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Openat2)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Openat2)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Openat2)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Openat2)}},
			},
		},
	},
	PidfdGetfd: {
		id:      PidfdGetfd,
		id32Bit: Sys32pidfd_getfd,
		name:    "pidfd_getfd",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "pidfd"},
			{Type: "int", Name: "targetfd"},
			{Type: "unsigned int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(PidfdGetfd)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(PidfdGetfd)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(PidfdGetfd)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(PidfdGetfd)}},
			},
		},
	},
	Faccessat2: {
		id:      Faccessat2,
		id32Bit: Sys32faccessat2,
		name:    "faccessat2",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_file_attr"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const char*", Name: "path"},
			{Type: "int", Name: "mode"},
			{Type: "int", Name: "flag"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Faccessat2)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Faccessat2)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Faccessat2)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Faccessat2)}},
			},
		},
	},
	ProcessMadvise: {
		id:      ProcessMadvise,
		id32Bit: Sys32process_madvise,
		name:    "process_madvise",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "pidfd"},
			{Type: "void*", Name: "addr"},
			{Type: "size_t", Name: "length"},
			{Type: "int", Name: "advice"},
			{Type: "unsigned long", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(ProcessMadvise)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(ProcessMadvise)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(ProcessMadvise)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(ProcessMadvise)}},
			},
		},
	},
	EpollPwait2: {
		id:      EpollPwait2,
		id32Bit: Sys32epoll_pwait2,
		name:    "epoll_pwait2",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs", "fs_mux_io"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "struct epoll_event*", Name: "events"},
			{Type: "int", Name: "maxevents"},
			{Type: "const struct timespec*", Name: "timeout"},
			{Type: "const sigset_t*", Name: "sigset"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(EpollPwait2)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(EpollPwait2)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(EpollPwait2)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(EpollPwait2)}},
			},
		},
	},
	MountSetattr: {
		id:      MountSetattr,
		id32Bit: Sys32mount_setattr,
		name:    "mount_setattr",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "dfd"},
			{Type: "char*", Name: "path"},
			{Type: "unsigned int", Name: "flags"},
			{Type: "struct mount_attr*", Name: "uattr"},
			{Type: "size_t", Name: "usize"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(MountSetattr)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(MountSetattr)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(MountSetattr)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(MountSetattr)}},
			},
		},
	},
	QuotactlFd: {
		id:      QuotactlFd,
		id32Bit: Sys32quotactl_fd,
		name:    "quotactl_fd",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "fs"},
		fields: []trace.ArgMeta{
			{Type: "unsigned int", Name: "fd"},
			{Type: "unsigned int", Name: "cmd"},
			{Type: "qid_t", Name: "id"},
			{Type: "void *", Name: "addr"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(QuotactlFd)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(QuotactlFd)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(QuotactlFd)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(QuotactlFd)}},
			},
		},
	},
	LandlockCreateRuleset: {
		id:      LandlockCreateRuleset,
		id32Bit: Sys32landlock_create_ruleset,
		name:    "landlock_create_ruleset",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "fs"},
		fields: []trace.ArgMeta{
			{Type: "struct landlock_ruleset_attr*", Name: "attr"},
			{Type: "size_t", Name: "size"},
			{Type: "u32", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(LandlockCreateRuleset)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(LandlockCreateRuleset)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(LandlockCreateRuleset)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(LandlockCreateRuleset)}},
			},
		},
	},
	LandlockAddRule: {
		id:      LandlockAddRule,
		id32Bit: Sys32landlock_add_rule,
		name:    "landlock_add_rule",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "fs"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "ruleset_fd"},
			{Type: "landlock_rule_type", Name: "rule_type"},
			{Type: "void*", Name: "rule_attr"},
			{Type: "u32", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(LandlockAddRule)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(LandlockAddRule)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(LandlockAddRule)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(LandlockAddRule)}},
			},
		},
	},
	LandlockRestrictSelf: {
		id:      LandlockRestrictSelf,
		id32Bit: Sys32landlock_restrict_self,
		name:    "landlock_restrict_self",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "proc", "fs"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "ruleset_fd"},
			{Type: "u32", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(LandlockRestrictSelf)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(LandlockRestrictSelf)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(LandlockRestrictSelf)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(LandlockRestrictSelf)}},
			},
		},
	},
	MemfdSecret: {
		id:      MemfdSecret,
		id32Bit: Sys32memfd_secret,
		name:    "memfd_secret",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls"},
		fields: []trace.ArgMeta{
			{Type: "unsigned int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(MemfdSecret)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(MemfdSecret)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(MemfdSecret)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(MemfdSecret)}},
			},
		},
	},
	ProcessMrelease: {
		id:      ProcessMrelease,
		id32Bit: Sys32process_mrelease,
		name:    "process_mrelease",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "pidfd"},
			{Type: "unsigned int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(ProcessMrelease)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(ProcessMrelease)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(ProcessMrelease)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(ProcessMrelease)}},
			},
		},
	},
	Waitpid: {
		id:      Waitpid,
		id32Bit: Sys32waitpid,
		name:    "waitpid",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "int*", Name: "status"},
			{Type: "int", Name: "options"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Waitpid)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Waitpid)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Waitpid)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Waitpid)}},
			},
		},
	},
	Oldfstat: {
		id:      Oldfstat,
		id32Bit: Sys32oldfstat,
		name:    "oldfstat",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Oldfstat)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Oldfstat)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Oldfstat)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Oldfstat)}},
			},
		},
	},
	Break: {
		id:      Break,
		id32Bit: Sys32break,
		name:    "break",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Break)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Break)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Break)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Break)}},
			},
		},
	},
	Oldstat: {
		id:      Oldstat,
		id32Bit: Sys32oldstat,
		name:    "oldstat",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "char*", Name: "filename"},
			{Type: "struct __old_kernel_stat*", Name: "statbuf"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Oldstat)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Oldstat)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Oldstat)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Oldstat)}},
			},
		},
	},
	Umount: {
		id:      Umount,
		id32Bit: Sys32umount,
		name:    "umount",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "target"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Umount)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Umount)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Umount)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Umount)}},
			},
		},
	},
	Stime: {
		id:      Stime,
		id32Bit: Sys32stime,
		name:    "stime",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "const time_t*", Name: "t"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Stime)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Stime)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Stime)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Stime)}},
			},
		},
	},
	Stty: {
		id:      Stty,
		id32Bit: Sys32stty,
		name:    "stty",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Stty)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Stty)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Stty)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Stty)}},
			},
		},
	},
	Gtty: {
		id:      Gtty,
		id32Bit: Sys32gtty,
		name:    "gtty",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Gtty)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Gtty)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Gtty)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Gtty)}},
			},
		},
	},
	Nice: {
		id:      Nice,
		id32Bit: Sys32nice,
		name:    "nice",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "inc"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Nice)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Nice)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Nice)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Nice)}},
			},
		},
	},
	Ftime: {
		id:      Ftime,
		id32Bit: Sys32ftime,
		name:    "ftime",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Ftime)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Ftime)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Ftime)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Ftime)}},
			},
		},
	},
	Prof: {
		id:      Prof,
		id32Bit: Sys32prof,
		name:    "prof",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Prof)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Prof)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Prof)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Prof)}},
			},
		},
	},
	Signal: {
		id:      Signal,
		id32Bit: Sys32signal,
		name:    "signal",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "signum"},
			{Type: "sighandler_t", Name: "handler"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Signal)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Signal)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Signal)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Signal)}},
			},
		},
	},
	Lock: {
		id:      Lock,
		id32Bit: Sys32lock,
		name:    "lock",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Lock)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Lock)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Lock)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Lock)}},
			},
		},
	},
	Mpx: {
		id:      Mpx,
		id32Bit: Sys32mpx,
		name:    "mpx",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Mpx)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Mpx)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Mpx)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Mpx)}},
			},
		},
	},
	Ulimit: {
		id:      Ulimit,
		id32Bit: Sys32ulimit,
		name:    "ulimit",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Ulimit)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Ulimit)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Ulimit)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Ulimit)}},
			},
		},
	},
	Oldolduname: {
		id:      Oldolduname,
		id32Bit: Sys32oldolduname,
		name:    "oldolduname",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "struct oldold_utsname*", Name: "name"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Oldolduname)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Oldolduname)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Oldolduname)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Oldolduname)}},
			},
		},
	},
	Sigaction: {
		id:      Sigaction,
		id32Bit: Sys32sigaction,
		name:    "sigaction",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "sig"},
			{Type: "const struct sigaction*", Name: "act"},
			{Type: "struct sigaction*", Name: "oact"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Sigaction)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Sigaction)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Sigaction)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Sigaction)}},
			},
		},
	},
	Sgetmask: {
		id:      Sgetmask,
		id32Bit: Sys32sgetmask,
		name:    "sgetmask",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Sgetmask)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Sgetmask)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Sgetmask)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Sgetmask)}},
			},
		},
	},
	Ssetmask: {
		id:      Ssetmask,
		id32Bit: Sys32ssetmask,
		name:    "ssetmask",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "long", Name: "newmask"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Ssetmask)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Ssetmask)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Ssetmask)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Ssetmask)}},
			},
		},
	},
	Sigsuspend: {
		id:      Sigsuspend,
		id32Bit: Sys32sigsuspend,
		name:    "sigsuspend",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "const sigset_t*", Name: "mask"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Sigsuspend)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Sigsuspend)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Sigsuspend)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Sigsuspend)}},
			},
		},
	},
	Sigpending: {
		id:      Sigpending,
		id32Bit: Sys32sigpending,
		name:    "sigpending",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "sigset_t*", Name: "set"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Sigpending)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Sigpending)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Sigpending)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Sigpending)}},
			},
		},
	},
	Oldlstat: {
		id:      Oldlstat,
		id32Bit: Sys32oldlstat,
		name:    "oldlstat",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "struct stat*", Name: "statbuf"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Oldlstat)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Oldlstat)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Oldlstat)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Oldlstat)}},
			},
		},
	},
	Readdir: {
		id:      Readdir,
		id32Bit: Sys32readdir,
		name:    "readdir",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "unsigned int", Name: "fd"},
			{Type: "struct old_linux_dirent*", Name: "dirp"},
			{Type: "unsigned int", Name: "count"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Readdir)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Readdir)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Readdir)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Readdir)}},
			},
		},
	},
	Profil: {
		id:      Profil,
		id32Bit: Sys32profil,
		name:    "profil",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Profil)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Profil)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Profil)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Profil)}},
			},
		},
	},
	Socketcall: {
		id:      Socketcall,
		id32Bit: Sys32socketcall,
		name:    "socketcall",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "call"},
			{Type: "unsigned long*", Name: "args"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Socketcall)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Socketcall)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Socketcall)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Socketcall)}},
			},
		},
	},
	Olduname: {
		id:      Olduname,
		id32Bit: Sys32olduname,
		name:    "olduname",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "struct utsname*", Name: "buf"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Olduname)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Olduname)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Olduname)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Olduname)}},
			},
		},
	},
	Idle: {
		id:      Idle,
		id32Bit: Sys32idle,
		name:    "idle",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Idle)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Idle)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Idle)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Idle)}},
			},
		},
	},
	Vm86old: {
		id:      Vm86old,
		id32Bit: Sys32vm86old,
		name:    "vm86old",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "struct vm86_struct*", Name: "info"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Vm86old)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Vm86old)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Vm86old)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Vm86old)}},
			},
		},
	},
	Ipc: {
		id:      Ipc,
		id32Bit: Sys32ipc,
		name:    "ipc",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "unsigned int", Name: "call"},
			{Type: "int", Name: "first"},
			{Type: "unsigned long", Name: "second"},
			{Type: "unsigned long", Name: "third"},
			{Type: "void*", Name: "ptr"},
			{Type: "long", Name: "fifth"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Ipc)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Ipc)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Ipc)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Ipc)}},
			},
		},
	},
	Sigreturn: {
		id:      Sigreturn,
		id32Bit: Sys32sigreturn,
		name:    "sigreturn",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Sigreturn)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Sigreturn)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Sigreturn)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Sigreturn)}},
			},
		},
	},
	Sigprocmask: {
		id:      Sigprocmask,
		id32Bit: Sys32sigprocmask,
		name:    "sigprocmask",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "how"},
			{Type: "const sigset_t *restrict", Name: "set"},
			{Type: "sigset_t *restrict", Name: "oldset"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Sigprocmask)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Sigprocmask)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Sigprocmask)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Sigprocmask)}},
			},
		},
	},
	Bdflush: {
		id:      Bdflush,
		id32Bit: Sys32bdflush,
		name:    "bdflush",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Bdflush)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Bdflush)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Bdflush)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Bdflush)}},
			},
		},
	},
	Afs_syscall: {
		id:      Afs_syscall,
		id32Bit: Sys32afs_syscall,
		name:    "afs_syscall",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Afs_syscall)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Afs_syscall)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Afs_syscall)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Afs_syscall)}},
			},
		},
	},
	Llseek: {
		id:      Llseek,
		id32Bit: Sys32_llseek,
		name:    "llseek",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "unsigned int", Name: "fd"},
			{Type: "unsigned long", Name: "offset_high"},
			{Type: "unsigned long", Name: "offset_low"},
			{Type: "loff_t*", Name: "result"},
			{Type: "unsigned int", Name: "whence"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Llseek)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Llseek)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Llseek)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Llseek)}},
			},
		},
	},
	OldSelect: {
		id:      OldSelect,
		id32Bit: Sys32select,
		name:    "old_select",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "nfds"},
			{Type: "fd_set*", Name: "readfds"},
			{Type: "fd_set*", Name: "writefds"},
			{Type: "fd_set*", Name: "exceptfds"},
			{Type: "struct timeval*", Name: "timeout"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(OldSelect)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(OldSelect)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(OldSelect)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(OldSelect)}},
			},
		},
	},
	Vm86: {
		id:      Vm86,
		id32Bit: Sys32vm86,
		name:    "vm86",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "unsigned long", Name: "fn"},
			{Type: "struct vm86plus_struct*", Name: "v86"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Vm86)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Vm86)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Vm86)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Vm86)}},
			},
		},
	},
	OldGetrlimit: {
		id:      OldGetrlimit,
		id32Bit: Sys32getrlimit,
		name:    "old_getrlimit",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "resource"},
			{Type: "struct rlimit*", Name: "rlim"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(OldGetrlimit)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(OldGetrlimit)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(OldGetrlimit)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(OldGetrlimit)}},
			},
		},
	},
	Mmap2: {
		id:      Mmap2,
		id32Bit: Sys32mmap2,
		name:    "mmap2",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "unsigned long", Name: "addr"},
			{Type: "unsigned long", Name: "length"},
			{Type: "unsigned long", Name: "prot"},
			{Type: "unsigned long", Name: "flags"},
			{Type: "unsigned long", Name: "fd"},
			{Type: "unsigned long", Name: "pgoffset"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Mmap2)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Mmap2)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Mmap2)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Mmap2)}},
			},
		},
	},
	Truncate64: {
		id:      Truncate64,
		id32Bit: Sys32truncate64,
		name:    "truncate64",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "off_t", Name: "length"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Truncate64)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Truncate64)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Truncate64)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Truncate64)}},
			},
		},
	},
	Ftruncate64: {
		id:      Ftruncate64,
		id32Bit: Sys32ftruncate64,
		name:    "ftruncate64",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "off_t", Name: "length"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Ftruncate64)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Ftruncate64)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Ftruncate64)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Ftruncate64)}},
			},
		},
	},
	Stat64: {
		id:      Stat64,
		id32Bit: Sys32stat64,
		name:    "stat64",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "struct stat64*", Name: "statbuf"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Stat64)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Stat64)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Stat64)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Stat64)}},
			},
		},
	},
	Lstat64: {
		id:      Lstat64,
		id32Bit: Sys32lstat64,
		name:    "lstat64",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "struct stat64*", Name: "statbuf"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Lstat64)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Lstat64)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Lstat64)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Lstat64)}},
			},
		},
	},
	Fstat64: {
		id:      Fstat64,
		id32Bit: Sys32fstat64,
		name:    "fstat64",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "struct stat64*", Name: "statbuf"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Fstat64)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Fstat64)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Fstat64)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Fstat64)}},
			},
		},
	},
	Lchown16: {
		id:      Lchown16,
		id32Bit: Sys32lchown,
		name:    "lchown16",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "old_uid_t", Name: "owner"},
			{Type: "old_gid_t", Name: "group"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Lchown16)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Lchown16)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Lchown16)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Lchown16)}},
			},
		},
	},
	Getuid16: {
		id:      Getuid16,
		id32Bit: Sys32getuid,
		name:    "getuid16",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getuid16)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getuid16)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getuid16)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getuid16)}},
			},
		},
	},
	Getgid16: {
		id:      Getgid16,
		id32Bit: Sys32getgid,
		name:    "getgid16",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getgid16)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getgid16)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getgid16)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getgid16)}},
			},
		},
	},
	Geteuid16: {
		id:      Geteuid16,
		id32Bit: Sys32geteuid,
		name:    "geteuid16",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Geteuid16)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Geteuid16)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Geteuid16)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Geteuid16)}},
			},
		},
	},
	Getegid16: {
		id:      Getegid16,
		id32Bit: Sys32getegid,
		name:    "getegid16",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getegid16)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getegid16)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getegid16)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getegid16)}},
			},
		},
	},
	Setreuid16: {
		id:      Setreuid16,
		id32Bit: Sys32setreuid,
		name:    "setreuid16",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "old_uid_t", Name: "ruid"},
			{Type: "old_uid_t", Name: "euid"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setreuid16)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setreuid16)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setreuid16)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setreuid16)}},
			},
		},
	},
	Setregid16: {
		id:      Setregid16,
		id32Bit: Sys32setregid,
		name:    "setregid16",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "old_gid_t", Name: "rgid"},
			{Type: "old_gid_t", Name: "egid"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setregid16)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setregid16)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setregid16)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setregid16)}},
			},
		},
	},
	Getgroups16: {
		id:      Getgroups16,
		id32Bit: Sys32getgroups,
		name:    "getgroups16",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "size"},
			{Type: "old_gid_t*", Name: "list"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getgroups16)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getgroups16)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getgroups16)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getgroups16)}},
			},
		},
	},
	Setgroups16: {
		id:      Setgroups16,
		id32Bit: Sys32setgroups,
		name:    "setgroups16",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "size_t", Name: "size"},
			{Type: "const gid_t*", Name: "list"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setgroups16)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setgroups16)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setgroups16)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setgroups16)}},
			},
		},
	},
	Fchown16: {
		id:      Fchown16,
		id32Bit: Sys32fchown,
		name:    "fchown16",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "unsigned int", Name: "fd"},
			{Type: "old_uid_t", Name: "user"},
			{Type: "old_gid_t", Name: "group"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Fchown16)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Fchown16)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Fchown16)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Fchown16)}},
			},
		},
	},
	Setresuid16: {
		id:      Setresuid16,
		id32Bit: Sys32setresuid,
		name:    "setresuid16",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "old_uid_t", Name: "ruid"},
			{Type: "old_uid_t", Name: "euid"},
			{Type: "old_uid_t", Name: "suid"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setresuid16)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setresuid16)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setresuid16)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setresuid16)}},
			},
		},
	},
	Getresuid16: {
		id:      Getresuid16,
		id32Bit: Sys32getresuid,
		name:    "getresuid16",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "old_uid_t*", Name: "ruid"},
			{Type: "old_uid_t*", Name: "euid"},
			{Type: "old_uid_t*", Name: "suid"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getresuid16)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getresuid16)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getresuid16)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getresuid16)}},
			},
		},
	},
	Setresgid16: {
		id:      Setresgid16,
		id32Bit: Sys32setresgid,
		name:    "setresgid16",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "old_uid_t", Name: "rgid"},
			{Type: "old_uid_t", Name: "euid"},
			{Type: "old_uid_t", Name: "suid"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setresgid16)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setresgid16)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setresgid16)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setresgid16)}},
			},
		},
	},
	Getresgid16: {
		id:      Getresgid16,
		id32Bit: Sys32getresgid,
		name:    "getresgid16",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "old_gid_t*", Name: "rgid"},
			{Type: "old_gid_t*", Name: "egid"},
			{Type: "old_gid_t*", Name: "sgid"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Getresgid16)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Getresgid16)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Getresgid16)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Getresgid16)}},
			},
		},
	},
	Chown16: {
		id:      Chown16,
		id32Bit: Sys32chown,
		name:    "chown16",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "old_uid_t", Name: "owner"},
			{Type: "old_gid_t", Name: "group"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Chown16)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Chown16)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Chown16)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Chown16)}},
			},
		},
	},
	Setuid16: {
		id:      Setuid16,
		id32Bit: Sys32setuid,
		name:    "setuid16",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "old_uid_t", Name: "uid"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setuid16)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setuid16)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setuid16)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setuid16)}},
			},
		},
	},
	Setgid16: {
		id:      Setgid16,
		id32Bit: Sys32setgid,
		name:    "setgid16",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "old_gid_t", Name: "gid"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setgid16)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setgid16)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setgid16)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setgid16)}},
			},
		},
	},
	Setfsuid16: {
		id:      Setfsuid16,
		id32Bit: Sys32setfsuid,
		name:    "setfsuid16",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "old_uid_t", Name: "fsuid"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setfsuid16)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setfsuid16)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setfsuid16)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setfsuid16)}},
			},
		},
	},
	Setfsgid16: {
		id:      Setfsgid16,
		id32Bit: Sys32setfsgid,
		name:    "setfsgid16",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "old_gid_t", Name: "fsgid"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Setfsgid16)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Setfsgid16)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Setfsgid16)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Setfsgid16)}},
			},
		},
	},
	Fcntl64: {
		id:      Fcntl64,
		id32Bit: Sys32fcntl64,
		name:    "fcntl64",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "int", Name: "cmd"},
			{Type: "unsigned long", Name: "arg"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Fcntl64)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Fcntl64)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Fcntl64)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Fcntl64)}},
			},
		},
	},
	Sendfile32: {
		id:      Sendfile32,
		id32Bit: Sys32sendfile,
		name:    "sendfile32",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "out_fd"},
			{Type: "int", Name: "in_fd"},
			{Type: "off_t*", Name: "offset"},
			{Type: "size_t", Name: "count"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Sendfile32)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Sendfile32)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Sendfile32)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Sendfile32)}},
			},
		},
	},
	Statfs64: {
		id:      Statfs64,
		id32Bit: Sys32statfs64,
		name:    "statfs64",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "size_t", Name: "sz"},
			{Type: "struct statfs64*", Name: "buf"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Statfs64)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Statfs64)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Statfs64)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Statfs64)}},
			},
		},
	},
	Fstatfs64: {
		id:      Fstatfs64,
		id32Bit: Sys32fstatfs64,
		name:    "fstatfs64",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "size_t", Name: "sz"},
			{Type: "struct statfs64*", Name: "buf"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Fstatfs64)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Fstatfs64)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Fstatfs64)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Fstatfs64)}},
			},
		},
	},
	Fadvise64_64: {
		id:      Fadvise64_64,
		id32Bit: Sys32fadvise64_64,
		name:    "fadvise64_64",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "loff_t", Name: "offset"},
			{Type: "loff_t", Name: "len"},
			{Type: "int", Name: "advice"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Fadvise64_64)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Fadvise64_64)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Fadvise64_64)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Fadvise64_64)}},
			},
		},
	},
	ClockGettime32: {
		id:      ClockGettime32,
		id32Bit: Sys32clock_gettime,
		name:    "clock_gettime32",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "clockid_t", Name: "which_clock"},
			{Type: "struct old_timespec32*", Name: "tp"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(ClockGettime32)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(ClockGettime32)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(ClockGettime32)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(ClockGettime32)}},
			},
		},
	},
	ClockSettime32: {
		id:      ClockSettime32,
		id32Bit: Sys32clock_settime,
		name:    "clock_settime32",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "clockid_t", Name: "which_clock"},
			{Type: "struct old_timespec32*", Name: "tp"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(ClockSettime32)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(ClockSettime32)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(ClockSettime32)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(ClockSettime32)}},
			},
		},
	},
	ClockAdjtime64: {
		id:      ClockAdjtime64,
		id32Bit: Sys32clock_adjtime64,
		name:    "clock_adjtime64",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(ClockAdjtime64)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(ClockAdjtime64)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(ClockAdjtime64)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(ClockAdjtime64)}},
			},
		},
	},
	ClockGetresTime32: {
		id:      ClockGetresTime32,
		id32Bit: Sys32clock_getres,
		name:    "clock_getres_time32",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "clockid_t", Name: "which_clock"},
			{Type: "struct old_timespec32*", Name: "tp"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(ClockGetresTime32)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(ClockGetresTime32)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(ClockGetresTime32)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(ClockGetresTime32)}},
			},
		},
	},
	ClockNanosleepTime32: {
		id:      ClockNanosleepTime32,
		id32Bit: Sys32clock_nanosleep,
		name:    "clock_nanosleep_time32",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "clockid_t", Name: "which_clock"},
			{Type: "int", Name: "flags"},
			{Type: "struct old_timespec32*", Name: "rqtp"},
			{Type: "struct old_timespec32*", Name: "rmtp"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(ClockNanosleepTime32)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(ClockNanosleepTime32)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(ClockNanosleepTime32)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(ClockNanosleepTime32)}},
			},
		},
	},
	TimerGettime32: {
		id:      TimerGettime32,
		id32Bit: Sys32timer_gettime,
		name:    "timer_gettime32",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "timer_t", Name: "timer_id"},
			{Type: "struct old_itimerspec32*", Name: "setting"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(TimerGettime32)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(TimerGettime32)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(TimerGettime32)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(TimerGettime32)}},
			},
		},
	},
	TimerSettime32: {
		id:      TimerSettime32,
		id32Bit: Sys32timer_settime,
		name:    "timer_settime32",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "timer_t", Name: "timer_id"},
			{Type: "int", Name: "flags"},
			{Type: "struct old_itimerspec32*", Name: "new"},
			{Type: "struct old_itimerspec32*", Name: "old"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(TimerSettime32)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(TimerSettime32)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(TimerSettime32)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(TimerSettime32)}},
			},
		},
	},
	TimerfdGettime32: {
		id:      TimerfdGettime32,
		id32Bit: Sys32timerfd_gettime,
		name:    "timerfd_gettime32",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "ufd"},
			{Type: "struct old_itimerspec32*", Name: "otmr"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(TimerfdGettime32)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(TimerfdGettime32)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(TimerfdGettime32)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(TimerfdGettime32)}},
			},
		},
	},
	TimerfdSettime32: {
		id:      TimerfdSettime32,
		id32Bit: Sys32timerfd_settime,
		name:    "timerfd_settime32",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "ufd"},
			{Type: "int", Name: "flags"},
			{Type: "struct old_itimerspec32*", Name: "utmr"},
			{Type: "struct old_itimerspec32*", Name: "otmr"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(TimerfdSettime32)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(TimerfdSettime32)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(TimerfdSettime32)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(TimerfdSettime32)}},
			},
		},
	},
	UtimensatTime32: {
		id:      UtimensatTime32,
		id32Bit: Sys32utimensat,
		name:    "utimensat_time32",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "unsigned int", Name: "dfd"},
			{Type: "char*", Name: "filename"},
			{Type: "struct old_timespec32*", Name: "t"},
			{Type: "int", Name: "flags"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(UtimensatTime32)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(UtimensatTime32)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(UtimensatTime32)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(UtimensatTime32)}},
			},
		},
	},
	Pselect6Time32: {
		id:      Pselect6Time32,
		id32Bit: Sys32pselect6,
		name:    "pselect6_time32",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "n"},
			{Type: "fd_set*", Name: "inp"},
			{Type: "fd_set*", Name: "outp"},
			{Type: "fd_set*", Name: "exp"},
			{Type: "struct old_timespec32*", Name: "tsp"},
			{Type: "void*", Name: "sig"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Pselect6Time32)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(Pselect6Time32)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Pselect6Time32)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(Pselect6Time32)}},
			},
		},
	},
	PpollTime32: {
		id:      PpollTime32,
		id32Bit: Sys32ppoll,
		name:    "ppoll_time32",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "struct pollfd*", Name: "ufds"},
			{Type: "unsigned int", Name: "nfds"},
			{Type: "struct old_timespec32*", Name: "tsp"},
			{Type: "sigset_t*", Name: "sigmask"},
			{Type: "size_t", Name: "sigsetsize"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(PpollTime32)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(PpollTime32)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(PpollTime32)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(PpollTime32)}},
			},
		},
	},
	IoPgeteventsTime32: {
		id:      IoPgeteventsTime32,
		id32Bit: Sys32io_pgetevents,
		name:    "io_pgetevents_time32",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(IoPgeteventsTime32)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(IoPgeteventsTime32)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(IoPgeteventsTime32)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(IoPgeteventsTime32)}},
			},
		},
	},
	RecvmmsgTime32: {
		id:      RecvmmsgTime32,
		id32Bit: Sys32recvmmsg,
		name:    "recvmmsg_time32",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "struct mmsghdr*", Name: "mmsg"},
			{Type: "unsigned int", Name: "vlen"},
			{Type: "unsigned int", Name: "flags"},
			{Type: "struct old_timespec32*", Name: "timeout"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(RecvmmsgTime32)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(RecvmmsgTime32)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(RecvmmsgTime32)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(RecvmmsgTime32)}},
			},
		},
	},
	MqTimedsendTime32: {
		id:      MqTimedsendTime32,
		id32Bit: Sys32mq_timedsend,
		name:    "mq_timedsend_time32",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "mqd_t", Name: "mqdes"},
			{Type: "char*", Name: "u_msg_ptr"},
			{Type: "unsigned int", Name: "msg_len"},
			{Type: "unsigned int", Name: "msg_prio"},
			{Type: "struct old_timespec32*", Name: "u_abs_timeout"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(MqTimedsendTime32)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(MqTimedsendTime32)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(MqTimedsendTime32)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(MqTimedsendTime32)}},
			},
		},
	},
	MqTimedreceiveTime32: {
		id:      MqTimedreceiveTime32,
		id32Bit: Sys32mq_timedreceive,
		name:    "mq_timedreceive_time32",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "mqd_t", Name: "mqdes"},
			{Type: "char*", Name: "u_msg_ptr"},
			{Type: "unsigned int", Name: "msg_len"},
			{Type: "unsigned int*", Name: "u_msg_prio"},
			{Type: "struct old_timespec32*", Name: "u_abs_timeout"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(MqTimedreceiveTime32)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(MqTimedreceiveTime32)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(MqTimedreceiveTime32)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(MqTimedreceiveTime32)}},
			},
		},
	},
	RtSigtimedwaitTime32: {
		id:      RtSigtimedwaitTime32,
		id32Bit: Sys32rt_sigtimedwait,
		name:    "rt_sigtimedwait_time32",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "sigset_t*", Name: "uthese"},
			{Type: "siginfo_t*", Name: "uinfo"},
			{Type: "struct old_timespec32*", Name: "uts"},
			{Type: "size_t", Name: "sigsetsize"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(RtSigtimedwaitTime32)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(RtSigtimedwaitTime32)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(RtSigtimedwaitTime32)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(RtSigtimedwaitTime32)}},
			},
		},
	},
	FutexTime32: {
		id:      FutexTime32,
		id32Bit: Sys32futex,
		name:    "futex_time32",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "u32*", Name: "uaddr"},
			{Type: "int", Name: "op"},
			{Type: "u32", Name: "val"},
			{Type: "struct old_timespec32*", Name: "utime"},
			{Type: "u32*", Name: "uaddr2"},
			{Type: "u32", Name: "val3"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(FutexTime32)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(FutexTime32)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(FutexTime32)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(FutexTime32)}},
			},
		},
	},
	SchedRrGetInterval32: {
		id:      SchedRrGetInterval32,
		id32Bit: Sys32sched_rr_get_interval,
		name:    "sched_rr_get_interval_time32",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"syscalls", "32bit_unique"},
		fields: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "struct old_timespec32*", Name: "interval"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(SchedRrGetInterval32)}},
				{"sys_enter_submit_tail", "sys_enter_submit", []uint32{uint32(SchedRrGetInterval32)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(SchedRrGetInterval32)}},
				{"sys_exit_submit_tail", "sys_exit_submit", []uint32{uint32(SchedRrGetInterval32)}},
			},
		},
	},
	//
	// End of Syscalls
	//
	SysEnter: {
		id:      SysEnter,
		id32Bit: Sys32Undefined,
		name:    "sys_enter",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SysEnter, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "syscall"},
		},
	},
	SysExit: {
		id:      SysExit,
		id32Bit: Sys32Undefined,
		name:    "sys_exit",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SysExit, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "syscall"},
		},
	},
	SchedProcessFork: {
		id:      SchedProcessFork,
		id32Bit: Sys32Undefined,
		name:    "sched_process_fork",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SchedProcessFork, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			// Real Parent
			{Type: "int", Name: "parent_tid"},
			{Type: "int", Name: "parent_ns_tid"},
			{Type: "int", Name: "parent_pid"},
			{Type: "int", Name: "parent_ns_pid"},
			{Type: "unsigned long", Name: "parent_start_time"},
			// Child
			{Type: "int", Name: "child_tid"},
			{Type: "int", Name: "child_ns_tid"},
			{Type: "int", Name: "child_pid"},
			{Type: "int", Name: "child_ns_pid"},
			{Type: "unsigned long", Name: "start_time"}, // child_start_time
			// Arguments set by OPT_PROCESS_FORK (when process tree source is enabled for fork events).
			// Parent Process (Go up in hierarchy until parent is a process and not a lwp)
			{Type: "int", Name: "parent_process_tid"},
			{Type: "int", Name: "parent_process_ns_tid"},
			{Type: "int", Name: "parent_process_pid"},
			{Type: "int", Name: "parent_process_ns_pid"},
			{Type: "unsigned long", Name: "parent_process_start_time"},
			// Thread Group Leader
			{Type: "int", Name: "leader_tid"},
			{Type: "int", Name: "leader_ns_tid"},
			{Type: "int", Name: "leader_pid"},
			{Type: "int", Name: "leader_ns_pid"},
			{Type: "unsigned long", Name: "leader_start_time"},
		},
	},
	SchedProcessExec: {
		id:      SchedProcessExec,
		id32Bit: Sys32Undefined,
		name:    "sched_process_exec",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SchedProcessExec, required: true},
				{handle: probes.LoadElfPhdrs, required: false},
			},
			tailCalls: []TailCall{
				{
					"prog_array_tp",
					"sched_process_exec_event_submit_tail",
					[]uint32{TailSchedProcessExecEventSubmit},
				},
			},
			capabilities: Capabilities{
				base: []cap.Value{
					// 1. set by processSchedProcessFork IF CalcHashes enabled
					// 2. set by processSchedProcessExec by CaptureExec if needed
					// cap.SYS_PTRACE,
				},
			},
		},
		sets: []string{"default", "proc"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "cmdpath"},
			{Type: "const char*", Name: "pathname"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "unsigned long", Name: "ctime"},
			{Type: "umode_t", Name: "inode_mode"},
			{Type: "const char*", Name: "interpreter_pathname"},
			{Type: "dev_t", Name: "interpreter_dev"},
			{Type: "unsigned long", Name: "interpreter_inode"},
			{Type: "unsigned long", Name: "interpreter_ctime"},
			{Type: "const char**", Name: "argv"},
			{Type: "const char*", Name: "interp"},
			{Type: "umode_t", Name: "stdin_type"},
			{Type: "char*", Name: "stdin_path"},
			{Type: "int", Name: "invoked_from_kernel"},
			{Type: "const char*", Name: "prev_comm"},
			{Type: "const char**", Name: "env"},
		},
	},
	SchedProcessExit: {
		id:      SchedProcessExit,
		id32Bit: Sys32Undefined,
		name:    "sched_process_exit",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SchedProcessExit, required: true},
				{handle: probes.SchedProcessFree, required: true},
			},
		},
		sets: []string{"proc", "proc_life"},
		fields: []trace.ArgMeta{
			{Type: "long", Name: "exit_code"},
			// The field value represents that all threads exited at the event time.
			// Multiple exits of threads of the same process group at the same time could result that all threads exit
			// events would have 'true' value in this field altogether.
			{Type: "bool", Name: "process_group_exit"},
		},
	},
	SchedSwitch: {
		id:      SchedSwitch,
		id32Bit: Sys32Undefined,
		name:    "sched_switch",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SchedSwitch, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "cpu"},
			{Type: "int", Name: "prev_tid"},
			{Type: "const char*", Name: "prev_comm"},
			{Type: "int", Name: "next_tid"},
			{Type: "const char*", Name: "next_comm"},
		},
	},
	DoExit: {
		id:      DoExit,
		id32Bit: Sys32Undefined,
		name:    "do_exit",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{{handle: probes.DoExit, required: true}},
		},
		sets:   []string{"proc", "proc_life"},
		fields: []trace.ArgMeta{},
	},
	CapCapable: {
		id:      CapCapable,
		id32Bit: Sys32Undefined,
		name:    "cap_capable",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.CapCapable, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "cap"},
		},
	},
	VfsWrite: {
		id:      VfsWrite,
		id32Bit: Sys32Undefined,
		name:    "vfs_write",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.VfsWrite, required: true},
				{handle: probes.VfsWriteRet, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "size_t", Name: "count"},
			{Type: "off_t", Name: "pos"},
		},
	},
	VfsWritev: {
		id:      VfsWritev,
		id32Bit: Sys32Undefined,
		name:    "vfs_writev",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.VfsWriteV, required: true},
				{handle: probes.VfsWriteVRet, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "unsigned long", Name: "vlen"},
			{Type: "off_t", Name: "pos"},
		},
	},
	MemProtAlert: {
		id:      MemProtAlert,
		id32Bit: Sys32Undefined,
		name:    "mem_prot_alert",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecurityMmapAddr, required: true},
				{handle: probes.SecurityFileMProtect, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "u32", Name: "alert"},
			{Type: "void*", Name: "addr"},
			{Type: "size_t", Name: "len"},
			{Type: "int", Name: "prot"},
			{Type: "int", Name: "prev_prot"},
			{Type: "const char*", Name: "pathname"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "u64", Name: "ctime"},
		},
	},
	CommitCreds: {
		id:      CommitCreds,
		id32Bit: Sys32Undefined,
		name:    "commit_creds",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.CommitCreds, required: true},
			},
		},
		sets: []string{"default"},
		fields: []trace.ArgMeta{
			{Type: "slim_cred_t", Name: "old_cred"},
			{Type: "slim_cred_t", Name: "new_cred"},
		},
	},
	SwitchTaskNS: {
		id:      SwitchTaskNS,
		id32Bit: Sys32Undefined,
		name:    "switch_task_ns",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SwitchTaskNS, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "u32", Name: "new_mnt"},
			{Type: "u32", Name: "new_pid"},
			{Type: "u32", Name: "new_uts"},
			{Type: "u32", Name: "new_ipc"},
			{Type: "u32", Name: "new_net"},
			{Type: "u32", Name: "new_cgroup"},
		},
	},
	MagicWrite: {
		id:      MagicWrite,
		id32Bit: Sys32Undefined,
		name:    "magic_write",
		version: NewVersion(1, 0, 0),
		docPath: "security_alerts/magic_write.md",
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.VfsWriteMagic, required: true},
				{handle: probes.VfsWriteMagicRet, required: true},
				{handle: probes.VfsWriteVMagic, required: false},
				{handle: probes.VfsWriteVMagicRet, required: false},
				{handle: probes.KernelWriteMagic, required: false},
				{handle: probes.KernelWriteMagicRet, required: false},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "bytes", Name: "bytes"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
		},
	},
	CgroupAttachTask: {
		id:      CgroupAttachTask,
		id32Bit: Sys32Undefined,
		name:    "cgroup_attach_task",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.CgroupAttachTask, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "cgroup_path"},
			{Type: "const char*", Name: "comm"},
			{Type: "pid_t", Name: "pid"},
		},
	},
	CgroupMkdir: {
		id:      CgroupMkdir,
		id32Bit: Sys32Undefined,
		name:    "cgroup_mkdir",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.CgroupMkdir, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "u64", Name: "cgroup_id"},
			{Type: "const char*", Name: "cgroup_path"},
			{Type: "u32", Name: "hierarchy_id"},
		},
	},
	CgroupRmdir: {
		id:      CgroupRmdir,
		id32Bit: Sys32Undefined,
		name:    "cgroup_rmdir",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.CgroupRmdir, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "u64", Name: "cgroup_id"},
			{Type: "const char*", Name: "cgroup_path"},
			{Type: "u32", Name: "hierarchy_id"},
		},
	},
	SecurityBprmCheck: {
		id:      SecurityBprmCheck,
		id32Bit: Sys32Undefined,
		name:    "security_bprm_check",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecurityBPRMCheck, required: true},
				{handle: probes.SyscallEnter__Internal, required: true},
			},
			tailCalls: []TailCall{
				{
					"sys_enter_init_tail",
					"sys_enter_init",
					[]uint32{
						uint32(Execve), uint32(Execveat),
					},
				},
			},
		},
		sets: []string{"lsm_hooks", "proc", "proc_life"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "const char*const*", Name: "argv"},
			{Type: "const char*const*", Name: "envp"},
		},
	},
	SecurityFileOpen: {
		id:      SecurityFileOpen,
		id32Bit: Sys32Undefined,
		name:    "security_file_open",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecurityFileOpen, required: true},
			},
		},
		sets: []string{"lsm_hooks", "fs", "fs_file_ops"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "int", Name: "flags"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "unsigned long", Name: "ctime"},
			{Type: "const char*", Name: "syscall_pathname"},
		},
	},
	SecurityInodeUnlink: {
		id:      SecurityInodeUnlink,
		id32Bit: Sys32Undefined,
		name:    "security_inode_unlink",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecurityInodeUnlink, required: true},
			},
		},
		sets: []string{"default", "lsm_hooks", "fs", "fs_file_ops"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "dev_t", Name: "dev"},
			{Type: "u64", Name: "ctime"},
		},
	},
	SecuritySocketCreate: {
		id:      SecuritySocketCreate,
		id32Bit: Sys32Undefined,
		name:    "security_socket_create",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecuritySocketCreate, required: true},
			},
		},
		sets: []string{"lsm_hooks", "net", "net_sock"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "family"},
			{Type: "int", Name: "type"},
			{Type: "int", Name: "protocol"},
			{Type: "int", Name: "kern"},
		},
	},
	SecuritySocketListen: {
		id:      SecuritySocketListen,
		id32Bit: Sys32Undefined,
		name:    "security_socket_listen",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecuritySocketListen, required: true},
				{handle: probes.SyscallEnter__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Listen)}},
			},
		},
		sets: []string{"lsm_hooks", "net", "net_sock"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct sockaddr*", Name: "local_addr"},
			{Type: "int", Name: "backlog"},
		},
	},
	SecuritySocketConnect: {
		id:      SecuritySocketConnect,
		id32Bit: Sys32Undefined,
		name:    "security_socket_connect",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecuritySocketConnect, required: true},
			},
		},
		sets: []string{"default", "lsm_hooks", "net", "net_sock"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "int", Name: "type"},
			{Type: "struct sockaddr*", Name: "remote_addr"},
		},
	},
	NetTCPConnect: {
		id:      NetTCPConnect,
		id32Bit: Sys32Undefined,
		name:    "net_tcp_connect",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			ids: []ID{
				SecuritySocketConnect,
			},
		},
		sets: []string{"default", "flows"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "dst"},
			{Type: "int", Name: "dst_port"},
			{Type: "const char **", Name: "dst_dns"},
		},
	},
	SecuritySocketAccept: {
		id:      SecuritySocketAccept,
		id32Bit: Sys32Undefined,
		name:    "security_socket_accept",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecuritySocketAccept, required: true},
			},
		},
		sets: []string{"default", "lsm_hooks", "net", "net_sock"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct sockaddr*", Name: "local_addr"},
		},
	},
	// TODO: NetTCPAccept ? Problem: we don't have the remote address in current security_socket_accept
	SecuritySocketBind: {
		id:      SecuritySocketBind,
		id32Bit: Sys32Undefined,
		name:    "security_socket_bind",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecuritySocketBind, required: true},
			},
		},
		sets: []string{"default", "lsm_hooks", "net", "net_sock"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct sockaddr*", Name: "local_addr"},
		},
	},
	SecuritySocketSetsockopt: {
		id:      SecuritySocketSetsockopt,
		id32Bit: Sys32Undefined,
		name:    "security_socket_setsockopt",
		version: NewVersion(1, 0, 0),
		docPath: "lsm_hooks/security_socket_setsockopt.md",
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecuritySocketSetsockopt, required: true},
			},
		},
		sets: []string{"lsm_hooks", "net", "net_sock"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "int", Name: "level"},
			{Type: "int", Name: "optname"},
			{Type: "struct sockaddr*", Name: "local_addr"},
		},
	},
	SecuritySbMount: {
		id:      SecuritySbMount,
		id32Bit: Sys32Undefined,
		name:    "security_sb_mount",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecuritySbMount, required: true},
			},
		},
		sets: []string{"default", "lsm_hooks", "fs"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "dev_name"},
			{Type: "const char*", Name: "path"},
			{Type: "const char*", Name: "type"},
			{Type: "unsigned long", Name: "flags"},
		},
	},
	SecurityBPF: {
		id:      SecurityBPF,
		id32Bit: Sys32Undefined,
		name:    "security_bpf",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecurityBPF, required: true},
			},
		},
		sets: []string{"lsm_hooks"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "cmd"},
		},
	},
	SecurityBPFMap: {
		id:      SecurityBPFMap,
		id32Bit: Sys32Undefined,
		name:    "security_bpf_map",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecurityBPFMap, required: true},
			},
		},
		sets: []string{"lsm_hooks"},
		fields: []trace.ArgMeta{
			{Type: "unsigned int", Name: "map_id"},
			{Type: "const char*", Name: "map_name"},
		},
	},
	SecurityKernelReadFile: {
		id:      SecurityKernelReadFile,
		id32Bit: Sys32Undefined,
		name:    "security_kernel_read_file",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecurityKernelReadFile, required: true},
			},
		},
		sets: []string{"lsm_hooks"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "int", Name: "type"},
			{Type: "unsigned long", Name: "ctime"},
		},
	},
	SecurityPostReadFile: {
		id:      SecurityPostReadFile,
		id32Bit: Sys32Undefined,
		name:    "security_kernel_post_read_file",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecurityKernelPostReadFile, required: true},
			},
		},
		sets: []string{"lsm_hooks"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "long", Name: "size"},
			{Type: "int", Name: "type"},
		},
	},
	SecurityInodeMknod: {
		id:      SecurityInodeMknod,
		id32Bit: Sys32Undefined,
		name:    "security_inode_mknod",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecurityInodeMknod, required: true},
			},
		},
		sets: []string{"lsm_hooks"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "file_name"},
			{Type: "umode_t", Name: "mode"},
			{Type: "dev_t", Name: "dev"},
		},
	},
	SecurityInodeSymlinkEventId: {
		id:      SecurityInodeSymlinkEventId,
		id32Bit: Sys32Undefined,
		name:    "security_inode_symlink",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecurityInodeSymlink, required: true},
			},
		},
		sets: []string{"lsm_hooks", "fs", "fs_file_ops"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "linkpath"},
			{Type: "const char*", Name: "target"},
		},
	},
	SecurityMmapFile: {
		id:      SecurityMmapFile,
		id32Bit: Sys32Undefined,
		name:    "security_mmap_file",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecurityMmapFile, required: true},
			},
		},
		sets: []string{"lsm_hooks", "fs", "fs_file_ops", "proc", "proc_mem"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "int", Name: "flags"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "unsigned long", Name: "ctime"},
			{Type: "unsigned long", Name: "prot"},
			{Type: "unsigned long", Name: "mmap_flags"},
		},
	},
	DoMmap: {
		id:      DoMmap,
		id32Bit: Sys32Undefined,
		name:    "do_mmap",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.DoMmap, required: true},
				{handle: probes.DoMmapRet, required: true},
			},
		},
		sets: []string{"fs", "fs_file_ops", "proc", "proc_mem"},
		fields: []trace.ArgMeta{
			{Type: "void*", Name: "addr"},
			{Type: "const char*", Name: "pathname"},
			{Type: "unsigned int", Name: "flags"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "unsigned long", Name: "ctime"},
			{Type: "unsigned long", Name: "pgoff"},
			{Type: "unsigned long", Name: "len"},
			{Type: "unsigned long", Name: "prot"},
			{Type: "unsigned long", Name: "mmap_flags"},
		},
	},
	SecurityFileMprotect: {
		id:      SecurityFileMprotect,
		id32Bit: Sys32Undefined,
		name:    "security_file_mprotect",
		version: NewVersion(1, 0, 0),
		docPath: "lsm_hooks/security_file_mprotect.md",
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecurityFileMProtect, required: true},
				{handle: probes.SyscallEnter__Internal, required: true},
			},
			tailCalls: []TailCall{
				{"sys_enter_init_tail", "sys_enter_init", []uint32{uint32(Mprotect), uint32(PkeyMprotect)}},
			},
		},
		sets: []string{"lsm_hooks", "proc", "proc_mem", "fs", "fs_file_ops"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "int", Name: "prot"},
			{Type: "unsigned long", Name: "ctime"},
			{Type: "int", Name: "prev_prot"},
			{Type: "void*", Name: "addr"},
			{Type: "size_t", Name: "len"},
			{Type: "int", Name: "pkey"},
		},
	},
	InitNamespaces: {
		id:      InitNamespaces,
		id32Bit: Sys32Undefined,
		name:    "init_namespaces",
		version: NewVersion(1, 0, 0),
		sets:    []string{},
		dependencies: Dependencies{
			capabilities: Capabilities{
				base: []cap.Value{
					cap.SYS_PTRACE,
				},
			},
		},
		fields: []trace.ArgMeta{
			{Type: "u32", Name: "cgroup"},
			{Type: "u32", Name: "ipc"},
			{Type: "u32", Name: "mnt"},
			{Type: "u32", Name: "net"},
			{Type: "u32", Name: "pid"},
			{Type: "u32", Name: "pid_for_children"},
			{Type: "u32", Name: "time"},
			{Type: "u32", Name: "time_for_children"},
			{Type: "u32", Name: "user"},
			{Type: "u32", Name: "uts"},
		},
	},
	TraceeInfo: {
		id:           TraceeInfo,
		id32Bit:      Sys32Undefined,
		name:         "tracee_info",
		version:      NewVersion(1, 0, 0),
		sets:         []string{},
		dependencies: Dependencies{},
		fields: []trace.ArgMeta{
			{Type: "u64", Name: "boot_time"},
			{Type: "u64", Name: "start_time"},
			{Type: "const char*", Name: "version"},
		},
	},
	SocketDup: {
		id:      SocketDup,
		id32Bit: Sys32Undefined,
		name:    "socket_dup",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.Dup, required: true},
				{handle: probes.DupRet, required: true},
				{handle: probes.Dup2, required: false},
				{handle: probes.Dup2Ret, required: false},
				{handle: probes.Dup3, required: true},
				{handle: probes.Dup3Ret, required: true},
			},
			tailCalls: []TailCall{
				{"generic_sys_exit_tails", "sys_dup_exit_tail", []uint32{uint32(Dup), uint32(Dup2), uint32(Dup3)}},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "oldfd"},
			{Type: "int", Name: "newfd"},
			{Type: "struct sockaddr*", Name: "remote_addr"},
		},
	},
	HiddenInodes: {
		id:      HiddenInodes,
		id32Bit: Sys32Undefined,
		name:    "hidden_inodes",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.Filldir64, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "char*", Name: "hidden_process"},
		},
	},
	KernelWrite: {
		id:      KernelWrite,
		id32Bit: Sys32Undefined,
		name:    "__kernel_write",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.KernelWrite, required: true},
				{handle: probes.KernelWriteRet, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "size_t", Name: "count"},
			{Type: "off_t", Name: "pos"},
		},
	},
	DirtyPipeSplice: {
		id:      DirtyPipeSplice,
		id32Bit: Sys32Undefined,
		name:    "dirty_pipe_splice",
		version: NewVersion(1, 0, 0),
		sets:    []string{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.DoSplice, required: true},
				{handle: probes.DoSpliceRet, required: true},
			},
			kSymbols: []KSymbol{
				{symbol: "pipe_write", required: true},
			},
		},
		fields: []trace.ArgMeta{
			{Type: "unsigned long", Name: "inode_in"},
			{Type: "umode_t", Name: "in_file_type"},
			{Type: "const char*", Name: "in_file_path"},
			{Type: "loff_t", Name: "exposed_data_start_offset"},
			{Type: "size_t", Name: "exposed_data_len"},
			{Type: "unsigned long", Name: "inode_out"},
			{Type: "unsigned int", Name: "out_pipe_last_buffer_flags"},
		},
	},
	ContainerCreate: {
		id:      ContainerCreate,
		id32Bit: Sys32Undefined,
		name:    "container_create",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			ids: []ID{CgroupMkdir},
		},
		sets: []string{"default", "containers"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "runtime"},
			{Type: "const char*", Name: "container_id"},
			{Type: "unsigned long", Name: "ctime"},
			{Type: "const char*", Name: "container_image"},
			{Type: "const char*", Name: "container_image_digest"},
			{Type: "const char*", Name: "container_name"},
			{Type: "const char*", Name: "pod_name"},
			{Type: "const char*", Name: "pod_namespace"},
			{Type: "const char*", Name: "pod_uid"},
			{Type: "bool", Name: "pod_sandbox"},
		},
	},
	ContainerRemove: {
		id:      ContainerRemove,
		id32Bit: Sys32Undefined,
		name:    "container_remove",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			ids: []ID{CgroupRmdir},
		},
		sets: []string{"default", "containers"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "runtime"},
			{Type: "const char*", Name: "container_id"},
		},
	},
	ExistingContainer: {
		id:      ExistingContainer,
		id32Bit: Sys32Undefined,
		name:    "existing_container",
		version: NewVersion(1, 0, 0),
		sets:    []string{"containers"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "runtime"},
			{Type: "const char*", Name: "container_id"},
			{Type: "unsigned long", Name: "ctime"},
			{Type: "const char*", Name: "container_image"},
			{Type: "const char*", Name: "container_image_digest"},
			{Type: "const char*", Name: "container_name"},
			{Type: "const char*", Name: "pod_name"},
			{Type: "const char*", Name: "pod_namespace"},
			{Type: "const char*", Name: "pod_uid"},
			{Type: "bool", Name: "pod_sandbox"},
		},
	},
	ProcCreate: {
		id:      ProcCreate,
		id32Bit: Sys32Undefined,
		name:    "proc_create",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.ProcCreate, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "char*", Name: "name"},
			{Type: "void*", Name: "proc_ops_addr"},
		},
	},
	KprobeAttach: {
		id:      KprobeAttach,
		id32Bit: Sys32Undefined,
		name:    "kprobe_attach",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.RegisterKprobe, required: true},
				{handle: probes.RegisterKprobeRet, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "char*", Name: "symbol_name"},
			{Type: "void*", Name: "pre_handler_addr"},
			{Type: "void*", Name: "post_handler_addr"},
		},
	},
	CallUsermodeHelper: {
		id:      CallUsermodeHelper,
		id32Bit: Sys32Undefined,
		name:    "call_usermodehelper",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.CallUsermodeHelper, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "const char*const*", Name: "argv"},
			{Type: "const char*const*", Name: "envp"},
			{Type: "int", Name: "wait"},
		},
	},
	DebugfsCreateFile: {
		id:      DebugfsCreateFile,
		id32Bit: Sys32Undefined,
		name:    "debugfs_create_file",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.DebugfsCreateFile, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "file_name"},
			{Type: "const char*", Name: "path"},
			{Type: "umode_t", Name: "mode"},
			{Type: "void*", Name: "proc_ops_addr"},
		},
	},
	SyscallTableCheck: {
		id:       SyscallTableCheck,
		id32Bit:  Sys32Undefined,
		name:     "syscall_table_check",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallTableCheck, required: true},
			},
			kSymbols: []KSymbol{
				{symbol: "sys_call_table", required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "syscall_id"},
			{Type: "unsigned long", Name: "syscall_address"},
		},
	},
	HiddenKernelModule: {
		id:      HiddenKernelModule,
		id32Bit: Sys32Undefined,
		name:    "hidden_kernel_module",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			ids: []ID{
				HiddenKernelModuleSeeker,
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "address"},
			{Type: "const char*", Name: "name"},
			{Type: "const char*", Name: "srcversion"},
		},
	},
	HiddenKernelModuleSeeker: {
		id:       HiddenKernelModuleSeeker,
		id32Bit:  Sys32Undefined,
		name:     "hidden_kernel_module_seeker",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.HiddenKernelModuleSeeker, required: true},
				{handle: probes.HiddenKernelModuleVerifier, required: true},
				{handle: probes.ModuleLoad, required: true},
				{handle: probes.ModuleFree, required: true},
				{handle: probes.DoInitModule, required: true},
				{handle: probes.DoInitModuleRet, required: true},
			},
			kSymbols: []KSymbol{
				{symbol: "modules", required: true},
				{symbol: "module_kset", required: true},
				{symbol: "mod_tree", required: true},
			},
			tailCalls: []TailCall{
				{"prog_array", "lkm_seeker_proc_tail", []uint32{TailHiddenKernelModuleProc}},
				{"prog_array", "lkm_seeker_kset_tail", []uint32{TailHiddenKernelModuleKset}},
				{"prog_array", "lkm_seeker_mod_tree_tail", []uint32{TailHiddenKernelModuleModTree}},
				{"prog_array", "lkm_seeker_new_mod_only_tail", []uint32{TailHiddenKernelModuleNewModOnly}},
				{"prog_array", "lkm_seeker_modtree_loop", []uint32{TailHiddenKernelModuleModTreeLoop}},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "unsigned long", Name: "address"},
			{Type: "bytes", Name: "name"},
			{Type: "unsigned int", Name: "flags"},
			{Type: "bytes", Name: "srcversion"},
		},
	},
	HookedSyscall: {
		id:      HookedSyscall,
		id32Bit: Sys32Undefined,
		name:    "hooked_syscall",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			ids: []ID{
				SyscallTableCheck,
				DoInitModule,
			},
			capabilities: Capabilities{
				base: []cap.Value{
					cap.SYSLOG, // read /proc/kallsyms
				},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "syscall"},
			{Type: "const char*", Name: "address"},
			{Type: "const char*", Name: "function"},
			{Type: "const char*", Name: "owner"},
		},
	},
	DebugfsCreateDir: {
		id:      DebugfsCreateDir,
		id32Bit: Sys32Undefined,
		name:    "debugfs_create_dir",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.DebugfsCreateDir, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "name"},
			{Type: "const char*", Name: "path"},
		},
	},
	DeviceAdd: {
		id:      DeviceAdd,
		id32Bit: Sys32Undefined,
		name:    "device_add",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.DeviceAdd, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "name"},
			{Type: "const char*", Name: "parent_name"},
		},
	},
	RegisterChrdev: {
		id:      RegisterChrdev,
		id32Bit: Sys32Undefined,
		name:    "register_chrdev",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.RegisterChrdev, required: true},
				{handle: probes.RegisterChrdevRet, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "unsigned int", Name: "requested_major_number"},
			{Type: "unsigned int", Name: "granted_major_number"},
			{Type: "const char*", Name: "char_device_name"},
			{Type: "struct file_operations *", Name: "char_device_fops"},
		},
	},
	SharedObjectLoaded: {
		id:      SharedObjectLoaded,
		id32Bit: Sys32Undefined,
		name:    "shared_object_loaded",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecurityMmapFile, required: true},
			},
			capabilities: Capabilities{
				base: []cap.Value{
					cap.SYS_PTRACE, // loadSharedObjectDynamicSymbols()
				},
			},
		},
		sets: []string{"lsm_hooks", "fs", "fs_file_ops", "proc", "proc_mem"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "int", Name: "flags"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "unsigned long", Name: "ctime"},
		},
	},
	SymbolsLoaded: {
		id:      SymbolsLoaded,
		id32Bit: Sys32Undefined,
		name:    "symbols_loaded",
		version: NewVersion(1, 0, 0),
		docPath: "security_alerts/symbols_load.md",
		dependencies: Dependencies{
			ids: []ID{
				SharedObjectLoaded,
				SchedProcessExec, // Used to get mount namespace cache
			},
		},
		sets: []string{"derived", "fs", "security_alert"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "library_path"},
			{Type: "const char*const*", Name: "symbols"},
			{Type: "const char *", Name: "sha256"},
		},
	},
	SymbolsCollision: {
		id:      SymbolsCollision,
		id32Bit: Sys32Undefined,
		name:    "symbols_collision",
		version: NewVersion(1, 0, 0),
		docPath: "security_alerts/symbols_collision.md",
		dependencies: Dependencies{
			ids: []ID{
				SharedObjectLoaded,
				SchedProcessExec, // Used to get mount namespace cache
			},
		},
		sets: []string{"lsm_hooks", "fs", "fs_file_ops", "proc", "proc_mem"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "loaded_path"},
			{Type: "const char*", Name: "collision_path"},
			{Type: "const char*const*", Name: "symbols"},
		},
	},
	CaptureFileWrite: {
		id:       CaptureFileWrite,
		id32Bit:  Sys32Undefined,
		name:     "capture_file_write",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.VfsWrite, required: true},
				{handle: probes.VfsWriteRet, required: true},
				{handle: probes.VfsWriteV, required: false},
				{handle: probes.VfsWriteVRet, required: false},
				{handle: probes.KernelWrite, required: false},
				{handle: probes.KernelWriteRet, required: false},
				{handle: probes.SecurityInodeUnlink, required: false}, // Used for ELF filter
			},
			tailCalls: []TailCall{
				{"prog_array", "trace_ret_vfs_write_tail", []uint32{TailVfsWrite}},
				{"prog_array", "trace_ret_vfs_writev_tail", []uint32{TailVfsWritev}},
				{"prog_array", "trace_ret_kernel_write_tail", []uint32{TailKernelWrite}},
				{"prog_array", "send_bin", []uint32{TailSendBin}},
			},
			kSymbols: []KSymbol{
				{symbol: "pipe_write", required: true},
			},
		},
	},
	CaptureFileRead: {
		id:       CaptureFileRead,
		id32Bit:  Sys32Undefined,
		name:     "capture_file_read",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.VfsRead, required: true},
				{handle: probes.VfsReadRet, required: true},
				{handle: probes.VfsReadV, required: false},
				{handle: probes.VfsReadVRet, required: false},
				{handle: probes.SecurityInodeUnlink, required: false}, // Used for ELF filter
			},
			tailCalls: []TailCall{
				{"prog_array", "trace_ret_vfs_read_tail", []uint32{TailVfsRead}},
				{"prog_array", "trace_ret_vfs_readv_tail", []uint32{TailVfsReadv}},
				{"prog_array", "send_bin", []uint32{TailSendBin}},
			},
			kSymbols: []KSymbol{
				{symbol: "pipe_write", required: true},
			},
		},
	},
	CaptureExec: {
		id:       CaptureExec,
		id32Bit:  Sys32Undefined,
		name:     "capture_exec",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			ids: []ID{
				SchedProcessExec,
			},
			capabilities: Capabilities{
				base: []cap.Value{
					cap.SYS_PTRACE, // processSchedProcessExec() performance
				},
			},
		},
	},
	CaptureModule: {
		id:       CaptureModule,
		id32Bit:  Sys32Undefined,
		name:     "capture_module",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
				{handle: probes.SecurityKernelPostReadFile, required: true},
			},
			ids: []ID{
				SchedProcessExec,
			},
			tailCalls: []TailCall{
				{"sys_enter_tails", "syscall__init_module", []uint32{uint32(InitModule)}},
				{"prog_array_tp", "send_bin_tp", []uint32{TailSendBinTP}},
				{"prog_array", "send_bin", []uint32{TailSendBin}},
			},
		},
	},
	CaptureMem: {
		id:       CaptureMem,
		id32Bit:  Sys32Undefined,
		name:     "capture_mem",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			tailCalls: []TailCall{
				{"prog_array", "send_bin", []uint32{TailSendBin}},
			},
		},
	},
	CaptureBpf: {
		id:       CaptureBpf,
		id32Bit:  Sys32Undefined,
		name:     "capture_bpf",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecurityBPF, required: true},
			},
			tailCalls: []TailCall{
				{"prog_array", "send_bin", []uint32{TailSendBin}},
			},
		},
	},
	DoInitModule: {
		id:      DoInitModule,
		id32Bit: Sys32Undefined,
		name:    "do_init_module",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.DoInitModule, required: true},
				{handle: probes.DoInitModuleRet, required: true},
			},
			capabilities: Capabilities{
				base: []cap.Value{
					cap.SYSLOG, // read /proc/kallsyms
				},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "name"},
			{Type: "const char*", Name: "version"},
			{Type: "const char*", Name: "src_version"},
		},
	},
	ModuleLoad: {
		id:      ModuleLoad,
		id32Bit: Sys32Undefined,
		name:    "module_load",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.ModuleLoad, required: true},
			},
		},
		sets: []string{"default"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "name"},
			{Type: "const char*", Name: "version"},
			{Type: "const char*", Name: "src_version"},
			{Type: "const char*", Name: "pathname"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "u64", Name: "ctime"},
		},
	},
	ModuleFree: {
		id:      ModuleFree,
		id32Bit: Sys32Undefined,
		name:    "module_free",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.ModuleFree, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "name"},
			{Type: "const char*", Name: "version"},
			{Type: "const char*", Name: "src_version"},
		},
	},
	SocketAccept: {
		id:       SocketAccept,
		id32Bit:  Sys32Undefined,
		name:     "socket_accept",
		version:  NewVersion(1, 0, 0),
		internal: false,
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SyscallEnter__Internal, required: true},
				{handle: probes.SyscallExit__Internal, required: true},
			},
			ids: []ID{
				SecuritySocketAccept,
			},
			tailCalls: []TailCall{
				{"sys_exit_tails", "syscall__accept4", []uint32{uint32(Accept), uint32(Accept4)}},
				{"sys_exit_init_tail", "sys_exit_init", []uint32{uint32(Accept), uint32(Accept4)}},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct sockaddr*", Name: "local_addr"},
			{Type: "struct sockaddr*", Name: "remote_addr"}},
	},
	LoadElfPhdrs: {
		id:      LoadElfPhdrs,
		id32Bit: Sys32Undefined,
		name:    "load_elf_phdrs",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.LoadElfPhdrs, required: true},
			},
		},
		sets: []string{"proc"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
		},
	},
	HookedProcFops: {
		id:      HookedProcFops,
		id32Bit: Sys32Undefined,
		name:    "hooked_proc_fops",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecurityFilePermission, required: true},
			},
			kSymbols: []KSymbol{
				{symbol: "_stext", required: true},
				{symbol: "_etext", required: true},
			},
			ids: []ID{
				DoInitModule,
			},
			capabilities: Capabilities{
				base: []cap.Value{
					cap.SYSLOG, // read /proc/kallsyms
				},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "[]trace.HookedSymbolData", Name: "hooked_fops_pointers"},
		},
	},
	PrintNetSeqOps: {
		id:      PrintNetSeqOps,
		id32Bit: Sys32Undefined,
		name:    "print_net_seq_ops",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.PrintNetSeqOps, required: true},
			},
			kSymbols: []KSymbol{
				{symbol: "tcp4_seq_ops", required: true},
				{symbol: "tcp6_seq_ops", required: true},
				{symbol: "udp_seq_ops", required: true},
				{symbol: "udp6_seq_ops", required: true},
				{symbol: "raw_seq_ops", required: true},
				{symbol: "raw6_seq_ops", required: true},
			},
		},
		internal: true,
		sets:     []string{},
		fields: []trace.ArgMeta{
			{Type: "unsigned long[]", Name: "net_seq_ops"},
			{Type: "unsigned long", Name: trigger.ContextArgName},
		},
	},
	HookedSeqOps: {
		id:      HookedSeqOps,
		id32Bit: Sys32Undefined,
		name:    "hooked_seq_ops",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			kSymbols: []KSymbol{
				{symbol: "_stext", required: true},
				{symbol: "_etext", required: true},
			},
			ids: []ID{
				PrintNetSeqOps,
				DoInitModule,
			},
			capabilities: Capabilities{
				base: []cap.Value{
					cap.SYSLOG, // read /proc/kallsyms
				},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "map[string]trace.HookedSymbolData", Name: "hooked_seq_ops"},
		},
	},
	TaskRename: {
		id:      TaskRename,
		id32Bit: Sys32Undefined,
		name:    "task_rename",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.TaskRename, required: true},
			},
		},
		sets: []string{"proc"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "old_name"},
			{Type: "const char*", Name: "new_name"},
		},
	},
	SecurityInodeRename: {
		id:      SecurityInodeRename,
		id32Bit: Sys32Undefined,
		name:    "security_inode_rename",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecurityInodeRename, required: true},
			},
		},
		sets: []string{"default"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "old_path"},
			{Type: "const char*", Name: "new_path"},
		},
	},
	DoSigaction: {
		id:      DoSigaction,
		id32Bit: Sys32Undefined,
		name:    "do_sigaction",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.DoSigaction, required: true},
			},
		},
		sets: []string{"proc"},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "sig"},
			{Type: "bool", Name: "is_sa_initialized"},
			{Type: "unsigned long", Name: "sa_flags"},
			{Type: "unsigned long", Name: "sa_mask"},
			{Type: "u8", Name: "sa_handle_method"},
			{Type: "void*", Name: "sa_handler"},
			{Type: "bool", Name: "is_old_sa_initialized"},
			{Type: "unsigned long", Name: "old_sa_flags"},
			{Type: "unsigned long", Name: "old_sa_mask"},
			{Type: "u8", Name: "old_sa_handle_method"},
			{Type: "void*", Name: "old_sa_handler"},
		},
	},
	BpfAttach: {
		id:      BpfAttach,
		id32Bit: Sys32Undefined,
		name:    "bpf_attach",
		version: NewVersion(1, 0, 0),
		docPath: "docs/events/builtin/extra/bpf_attach.md",
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecurityFileIoctl, required: true},
				{handle: probes.SecurityBpfProg, required: true},
				{handle: probes.SecurityBPF, required: true},
				{handle: probes.TpProbeRegPrioMayExist, required: true},
				{handle: probes.CheckHelperCall, required: false},
				{handle: probes.CheckMapFuncCompatibility, required: false},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "prog_type"},
			{Type: "const char*", Name: "prog_name"},
			{Type: "u32", Name: "prog_id"},
			{Type: "unsigned long[]", Name: "prog_helpers"},
			{Type: "const char*", Name: "symbol_name"},
			{Type: "u64", Name: "symbol_addr"},
			{Type: "int", Name: "attach_type"},
		},
	},
	KallsymsLookupName: {
		id:      KallsymsLookupName,
		id32Bit: Sys32Undefined,
		name:    "kallsyms_lookup_name",
		version: NewVersion(1, 0, 0),
		docPath: "kprobes/kallsyms_lookup_name.md",
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.KallsymsLookupName, required: true},
				{handle: probes.KallsymsLookupNameRet, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "symbol_name"},
			{Type: "void*", Name: "symbol_address"},
		},
	},
	PrintMemDump: {
		id:      PrintMemDump,
		id32Bit: Sys32Undefined,
		name:    "print_mem_dump",
		version: NewVersion(1, 0, 0),
		sets:    []string{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.PrintMemDump, required: true},
			},
			ids: []ID{
				DoInitModule,
			},
			kSymbols: []KSymbol{
				// Special case for this event: Single symbol, common to all kernel versions. Placed
				// here so the ksymbols engine is always enabled, during tracee startup. The symbols
				// are resolved dynamically, during runtime depending on the arguments passed to
				// the event.
				{symbol: "_stext", required: true},
			},
			capabilities: Capabilities{
				base: []cap.Value{
					cap.SYSLOG, // read /proc/kallsyms
				},
			},
		},
		fields: []trace.ArgMeta{
			{Type: "bytes", Name: "bytes"},
			{Type: "void*", Name: "address"},
			{Type: "u64", Name: "length"},
			{Type: "u64", Name: "caller_context_id"},
			{Type: "char*", Name: "arch"},
			{Type: "char*", Name: "symbol_name"},
			{Type: "char*", Name: "symbol_owner"},
		},
	},
	VfsRead: {
		id:      VfsRead,
		id32Bit: Sys32Undefined,
		name:    "vfs_read",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.VfsRead, required: true},
				{handle: probes.VfsReadRet, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "size_t", Name: "count"},
			{Type: "off_t", Name: "pos"},
		},
	},
	VfsReadv: {
		id:      VfsReadv,
		id32Bit: Sys32Undefined,
		name:    "vfs_readv",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.VfsReadV, required: true},
				{handle: probes.VfsReadVRet, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "unsigned long", Name: "vlen"},
			{Type: "off_t", Name: "pos"},
		},
	},
	VfsUtimes: {
		id:      VfsUtimes,
		id32Bit: Sys32Undefined,
		name:    "vfs_utimes",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.VfsUtimes, required: false},    // this probe exits in kernels >= 5.9
				{handle: probes.UtimesCommon, required: false}, // this probe exits in kernels < 5.9
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "u64", Name: "atime"},
			{Type: "u64", Name: "mtime"},
		},
	},
	DoTruncate: {
		id:      DoTruncate,
		id32Bit: Sys32Undefined,
		name:    "do_truncate",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.DoTruncate, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "dev_t", Name: "dev"},
			{Type: "u64", Name: "length"},
		},
	},
	FileModification: {
		id:      FileModification,
		id32Bit: Sys32Undefined,
		name:    "file_modification",
		version: NewVersion(1, 0, 0),
		docPath: "kprobes/file_modification.md",
		sets:    []string{},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "file_path"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "unsigned long", Name: "old_ctime"},
			{Type: "unsigned long", Name: "new_ctime"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.FdInstall, required: true},
				{handle: probes.FilpClose, required: true},
				{handle: probes.FileUpdateTime, required: true},
				{handle: probes.FileUpdateTimeRet, required: true},
				{handle: probes.FileModified, required: false},    // not required because doesn't ...
				{handle: probes.FileModifiedRet, required: false}, // ... exist in kernels < 5.3
			},
		},
	},
	InotifyWatch: {
		id:      InotifyWatch,
		id32Bit: Sys32Undefined,
		name:    "inotify_watch",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.InotifyFindInode, required: true},
				{handle: probes.InotifyFindInodeRet, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "dev_t", Name: "dev"},
		},
	},
	SecurityBpfProg: {
		id:      SecurityBpfProg,
		id32Bit: Sys32Undefined,
		name:    "security_bpf_prog",
		version: NewVersion(1, 0, 0),
		docPath: "docs/events/builtin/extra/security_bpf_prog.md",
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecurityBpfProg, required: true},
				{handle: probes.BpfCheck, required: true},
				{handle: probes.CheckHelperCall, required: false},
				{handle: probes.CheckMapFuncCompatibility, required: false},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "type"},
			{Type: "const char*", Name: "name"},
			{Type: "unsigned long[]", Name: "helpers"},
			{Type: "u32", Name: "id"},
			{Type: "bool", Name: "load"},
		},
	},
	ExecuteFinished: {
		id:       ExecuteFinished,
		id32Bit:  Sys32Undefined,
		name:     "execute_finished",
		version:  NewVersion(1, 0, 0),
		sets:     []string{"proc"},
		internal: true,
		dependencies: Dependencies{
			probes: []Probe{
				// TODO: Change all of these probes to tracepoints (requires debugfs)
				{handle: probes.ExecuteFinishedX86, required: false},
				{handle: probes.ExecuteAtFinishedX86, required: false},
				{handle: probes.ExecuteFinishedCompatX86, required: false},
				{handle: probes.ExecuteAtFinishedCompatX86, required: false},
				{handle: probes.ExecuteFinishedARM, required: false},
				{handle: probes.ExecuteAtFinishedARM, required: false},
				{handle: probes.ExecuteFinishedCompatARM, required: false},
				{handle: probes.ExecuteAtFinishedCompatARM, required: false},
			},
		},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "int", Name: "flags"},
			{Type: "const char*", Name: "pathname"},
			{Type: "const char*", Name: "binary.path"},
			{Type: "dev_t", Name: "binary.device_id"},
			{Type: "unsigned long", Name: "binary.inode_number"},
			{Type: "unsigned long", Name: "binary.ctime"},
			{Type: "umode_t", Name: "binary.inode_mode"},
			{Type: "const char*", Name: "interpreter_path"},
			{Type: "umode_t", Name: "stdin_type"},
			{Type: "char*", Name: "stdin_path"},
			{Type: "int", Name: "kernel_invoked"},
			{Type: "const char*const*", Name: "argv"},
			{Type: "const char*const*", Name: "envp"},
		},
	},
	ProcessExecuteFailedInternal: {
		id:       ProcessExecuteFailedInternal,
		id32Bit:  Sys32Undefined,
		name:     "process_execute_failed_internal",
		version:  NewVersion(1, 0, 0),
		sets:     []string{"proc"},
		internal: true,
		dependencies: Dependencies{
			ids: []ID{ExecuteFinished},
			probes: []Probe{
				{handle: probes.ExecBinprm, required: false},
				{handle: probes.SecurityBprmCredsForExec, required: false}, // TODO: Change to required once fallbacks are supported
			},
			tailCalls: []TailCall{
				{"prog_array", "process_execute_failed_tail", []uint32{TailProcessExecuteFailed}},
			},
		},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "int", Name: "flags"},
			{Type: "const char*", Name: "pathname"},
			{Type: "const char*", Name: "binary.path"},
			{Type: "dev_t", Name: "binary.device_id"},
			{Type: "unsigned long", Name: "binary.inode_number"},
			{Type: "unsigned long", Name: "binary.ctime"},
			{Type: "umode_t", Name: "binary.inode_mode"},
			{Type: "const char*", Name: "interpreter_path"},
			{Type: "umode_t", Name: "stdin_type"},
			{Type: "char*", Name: "stdin_path"},
			{Type: "int", Name: "kernel_invoked"},
			{Type: "const char*const*", Name: "argv"},
			{Type: "const char*const*", Name: "envp"},
		},
	},
	ProcessExecuteFailed: {
		id:      ProcessExecuteFailed,
		id32Bit: Sys32Undefined,
		name:    "process_execute_failed",
		version: NewVersion(1, 0, 0),
		sets:    []string{"proc"},
		dependencies: Dependencies{
			ids: []ID{ProcessExecuteFailedInternal},
		},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "int", Name: "flags"},
			{Type: "const char*", Name: "pathname"},
			{Type: "const char*", Name: "binary.path"},
			{Type: "dev_t", Name: "binary.device_id"},
			{Type: "unsigned long", Name: "binary.inode_number"},
			{Type: "unsigned long", Name: "binary.ctime"},
			{Type: "umode_t", Name: "binary.inode_mode"},
			{Type: "const char*", Name: "interpreter_path"},
			{Type: "umode_t", Name: "stdin_type"},
			{Type: "char*", Name: "stdin_path"},
			{Type: "int", Name: "kernel_invoked"},
			{Type: "const char*const*", Name: "argv"},
			{Type: "const char*const*", Name: "envp"},
		},
	},
	FtraceHook: {
		id:      FtraceHook,
		id32Bit: Sys32Undefined,
		name:    "ftrace_hook",
		dependencies: Dependencies{
			ids: []ID{
				DoInitModule,
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "symbol"},
			{Type: "const char*", Name: "trampoline"},
			{Type: "const char*", Name: "callback"},
			{Type: "off_t", Name: "callback_offset"},
			{Type: "const char*", Name: "callback_owner"},
			{Type: "const char*", Name: "flags"},
			{Type: "unsigned long", Name: "count"},
		},
	},
	SecurityPathNotify: {
		id:      SecurityPathNotify,
		id32Bit: Sys32Undefined,
		name:    "security_path_notify",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecurityPathNotify, required: true},
			},
		},
		sets: []string{"lsm_hooks", "fs_monitor"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "dev_t", Name: "dev"},
			{Type: "u64", Name: "mask"},
			{Type: "unsigned int", Name: "obj_type"},
		},
	},
	SetFsPwd: {
		id:      SetFsPwd,
		id32Bit: Sys32Undefined,
		name:    "set_fs_pwd",
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SetFsPwd, required: true},
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "unresolved_path"},
			{Type: "const char*", Name: "resolved_path"},
		},
	},
	SecurityTaskSetrlimit: {
		id:      SecurityTaskSetrlimit,
		id32Bit: Sys32Undefined,
		name:    "security_task_setrlimit",
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecurityTaskSetrlimit, required: true},
			},
		},
		sets: []string{"lsm"},
		fields: []trace.ArgMeta{
			{Type: "u32", Name: "target_host_pid"},
			{Type: "int", Name: "resource"},
			{Type: "u64", Name: "new_rlim_cur"},
			{Type: "u64", Name: "new_rlim_max"},
		},
	},
	SecuritySettime64: {
		id:      SecuritySettime64,
		id32Bit: Sys32Undefined,
		name:    "security_settime64",
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecuritySettime64, required: true},
			},
		},
		sets: []string{"lsm"},
		fields: []trace.ArgMeta{
			{Type: "u64", Name: "tv_sec"},
			{Type: "u64", Name: "tv_nsec"},
			{Type: "int", Name: "tz_minuteswest"},
			{Type: "int", Name: "tz_dsttime"},
		},
	},
	ChmodCommon: {
		id:      ChmodCommon,
		id32Bit: Sys32Undefined,
		name:    "chmod_common",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{"default"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "umode_t", Name: "mode"},
		},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.ChmodCommon, required: true},
			},
		},
	},
	SuspiciousSyscallSource: {
		id:      SuspiciousSyscallSource,
		id32Bit: Sys32Undefined,
		name:    "suspicious_syscall_source",
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SchedProcessFork, required: false}, // for thread stack tracking
				{handle: probes.SchedProcessExec, required: false}, // for thread stack tracking
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "syscall"},
			{Type: "void*", Name: "ip"},
			{Type: "char*", Name: "vma_type"},
			{Type: "void*", Name: "vma_start"},
			{Type: "unsigned long", Name: "vma_size"},
			{Type: "unsigned long", Name: "vma_flags"},
		},
	},
	StackPivot: {
		id:      StackPivot,
		id32Bit: Sys32Undefined,
		name:    "stack_pivot",
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SchedProcessFork, required: false}, // for thread stack tracking
				{handle: probes.SchedProcessExec, required: false}, // for thread stack tracking
			},
		},
		sets: []string{},
		fields: []trace.ArgMeta{
			{Type: "int", Name: "syscall"},
			{Type: "void*", Name: "sp"},
			{Type: "char*", Name: "vma_type"},
			{Type: "void*", Name: "vma_start"},
			{Type: "unsigned long", Name: "vma_size"},
			{Type: "unsigned long", Name: "vma_flags"},
		},
	},
	//
	// Begin of Signal Events (Control Plane)
	//
	SignalCgroupMkdir: {
		id:       SignalCgroupMkdir,
		id32Bit:  Sys32Undefined,
		name:     "signal_cgroup_mkdir",
		internal: true,
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SignalCgroupMkdir, required: true},
			},
		},
		sets: []string{"signal"},
		fields: []trace.ArgMeta{
			{Type: "u64", Name: "cgroup_id"},
			{Type: "const char*", Name: "cgroup_path"},
			{Type: "u32", Name: "hierarchy_id"},
		},
	},
	SignalCgroupRmdir: {
		id:       SignalCgroupRmdir,
		id32Bit:  Sys32Undefined,
		name:     "signal_cgroup_rmdir",
		internal: true,
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SignalCgroupRmdir, required: true},
			},
		},
		sets: []string{"signal"},
		fields: []trace.ArgMeta{
			{Type: "u64", Name: "cgroup_id"},
			{Type: "const char*", Name: "cgroup_path"},
			{Type: "u32", Name: "hierarchy_id"},
		},
	},
	SignalSchedProcessFork: {
		id:       SignalSchedProcessFork,
		id32Bit:  Sys32Undefined,
		name:     "signal_sched_process_fork",
		internal: true,
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SignalSchedProcessFork, required: true},
			},
		},
		sets: []string{"signal"},
		fields: []trace.ArgMeta{
			{Type: "u64", Name: "timestamp"},
			// Real Parent
			{Type: "int", Name: "parent_tid"},
			{Type: "int", Name: "parent_ns_tid"},
			{Type: "int", Name: "parent_pid"},
			{Type: "int", Name: "parent_ns_pid"},
			{Type: "unsigned long", Name: "parent_start_time"},
			// Child
			{Type: "int", Name: "child_tid"},
			{Type: "int", Name: "child_ns_tid"},
			{Type: "int", Name: "child_pid"},
			{Type: "int", Name: "child_ns_pid"},
			{Type: "unsigned long", Name: "start_time"}, // child_start_time
			// Parent Process (Go up in hierarchy until parent is a process and not a lwp)
			{Type: "int", Name: "parent_process_tid"},
			{Type: "int", Name: "parent_process_ns_tid"},
			{Type: "int", Name: "parent_process_pid"},
			{Type: "int", Name: "parent_process_ns_pid"},
			{Type: "unsigned long", Name: "parent_process_start_time"},
			// Thread Group Leader
			{Type: "int", Name: "leader_tid"},
			{Type: "int", Name: "leader_ns_tid"},
			{Type: "int", Name: "leader_pid"},
			{Type: "int", Name: "leader_ns_pid"},
			{Type: "unsigned long", Name: "leader_start_time"},
		},
	},
	SignalSchedProcessExec: {
		id:       SignalSchedProcessExec,
		id32Bit:  Sys32Undefined,
		name:     "signal_sched_process_exec",
		internal: true,
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SignalSchedProcessExec, required: true},
				{handle: probes.SchedProcessFork, required: true}, // proc_info_map
				{handle: probes.SchedProcessFree, required: true}, // proc_info_map
				{handle: probes.LoadElfPhdrs, required: false},    // interpreter info
			},
		},
		sets: []string{"signal"},
		fields: []trace.ArgMeta{
			{Type: "u64", Name: "timestamp"},
			{Type: "u32", Name: "task_hash"},
			{Type: "u32", Name: "parent_hash"},
			{Type: "u32", Name: "leader_hash"},
			// command
			{Type: "const char*", Name: "cmdpath"},
			{Type: "const char*", Name: "pathname"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "unsigned long", Name: "ctime"},
			{Type: "umode_t", Name: "inode_mode"},
			// interpreter
			{Type: "const char*", Name: "interpreter_pathname"},
			{Type: "dev_t", Name: "interpreter_dev"},
			{Type: "unsigned long", Name: "interpreter_inode"},
			{Type: "unsigned long", Name: "interpreter_ctime"},
			// other
			{Type: "const char**", Name: "argv"},
			{Type: "const char*", Name: "interp"},
			{Type: "umode_t", Name: "stdin_type"},
			{Type: "char*", Name: "stdin_path"},
			{Type: "int", Name: "invoked_from_kernel"},
		},
	},
	SignalSchedProcessExit: {
		id:       SignalSchedProcessExit,
		id32Bit:  Sys32Undefined,
		name:     "signal_sched_process_exit",
		internal: true,
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SignalSchedProcessExit, required: true},
			},
		},
		sets: []string{"signal"},
		fields: []trace.ArgMeta{
			{Type: "u64", Name: "timestamp"},
			{Type: "u32", Name: "task_hash"},
			{Type: "u32", Name: "parent_hash"},
			{Type: "u32", Name: "leader_hash"},
			{Type: "long", Name: "exit_code"},
			{Type: "bool", Name: "process_group_exit"},
		},
	},
	//
	// Begin of Network Protocol Event Types
	//
	NetPacketBase: {
		id:       NetPacketBase,
		id32Bit:  Sys32Undefined,
		name:     "net_packet_base",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			capabilities: Capabilities{
				ebpf: []cap.Value{
					cap.NET_ADMIN, // needed for BPF_PROG_TYPE_CGROUP_SKB
				},
			},
			probes: []Probe{
				{handle: probes.CgroupSKBIngress, required: true},
				{handle: probes.CgroupSKBEgress, required: true},
				{handle: probes.SockAllocFile, required: true},
				{handle: probes.SockAllocFileRet, required: true},
				{handle: probes.CgroupBPFRunFilterSKB, required: true},
				{handle: probes.SecuritySocketRecvmsg, required: true},
				{handle: probes.SecuritySocketSendmsg, required: true},
				{handle: probes.SecuritySkClone, required: true},
			},
		},
		sets:   []string{"network_events"},
		fields: []trace.ArgMeta{},
	},
	NetPacketRaw: {
		id:      NetPacketRaw,
		id32Bit: Sys32Undefined,
		name:    "net_packet_raw",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			ids: []ID{
				NetPacketBase,
			},
		},
		sets: []string{"packets"},
		fields: []trace.ArgMeta{
			{Type: "bytes", Name: "data"},
		},
	},
	NetPacketIPBase: {
		id:       NetPacketIPBase,
		id32Bit:  Sys32Undefined,
		name:     "net_packet_ip_base",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			ids: []ID{
				NetPacketBase,
			},
		},
		sets: []string{"network_events"},
		fields: []trace.ArgMeta{
			{Type: "bytes", Name: "payload"},
		},
	},
	NetPacketIPv4: {
		id:      NetPacketIPv4,
		id32Bit: Sys32Undefined,
		name:    "net_packet_ipv4",
		version: NewVersion(1, 1, 0),
		dependencies: Dependencies{
			ids: []ID{
				NetPacketIPBase,
			},
		},
		sets: []string{"network_events"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "src"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "const char*", Name: "dst"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "trace.PacketMetadata", Name: "metadata"},
			{Type: "trace.ProtoIPv4", Name: "proto_ipv4"},
		},
	},
	NetPacketIPv6: {
		id:      NetPacketIPv6,
		id32Bit: Sys32Undefined,
		name:    "net_packet_ipv6",
		version: NewVersion(1, 1, 0),
		dependencies: Dependencies{
			ids: []ID{
				NetPacketIPBase,
			},
		},
		sets: []string{"network_events"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "src"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "const char*", Name: "dst"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "trace.PacketMetadata", Name: "metadata"},
			{Type: "trace.ProtoIPv6", Name: "proto_ipv6"},
		},
	},
	NetPacketTCPBase: {
		id:       NetPacketTCPBase,
		id32Bit:  Sys32Undefined,
		name:     "net_packet_tcp_base",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			ids: []ID{
				NetPacketBase,
			},
		},
		sets: []string{"network_events"},
		fields: []trace.ArgMeta{
			{Type: "bytes", Name: "payload"},
		},
	},
	NetPacketTCP: {
		id:      NetPacketTCP,
		id32Bit: Sys32Undefined,
		name:    "net_packet_tcp",
		version: NewVersion(1, 1, 0),
		dependencies: Dependencies{
			ids: []ID{
				NetPacketTCPBase,
			},
		},
		sets: []string{"network_events"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "src"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "const char*", Name: "dst"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "u16", Name: "src_port"},    // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "u16", Name: "dst_port"},    // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "trace.PacketMetadata", Name: "metadata"},
			{Type: "trace.ProtoTCP", Name: "proto_tcp"},
		},
	},
	NetPacketUDPBase: {
		id:       NetPacketUDPBase,
		id32Bit:  Sys32Undefined,
		name:     "net_packet_udp_base",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			ids: []ID{
				NetPacketBase,
			},
		},
		sets: []string{"network_events"},
		fields: []trace.ArgMeta{
			{Type: "bytes", Name: "payload"},
		},
	},
	NetPacketUDP: {
		id:      NetPacketUDP,
		id32Bit: Sys32Undefined,
		name:    "net_packet_udp",
		version: NewVersion(1, 1, 0),
		dependencies: Dependencies{
			ids: []ID{
				NetPacketUDPBase,
			},
		},
		sets: []string{"network_events"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "src"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "const char*", Name: "dst"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "u16", Name: "src_port"},    // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "u16", Name: "dst_port"},    // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "trace.PacketMetadata", Name: "metadata"},
			{Type: "trace.ProtoUDP", Name: "proto_udp"},
		},
	},
	NetPacketICMPBase: {
		id:      NetPacketICMPBase,
		id32Bit: Sys32Undefined,
		name:    "net_packet_icmp_base",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			ids: []ID{
				NetPacketBase,
			},
		},
		internal: true,
		sets:     []string{"network_events"},
		fields: []trace.ArgMeta{
			{Type: "bytes", Name: "payload"},
		},
	},
	NetPacketICMP: {
		id:      NetPacketICMP,
		id32Bit: Sys32Undefined,
		name:    "net_packet_icmp",
		version: NewVersion(1, 1, 0),
		dependencies: Dependencies{
			ids: []ID{
				NetPacketICMPBase,
			},
		},
		sets: []string{"default", "network_events"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "src"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "const char*", Name: "dst"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "trace.PacketMetadata", Name: "metadata"},
			{Type: "trace.ProtoICMP", Name: "proto_icmp"},
		},
	},
	NetPacketICMPv6Base: {
		id:       NetPacketICMPv6Base,
		id32Bit:  Sys32Undefined,
		name:     "net_packet_icmpv6_base",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			ids: []ID{
				NetPacketBase,
			},
		},
		sets: []string{"network_events"},
		fields: []trace.ArgMeta{
			{Type: "bytes", Name: "payload"},
		},
	},
	NetPacketICMPv6: {
		id:      NetPacketICMPv6,
		id32Bit: Sys32Undefined,
		name:    "net_packet_icmpv6",
		version: NewVersion(1, 1, 0),
		dependencies: Dependencies{
			ids: []ID{
				NetPacketICMPv6Base,
			},
		},
		sets: []string{"default", "network_events"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "src"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "const char*", Name: "dst"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "trace.PacketMetadata", Name: "metadata"},
			{Type: "trace.ProtoICMPv6", Name: "proto_icmpv6"},
		},
	},
	NetPacketDNSBase: {
		id:       NetPacketDNSBase,
		id32Bit:  Sys32Undefined,
		name:     "net_packet_dns_base",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			ids: []ID{
				NetPacketBase,
			},
		},
		sets: []string{"network_events"},
		fields: []trace.ArgMeta{
			{Type: "bytes", Name: "payload"},
		},
	},
	NetPacketDNS: {
		id:      NetPacketDNS,
		id32Bit: Sys32Undefined,
		name:    "net_packet_dns", // preferred event to write signatures
		version: NewVersion(1, 1, 0),
		dependencies: Dependencies{
			ids: []ID{
				NetPacketDNSBase,
			},
		},
		sets: []string{"network_events"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "src"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "const char*", Name: "dst"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "u16", Name: "src_port"},    // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "u16", Name: "dst_port"},    // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "trace.PacketMetadata", Name: "metadata"},
			{Type: "trace.ProtoDNS", Name: "proto_dns"},
		},
	},
	NetPacketDNSRequest: {
		id:      NetPacketDNSRequest,
		id32Bit: Sys32Undefined,
		name:    "net_packet_dns_request", // simple dns event compatible dns_request (deprecated)
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			ids: []ID{
				NetPacketDNSBase,
			},
		},
		sets: []string{"default", "network_events"},
		fields: []trace.ArgMeta{
			{Type: "trace.PktMeta", Name: "metadata"},
			{Type: "[]trace.DnsQueryData", Name: "dns_questions"},
		},
	},
	NetPacketDNSResponse: {
		id:      NetPacketDNSResponse,
		id32Bit: Sys32Undefined,
		name:    "net_packet_dns_response", // simple dns event compatible dns_response (deprecated)
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			ids: []ID{
				NetPacketDNSBase,
			},
		},
		sets: []string{"default", "network_events"},
		fields: []trace.ArgMeta{
			{Type: "trace.PktMeta", Name: "metadata"},
			{Type: "[]trace.DnsResponseData", Name: "dns_response"},
		},
	},
	NetPacketHTTPBase: {
		id:       NetPacketHTTPBase,
		id32Bit:  Sys32Undefined,
		name:     "net_packet_http_base",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			ids: []ID{
				NetPacketBase,
			},
		},
		sets: []string{"network_events"},
		fields: []trace.ArgMeta{
			{Type: "bytes", Name: "payload"},
		},
	},
	NetPacketHTTP: {
		id:      NetPacketHTTP,
		id32Bit: Sys32Undefined,
		name:    "net_packet_http", // preferred event to write signatures
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			ids: []ID{
				NetPacketHTTPBase,
			},
		},
		sets: []string{"network_events"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "src"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "const char*", Name: "dst"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "u16", Name: "src_port"},    // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "u16", Name: "dst_port"},    // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "trace.PacketMetadata", Name: "metadata"},
			{Type: "trace.ProtoHTTP", Name: "proto_http"},
		},
	},
	NetPacketHTTPRequest: {
		id:      NetPacketHTTPRequest,
		id32Bit: Sys32Undefined,
		name:    "net_packet_http_request",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			ids: []ID{
				NetPacketHTTPBase,
			},
		},
		sets: []string{"default", "network_events"},
		fields: []trace.ArgMeta{
			{Type: "trace.PktMeta", Name: "metadata"},
			{Type: "trace.ProtoHTTPRequest", Name: "http_request"},
		},
	},
	NetPacketHTTPResponse: {
		id:      NetPacketHTTPResponse,
		id32Bit: Sys32Undefined,
		name:    "net_packet_http_response",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			ids: []ID{
				NetPacketHTTPBase,
			},
		},
		sets: []string{"default", "network_events"},
		fields: []trace.ArgMeta{
			{Type: "trace.PktMeta", Name: "metadata"},
			{Type: "trace.ProtoHTTPResponse", Name: "http_response"},
		},
	},
	NetPacketCapture: {
		id:       NetPacketCapture, // Packets with full payload (sent in a dedicated perfbuffer)
		id32Bit:  Sys32Undefined,
		name:     "net_packet_capture",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			ids: []ID{
				NetPacketBase,
			},
		},
		fields: []trace.ArgMeta{
			{Type: "bytes", Name: "payload"},
		},
	},
	CaptureNetPacket: {
		id:       CaptureNetPacket, // Pseudo Event: used to capture packets
		id32Bit:  Sys32Undefined,
		name:     "capture_net_packet",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			ids: []ID{
				NetPacketCapture,
			},
		},
	},
	NetPacketFlow: {
		id:       NetPacketFlow,
		id32Bit:  Sys32Undefined,
		name:     "net_packet_flow_base",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			ids: []ID{
				NetPacketBase,
			},
		},
		sets: []string{"network_events"},
		fields: []trace.ArgMeta{
			{Type: "bytes", Name: "payload"},
		},
	},
	NetFlowTCPBegin: {
		id:      NetFlowTCPBegin,
		id32Bit: Sys32Undefined,
		name:    "net_flow_tcp_begin",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			ids: []ID{
				NetPacketFlow,
			},
		},
		sets: []string{"network_events", "flows"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "conn_direction"},
			{Type: "const char*", Name: "src"},
			{Type: "const char*", Name: "dst"},
			{Type: "u16", Name: "src_port"},
			{Type: "u16", Name: "dst_port"},
			{Type: "const char **", Name: "src_dns"},
			{Type: "const char **", Name: "dst_dns"},
		},
	},
	NetFlowTCPEnd: {
		id:      NetFlowTCPEnd,
		id32Bit: Sys32Undefined,
		name:    "net_flow_tcp_end",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			ids: []ID{
				NetPacketFlow,
			},
		},
		sets: []string{"network_events", "flows"},
		fields: []trace.ArgMeta{
			{Type: "const char*", Name: "conn_direction"},
			{Type: "const char*", Name: "src"},
			{Type: "const char*", Name: "dst"},
			{Type: "u16", Name: "src_port"},
			{Type: "u16", Name: "dst_port"},
			{Type: "const char **", Name: "src_dns"},
			{Type: "const char **", Name: "dst_dns"},
		},
	},

	// Test Events
	ExecTest: {
		id:      ExecTest,
		id32Bit: Sys32Undefined,
		name:    "exec_test",
		version: NewVersion(1, 0, 0),
		syscall: false,
		sets:    []string{"tests", "dependencies"},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.ExecTest, required: true},
				{handle: probes.EmptyKprobe, required: true},
			},
		},
		fields: []trace.ArgMeta{},
	},
	MissingKsymbol: {
		id:      MissingKsymbol,
		id32Bit: Sys32Undefined,
		name:    "missing_ksymbol",
		version: NewVersion(1, 0, 0),
		syscall: false,
		sets:    []string{"tests", "dependencies"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			kSymbols: []KSymbol{
				{symbol: "non_existing_symbol", required: true},
			},
			probes: []Probe{
				{handle: probes.ExecTest, required: true},
			},
			ids: []ID{ExecTest},
		},
	},
	FailedAttach: {
		id:      FailedAttach,
		id32Bit: Sys32Undefined,
		name:    "failed_attach",
		version: NewVersion(1, 0, 0),
		syscall: false,
		sets:    []string{"tests", "dependencies"},
		fields:  []trace.ArgMeta{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.TestUnavailableHook, required: true},
				{handle: probes.ExecTest, required: true},
			},
			ids: []ID{ExecTest},
		},
	},
}
