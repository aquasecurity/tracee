package events

import (
	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
	"github.com/aquasecurity/tracee/pkg/events/data"
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
	ZeroedInodes
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
	OpenFileNS
	OpenFileMount
	SecuritySbUmount
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
	SignalHeartbeat
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "buf"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "count"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "buf"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "count"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "mode"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "statbuf"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "statbuf"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "statbuf"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "fds"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "nfds"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "timeout"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "offset"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "whence"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "addr"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "length"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "prot"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "off"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "addr"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "len"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "prot"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "addr"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "length"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "addr"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "signum"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "act"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "oldact"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "sigsetsize"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "how"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "set"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "oldset"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "sigsetsize"}},
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
		fields:  []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "request"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "arg"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "buf"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "count"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "offset"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "buf"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "count"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "offset"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "iov"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "iovcnt"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "iov"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "iovcnt"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "mode"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_ARR_2_T, ArgMeta: trace.ArgMeta{Type: "[2]int32", Name: "pipefd"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "nfds"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "readfds"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "writefds"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "exceptfds"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "timeout"}},
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
		fields:  []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "old_address"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "old_size"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "new_size"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "new_address"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "addr"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "length"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "addr"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "length"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "vec"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "addr"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "length"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "advice"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "key"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "size"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "shmflg"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "shmid"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "shmaddr"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "shmflg"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "shmid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "cmd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "buf"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "oldfd"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "oldfd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "newfd"}},
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
		fields:  []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.TIMESPEC_T, ArgMeta: trace.ArgMeta{Type: "float64", Name: "req"}},
			{DecodeAs: data.TIMESPEC_T, ArgMeta: trace.ArgMeta{Type: "float64", Name: "rem"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "which"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "curr_value"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "seconds"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "which"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "new_value"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "old_value"}},
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
		fields:  []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "out_fd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "in_fd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "offset"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "count"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "domain"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "type"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "protocol"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sockfd"}},
			{DecodeAs: data.SOCK_ADDR_T, ArgMeta: trace.ArgMeta{Type: "SockAddr", Name: "addr"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "addrlen"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sockfd"}},
			{DecodeAs: data.SOCK_ADDR_T, ArgMeta: trace.ArgMeta{Type: "SockAddr", Name: "addr"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "addrlen"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sockfd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "buf"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "len"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
			{DecodeAs: data.SOCK_ADDR_T, ArgMeta: trace.ArgMeta{Type: "SockAddr", Name: "dest_addr"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "addrlen"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sockfd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "buf"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "len"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
			{DecodeAs: data.SOCK_ADDR_T, ArgMeta: trace.ArgMeta{Type: "SockAddr", Name: "src_addr"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "addrlen"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sockfd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "msg"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sockfd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "msg"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sockfd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "how"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sockfd"}},
			{DecodeAs: data.SOCK_ADDR_T, ArgMeta: trace.ArgMeta{Type: "SockAddr", Name: "addr"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "addrlen"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sockfd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "backlog"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sockfd"}},
			{DecodeAs: data.SOCK_ADDR_T, ArgMeta: trace.ArgMeta{Type: "SockAddr", Name: "addr"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "addrlen"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sockfd"}},
			{DecodeAs: data.SOCK_ADDR_T, ArgMeta: trace.ArgMeta{Type: "SockAddr", Name: "addr"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "addrlen"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "domain"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "type"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "protocol"}},
			{DecodeAs: data.INT_ARR_2_T, ArgMeta: trace.ArgMeta{Type: "[2]int32", Name: "sv"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sockfd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "level"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "optname"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "optval"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "optlen"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sockfd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "level"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "optname"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "optval"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "optlen"}},
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
		fields: []DataField{
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "flags"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "stack"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "parent_tid"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "child_tid"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "tls"}},
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
		fields:  []DataField{},
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
		fields:  []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.STR_ARR_T, ArgMeta: trace.ArgMeta{Type: "[]string", Name: "argv"}},
			{DecodeAs: data.STR_ARR_T, ArgMeta: trace.ArgMeta{Type: "[]string", Name: "envp"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "status"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "wstatus"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "options"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "rusage"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sig"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "buf"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "key"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "nsems"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "semflg"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "semid"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "sops"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "nsops"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "semid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "semnum"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "cmd"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "arg"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "shmaddr"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "key"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "msgflg"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "msqid"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "msgp"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "msgsz"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "msgflg"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "msqid"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "msgp"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "msgsz"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "msgtyp"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "msgflg"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "msqid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "cmd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "buf"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "cmd"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "arg"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "operation"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "path"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "length"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "length"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "dirp"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "count"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "buf"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "size"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "path"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "oldpath"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "newpath"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "mode"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
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
		sets:    []string{"default", "syscalls", "fs", "fs_file_ops"},
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "mode"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "oldpath"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "newpath"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "target"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "linkpath"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "buf"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "bufsiz"}},
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
		sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "mode"}},
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
		sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "mode"}},
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
		sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "owner"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "group"}},
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
		sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "owner"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "group"}},
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
		sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "owner"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "group"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "mask"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "tv"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "tz"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "resource"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "rlim"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "who"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "usage"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "info"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "buf"}},
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
		fields: []DataField{
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "request"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "addr"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "data"}},
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
		fields:  []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "type"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "bufp"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "len"}},
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
		fields:  []DataField{},
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
		sets:    []string{"default", "syscalls", "proc", "proc_ids"},
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "uid"}},
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
		sets:    []string{"default", "syscalls", "proc", "proc_ids"},
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "gid"}},
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
		fields:  []DataField{},
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
		fields:  []DataField{},
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
		sets:    []string{"default", "syscalls", "proc", "proc_ids"},
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pgid"}},
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
		fields:  []DataField{},
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
		fields:  []DataField{},
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
		fields:  []DataField{},
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
		sets:    []string{"default", "syscalls", "proc", "proc_ids"},
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "ruid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "euid"}},
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
		sets:    []string{"default", "syscalls", "proc", "proc_ids"},
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "rgid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "egid"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "size"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "list"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "size"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "list"}},
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
		sets:    []string{"default", "syscalls", "proc", "proc_ids"},
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "ruid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "euid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "suid"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "ruid"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "euid"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "suid"}},
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
		sets:    []string{"default", "syscalls", "proc", "proc_ids"},
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "rgid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "egid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sgid"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "rgid"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "egid"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "sgid"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
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
		sets:    []string{"default", "syscalls", "proc", "proc_ids"},
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fsuid"}},
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
		sets:    []string{"default", "syscalls", "proc", "proc_ids"},
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fsgid"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "hdrp"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "datap"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "hdrp"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "datap"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "set"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "sigsetsize"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "set"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "info"}},
			{DecodeAs: data.TIMESPEC_T, ArgMeta: trace.ArgMeta{Type: "float64", Name: "timeout"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "sigsetsize"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "tgid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sig"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "info"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "mask"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "sigsetsize"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "ss"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "old_ss"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "filename"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "times"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "mode"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "library"}},
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
		fields: []DataField{
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "persona"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "ubuf"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "path"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "buf"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "buf"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "option"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "which"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "who"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "which"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "who"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "prio"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "param"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "param"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "policy"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "param"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "policy"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "policy"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
			{DecodeAs: data.TIMESPEC_T, ArgMeta: trace.ArgMeta{Type: "float64", Name: "tp"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "addr"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "len"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "addr"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "len"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields:  []DataField{},
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
		fields:  []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "func"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "ptr"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "bytecount"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "new_root"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "put_old"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "args"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "option"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "arg2"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "arg3"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "arg4"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "arg5"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "option"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "addr"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "buf"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "resource"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "rlim"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "path"}},
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
		fields:  []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "filename"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "tv"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "tz"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "source"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "target"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "filesystemtype"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "mountflags"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "data"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "target"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "path"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "swapflags"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "path"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "magic"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "magic2"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "cmd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "arg"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "name"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "len"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "name"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "len"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "level"}},
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
		fields: []DataField{
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "from"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "num"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "turn_on"}},
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
		fields:  []DataField{},
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
		sets:    []string{"default", "syscalls", "system", "system_module"},
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "module_image"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "len"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "param_values"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "name"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields:  []DataField{},
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
		fields:  []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "cmd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "special"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "id"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "addr"}},
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
		fields:  []DataField{},
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
		fields:  []DataField{},
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
		fields:  []DataField{},
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
		fields:  []DataField{},
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
		fields:  []DataField{},
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
		fields:  []DataField{},
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
		fields:  []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "offset"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "count"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "path"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "name"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "value"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "size"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "path"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "name"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "value"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "size"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "name"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "value"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "size"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "path"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "name"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "value"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "size"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "path"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "name"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "value"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "size"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "name"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "value"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "size"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "path"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "list"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "size"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "path"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "list"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "size"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "list"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "size"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "path"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "name"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "path"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "name"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "name"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "tid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sig"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "tloc"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "uaddr"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "futex_op"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "val"}},
			{DecodeAs: data.TIMESPEC_T, ArgMeta: trace.ArgMeta{Type: "float64", Name: "timeout"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "uaddr2"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "val3"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "cpusetsize"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "mask"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "cpusetsize"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "mask"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "u_info"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "nr_events"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "ctx_idp"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "ctx_id"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "ctx_id"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "min_nr"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "nr"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "events"}},
			{DecodeAs: data.TIMESPEC_T, ArgMeta: trace.ArgMeta{Type: "float64", Name: "timeout"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "ctx_id"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "nr"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "iocbpp"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "ctx_id"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "iocb"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "result"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "u_info"}},
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
		fields: []DataField{
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "cookie"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "buffer"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "len"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "size"}},
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
		fields:  []DataField{},
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
		fields:  []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "addr"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "size"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "prot"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "pgoff"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "fd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "dirp"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "count"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "tidptr"}},
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
		fields:  []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "semid"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "sops"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "nsops"}},
			{DecodeAs: data.TIMESPEC_T, ArgMeta: trace.ArgMeta{Type: "float64", Name: "timeout"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "offset"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "len"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "advice"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "clockid"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "sevp"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "timer_id"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "timer_id"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "new_value"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "old_value"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "timer_id"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "curr_value"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "timer_id"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "timer_id"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "clockid"}},
			{DecodeAs: data.TIMESPEC_T, ArgMeta: trace.ArgMeta{Type: "float64", Name: "tp"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "clockid"}},
			{DecodeAs: data.TIMESPEC_T, ArgMeta: trace.ArgMeta{Type: "float64", Name: "tp"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "clockid"}},
			{DecodeAs: data.TIMESPEC_T, ArgMeta: trace.ArgMeta{Type: "float64", Name: "res"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "clockid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
			{DecodeAs: data.TIMESPEC_T, ArgMeta: trace.ArgMeta{Type: "float64", Name: "request"}},
			{DecodeAs: data.TIMESPEC_T, ArgMeta: trace.ArgMeta{Type: "float64", Name: "remain"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "status"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "epfd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "events"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "maxevents"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "timeout"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "epfd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "op"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "event"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "tgid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "tid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sig"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "filename"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "times"}},
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
		fields:  []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "addr"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "len"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "mode"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "nodemask"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "maxnode"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "mode"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "nodemask"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "maxnode"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "mode"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "nodemask"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "maxnode"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "addr"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "name"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "oflag"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "mode"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "attr"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "name"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "mqdes"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "msg_ptr"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "msg_len"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "msg_prio"}},
			{DecodeAs: data.TIMESPEC_T, ArgMeta: trace.ArgMeta{Type: "float64", Name: "abs_timeout"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "mqdes"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "msg_ptr"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "msg_len"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "msg_prio"}},
			{DecodeAs: data.TIMESPEC_T, ArgMeta: trace.ArgMeta{Type: "float64", Name: "abs_timeout"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "mqdes"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "sevp"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "mqdes"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "newattr"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "oldattr"}},
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
		fields: []DataField{
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "entry"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "nr_segments"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "segments"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "idtype"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "id"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "infop"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "options"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "rusage"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "type"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "description"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "payload"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "plen"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "keyring"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "type"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "description"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "callout_info"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "dest_keyring"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "operation"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "arg2"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "arg3"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "arg4"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "arg5"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "which"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "who"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "ioprio"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "which"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "who"}},
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
		fields:  []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "mask"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "wd"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "maxnode"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "old_nodes"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "new_nodes"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "dirfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "mode"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "dirfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "mode"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "dirfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "mode"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
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
		sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "dirfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "owner"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "group"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "dirfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "times"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "dirfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "statbuf"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "dirfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "olddirfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "oldpath"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "newdirfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "newpath"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "olddirfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "oldpath"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "newdirfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "newpath"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "target"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "newdirfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "linkpath"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "dirfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "buf"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "bufsiz"}},
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
		sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "dirfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "mode"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "dirfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "mode"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "nfds"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "readfds"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "writefds"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "exceptfds"}},
			{DecodeAs: data.TIMESPEC_T, ArgMeta: trace.ArgMeta{Type: "float64", Name: "timeout"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "sigmask"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "fds"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "nfds"}},
			{DecodeAs: data.TIMESPEC_T, ArgMeta: trace.ArgMeta{Type: "float64", Name: "tmo_p"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "sigmask"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "sigsetsize"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "head"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "len"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "head_ptr"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "len_ptr"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd_in"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "off_in"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd_out"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "off_out"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "len"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd_in"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd_out"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "len"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "offset"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "nbytes"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "iov"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "nr_segs"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "count"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "pages"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "nodes"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "status"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "dirfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.TIMESPEC_T, ArgMeta: trace.ArgMeta{Type: "float64", Name: "times"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "epfd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "events"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "maxevents"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "timeout"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "sigmask"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "sigsetsize"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "mask"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "clockid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "initval"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "mode"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "offset"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "len"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "new_value"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "old_value"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "curr_value"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sockfd"}},
			{DecodeAs: data.SOCK_ADDR_T, ArgMeta: trace.ArgMeta{Type: "SockAddr", Name: "addr"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "addrlen"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "mask"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "sizemask"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "initval"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "oldfd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "newfd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_ARR_2_T, ArgMeta: trace.ArgMeta{Type: "[2]int32", Name: "pipefd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "iov"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "iovcnt"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "pos_l"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "pos_h"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "iov"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "iovcnt"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "pos_l"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "pos_h"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "tgid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "tid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sig"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "info"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "attr"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "cpu"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "group_fd"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sockfd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "msgvec"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "vlen"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
			{DecodeAs: data.TIMESPEC_T, ArgMeta: trace.ArgMeta{Type: "float64", Name: "timeout"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "event_f_flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fanotify_fd"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "mask"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "dirfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "resource"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "new_limit"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "old_limit"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "dirfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "handle"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "mount_id"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "mount_fd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "handle"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "clk_id"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "buf"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sockfd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "msgvec"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "vlen"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		sets:    []string{"default", "syscalls", "proc"},
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "nstype"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "cpu"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "node"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "tcache"}},
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
		sets:    []string{"default", "syscalls", "proc"},
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "local_iov"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "liovcnt"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "remote_iov"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "riovcnt"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "local_iov"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "liovcnt"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "remote_iov"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "riovcnt"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid1"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid2"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "type"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "idx1"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "idx2"}},
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
		sets:    []string{"default", "syscalls", "system", "system_module"},
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "param_values"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "attr"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "attr"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "size"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "olddirfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "oldpath"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "newdirfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "newpath"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "operation"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "args"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "buf"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "buflen"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
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
		sets:    []string{"default", "syscalls", "fs", "fs_file_ops"},
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "name"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "kernel_fd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "initrd_fd"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "cmdline_len"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "cmdline"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "cmd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "attr"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "size"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "dirfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.STR_ARR_T, ArgMeta: trace.ArgMeta{Type: "[]string", Name: "argv"}},
			{DecodeAs: data.STR_ARR_T, ArgMeta: trace.ArgMeta{Type: "[]string", Name: "envp"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "cmd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "addr"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "len"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd_in"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "off_in"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd_out"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "off_out"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "len"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "iov"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "iovcnt"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "pos_l"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "pos_h"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "iov"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "iovcnt"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "pos_l"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "pos_h"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "addr"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "len"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "prot"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pkey"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "access_rights"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pkey"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "dirfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "mask"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "statxbuf"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "ctx_id"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "min_nr"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "nr"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "events"}},
			{DecodeAs: data.TIMESPEC_T, ArgMeta: trace.ArgMeta{Type: "float64", Name: "timeout"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "usig"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "rseq"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "rseq_len"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "sig"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pidfd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sig"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "info"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "entries"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "p"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "fd"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "to_submit"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "min_complete"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "sig"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "fd"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "opcode"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "arg"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "nr_args"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "dfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "filename"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
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
		sets:    []string{"default", "syscalls", "fs"},
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "from_dfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "from_path"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "to_dfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "to_path"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "fsname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "fs_fd"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "cmd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "key"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "value"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "aux"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fsfd"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "ms_flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "dirfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "cl_args"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "size"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "first"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "last"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "dirfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "how"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "size"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pidfd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "targetfd"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "path"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "mode"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flag"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pidfd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "addr"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "length"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "advice"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "events"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "maxevents"}},
			{DecodeAs: data.TIMESPEC_T, ArgMeta: trace.ArgMeta{Type: "float64", Name: "timeout"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "sigset"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "dfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "path"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "uattr"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "usize"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "fd"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "cmd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "id"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "addr"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "attr"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "size"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "ruleset_fd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "rule_type"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "rule_attr"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "ruleset_fd"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pidfd"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "status"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "options"}},
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
		fields:  []DataField{},
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
		fields:  []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "filename"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "statbuf"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "target"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "t"}},
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
		fields:  []DataField{},
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
		fields:  []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "inc"}},
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
		fields:  []DataField{},
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
		fields:  []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "signum"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "handler"}},
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
		fields:  []DataField{},
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
		fields:  []DataField{},
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
		fields:  []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "name"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sig"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "act"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "oact"}},
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
		fields:  []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "newmask"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "mask"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "set"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "statbuf"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "fd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "dirp"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "count"}},
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
		fields:  []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "call"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "args"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "buf"}},
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
		fields:  []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "info"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "call"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "first"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "second"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "third"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "ptr"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "fifth"}},
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
		fields:  []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "how"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "set"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "oldset"}},
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
		fields:  []DataField{},
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
		fields:  []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "fd"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "offset_high"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "offset_low"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "result"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "whence"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "nfds"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "readfds"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "writefds"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "exceptfds"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "timeout"}},
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
		fields: []DataField{
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "fn"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "v86"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "resource"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "rlim"}},
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
		fields: []DataField{
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "addr"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "length"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "prot"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "flags"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "fd"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "pgoffset"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "path"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "length"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "length"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "statbuf"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "statbuf"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "statbuf"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "owner"}},
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "group"}},
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
		fields:  []DataField{},
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
		fields:  []DataField{},
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
		fields:  []DataField{},
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
		fields:  []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "ruid"}},
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "euid"}},
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
		fields: []DataField{
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "rgid"}},
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "egid"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "size"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "list"}},
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
		fields: []DataField{
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "size"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "list"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "fd"}},
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "user"}},
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "group"}},
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
		fields: []DataField{
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "ruid"}},
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "euid"}},
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "suid"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "ruid"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "euid"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "suid"}},
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
		fields: []DataField{
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "rgid"}},
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "euid"}},
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "suid"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "rgid"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "egid"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "sgid"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "owner"}},
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "group"}},
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
		fields: []DataField{
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "uid"}},
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
		fields: []DataField{
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "gid"}},
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
		fields: []DataField{
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "fsuid"}},
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
		fields: []DataField{
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "fsgid"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "cmd"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "arg"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "out_fd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "in_fd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "offset"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "count"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "path"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "sz"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "buf"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "sz"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "buf"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "offset"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "len"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "advice"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "which_clock"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "tp"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "which_clock"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "tp"}},
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
		fields:  []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "which_clock"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "tp"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "which_clock"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "rqtp"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "rmtp"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "timer_id"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "setting"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "timer_id"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "new"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "old"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "ufd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "otmr"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "ufd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "utmr"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "otmr"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dfd"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "filename"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "t"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "n"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "inp"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "outp"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "exp"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "tsp"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "sig"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "ufds"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "nfds"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "tsp"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "sigmask"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "sigsetsize"}},
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
		fields:  []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "fd"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "mmsg"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "vlen"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "timeout"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "mqdes"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "u_msg_ptr"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "msg_len"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "msg_prio"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "u_abs_timeout"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "mqdes"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "u_msg_ptr"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "msg_len"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "u_msg_prio"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "u_abs_timeout"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "uthese"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "uinfo"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "uts"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "sigsetsize"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "uaddr"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "op"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "val"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "utime"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "uaddr2"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "val3"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "interval"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "syscall"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "syscall"}},
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
		fields: []DataField{
			// Real Parent
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "parent_tid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "parent_ns_tid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "parent_pid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "parent_ns_pid"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "time.Time", Name: "parent_start_time"}},
			// Child
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "child_tid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "child_ns_tid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "child_pid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "child_ns_pid"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "time.Time", Name: "start_time"}}, // child_start_tim}e
			// Arguments set by OPT_PROCESS_FORK (when process tree source is enabled for fork events).
			// Parent Process (Go up in hierarchy until parent is a process and not a lwp
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "parent_process_tid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "parent_process_ns_tid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "parent_process_pid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "parent_process_ns_pid"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "time.Time", Name: "parent_process_start_time"}},
			// Thread Group Leader
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "leader_tid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "leader_ns_tid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "leader_pid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "leader_ns_pid"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "time.Time", Name: "leader_start_time"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "cmdpath"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "inode"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "ctime"}},
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "inode_mode"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "interpreter_pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "interpreter_dev"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "interpreter_inode"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "interpreter_ctime"}},
			{DecodeAs: data.ARGS_ARR_T, ArgMeta: trace.ArgMeta{Type: "[]string", Name: "argv"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "interp"}},
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "stdin_type"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "stdin_path"}},
			{DecodeAs: data.BOOL_T, ArgMeta: trace.ArgMeta{Type: "bool", Name: "invoked_from_kernel"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "prev_comm"}},
			{DecodeAs: data.ARGS_ARR_T, ArgMeta: trace.ArgMeta{Type: "[]string", Name: "env"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "exit_code"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "signal_code"}},
			// The field value represents that all threads exited at the event time.
			// Multiple exits of threads of the same process group at the same time could result that all threads exit
			// events would have 'true' value in this field altogether.
			{DecodeAs: data.BOOL_T, ArgMeta: trace.ArgMeta{Type: "bool", Name: "process_group_exit"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "cpu"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "prev_tid"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "prev_comm"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "next_tid"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "next_comm"}},
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
		fields: []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "cap"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "inode"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "count"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "pos"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "inode"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "vlen"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "pos"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "alert"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "addr"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "len"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "prot"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "prev_prot"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "inode"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "ctime"}},
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
		sets: []string{},
		fields: []DataField{
			{DecodeAs: data.CRED_T, ArgMeta: trace.ArgMeta{Type: "trace.SlimCred", Name: "old_cred"}},
			{DecodeAs: data.CRED_T, ArgMeta: trace.ArgMeta{Type: "trace.SlimCred", Name: "new_cred"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "new_mnt"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "new_pid"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "new_uts"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "new_ipc"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "new_net"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "new_cgroup"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.BYTES_T, ArgMeta: trace.ArgMeta{Type: "[]byte", Name: "bytes"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "inode"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "cgroup_path"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "comm"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pid"}},
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
		fields: []DataField{
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "cgroup_id"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "cgroup_path"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "hierarchy_id"}},
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
		fields: []DataField{
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "cgroup_id"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "cgroup_path"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "hierarchy_id"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "inode"}},
			{DecodeAs: data.STR_ARR_T, ArgMeta: trace.ArgMeta{Type: "[]string", Name: "argv"}},
			{DecodeAs: data.STR_ARR_T, ArgMeta: trace.ArgMeta{Type: "[]string", Name: "envp"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "inode"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "ctime"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "syscall_pathname"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "inode"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "ctime"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "family"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "type"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "protocol"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "kern"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sockfd"}},
			{DecodeAs: data.SOCK_ADDR_T, ArgMeta: trace.ArgMeta{Type: "SockAddr", Name: "local_addr"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "backlog"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sockfd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "type"}},
			{DecodeAs: data.SOCK_ADDR_T, ArgMeta: trace.ArgMeta{Type: "SockAddr", Name: "remote_addr"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "dst"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "dst_port"}},
			{DecodeAs: data.ARGS_ARR_T, ArgMeta: trace.ArgMeta{Type: "[]string", Name: "dst_dns"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sockfd"}},
			{DecodeAs: data.SOCK_ADDR_T, ArgMeta: trace.ArgMeta{Type: "SockAddr", Name: "local_addr"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sockfd"}},
			{DecodeAs: data.SOCK_ADDR_T, ArgMeta: trace.ArgMeta{Type: "SockAddr", Name: "local_addr"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sockfd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "level"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "optname"}},
			{DecodeAs: data.SOCK_ADDR_T, ArgMeta: trace.ArgMeta{Type: "SockAddr", Name: "local_addr"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "dev_name"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "path"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "type"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "flags"}},
		},
	},
	SecuritySbUmount: {
		id:      SecuritySbUmount,
		id32Bit: Sys32Undefined,
		name:    "security_sb_umount",
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecuritySbUmount, required: true},
			},
		},
		sets: []string{"default", "lsm_hooks", "fs"},
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "mountpoint"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "type"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "cmd"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "map_id"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "map_name"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "inode"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "type"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "ctime"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "size"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "type"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "file_name"}},
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "mode"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "linkpath"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "target"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "inode"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "ctime"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "prot"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "mmap_flags"}},
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
		fields: []DataField{
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "addr"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "inode"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "ctime"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "pgoff"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "len"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "prot"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "mmap_flags"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "prot"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "ctime"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "prev_prot"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "addr"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "len"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "pkey"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "cgroup"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "ipc"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "mnt"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "net"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "pid"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "pid_for_children"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "time"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "time_for_children"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "user"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "uts"}},
		},
	},
	TraceeInfo: {
		id:           TraceeInfo,
		id32Bit:      Sys32Undefined,
		name:         "tracee_info",
		version:      NewVersion(1, 0, 0),
		sets:         []string{},
		dependencies: Dependencies{},
		fields: []DataField{
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "boot_time"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "time.Time", Name: "start_time"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "version"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "oldfd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "newfd"}},
			{DecodeAs: data.SOCK_ADDR_T, ArgMeta: trace.ArgMeta{Type: "SockAddr", Name: "remote_addr"}},
		},
	},
	ZeroedInodes: {
		id:      ZeroedInodes,
		id32Bit: Sys32Undefined,
		name:    "zeroed_inodes",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.Filldir64, required: true},
			},
		},
		sets: []string{},
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "dirent_name"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "inode"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "count"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "pos"}},
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
		fields: []DataField{
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "inode_in"}},
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "in_file_type"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "in_file_path"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "exposed_data_start_offset"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "exposed_data_len"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "inode_out"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "out_pipe_last_buffer_flags"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "runtime"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "container_id"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "ctime"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "container_image"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "container_image_digest"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "container_name"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pod_name"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pod_namespace"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pod_uid"}},
			{DecodeAs: data.BOOL_T, ArgMeta: trace.ArgMeta{Type: "bool", Name: "pod_sandbox"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "runtime"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "container_id"}},
		},
	},
	ExistingContainer: {
		id:      ExistingContainer,
		id32Bit: Sys32Undefined,
		name:    "existing_container",
		version: NewVersion(1, 0, 0),
		sets:    []string{"containers"},
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "runtime"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "container_id"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "ctime"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "container_image"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "container_image_digest"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "container_name"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pod_name"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pod_namespace"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pod_uid"}},
			{DecodeAs: data.BOOL_T, ArgMeta: trace.ArgMeta{Type: "bool", Name: "pod_sandbox"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "name"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "proc_ops_addr"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "symbol_name"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "pre_handler_addr"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "post_handler_addr"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.STR_ARR_T, ArgMeta: trace.ArgMeta{Type: "[]string", Name: "argv"}},
			{DecodeAs: data.STR_ARR_T, ArgMeta: trace.ArgMeta{Type: "[]string", Name: "envp"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "wait"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "file_name"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "path"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "mode"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "proc_ops_addr"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "syscall_id"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "syscall_address"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "address"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "name"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "srcversion"}},
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
		fields: []DataField{
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "address"}},
			{DecodeAs: data.BYTES_T, ArgMeta: trace.ArgMeta{Type: "[]byte", Name: "name"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "flags"}},
			{DecodeAs: data.BYTES_T, ArgMeta: trace.ArgMeta{Type: "[]byte", Name: "srcversion"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "syscall"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "address"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "function"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "owner"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "name"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "path"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "name"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "parent_name"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "requested_major_number"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "granted_major_number"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "char_device_name"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "char_device_fops"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "inode"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "ctime"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "library_path"}},
			{DecodeAs: data.STR_ARR_T, ArgMeta: trace.ArgMeta{Type: "[]string", Name: "symbols"}},
			{ArgMeta: trace.ArgMeta{Type: "string", Name: "sha256"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "loaded_path"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "collision_path"}},
			{DecodeAs: data.STR_ARR_T, ArgMeta: trace.ArgMeta{Type: "[]string", Name: "symbols"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "name"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "version"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "src_version"}},
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
		sets: []string{},
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "name"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "version"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "src_version"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "inode"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "ctime"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "name"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "version"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "src_version"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sockfd"}},
			{DecodeAs: data.SOCK_ADDR_T, ArgMeta: trace.ArgMeta{Type: "SockAddr", Name: "local_addr"}},
			{DecodeAs: data.SOCK_ADDR_T, ArgMeta: trace.ArgMeta{Type: "SockAddr", Name: "remote_addr"}}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "inode"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT64_ARR_T, ArgMeta: trace.ArgMeta{Type: "[]trace.HookedSymbolData", Name: "hooked_fops_pointers"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT64_ARR_T, ArgMeta: trace.ArgMeta{Type: "[]uint64", Name: "net_seq_ops"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: trigger.ContextArgName}},
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
		fields: []DataField{
			{ArgMeta: trace.ArgMeta{Type: "map[string]trace.HookedSymbolData", Name: "hooked_seq_ops"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "old_name"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "new_name"}},
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
		sets: []string{},
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "old_path"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "new_path"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "sig"}},
			{DecodeAs: data.BOOL_T, ArgMeta: trace.ArgMeta{Type: "bool", Name: "is_sa_initialized"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "sa_flags"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "sa_mask"}},
			{DecodeAs: data.U8_T, ArgMeta: trace.ArgMeta{Type: "uint8", Name: "sa_handle_method"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "sa_handler"}},
			{DecodeAs: data.BOOL_T, ArgMeta: trace.ArgMeta{Type: "bool", Name: "is_old_sa_initialized"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "old_sa_flags"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "old_sa_mask"}},
			{DecodeAs: data.U8_T, ArgMeta: trace.ArgMeta{Type: "uint8", Name: "old_sa_handle_method"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "old_sa_handler"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "prog_type"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "prog_name"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "prog_id"}},
			{DecodeAs: data.UINT64_ARR_T, ArgMeta: trace.ArgMeta{Type: "[]uint64", Name: "prog_helpers"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "symbol_name"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "symbol_addr"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "attach_type"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "symbol_name"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "symbol_address"}},
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
		fields: []DataField{
			{DecodeAs: data.BYTES_T, ArgMeta: trace.ArgMeta{Type: "[]byte", Name: "bytes"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "address"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "length"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "caller_context_id"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "arch"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "symbol_name"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "symbol_owner"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "inode"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "count"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "pos"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "inode"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "vlen"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "pos"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "inode"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "atime"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "mtime"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "inode"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "length"}},
		},
	},
	FileModification: {
		id:      FileModification,
		id32Bit: Sys32Undefined,
		name:    "file_modification",
		version: NewVersion(1, 0, 0),
		docPath: "kprobes/file_modification.md",
		sets:    []string{},
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "file_path"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "inode"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "old_ctime"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "new_ctime"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "inode"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "type"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "name"}},
			{DecodeAs: data.UINT64_ARR_T, ArgMeta: trace.ArgMeta{Type: "[]uint64", Name: "helpers"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "id"}},
			{DecodeAs: data.BOOL_T, ArgMeta: trace.ArgMeta{Type: "bool", Name: "load"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "dirfd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "binary.path"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "binary.device_id"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "binary.inode_number"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "binary.ctime"}},
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "binary.inode_mode"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "interpreter_path"}},
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "stdin_type"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "stdin_path"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "kernel_invoked"}},
			{DecodeAs: data.STR_ARR_T, ArgMeta: trace.ArgMeta{Type: "[]string", Name: "argv"}},
			{DecodeAs: data.STR_ARR_T, ArgMeta: trace.ArgMeta{Type: "[]string", Name: "envp"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "dirfd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "binary.path"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "binary.device_id"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "binary.inode_number"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "binary.ctime"}},
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "binary.inode_mode"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "interpreter_path"}},
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "stdin_type"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "stdin_path"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "kernel_invoked"}},
			{DecodeAs: data.STR_ARR_T, ArgMeta: trace.ArgMeta{Type: "[]string", Name: "argv"}},
			{DecodeAs: data.STR_ARR_T, ArgMeta: trace.ArgMeta{Type: "[]string", Name: "envp"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "dirfd"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "binary.path"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "binary.device_id"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "binary.inode_number"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "binary.ctime"}},
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "binary.inode_mode"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "interpreter_path"}},
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "stdin_type"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "stdin_path"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "kernel_invoked"}},
			{DecodeAs: data.STR_ARR_T, ArgMeta: trace.ArgMeta{Type: "[]string", Name: "argv"}},
			{DecodeAs: data.STR_ARR_T, ArgMeta: trace.ArgMeta{Type: "[]string", Name: "envp"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "symbol"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "trampoline"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "callback"}},
			{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Type: "int64", Name: "callback_offset"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "callback_owner"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "flags"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "count"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "inode"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "mask"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "obj_type"}},
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
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "unresolved_path"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "resolved_path"}},
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
		fields: []DataField{
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "target_host_pid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "resource"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "new_rlim_cur"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "new_rlim_max"}},
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
		fields: []DataField{
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "tv_sec"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "tv_nsec"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "tz_minuteswest"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "tz_dsttime"}},
		},
	},
	ChmodCommon: {
		id:      ChmodCommon,
		id32Bit: Sys32Undefined,
		name:    "chmod_common",
		version: NewVersion(1, 0, 0),
		syscall: true,
		sets:    []string{},
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "mode"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "syscall"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "ip"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "vma_type"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "vma_start"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "vma_size"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "vma_flags"}},
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
		fields: []DataField{
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "syscall"}}, // converted to syscall name (string) at processing stage
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "sp"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "vma_type"}},
			{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Type: "trace.Pointer", Name: "vma_start"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "vma_size"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "vma_flags"}},
		},
	},
	OpenFileNS: {
		id:      OpenFileNS,
		id32Bit: Sys32Undefined,
		name:    "open_file_ns",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecurityFileOpen, required: true},
			},
		},
		sets: []string{},
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "syscall_pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "mount_ns"}},
		},
	},
	OpenFileMount: {
		id:      OpenFileMount,
		id32Bit: Sys32Undefined,
		name:    "open_file_mount",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SecurityFileOpen, required: true},
			},
		},
		sets: []string{},
		fields: []DataField{
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "flags"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "syscall_pathname"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "mount_src"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "mount_dst"}},
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
		fields: []DataField{
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "cgroup_id"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "cgroup_path"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "hierarchy_id"}},
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
		fields: []DataField{
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "cgroup_id"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "cgroup_path"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "hierarchy_id"}},
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
		fields: []DataField{
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "timestamp"}},
			// Real Parent
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "parent_tid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "parent_ns_tid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "parent_pid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "parent_ns_pid"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "parent_start_time"}},
			// Child
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "child_tid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "child_ns_tid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "child_pid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "child_ns_pid"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "start_time"}}, // child_start_time
			// Parent Process (Go up in hierarchy until parent is a process and not a lwp)
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "parent_process_tid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "parent_process_ns_tid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "parent_process_pid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "parent_process_ns_pid"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "parent_process_start_time"}},
			// Thread Group Leader
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "leader_tid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "leader_ns_tid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "leader_pid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "leader_ns_pid"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "leader_start_time"}},
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
		fields: []DataField{
			// time
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "timestamp"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "task_start_time"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "parent_start_time"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "leader_start_time"}},
			// pid
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "task_pid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "parent_pid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "leader_pid"}},
			// command
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "cmdpath"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "dev"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "inode"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "ctime"}},
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "inode_mode"}},
			// interpreter
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "interpreter_pathname"}},
			{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Type: "uint32", Name: "interpreter_dev"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "interpreter_inode"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "interpreter_ctime"}},
			// other
			{DecodeAs: data.ARGS_ARR_T, ArgMeta: trace.ArgMeta{Type: "[]string", Name: "argv"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "interp"}},
			{DecodeAs: data.U16_T, ArgMeta: trace.ArgMeta{Type: "uint16", Name: "stdin_type"}},
			{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "string", Name: "stdin_path"}},
			{DecodeAs: data.BOOL_T, ArgMeta: trace.ArgMeta{Type: "bool", Name: "invoked_from_kernel"}},
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
		fields: []DataField{
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "timestamp"}},
			{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Type: "uint64", Name: "task_start_time"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "task_pid"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "exit_code"}},
			{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int32", Name: "signal_code"}},
			{DecodeAs: data.BOOL_T, ArgMeta: trace.ArgMeta{Type: "bool", Name: "process_group_exit"}},
		},
	},
	SignalHeartbeat: {
		id:       SignalHeartbeat,
		id32Bit:  Sys32Undefined,
		name:     "heartbeat_event",
		version:  NewVersion(1, 0, 0),
		internal: true,
		sets:     []string{"default"},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.SignalHeartbeat, required: true},
			},
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
		fields: []DataField{},
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
		fields: []DataField{
			{DecodeAs: data.BYTES_T, ArgMeta: trace.ArgMeta{Type: "[]byte", Name: "data"}},
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
		fields: []DataField{
			{DecodeAs: data.BYTES_T, ArgMeta: trace.ArgMeta{Type: "[]byte", Name: "payload"}},
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
		fields: []DataField{
			{ArgMeta: trace.ArgMeta{Type: "string", Name: "src"}}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{ArgMeta: trace.ArgMeta{Type: "string", Name: "dst"}}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{ArgMeta: trace.ArgMeta{Type: "trace.PacketMetadata", Name: "metadata"}},
			{ArgMeta: trace.ArgMeta{Type: "trace.ProtoIPv4", Name: "proto_ipv4"}},
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
		fields: []DataField{
			{ArgMeta: trace.ArgMeta{Type: "string", Name: "src"}}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{ArgMeta: trace.ArgMeta{Type: "string", Name: "dst"}}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{ArgMeta: trace.ArgMeta{Type: "trace.PacketMetadata", Name: "metadata"}},
			{ArgMeta: trace.ArgMeta{Type: "trace.ProtoIPv6", Name: "proto_ipv6"}},
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
		fields: []DataField{
			{DecodeAs: data.BYTES_T, ArgMeta: trace.ArgMeta{Type: "[]byte", Name: "payload"}},
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
		fields: []DataField{
			{ArgMeta: trace.ArgMeta{Type: "string", Name: "src"}},      // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{ArgMeta: trace.ArgMeta{Type: "string", Name: "dst"}},      // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{ArgMeta: trace.ArgMeta{Type: "uint16", Name: "src_port"}}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{ArgMeta: trace.ArgMeta{Type: "uint16", Name: "dst_port"}}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{ArgMeta: trace.ArgMeta{Type: "trace.PacketMetadata", Name: "metadata"}},
			{ArgMeta: trace.ArgMeta{Type: "trace.ProtoTCP", Name: "proto_tcp"}},
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
		fields: []DataField{
			{DecodeAs: data.BYTES_T, ArgMeta: trace.ArgMeta{Type: "[]byte", Name: "payload"}},
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
		fields: []DataField{
			{ArgMeta: trace.ArgMeta{Type: "string", Name: "src"}},      // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{ArgMeta: trace.ArgMeta{Type: "string", Name: "dst"}},      // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{ArgMeta: trace.ArgMeta{Type: "uint16", Name: "src_port"}}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{ArgMeta: trace.ArgMeta{Type: "uint16", Name: "dst_port"}}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{ArgMeta: trace.ArgMeta{Type: "trace.PacketMetadata", Name: "metadata"}},
			{ArgMeta: trace.ArgMeta{Type: "trace.ProtoUDP", Name: "proto_udp"}},
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
		fields: []DataField{
			{DecodeAs: data.BYTES_T, ArgMeta: trace.ArgMeta{Type: "[]byte", Name: "payload"}},
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
		fields: []DataField{
			{ArgMeta: trace.ArgMeta{Type: "string", Name: "src"}}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{ArgMeta: trace.ArgMeta{Type: "string", Name: "dst"}}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{ArgMeta: trace.ArgMeta{Type: "trace.PacketMetadata", Name: "metadata"}},
			{ArgMeta: trace.ArgMeta{Type: "trace.ProtoICMP", Name: "proto_icmp"}},
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
		fields: []DataField{
			{DecodeAs: data.BYTES_T, ArgMeta: trace.ArgMeta{Type: "[]byte", Name: "payload"}},
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
		fields: []DataField{
			{ArgMeta: trace.ArgMeta{Type: "string", Name: "src"}}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{ArgMeta: trace.ArgMeta{Type: "string", Name: "dst"}}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{ArgMeta: trace.ArgMeta{Type: "trace.PacketMetadata", Name: "metadata"}},
			{ArgMeta: trace.ArgMeta{Type: "trace.ProtoICMPv6", Name: "proto_icmpv6"}},
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
		fields: []DataField{
			{DecodeAs: data.BYTES_T, ArgMeta: trace.ArgMeta{Type: "[]byte", Name: "payload"}},
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
		fields: []DataField{
			{ArgMeta: trace.ArgMeta{Type: "string", Name: "src"}},      // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{ArgMeta: trace.ArgMeta{Type: "string", Name: "dst"}},      // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{ArgMeta: trace.ArgMeta{Type: "uint16", Name: "src_port"}}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{ArgMeta: trace.ArgMeta{Type: "uint16", Name: "dst_port"}}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{ArgMeta: trace.ArgMeta{Type: "trace.PacketMetadata", Name: "metadata"}},
			{ArgMeta: trace.ArgMeta{Type: "trace.ProtoDNS", Name: "proto_dns"}},
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
		fields: []DataField{
			{ArgMeta: trace.ArgMeta{Type: "trace.PktMeta", Name: "metadata"}},
			{ArgMeta: trace.ArgMeta{Type: "[]trace.DnsQueryData", Name: "dns_questions"}},
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
		fields: []DataField{
			{ArgMeta: trace.ArgMeta{Type: "trace.PktMeta", Name: "metadata"}},
			{ArgMeta: trace.ArgMeta{Type: "[]trace.DnsResponseData", Name: "dns_response"}},
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
		fields: []DataField{
			{DecodeAs: data.BYTES_T, ArgMeta: trace.ArgMeta{Type: "[]byte", Name: "payload"}},
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
		fields: []DataField{
			{ArgMeta: trace.ArgMeta{Name: "src"}},      // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{ArgMeta: trace.ArgMeta{Name: "dst"}},      // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{ArgMeta: trace.ArgMeta{Name: "src_port"}}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{ArgMeta: trace.ArgMeta{Name: "dst_port"}}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{ArgMeta: trace.ArgMeta{Type: "trace.PacketMetadata", Name: "metadata"}},
			{ArgMeta: trace.ArgMeta{Type: "trace.ProtoHTTP", Name: "proto_http"}},
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
		fields: []DataField{
			{ArgMeta: trace.ArgMeta{Type: "trace.PktMeta", Name: "metadata"}},
			{ArgMeta: trace.ArgMeta{Type: "trace.ProtoHTTPRequest", Name: "http_request"}},
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
		fields: []DataField{
			{ArgMeta: trace.ArgMeta{Type: "trace.PktMeta", Name: "metadata"}},
			{ArgMeta: trace.ArgMeta{Type: "trace.ProtoHTTPResponse", Name: "http_response"}},
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
		fields: []DataField{
			{DecodeAs: data.BYTES_T, ArgMeta: trace.ArgMeta{Type: "[]byte", Name: "payload"}},
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
		fields: []DataField{
			{DecodeAs: data.BYTES_T, ArgMeta: trace.ArgMeta{Type: "[]byte", Name: "payload"}},
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
		fields: []DataField{
			{ArgMeta: trace.ArgMeta{Type: "string", Name: "conn_direction"}},
			{ArgMeta: trace.ArgMeta{Type: "string", Name: "src"}},
			{ArgMeta: trace.ArgMeta{Type: "string", Name: "dst"}},
			{ArgMeta: trace.ArgMeta{Type: "uint16", Name: "src_port"}},
			{ArgMeta: trace.ArgMeta{Type: "uint16", Name: "dst_port"}},
			{ArgMeta: trace.ArgMeta{Type: "[]string", Name: "src_dns"}},
			{ArgMeta: trace.ArgMeta{Type: "[]string", Name: "dst_dns"}},
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
		fields: []DataField{
			{ArgMeta: trace.ArgMeta{Type: "string", Name: "conn_direction"}},
			{ArgMeta: trace.ArgMeta{Type: "string", Name: "src"}},
			{ArgMeta: trace.ArgMeta{Type: "string", Name: "dst"}},
			{ArgMeta: trace.ArgMeta{Type: "uint16", Name: "src_port"}},
			{ArgMeta: trace.ArgMeta{Type: "uint16", Name: "dst_port"}},
			{ArgMeta: trace.ArgMeta{Type: "[]string", Name: "src_dns"}},
			{ArgMeta: trace.ArgMeta{Type: "[]string", Name: "dst_dns"}},
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
		fields: []DataField{},
	},
	MissingKsymbol: {
		id:      MissingKsymbol,
		id32Bit: Sys32Undefined,
		name:    "missing_ksymbol",
		version: NewVersion(1, 0, 0),
		syscall: false,
		sets:    []string{"tests", "dependencies"},
		fields:  []DataField{},
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
		fields:  []DataField{},
		dependencies: Dependencies{
			probes: []Probe{
				{handle: probes.TestUnavailableHook, required: true},
				{handle: probes.ExecTest, required: true},
			},
			ids: []ID{ExecTest},
		},
	},
}
