package events

import (
	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
	"github.com/aquasecurity/tracee/pkg/events/trigger"
	"github.com/aquasecurity/tracee/types/trace"
)

const (
	Sys32Undefined ID = 0xfffffff - 1 // u32 overflows are compiler implementation dependent.
	Undefined      ID = 0xfffffff
)

type ID int32

// Common events (used by all architectures).
// Events should match defined values in ebpf code.

const (
	NetPacketBase ID = iota + 700
	NetPacketIPBase
	NetPacketTCPBase
	NetPacketUDPBase
	NetPacketICMPBase
	NetPacketICMPv6Base
	NetPacketDNSBase
	NetPacketHTTPBase
	NetPacketCapture
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
	PrintSyscallTable
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
	HiddenKernelModuleSeeker
	ModuleLoad
	ModuleFree
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
	MaxUserNetID
	InitNamespaces
	ContainerCreate
	ContainerRemove
	ExistingContainer
	HookedSyscalls
	HookedSeqOps
	SymbolsLoaded
	SymbolsCollision
	HiddenKernelModule
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

// Signature events
const (
	StartSignatureID ID = 6000
	MaxSignatureID   ID = 6999
)

//
// All Events
//

var Definitions *EventGroup

var CoreDefinitions = map[ID]*Event{
	Read: NewEvent(
		Read,
		Sys32read, // id32Bit
		"read",    // name
		"",        // docPath
		false,     // internal
		true,      // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_read_write",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "void*", Name: "buf"},
			{Type: "size_t", Name: "count"},
		},
	),
	Write: NewEvent(
		Write,
		Sys32write, // id32Bit
		"write",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_read_write",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "void*", Name: "buf"},
			{Type: "size_t", Name: "count"},
		},
	),
	Open: NewEvent(
		Open,
		Sys32open, // id32Bit
		"open",    // name
		"",        // docPath
		false,     // internal
		true,      // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "int", Name: "flags"},
			{Type: "mode_t", Name: "mode"},
		},
	),
	Close: NewEvent(
		Close,
		Sys32close, // id32Bit
		"close",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
		},
	),
	Stat: NewEvent(
		Stat,
		Sys32stat, // id32Bit
		"stat",    // name
		"",        // docPath
		false,     // internal
		true,      // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "struct stat*", Name: "statbuf"},
		},
	),
	Fstat: NewEvent(
		Fstat,
		Sys32fstat, // id32Bit
		"fstat",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "struct stat*", Name: "statbuf"},
		},
	),
	Lstat: NewEvent(
		Lstat,
		Sys32lstat, // id32Bit
		"lstat",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "struct stat*", Name: "statbuf"},
		},
	),
	Poll: NewEvent(
		Poll,
		Sys32poll, // id32Bit
		"poll",    // name
		"",        // docPath
		false,     // internal
		true,      // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_mux_io",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "struct pollfd*", Name: "fds"},
			{Type: "unsigned int", Name: "nfds"},
			{Type: "int", Name: "timeout"},
		},
	),
	Lseek: NewEvent(
		Lseek,
		Sys32lseek, // id32Bit
		"lseek",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_read_write",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "off_t", Name: "offset"},
			{Type: "unsigned int", Name: "whence"},
		},
	),
	Mmap: NewEvent(
		Mmap,
		Sys32mmap, // id32Bit
		"mmap",    // name
		"",        // docPath
		false,     // internal
		true,      // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_mem",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "void*", Name: "addr"},
			{Type: "size_t", Name: "length"},
			{Type: "int", Name: "prot"},
			{Type: "int", Name: "flags"},
			{Type: "int", Name: "fd"},
			{Type: "off_t", Name: "off"},
		},
	),
	Mprotect: NewEvent(
		Mprotect,
		Sys32mprotect, // id32Bit
		"mprotect",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_mem",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "void*", Name: "addr"},
			{Type: "size_t", Name: "len"},
			{Type: "int", Name: "prot"},
		},
	),
	Munmap: NewEvent(
		Munmap,
		Sys32munmap, // id32Bit
		"munmap",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_mem",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "void*", Name: "addr"},
			{Type: "size_t", Name: "length"},
		},
	),
	Brk: NewEvent(
		Brk,
		Sys32brk, // id32Bit
		"brk",    // name
		"",       // docPath
		false,    // internal
		true,     // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_mem",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "void*", Name: "addr"},
		},
	),
	RtSigaction: NewEvent(
		RtSigaction,
		Sys32rt_sigaction, // id32Bit
		"rt_sigaction",    // name
		"",                // docPath
		false,             // internal
		true,              // syscall
		[]string{
			"syscalls",
			"signals",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "signum"},
			{Type: "const struct sigaction*", Name: "act"},
			{Type: "struct sigaction*", Name: "oldact"},
			{Type: "size_t", Name: "sigsetsize"},
		},
	),
	RtSigprocmask: NewEvent(
		RtSigprocmask,
		Sys32rt_sigprocmask, // id32Bit
		"rt_sigprocmask",    // name
		"",                  // docPath
		false,               // internal
		true,                // syscall
		[]string{
			"syscalls",
			"signals",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "how"},
			{Type: "sigset_t*", Name: "set"},
			{Type: "sigset_t*", Name: "oldset"},
			{Type: "size_t", Name: "sigsetsize"},
		},
	),
	RtSigreturn: NewEvent(
		RtSigreturn,
		Sys32rt_sigreturn, // id32Bit
		"rt_sigreturn",    // name
		"",                // docPath
		false,             // internal
		true,              // syscall
		[]string{
			"syscalls",
			"signals",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Ioctl: NewEvent(
		Ioctl,
		Sys32ioctl, // id32Bit
		"ioctl",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_fd_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "unsigned long", Name: "request"},
			{Type: "unsigned long", Name: "arg"},
		},
	),
	Pread64: NewEvent(
		Pread64,
		Sys32pread64, // id32Bit
		"pread64",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_read_write",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "void*", Name: "buf"},
			{Type: "size_t", Name: "count"},
			{Type: "off_t", Name: "offset"},
		},
	),
	Pwrite64: NewEvent(
		Pwrite64,
		Sys32pwrite64, // id32Bit
		"pwrite64",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_read_write",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const void*", Name: "buf"},
			{Type: "size_t", Name: "count"},
			{Type: "off_t", Name: "offset"},
		},
	),
	Readv: NewEvent(
		Readv,
		Sys32readv, // id32Bit
		"readv",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_read_write",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const struct iovec*", Name: "iov"},
			{Type: "int", Name: "iovcnt"},
		},
	),
	Writev: NewEvent(
		Writev,
		Sys32writev, // id32Bit
		"writev",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_read_write",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const struct iovec*", Name: "iov"},
			{Type: "int", Name: "iovcnt"},
		},
	),
	Access: NewEvent(
		Access,
		Sys32access, // id32Bit
		"access",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "int", Name: "mode"},
		},
	),
	Pipe: NewEvent(
		Pipe,
		Sys32pipe, // id32Bit
		"pipe",    // name
		"",        // docPath
		false,     // internal
		true,      // syscall
		[]string{
			"syscalls",
			"ipc",
			"ipc_pipe",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int[2]", Name: "pipefd"},
		},
	),
	Select: NewEvent(
		Select,
		Sys32_newselect, // id32Bit
		"select",        // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_mux_io",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "nfds"},
			{Type: "fd_set*", Name: "readfds"},
			{Type: "fd_set*", Name: "writefds"},
			{Type: "fd_set*", Name: "exceptfds"},
			{Type: "struct timeval*", Name: "timeout"},
		},
	),
	SchedYield: NewEvent(
		SchedYield,
		Sys32sched_yield, // id32Bit
		"sched_yield",    // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_sched",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Mremap: NewEvent(
		Mremap,
		Sys32mremap, // id32Bit
		"mremap",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_mem",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "void*", Name: "old_address"},
			{Type: "size_t", Name: "old_size"},
			{Type: "size_t", Name: "new_size"},
			{Type: "int", Name: "flags"},
			{Type: "void*", Name: "new_address"},
		},
	),
	Msync: NewEvent(
		Msync,
		Sys32msync, // id32Bit
		"msync",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_sync",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "void*", Name: "addr"},
			{Type: "size_t", Name: "length"},
			{Type: "int", Name: "flags"},
		},
	),
	Mincore: NewEvent(
		Mincore,
		Sys32mincore, // id32Bit
		"mincore",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_mem",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "void*", Name: "addr"},
			{Type: "size_t", Name: "length"},
			{Type: "unsigned char*", Name: "vec"},
		},
	),
	Madvise: NewEvent(
		Madvise,
		Sys32madvise, // id32Bit
		"madvise",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_mem",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "void*", Name: "addr"},
			{Type: "size_t", Name: "length"},
			{Type: "int", Name: "advice"},
		},
	),
	Shmget: NewEvent(
		Shmget,
		Sys32shmget, // id32Bit
		"shmget",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"ipc",
			"ipc_shm",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "key_t", Name: "key"},
			{Type: "size_t", Name: "size"},
			{Type: "int", Name: "shmflg"},
		},
	),
	Shmat: NewEvent(
		Shmat,
		Sys32shmat, // id32Bit
		"shmat",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"ipc",
			"ipc_shm",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "shmid"},
			{Type: "const void*", Name: "shmaddr"},
			{Type: "int", Name: "shmflg"},
		},
	),
	Shmctl: NewEvent(
		Shmctl,
		Sys32shmctl, // id32Bit
		"shmctl",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"ipc",
			"ipc_shm",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "shmid"},
			{Type: "int", Name: "cmd"},
			{Type: "struct shmid_ds*", Name: "buf"},
		},
	),
	Dup: NewEvent(
		Dup,
		Sys32dup, // id32Bit
		"dup",    // name
		"",       // docPath
		false,    // internal
		true,     // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_fd_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "oldfd"},
		},
	),
	Dup2: NewEvent(
		Dup2,
		Sys32dup2, // id32Bit
		"dup2",    // name
		"",        // docPath
		false,     // internal
		true,      // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_fd_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "oldfd"},
			{Type: "int", Name: "newfd"},
		},
	),
	Pause: NewEvent(
		Pause,
		Sys32pause, // id32Bit
		"pause",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"signals",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Nanosleep: NewEvent(
		Nanosleep,
		Sys32nanosleep, // id32Bit
		"nanosleep",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"time",
			"time_timer",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const struct timespec*", Name: "req"},
			{Type: "struct timespec*", Name: "rem"},
		},
	),
	Getitimer: NewEvent(
		Getitimer,
		Sys32getitimer, // id32Bit
		"getitimer",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"time",
			"time_timer",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "which"},
			{Type: "struct itimerval*", Name: "curr_value"},
		},
	),
	Alarm: NewEvent(
		Alarm,
		Sys32alarm, // id32Bit
		"alarm",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"time",
			"time_timer",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned int", Name: "seconds"},
		},
	),
	Setitimer: NewEvent(
		Setitimer,
		Sys32setitimer, // id32Bit
		"setitimer",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"time",
			"time_timer",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "which"},
			{Type: "struct itimerval*", Name: "new_value"},
			{Type: "struct itimerval*", Name: "old_value"},
		},
	),
	Getpid: NewEvent(
		Getpid,
		Sys32getpid, // id32Bit
		"getpid",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_ids",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Sendfile: NewEvent(
		Sendfile,
		Sys32sendfile64, // id32Bit
		"sendfile",      // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_read_write",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "out_fd"},
			{Type: "int", Name: "in_fd"},
			{Type: "off_t*", Name: "offset"},
			{Type: "size_t", Name: "count"},
		},
	),
	Socket: NewEvent(
		Socket,
		Sys32socket, // id32Bit
		"socket",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"net",
			"net_sock",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "domain"},
			{Type: "int", Name: "type"},
			{Type: "int", Name: "protocol"},
		},
	),
	Connect: NewEvent(
		Connect,
		Sys32connect, // id32Bit
		"connect",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"net",
			"net_sock",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct sockaddr*", Name: "addr"},
			{Type: "int", Name: "addrlen"},
		},
	),
	Accept: NewEvent(
		Accept,
		Sys32Undefined, // id32Bit
		"accept",       // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"net",
			"net_sock",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct sockaddr*", Name: "addr"},
			{Type: "int*", Name: "addrlen"},
		},
	),
	Sendto: NewEvent(
		Sendto,
		Sys32sendto, // id32Bit
		"sendto",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"net",
			"net_snd_rcv",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "void*", Name: "buf"},
			{Type: "size_t", Name: "len"},
			{Type: "int", Name: "flags"},
			{Type: "struct sockaddr*", Name: "dest_addr"},
			{Type: "int", Name: "addrlen"},
		},
	),
	Recvfrom: NewEvent(
		Recvfrom,
		Sys32recvfrom, // id32Bit
		"recvfrom",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"net",
			"net_snd_rcv",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "void*", Name: "buf"},
			{Type: "size_t", Name: "len"},
			{Type: "int", Name: "flags"},
			{Type: "struct sockaddr*", Name: "src_addr"},
			{Type: "int*", Name: "addrlen"},
		},
	),
	Sendmsg: NewEvent(
		Sendmsg,
		Sys32sendmsg, // id32Bit
		"sendmsg",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"net",
			"net_snd_rcv",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct msghdr*", Name: "msg"},
			{Type: "int", Name: "flags"},
		},
	),
	Recvmsg: NewEvent(
		Recvmsg,
		Sys32recvmsg, // id32Bit
		"recvmsg",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"net",
			"net_snd_rcv",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct msghdr*", Name: "msg"},
			{Type: "int", Name: "flags"},
		},
	),
	Shutdown: NewEvent(
		Shutdown,
		Sys32shutdown, // id32Bit
		"shutdown",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"net",
			"net_sock",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "int", Name: "how"},
		},
	),
	Bind: NewEvent(
		Bind,
		Sys32bind, // id32Bit
		"bind",    // name
		"",        // docPath
		false,     // internal
		true,      // syscall
		[]string{
			"syscalls",
			"net",
			"net_sock",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct sockaddr*", Name: "addr"},
			{Type: "int", Name: "addrlen"},
		},
	),
	Listen: NewEvent(
		Listen,
		Sys32listen, // id32Bit
		"listen",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"net",
			"net_sock",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "int", Name: "backlog"},
		},
	),
	Getsockname: NewEvent(
		Getsockname,
		Sys32getsockname, // id32Bit
		"getsockname",    // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"syscalls",
			"net",
			"net_sock",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct sockaddr*", Name: "addr"},
			{Type: "int*", Name: "addrlen"},
		},
	),
	Getpeername: NewEvent(
		Getpeername,
		Sys32getpeername, // id32Bit
		"getpeername",    // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"syscalls",
			"net",
			"net_sock",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct sockaddr*", Name: "addr"},
			{Type: "int*", Name: "addrlen"},
		},
	),
	Socketpair: NewEvent(
		Socketpair,
		Sys32socketpair, // id32Bit
		"socketpair",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"net",
			"net_sock",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "domain"},
			{Type: "int", Name: "type"},
			{Type: "int", Name: "protocol"},
			{Type: "int[2]", Name: "sv"},
		},
	),
	Setsockopt: NewEvent(
		Setsockopt,
		Sys32setsockopt, // id32Bit
		"setsockopt",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"net",
			"net_sock",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "int", Name: "level"},
			{Type: "int", Name: "optname"},
			{Type: "const void*", Name: "optval"},
			{Type: "int", Name: "optlen"},
		},
	),
	Getsockopt: NewEvent(
		Getsockopt,
		Sys32getsockopt, // id32Bit
		"getsockopt",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"net",
			"net_sock",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "int", Name: "level"},
			{Type: "int", Name: "optname"},
			{Type: "void*", Name: "optval"},
			{Type: "int*", Name: "optlen"},
		},
	),
	Clone: NewEvent(
		Clone,
		Sys32clone, // id32Bit
		"clone",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_life",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned long", Name: "flags"},
			{Type: "void*", Name: "stack"},
			{Type: "int*", Name: "parent_tid"},
			{Type: "int*", Name: "child_tid"},
			{Type: "unsigned long", Name: "tls"},
		},
	),
	Fork: NewEvent(
		Fork,
		Sys32fork, // id32Bit
		"fork",    // name
		"",        // docPath
		false,     // internal
		true,      // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_life",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{}, // params
	),
	Vfork: NewEvent(
		Vfork,
		Sys32vfork, // id32Bit
		"vfork",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_life",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Execve: NewEvent(
		Execve,
		Sys32execve, // id32Bit
		"execve",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_life",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{
				NewTailCall(
					"sys_enter_tails",
					"syscall__execve",
					[]uint32{
						uint32(Execve),
					},
				),
			},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "const char*const*", Name: "argv"},
			{Type: "const char*const*", Name: "envp"},
		},
	),
	Exit: NewEvent(
		Exit,
		Sys32exit, // id32Bit
		"exit",    // name
		"",        // docPath
		false,     // internal
		true,      // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_life",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "status"},
		},
	),
	Wait4: NewEvent(
		Wait4,
		Sys32wait4, // id32Bit
		"wait4",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_life",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "int*", Name: "wstatus"},
			{Type: "int", Name: "options"},
			{Type: "struct rusage*", Name: "rusage"},
		},
	),
	Kill: NewEvent(
		Kill,
		Sys32kill, // id32Bit
		"kill",    // name
		"",        // docPath
		false,     // internal
		true,      // syscall
		[]string{
			"syscalls",
			"signals",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "int", Name: "sig"},
		},
	),
	Uname: NewEvent(
		Uname,
		Sys32uname, // id32Bit
		"uname",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"system",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "struct utsname*", Name: "buf"},
		},
	),
	Semget: NewEvent(
		Semget,
		Sys32semget, // id32Bit
		"semget",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"ipc",
			"ipc_sem",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "key_t", Name: "key"},
			{Type: "int", Name: "nsems"},
			{Type: "int", Name: "semflg"},
		},
	),
	Semop: NewEvent(
		Semop,
		Sys32Undefined, // id32Bit
		"semop",        // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"ipc",
			"ipc_sem",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "semid"},
			{Type: "struct sembuf*", Name: "sops"},
			{Type: "size_t", Name: "nsops"},
		},
	),
	Semctl: NewEvent(
		Semctl,
		Sys32semctl, // id32Bit
		"semctl",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"ipc",
			"ipc_sem",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "semid"},
			{Type: "int", Name: "semnum"},
			{Type: "int", Name: "cmd"},
			{Type: "unsigned long", Name: "arg"},
		},
	),
	Shmdt: NewEvent(
		Shmdt,
		Sys32shmdt, // id32Bit
		"shmdt",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"ipc",
			"ipc_shm",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const void*", Name: "shmaddr"},
		},
	),
	Msgget: NewEvent(
		Msgget,
		Sys32msgget, // id32Bit
		"msgget",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"ipc",
			"ipc_msgq",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "key_t", Name: "key"},
			{Type: "int", Name: "msgflg"},
		},
	),
	Msgsnd: NewEvent(
		Msgsnd,
		Sys32msgsnd, // id32Bit
		"msgsnd",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"ipc",
			"ipc_msgq",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "msqid"},
			{Type: "struct msgbuf*", Name: "msgp"},
			{Type: "size_t", Name: "msgsz"},
			{Type: "int", Name: "msgflg"},
		},
	),
	Msgrcv: NewEvent(
		Msgrcv,
		Sys32msgrcv, // id32Bit
		"msgrcv",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"ipc",
			"ipc_msgq",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "msqid"},
			{Type: "struct msgbuf*", Name: "msgp"},
			{Type: "size_t", Name: "msgsz"},
			{Type: "long", Name: "msgtyp"},
			{Type: "int", Name: "msgflg"},
		},
	),
	Msgctl: NewEvent(
		Msgctl,
		Sys32msgctl, // id32Bit
		"msgctl",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"ipc",
			"ipc_msgq",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "msqid"},
			{Type: "int", Name: "cmd"},
			{Type: "struct msqid_ds*", Name: "buf"},
		},
	),
	Fcntl: NewEvent(
		Fcntl,
		Sys32fcntl, // id32Bit
		"fcntl",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_fd_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "int", Name: "cmd"},
			{Type: "unsigned long", Name: "arg"},
		},
	),
	Flock: NewEvent(
		Flock,
		Sys32flock, // id32Bit
		"flock",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_fd_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "int", Name: "operation"},
		},
	),
	Fsync: NewEvent(
		Fsync,
		Sys32fsync, // id32Bit
		"fsync",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_sync",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
		},
	),
	Fdatasync: NewEvent(
		Fdatasync,
		Sys32fdatasync, // id32Bit
		"fdatasync",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_sync",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
		},
	),
	Truncate: NewEvent(
		Truncate,
		Sys32truncate, // id32Bit
		"truncate",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "off_t", Name: "length"},
		},
	),
	Ftruncate: NewEvent(
		Ftruncate,
		Sys32ftruncate, // id32Bit
		"ftruncate",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "off_t", Name: "length"},
		},
	),
	Getdents: NewEvent(
		Getdents,
		Sys32getdents, // id32Bit
		"getdents",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_dir_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "struct linux_dirent*", Name: "dirp"},
			{Type: "unsigned int", Name: "count"},
		},
	),
	Getcwd: NewEvent(
		Getcwd,
		Sys32getcwd, // id32Bit
		"getcwd",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_dir_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "char*", Name: "buf"},
			{Type: "size_t", Name: "size"},
		},
	),
	Chdir: NewEvent(
		Chdir,
		Sys32chdir, // id32Bit
		"chdir",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_dir_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "path"},
		},
	),
	Fchdir: NewEvent(
		Fchdir,
		Sys32fchdir, // id32Bit
		"fchdir",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_dir_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
		},
	),
	Rename: NewEvent(
		Rename,
		Sys32rename, // id32Bit
		"rename",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "oldpath"},
			{Type: "const char*", Name: "newpath"},
		},
	),
	Mkdir: NewEvent(
		Mkdir,
		Sys32mkdir, // id32Bit
		"mkdir",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_dir_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "mode_t", Name: "mode"},
		},
	),
	Rmdir: NewEvent(
		Rmdir,
		Sys32rmdir, // id32Bit
		"rmdir",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_dir_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
		},
	),
	Creat: NewEvent(
		Creat,
		Sys32creat, // id32Bit
		"creat",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"default",
			"syscalls",
			"fs",
			"fs_file_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "mode_t", Name: "mode"},
		},
	),
	Link: NewEvent(
		Link,
		Sys32link, // id32Bit
		"link",    // name
		"",        // docPath
		false,     // internal
		true,      // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_link_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "oldpath"},
			{Type: "const char*", Name: "newpath"},
		},
	),
	Unlink: NewEvent(
		Unlink,
		Sys32unlink, // id32Bit
		"unlink",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_link_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
		},
	),
	Symlink: NewEvent(
		Symlink,
		Sys32symlink, // id32Bit
		"symlink",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_link_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "target"},
			{Type: "const char*", Name: "linkpath"},
		},
	),
	Readlink: NewEvent(
		Readlink,
		Sys32readlink, // id32Bit
		"readlink",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_link_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "char*", Name: "buf"},
			{Type: "size_t", Name: "bufsiz"},
		},
	),
	Chmod: NewEvent(
		Chmod,
		Sys32chmod, // id32Bit
		"chmod",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"default",
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "mode_t", Name: "mode"},
		},
	),
	Fchmod: NewEvent(
		Fchmod,
		Sys32fchmod, // id32Bit
		"fchmod",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"default",
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "mode_t", Name: "mode"},
		},
	),
	Chown: NewEvent(
		Chown,
		Sys32chown32, // id32Bit
		"chown",      // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"default",
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "uid_t", Name: "owner"},
			{Type: "gid_t", Name: "group"},
		},
	),
	Fchown: NewEvent(
		Fchown,
		Sys32fchown32, // id32Bit
		"fchown",      // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"default",
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "uid_t", Name: "owner"},
			{Type: "gid_t", Name: "group"},
		},
	),
	Lchown: NewEvent(
		Lchown,
		Sys32lchown32, // id32Bit
		"lchown",      // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"default",
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "uid_t", Name: "owner"},
			{Type: "gid_t", Name: "group"},
		},
	),
	Umask: NewEvent(
		Umask,
		Sys32umask, // id32Bit
		"umask",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "mode_t", Name: "mask"},
		},
	),
	Gettimeofday: NewEvent(
		Gettimeofday,
		Sys32gettimeofday, // id32Bit
		"gettimeofday",    // name
		"",                // docPath
		false,             // internal
		true,              // syscall
		[]string{
			"syscalls",
			"time",
			"time_tod",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "struct timeval*", Name: "tv"},
			{Type: "struct timezone*", Name: "tz"},
		},
	),
	Getrlimit: NewEvent(
		Getrlimit,
		Sys32ugetrlimit, // id32Bit
		"getrlimit",     // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"proc",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "resource"},
			{Type: "struct rlimit*", Name: "rlim"},
		},
	),
	Getrusage: NewEvent(
		Getrusage,
		Sys32getrusage, // id32Bit
		"getrusage",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"proc",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "who"},
			{Type: "struct rusage*", Name: "usage"},
		},
	),
	Sysinfo: NewEvent(
		Sysinfo,
		Sys32sysinfo, // id32Bit
		"sysinfo",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"system",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "struct sysinfo*", Name: "info"},
		},
	),
	Times: NewEvent(
		Times,
		Sys32times, // id32Bit
		"times",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"proc",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "struct tms*", Name: "buf"},
		},
	),
	Ptrace: NewEvent(
		Ptrace,
		Sys32ptrace, // id32Bit
		"ptrace",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"default",
			"syscalls",
			"proc",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "long", Name: "request"},
			{Type: "pid_t", Name: "pid"},
			{Type: "void*", Name: "addr"},
			{Type: "void*", Name: "data"},
		},
	),
	Getuid: NewEvent(
		Getuid,
		Sys32getuid32, // id32Bit
		"getuid",      // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_ids",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Syslog: NewEvent(
		Syslog,
		Sys32syslog, // id32Bit
		"syslog",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"system",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "type"},
			{Type: "char*", Name: "bufp"},
			{Type: "int", Name: "len"},
		},
	),
	Getgid: NewEvent(
		Getgid,
		Sys32getgid32, // id32Bit
		"getgid",      // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_ids",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Setuid: NewEvent(
		Setuid,
		Sys32setuid32, // id32Bit
		"setuid",      // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"default",
			"syscalls",
			"proc",
			"proc_ids",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "uid_t", Name: "uid"},
		},
	),
	Setgid: NewEvent(
		Setgid,
		Sys32setgid32, // id32Bit
		"setgid",      // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"default",
			"syscalls",
			"proc",
			"proc_ids",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "gid_t", Name: "gid"},
		},
	),
	Geteuid: NewEvent(
		Geteuid,
		Sys32geteuid32, // id32Bit
		"geteuid",      // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_ids",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Getegid: NewEvent(
		Getegid,
		Sys32getegid32, // id32Bit
		"getegid",      // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_ids",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Setpgid: NewEvent(
		Setpgid,
		Sys32setpgid, // id32Bit
		"setpgid",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"default",
			"syscalls",
			"proc",
			"proc_ids",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "pid_t", Name: "pgid"},
		},
	),
	Getppid: NewEvent(
		Getppid,
		Sys32getppid, // id32Bit
		"getppid",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_ids",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Getpgrp: NewEvent(
		Getpgrp,
		Sys32getpgrp, // id32Bit
		"getpgrp",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_ids",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Setsid: NewEvent(
		Setsid,
		Sys32setsid, // id32Bit
		"setsid",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"default",
			"syscalls",
			"proc",
			"proc_ids",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Setreuid: NewEvent(
		Setreuid,
		Sys32setreuid32, // id32Bit
		"setreuid",      // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"default",
			"syscalls",
			"proc",
			"proc_ids",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "uid_t", Name: "ruid"},
			{Type: "uid_t", Name: "euid"},
		},
	),
	Setregid: NewEvent(
		Setregid,
		Sys32setregid32, // id32Bit
		"setregid",      // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"default",
			"syscalls",
			"proc",
			"proc_ids",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "gid_t", Name: "rgid"},
			{Type: "gid_t", Name: "egid"},
		},
	),
	Getgroups: NewEvent(
		Getgroups,
		Sys32getgroups32, // id32Bit
		"getgroups",      // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_ids",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "size"},
			{Type: "gid_t*", Name: "list"},
		},
	),
	Setgroups: NewEvent(
		Setgroups,
		Sys32setgroups32, // id32Bit
		"setgroups",      // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_ids",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "size"},
			{Type: "gid_t*", Name: "list"},
		},
	),
	Setresuid: NewEvent(
		Setresuid,
		Sys32setresuid32, // id32Bit
		"setresuid",      // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"default",
			"syscalls",
			"proc",
			"proc_ids",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "uid_t", Name: "ruid"},
			{Type: "uid_t", Name: "euid"},
			{Type: "uid_t", Name: "suid"},
		},
	),
	Getresuid: NewEvent(
		Getresuid,
		Sys32getresuid32, // id32Bit
		"getresuid",      // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_ids",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "uid_t*", Name: "ruid"},
			{Type: "uid_t*", Name: "euid"},
			{Type: "uid_t*", Name: "suid"},
		},
	),
	Setresgid: NewEvent(
		Setresgid,
		Sys32setresgid32, // id32Bit
		"setresgid",      // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"default",
			"syscalls",
			"proc",
			"proc_ids",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "gid_t", Name: "rgid"},
			{Type: "gid_t", Name: "egid"},
			{Type: "gid_t", Name: "sgid"},
		},
	),
	Getresgid: NewEvent(
		Getresgid,
		Sys32getresgid32, // id32Bit
		"getresgid",      // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_ids",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "gid_t*", Name: "rgid"},
			{Type: "gid_t*", Name: "egid"},
			{Type: "gid_t*", Name: "sgid"},
		},
	),
	Getpgid: NewEvent(
		Getpgid,
		Sys32getpgid, // id32Bit
		"getpgid",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_ids",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
		},
	),
	Setfsuid: NewEvent(
		Setfsuid,
		Sys32setfsuid32, // id32Bit
		"setfsuid",      // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"default",
			"syscalls",
			"proc",
			"proc_ids",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "uid_t", Name: "fsuid"},
		},
	),
	Setfsgid: NewEvent(
		Setfsgid,
		Sys32setfsgid32, // id32Bit
		"setfsgid",      // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"default",
			"syscalls",
			"proc",
			"proc_ids",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "gid_t", Name: "fsgid"},
		},
	),
	Getsid: NewEvent(
		Getsid,
		Sys32getsid, // id32Bit
		"getsid",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_ids",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
		},
	),
	Capget: NewEvent(
		Capget,
		Sys32capget, // id32Bit
		"capget",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"proc",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "cap_user_header_t", Name: "hdrp"},
			{Type: "cap_user_data_t", Name: "datap"},
		},
	),
	Capset: NewEvent(
		Capset,
		Sys32capset, // id32Bit
		"capset",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"proc",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "cap_user_header_t", Name: "hdrp"},
			{Type: "const cap_user_data_t", Name: "datap"},
		},
	),
	RtSigpending: NewEvent(
		RtSigpending,
		Sys32rt_sigpending, // id32Bit
		"rt_sigpending",    // name
		"",                 // docPath
		false,              // internal
		true,               // syscall
		[]string{
			"syscalls",
			"signals",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "sigset_t*", Name: "set"},
			{Type: "size_t", Name: "sigsetsize"},
		},
	),
	RtSigtimedwait: NewEvent(
		RtSigtimedwait,
		Sys32rt_sigtimedwait_time64, // id32Bit
		"rt_sigtimedwait",           // name
		"",                          // docPath
		false,                       // internal
		true,                        // syscall
		[]string{
			"syscalls",
			"signals",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const sigset_t*", Name: "set"},
			{Type: "siginfo_t*", Name: "info"},
			{Type: "const struct timespec*", Name: "timeout"},
			{Type: "size_t", Name: "sigsetsize"},
		},
	),
	RtSigqueueinfo: NewEvent(
		RtSigqueueinfo,
		Sys32rt_sigqueueinfo, // id32Bit
		"rt_sigqueueinfo",    // name
		"",                   // docPath
		false,                // internal
		true,                 // syscall
		[]string{
			"syscalls",
			"signals",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "pid_t", Name: "tgid"},
			{Type: "int", Name: "sig"},
			{Type: "siginfo_t*", Name: "info"},
		},
	),
	RtSigsuspend: NewEvent(
		RtSigsuspend,
		Sys32rt_sigsuspend, // id32Bit
		"rt_sigsuspend",    // name
		"",                 // docPath
		false,              // internal
		true,               // syscall
		[]string{
			"syscalls",
			"signals",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "sigset_t*", Name: "mask"},
			{Type: "size_t", Name: "sigsetsize"},
		},
	),
	Sigaltstack: NewEvent(
		Sigaltstack,
		Sys32sigaltstack, // id32Bit
		"sigaltstack",    // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"syscalls",
			"signals",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const stack_t*", Name: "ss"},
			{Type: "stack_t*", Name: "old_ss"},
		},
	),
	Utime: NewEvent(
		Utime,
		Sys32utime, // id32Bit
		"utime",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "filename"},
			{Type: "const struct utimbuf*", Name: "times"},
		},
	),
	Mknod: NewEvent(
		Mknod,
		Sys32mknod, // id32Bit
		"mknod",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "mode_t", Name: "mode"},
			{Type: "dev_t", Name: "dev"},
		},
	),
	Uselib: NewEvent(
		Uselib,
		Sys32uselib, // id32Bit
		"uselib",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"proc",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "library"},
		},
	),
	Personality: NewEvent(
		Personality,
		Sys32personality, // id32Bit
		"personality",    // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"syscalls",
			"system",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned long", Name: "persona"},
		},
	),
	Ustat: NewEvent(
		Ustat,
		Sys32ustat, // id32Bit
		"ustat",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_info",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "dev_t", Name: "dev"},
			{Type: "struct ustat*", Name: "ubuf"},
		},
	),
	Statfs: NewEvent(
		Statfs,
		Sys32statfs, // id32Bit
		"statfs",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_info",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "struct statfs*", Name: "buf"},
		},
	),
	Fstatfs: NewEvent(
		Fstatfs,
		Sys32fstatfs, // id32Bit
		"fstatfs",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_info",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "struct statfs*", Name: "buf"},
		},
	),
	Sysfs: NewEvent(
		Sysfs,
		Sys32sysfs, // id32Bit
		"sysfs",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_info",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "option"},
		},
	),
	Getpriority: NewEvent(
		Getpriority,
		Sys32getpriority, // id32Bit
		"get priority",   // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_sched",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "which"},
			{Type: "int", Name: "who"},
		},
	),
	Setpriority: NewEvent(
		Setpriority,
		Sys32setpriority, // id32Bit
		"setpriority",    // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_sched",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "which"},
			{Type: "int", Name: "who"},
			{Type: "int", Name: "prio"},
		},
	),
	SchedSetparam: NewEvent(
		SchedSetparam,
		Sys32sched_setparam, // id32Bit
		"sched_setparam",    // name
		"",                  // docPath
		false,               // internal
		true,                // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_sched",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "struct sched_param*", Name: "param"},
		},
	),
	SchedGetparam: NewEvent(
		SchedGetparam,
		Sys32sched_getparam, // id32Bit
		"sched_getparam",    // name
		"",                  // docPath
		false,               // internal
		true,                // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_sched",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "struct sched_param*", Name: "param"},
		},
	),
	SchedSetscheduler: NewEvent(
		SchedSetscheduler,
		Sys32sched_setscheduler, // id32Bit
		"sched_setscheduler",    // name
		"",                      // docPath
		false,                   // internal
		true,                    // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_sched",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "int", Name: "policy"},
			{Type: "struct sched_param*", Name: "param"},
		},
	),
	SchedGetscheduler: NewEvent(
		SchedGetscheduler,
		Sys32sched_getscheduler, // id32Bit
		"sched_getscheduler",    // name
		"",                      // docPath
		false,                   // internal
		true,                    // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_sched",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
		},
	),
	SchedGetPriorityMax: NewEvent(
		SchedGetPriorityMax,
		Sys32sched_get_priority_max, // id32Bit
		"sched_get_priority_max",    // name
		"",                          // docPath
		false,                       // internal
		true,                        // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_sched",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "policy"},
		},
	),
	SchedGetPriorityMin: NewEvent(
		SchedGetPriorityMin,
		Sys32sched_get_priority_min, // id32Bit
		"sched_get_priority_min",    // name
		"",                          // docPath
		false,                       // internal
		true,                        // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_sched",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "policy"},
		},
	),
	SchedRrGetInterval: NewEvent(
		SchedRrGetInterval,
		Sys32sched_rr_get_interval_time64, // id32Bit
		"sched_rr_get_interval",           // name
		"",                                // docPath
		false,                             // internal
		true,                              // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_sched",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "struct timespec*", Name: "tp"},
		},
	),
	Mlock: NewEvent(
		Mlock,
		Sys32mlock, // id32Bit
		"mlock",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_mem",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const void*", Name: "addr"},
			{Type: "size_t", Name: "len"},
		},
	),
	Munlock: NewEvent(
		Munlock,
		Sys32munlock, // id32Bit
		"munlock",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_mem",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const void*", Name: "addr"},
			{Type: "size_t", Name: "len"},
		},
	),
	Mlockall: NewEvent(
		Mlockall,
		Sys32mlockall, // id32Bit
		"mlockall",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_mem",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "flags"},
		},
	),
	Munlockall: NewEvent(
		Munlockall,
		Sys32munlockall, // id32Bit
		"munlockall",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_mem",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Vhangup: NewEvent(
		Vhangup,
		Sys32vhangup, // id32Bit
		"vhangup",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"system",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	ModifyLdt: NewEvent(
		ModifyLdt,
		Sys32modify_ldt, // id32Bit
		"modify_ldt",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_mem",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "func"},
			{Type: "void*", Name: "ptr"},
			{Type: "unsigned long", Name: "bytecount"},
		},
	),
	PivotRoot: NewEvent(
		PivotRoot,
		Sys32pivot_root, // id32Bit
		"pivot_root",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"fs",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "new_root"},
			{Type: "const char*", Name: "put_old"},
		},
	),
	Sysctl: NewEvent(
		Sysctl,
		Sys32_sysctl, // id32Bit
		"sysctl",     // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"system",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "struct __sysctl_args*", Name: "args"},
		},
	),
	Prctl: NewEvent(
		Prctl,
		Sys32prctl, // id32Bit
		"prctl",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"proc",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "option"},
			{Type: "unsigned long", Name: "arg2"},
			{Type: "unsigned long", Name: "arg3"},
			{Type: "unsigned long", Name: "arg4"},
			{Type: "unsigned long", Name: "arg5"},
		},
	),
	ArchPrctl: NewEvent(
		ArchPrctl,
		Sys32arch_prctl, // id32Bit
		"arch_prctl",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"proc",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "option"},
			{Type: "unsigned long", Name: "addr"},
		},
	),
	Adjtimex: NewEvent(
		Adjtimex,
		Sys32adjtimex, // id32Bit
		"adjtimex",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"time",
			"time_clock",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "struct timex*", Name: "buf"},
		},
	),
	Setrlimit: NewEvent(
		Setrlimit,
		Sys32setrlimit, // id32Bit
		"setrlimit",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"proc",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "resource"},
			{Type: "const struct rlimit*", Name: "rlim"},
		},
	),
	Chroot: NewEvent(
		Chroot,
		Sys32chroot, // id32Bit
		"chroot",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_dir_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "path"},
		},
	),
	Sync: NewEvent(
		Sync,
		Sys32sync, // id32Bit
		"sync",    // name
		"",        // docPath
		false,     // internal
		true,      // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_sync",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Acct: NewEvent(
		Acct,
		Sys32acct, // id32Bit
		"acct",    // name
		"",        // docPath
		false,     // internal
		true,      // syscall
		[]string{
			"syscalls",
			"system",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "filename"},
		},
	),
	Settimeofday: NewEvent(
		Settimeofday,
		Sys32settimeofday, // id32Bit
		"settimeofday",    // name
		"",                // docPath
		false,             // internal
		true,              // syscall
		[]string{
			"syscalls",
			"time",
			"time_tod",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const struct timeval*", Name: "tv"},
			{Type: "const struct timezone*", Name: "tz"},
		},
	),
	Mount: NewEvent(
		Mount,
		Sys32mount, // id32Bit
		"mount",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"fs",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "source"},
			{Type: "const char*", Name: "target"},
			{Type: "const char*", Name: "filesystemtype"},
			{Type: "unsigned long", Name: "mountflags"},
			{Type: "const void*", Name: "data"},
		},
	),
	Umount2: NewEvent(
		Umount2,
		Sys32umount2, // id32Bit
		"umount2",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"fs",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "target"},
			{Type: "int", Name: "flags"},
		},
	),
	Swapon: NewEvent(
		Swapon,
		Sys32swapon, // id32Bit
		"swapon",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"fs",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "int", Name: "swapflags"},
		},
	),
	Swapoff: NewEvent(
		Swapoff,
		Sys32swapoff, // id32Bit
		"swapoff",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"fs",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "path"},
		},
	),
	Reboot: NewEvent(
		Reboot,
		Sys32reboot, // id32Bit
		"reboot",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"system",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "magic"},
			{Type: "int", Name: "magic2"},
			{Type: "int", Name: "cmd"},
			{Type: "void*", Name: "arg"},
		},
	),
	Sethostname: NewEvent(
		Sethostname,
		Sys32sethostname, // id32Bit
		"sethostname",    // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"syscalls",
			"net",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "name"},
			{Type: "size_t", Name: "len"},
		},
	),
	Setdomainname: NewEvent(
		Setdomainname,
		Sys32setdomainname, // id32Bit
		"setdomainname",    // name
		"",                 // docPath
		false,              // internal
		true,               // syscall
		[]string{
			"syscalls",
			"net",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "name"},
			{Type: "size_t", Name: "len"},
		},
	),
	Iopl: NewEvent(
		Iopl,
		Sys32iopl, // id32Bit
		"iopl",    // name
		"",        // docPath
		false,     // internal
		true,      // syscall
		[]string{
			"syscalls",
			"system",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "level"},
		},
	),
	Ioperm: NewEvent(
		Ioperm,
		Sys32ioperm, // id32Bit
		"ioperm",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"system",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned long", Name: "from"},
			{Type: "unsigned long", Name: "num"},
			{Type: "int", Name: "turn_on"},
		},
	),
	CreateModule: NewEvent(
		CreateModule,
		Sys32create_module, // id32Bit
		"create_module",    // name
		"",                 // docPath
		false,              // internal
		true,               // syscall
		[]string{
			"syscalls",
			"system",
			"system_module",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	InitModule: NewEvent(
		InitModule,
		Sys32init_module, // id32Bit
		"init_module",    // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"default",
			"syscalls",
			"system",
			"system_module",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "void*", Name: "module_image"},
			{Type: "unsigned long", Name: "len"},
			{Type: "const char*", Name: "param_values"},
		},
	),
	DeleteModule: NewEvent(
		DeleteModule,
		Sys32delete_module, // id32Bit
		"delete_module",    // name
		"",                 // docPath
		false,              // internal
		true,               // syscall
		[]string{
			"syscalls",
			"system",
			"system_module",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "name"},
			{Type: "int", Name: "flags"},
		},
	),
	GetKernelSyms: NewEvent(
		GetKernelSyms,
		Sys32get_kernel_syms, // id32Bit
		"get_kernel_syms",    // name
		"",                   // docPath
		false,                // internal
		true,                 // syscall
		[]string{
			"syscalls",
			"system",
			"system_module",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	QueryModule: NewEvent(
		QueryModule,
		Sys32query_module, // id32Bit
		"query_module",    // name
		"",                // docPath
		false,             // internal
		true,              // syscall
		[]string{
			"syscalls",
			"system",
			"system_module",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Quotactl: NewEvent(
		Quotactl,
		Sys32quotactl, // id32Bit
		"quotactl",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"system",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "cmd"},
			{Type: "const char*", Name: "special"},
			{Type: "int", Name: "id"},
			{Type: "void*", Name: "addr"},
		},
	),
	Nfsservctl: NewEvent(
		Nfsservctl,
		Sys32nfsservctl, // id32Bit
		"nfsservctl",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"fs",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Getpmsg: NewEvent(
		Getpmsg,
		Sys32getpmsg, // id32Bit
		"getpmsg",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Putpmsg: NewEvent(
		Putpmsg,
		Sys32putpmsg, // id32Bit
		"putpmsg",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Afs: NewEvent(
		Afs,
		Sys32Undefined, // id32Bit
		"afs",          // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Tuxcall: NewEvent(
		Tuxcall,
		Sys32Undefined, // id32Bit
		"tuxcall",      // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Security: NewEvent(
		Security,
		Sys32Undefined, // id32Bit
		"security",     // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Gettid: NewEvent(
		Gettid,
		Sys32gettid, // id32Bit
		"gettid",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_ids",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Readahead: NewEvent(
		Readahead,
		Sys32readahead, // id32Bit
		"readahead",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"fs",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "off_t", Name: "offset"},
			{Type: "size_t", Name: "count"},
		},
	),
	Setxattr: NewEvent(
		Setxattr,
		Sys32setxattr, // id32Bit
		"setxattr",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "const char*", Name: "name"},
			{Type: "const void*", Name: "value"},
			{Type: "size_t", Name: "size"},
			{Type: "int", Name: "flags"},
		},
	),
	Lsetxattr: NewEvent(
		Lsetxattr,
		Sys32lsetxattr, // id32Bit
		"lsetxattr",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "const char*", Name: "name"},
			{Type: "const void*", Name: "value"},
			{Type: "size_t", Name: "size"},
			{Type: "int", Name: "flags"},
		},
	),
	Fsetxattr: NewEvent(
		Fsetxattr,
		Sys32fsetxattr, // id32Bit
		"fsetxattr",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const char*", Name: "name"},
			{Type: "const void*", Name: "value"},
			{Type: "size_t", Name: "size"},
			{Type: "int", Name: "flags"},
		},
	),
	Getxattr: NewEvent(
		Getxattr,
		Sys32getxattr, // id32Bit
		"getxattr",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "const char*", Name: "name"},
			{Type: "void*", Name: "value"},
			{Type: "size_t", Name: "size"},
		},
	),
	Lgetxattr: NewEvent(
		Lgetxattr,
		Sys32lgetxattr, // id32Bit
		"lgetxattr",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "const char*", Name: "name"},
			{Type: "void*", Name: "value"},
			{Type: "size_t", Name: "size"},
		},
	),
	Fgetxattr: NewEvent(
		Fgetxattr,
		Sys32fgetxattr, // id32Bit
		"fgetxattr",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const char*", Name: "name"},
			{Type: "void*", Name: "value"},
			{Type: "size_t", Name: "size"},
		},
	),
	Listxattr: NewEvent(
		Listxattr,
		Sys32listxattr, // id32Bit
		"listxattr",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "char*", Name: "list"},
			{Type: "size_t", Name: "size"},
		},
	),
	Llistxattr: NewEvent(
		Llistxattr,
		Sys32llistxattr, // id32Bit
		"llistxattr",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "char*", Name: "list"},
			{Type: "size_t", Name: "size"},
		},
	),
	Flistxattr: NewEvent(
		Flistxattr,
		Sys32flistxattr, // id32Bit
		"flistxattr",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "char*", Name: "list"},
			{Type: "size_t", Name: "size"},
		},
	),
	Removexattr: NewEvent(
		Removexattr,
		Sys32removexattr, // id32Bit
		"removexattr",    // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "const char*", Name: "name"},
		},
	),
	Lremovexattr: NewEvent(
		Lremovexattr,
		Sys32lremovexattr, // id32Bit
		"lremovexattr",    // name
		"",                // docPath
		false,             // internal
		true,              // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "const char*", Name: "name"},
		},
	),
	Fremovexattr: NewEvent(
		Fremovexattr,
		Sys32fremovexattr, // id32Bit
		"fremovexattr",    // name
		"",                // docPath
		false,             // internal
		true,              // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const char*", Name: "name"},
		},
	),
	Tkill: NewEvent(
		Tkill,
		Sys32tkill, // id32Bit
		"tkill",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"signals",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "tid"},
			{Type: "int", Name: "sig"},
		},
	),
	Time: NewEvent(
		Time,
		Sys32time, // id32Bit
		"time",    // name
		"",        // docPath
		false,     // internal
		true,      // syscall
		[]string{
			"syscalls",
			"time",
			"time_tod",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "time_t*", Name: "tloc"},
		},
	),
	Futex: NewEvent(
		Futex,
		Sys32futex_time64, // id32Bit
		"futex",           // name
		"",                // docPath
		false,             // internal
		true,              // syscall
		[]string{
			"syscalls",
			"ipc",
			"ipc_futex",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int*", Name: "uaddr"},
			{Type: "int", Name: "futex_op"},
			{Type: "int", Name: "val"},
			{Type: "const struct timespec*", Name: "timeout"},
			{Type: "int*", Name: "uaddr2"},
			{Type: "int", Name: "val3"},
		},
	),
	SchedSetaffinity: NewEvent(
		SchedSetaffinity,
		Sys32sched_setaffinity, // id32Bit
		"sched_setaffinity",    // name
		"",                     // docPath
		false,                  // internal
		true,                   // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_sched",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "size_t", Name: "cpusetsize"},
			{Type: "unsigned long*", Name: "mask"},
		},
	),
	SchedGetaffinity: NewEvent(
		SchedGetaffinity,
		Sys32sched_getaffinity, // id32Bit
		"sched_getaffinity",    // name
		"",                     // docPath
		false,                  // internal
		true,                   // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_sched",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "size_t", Name: "cpusetsize"},
			{Type: "unsigned long*", Name: "mask"},
		},
	),
	SetThreadArea: NewEvent(
		SetThreadArea,
		Sys32set_thread_area, // id32Bit
		"set_thread_area",    // name
		"",                   // docPath
		false,                // internal
		true,                 // syscall
		[]string{
			"syscalls",
			"proc",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "struct user_desc*", Name: "u_info"},
		},
	),
	IoSetup: NewEvent(
		IoSetup,
		Sys32io_setup, // id32Bit
		"io_setup",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_async_io",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned int", Name: "nr_events"},
			{Type: "io_context_t*", Name: "ctx_idp"},
		},
	),
	IoDestroy: NewEvent(
		IoDestroy,
		Sys32io_destroy, // id32Bit
		"io_destroy",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_async_io",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "io_context_t", Name: "ctx_id"},
		},
	),
	IoGetevents: NewEvent(
		IoGetevents,
		Sys32io_getevents, // id32Bit
		"io_getevents",    // name
		"",                // docPath
		false,             // internal
		true,              // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_async_io",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "io_context_t", Name: "ctx_id"},
			{Type: "long", Name: "min_nr"},
			{Type: "long", Name: "nr"},
			{Type: "struct io_event*", Name: "events"},
			{Type: "struct timespec*", Name: "timeout"},
		},
	),
	IoSubmit: NewEvent(
		IoSubmit,
		Sys32io_submit, // id32Bit
		"io_submit",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_async_io",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "io_context_t", Name: "ctx_id"},
			{Type: "long", Name: "nr"},
			{Type: "struct iocb**", Name: "iocbpp"},
		},
	),
	IoCancel: NewEvent(
		IoCancel,
		Sys32io_cancel, // id32Bit
		"io_cancel",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_async_io",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "io_context_t", Name: "ctx_id"},
			{Type: "struct iocb*", Name: "iocb"},
			{Type: "struct io_event*", Name: "result"},
		},
	),
	GetThreadArea: NewEvent(
		GetThreadArea,
		Sys32get_thread_area, // id32Bit
		"get_thread_area",    // name
		"",                   // docPath
		false,                // internal
		true,                 // syscall
		[]string{
			"syscalls",
			"proc",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "struct user_desc*", Name: "u_info"},
		},
	),
	LookupDcookie: NewEvent(
		LookupDcookie,
		Sys32lookup_dcookie, // id32Bit
		"lookup_dcookie",    // name
		"",                  // docPath
		false,               // internal
		true,                // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_dir_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "u64", Name: "cookie"},
			{Type: "char*", Name: "buffer"},
			{Type: "size_t", Name: "len"},
		},
	),
	EpollCreate: NewEvent(
		EpollCreate,
		Sys32epoll_create, // id32Bit
		"epoll_create",    // name
		"",                // docPath
		false,             // internal
		true,              // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_mux_io",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "size"},
		},
	),
	EpollCtlOld: NewEvent(
		EpollCtlOld,
		Sys32Undefined,  // id32Bit
		"epoll_ctl_old", // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_mux_io",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	EpollWaitOld: NewEvent(
		EpollWaitOld,
		Sys32Undefined,   // id32Bit
		"epoll_wait_old", // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_mux_io",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	RemapFilePages: NewEvent(
		RemapFilePages,
		Sys32remap_file_pages, // id32Bit
		"remap_file_pages",    // name
		"",                    // docPath
		false,                 // internal
		true,                  // syscall
		[]string{
			"syscalls",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "void*", Name: "addr"},
			{Type: "size_t", Name: "size"},
			{Type: "int", Name: "prot"},
			{Type: "size_t", Name: "pgoff"},
			{Type: "int", Name: "flags"},
		},
	),
	Getdents64: NewEvent(
		Getdents64,
		Sys32getdents64, // id32Bit
		"getdents64",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_dir_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned int", Name: "fd"},
			{Type: "struct linux_dirent64*", Name: "dirp"},
			{Type: "unsigned int", Name: "count"},
		},
	),
	SetTidAddress: NewEvent(
		SetTidAddress,
		Sys32set_tid_address, // id32Bit
		"set_tid_address",    // name
		"",                   // docPath
		false,                // internal
		true,                 // syscall
		[]string{
			"syscalls",
			"proc",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int*", Name: "tidptr"},
		},
	),
	RestartSyscall: NewEvent(
		RestartSyscall,
		Sys32restart_syscall, // id32Bit
		"restart_syscall",    // name
		"",                   // docPath
		false,                // internal
		true,                 // syscall
		[]string{
			"syscalls",
			"signals",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Semtimedop: NewEvent(
		Semtimedop,
		Sys32semtimedop_time64, // id32Bit
		"semtimedop",           // name
		"",                     // docPath
		false,                  // internal
		true,                   // syscall
		[]string{
			"syscalls",
			"ipc",
			"ipc_sem",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "semid"},
			{Type: "struct sembuf*", Name: "sops"},
			{Type: "size_t", Name: "nsops"},
			{Type: "const struct timespec*", Name: "timeout"},
		},
	),
	Fadvise64: NewEvent(
		Fadvise64,
		Sys32fadvise64, // id32Bit
		"fadvise64",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"fs",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "off_t", Name: "offset"},
			{Type: "size_t", Name: "len"},
			{Type: "int", Name: "advice"},
		},
	),
	TimerCreate: NewEvent(
		TimerCreate,
		Sys32timer_create, // id32Bit
		"timer_create",    // name
		"",                // docPath
		false,             // internal
		true,              // syscall
		[]string{
			"syscalls",
			"time",
			"time_timer",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const clockid_t", Name: "clockid"},
			{Type: "struct sigevent*", Name: "sevp"},
			{Type: "timer_t*", Name: "timer_id"},
		},
	),
	TimerSettime: NewEvent(
		TimerSettime,
		Sys32timer_settime64, // id32Bit
		"timer_settime",      // name
		"",                   // docPath
		false,                // internal
		true,                 // syscall
		[]string{
			"syscalls",
			"time",
			"time_timer",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "timer_t", Name: "timer_id"},
			{Type: "int", Name: "flags"},
			{Type: "const struct itimerspec*", Name: "new_value"},
			{Type: "struct itimerspec*", Name: "old_value"},
		},
	),
	TimerGettime: NewEvent(
		TimerGettime,
		Sys32timer_gettime64, // id32Bit
		"timer_gettime",      // name
		"",                   // docPath
		false,                // internal
		true,                 // syscall
		[]string{
			"syscalls",
			"time",
			"time_timer",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "timer_t", Name: "timer_id"},
			{Type: "struct itimerspec*", Name: "curr_value"},
		},
	),
	TimerGetoverrun: NewEvent(
		TimerGetoverrun,
		Sys32timer_getoverrun, // id32Bit
		"timer_getoverrun",    // name
		"",                    // docPath
		false,                 // internal
		true,                  // syscall
		[]string{
			"syscalls",
			"time",
			"time_timer",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "timer_t", Name: "timer_id"},
		},
	),
	TimerDelete: NewEvent(
		TimerDelete,
		Sys32timer_delete, // id32Bit
		"timer_delete",    // name
		"",                // docPath
		false,             // internal
		true,              // syscall
		[]string{
			"syscalls",
			"time",
			"time_timer",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "timer_t", Name: "timer_id"},
		},
	),
	ClockSettime: NewEvent(
		ClockSettime,
		Sys32clock_settime64, // id32Bit
		"clock_settime",      // name
		"",                   // docPath
		false,                // internal
		true,                 // syscall
		[]string{
			"syscalls",
			"time",
			"time_clock",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const clockid_t", Name: "clockid"},
			{Type: "const struct timespec*", Name: "tp"},
		},
	),
	ClockGettime: NewEvent(
		ClockGettime,
		Sys32clock_gettime64, // id32Bit
		"clock_gettime",      // name
		"",                   // docPath
		false,                // internal
		true,                 // syscall
		[]string{
			"syscalls",
			"time",
			"time_clock",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const clockid_t", Name: "clockid"},
			{Type: "struct timespec*", Name: "tp"},
		},
	),
	ClockGetres: NewEvent(
		ClockGetres,
		Sys32clock_getres_time64, // id32Bit
		"clock_getres",           // name
		"",                       // docPath
		false,                    // internal
		true,                     // syscall
		[]string{
			"syscalls",
			"time",
			"time_clock",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const clockid_t", Name: "clockid"},
			{Type: "struct timespec*", Name: "res"},
		},
	),
	ClockNanosleep: NewEvent(
		ClockNanosleep,
		Sys32clock_nanosleep_time64, // id32Bit
		"clock_nanosleep",           // name
		"",                          // docPath
		false,                       // internal
		true,                        // syscall
		[]string{
			"syscalls",
			"time",
			"time_clock",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const clockid_t", Name: "clockid"},
			{Type: "int", Name: "flags"},
			{Type: "const struct timespec*", Name: "request"},
			{Type: "struct timespec*", Name: "remain"},
		},
	),
	ExitGroup: NewEvent(
		ExitGroup,
		Sys32exit_group, // id32Bit
		"exit_group",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_life",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "status"},
		},
	),
	EpollWait: NewEvent(
		EpollWait,
		Sys32epoll_wait, // id32Bit
		"epoll_wait",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_mux_io",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "epfd"},
			{Type: "struct epoll_event*", Name: "events"},
			{Type: "int", Name: "maxevents"},
			{Type: "int", Name: "timeout"},
		},
	),
	EpollCtl: NewEvent(
		EpollCtl,
		Sys32epoll_ctl, // id32Bit
		"epoll_ctl",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_mux_io",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "epfd"},
			{Type: "int", Name: "op"},
			{Type: "int", Name: "fd"},
			{Type: "struct epoll_event*", Name: "event"},
		},
	),
	Tgkill: NewEvent(
		Tgkill,
		Sys32tgkill, // id32Bit
		"tgkill",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"signals",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "tgid"},
			{Type: "int", Name: "tid"},
			{Type: "int", Name: "sig"},
		},
	),
	Utimes: NewEvent(
		Utimes,
		Sys32utimes, // id32Bit
		"utimes",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "char*", Name: "filename"},
			{Type: "struct timeval*", Name: "times"},
		},
	),
	Vserver: NewEvent(
		Vserver,
		Sys32vserver, // id32Bit
		"vserver",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Mbind: NewEvent(
		Mbind,
		Sys32mbind, // id32Bit
		"mbind",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"system",
			"system_numa",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "void*", Name: "addr"},
			{Type: "unsigned long", Name: "len"},
			{Type: "int", Name: "mode"},
			{Type: "const unsigned long*", Name: "nodemask"},
			{Type: "unsigned long", Name: "maxnode"},
			{Type: "unsigned int", Name: "flags"},
		},
	),
	SetMempolicy: NewEvent(
		SetMempolicy,
		Sys32set_mempolicy, // id32Bit
		"set_mempolicy",    // name
		"",                 // docPath
		false,              // internal
		true,               // syscall
		[]string{
			"syscalls",
			"system",
			"system_numa",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "mode"},
			{Type: "const unsigned long*", Name: "nodemask"},
			{Type: "unsigned long", Name: "maxnode"},
		},
	),
	GetMempolicy: NewEvent(
		GetMempolicy,
		Sys32get_mempolicy, // id32Bit
		"get_mempolicy",    // name
		"",                 // docPath
		false,              // internal
		true,               // syscall
		[]string{
			"syscalls",
			"system",
			"system_numa",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int*", Name: "mode"},
			{Type: "unsigned long*", Name: "nodemask"},
			{Type: "unsigned long", Name: "maxnode"},
			{Type: "void*", Name: "addr"},
			{Type: "unsigned long", Name: "flags"},
		},
	),
	MqOpen: NewEvent(
		MqOpen,
		Sys32mq_open, // id32Bit
		"mq_open",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"ipc",
			"ipc_msgq",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "name"},
			{Type: "int", Name: "oflag"},
			{Type: "mode_t", Name: "mode"},
			{Type: "struct mq_attr*", Name: "attr"},
		},
	),
	MqUnlink: NewEvent(
		MqUnlink,
		Sys32mq_unlink, // id32Bit
		"mq_unlink",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"ipc",
			"ipc_msgq",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "name"},
		},
	),
	MqTimedsend: NewEvent(
		MqTimedsend,
		Sys32mq_timedsend_time64, // id32Bit
		"mq_timedsend",           // name
		"",                       // docPath
		false,                    // internal
		true,                     // syscall
		[]string{
			"syscalls",
			"ipc",
			"ipc_msgq",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "mqd_t", Name: "mqdes"},
			{Type: "const char*", Name: "msg_ptr"},
			{Type: "size_t", Name: "msg_len"},
			{Type: "unsigned int", Name: "msg_prio"},
			{Type: "const struct timespec*", Name: "abs_timeout"},
		},
	),
	MqTimedreceive: NewEvent(
		MqTimedreceive,
		Sys32mq_timedreceive_time64, // id32Bit
		"mq_timedreceive",           // name
		"",                          // docPath
		false,                       // internal
		true,                        // syscall
		[]string{
			"syscalls",
			"ipc",
			"ipc_msgq",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "mqd_t", Name: "mqdes"},
			{Type: "char*", Name: "msg_ptr"},
			{Type: "size_t", Name: "msg_len"},
			{Type: "unsigned int*", Name: "msg_prio"},
			{Type: "const struct timespec*", Name: "abs_timeout"},
		},
	),
	MqNotify: NewEvent(
		MqNotify,
		Sys32mq_notify, // id32Bit
		"mq_notify",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"ipc",
			"ipc_msgq",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "mqd_t", Name: "mqdes"},
			{Type: "const struct sigevent*", Name: "sevp"},
		},
	),
	MqGetsetattr: NewEvent(
		MqGetsetattr,
		Sys32mq_getsetattr, // id32Bit
		"mq_getsetattr",    // name
		"",                 // docPath
		false,              // internal
		true,               // syscall
		[]string{
			"syscalls",
			"ipc",
			"ipc_msgq",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "mqd_t", Name: "mqdes"},
			{Type: "const struct mq_attr*", Name: "newattr"},
			{Type: "struct mq_attr*", Name: "oldattr"},
		},
	),
	KexecLoad: NewEvent(
		KexecLoad,
		Sys32kexec_load, // id32Bit
		"kexec_load",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"system",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned long", Name: "entry"},
			{Type: "unsigned long", Name: "nr_segments"},
			{Type: "struct kexec_segment*", Name: "segments"},
			{Type: "unsigned long", Name: "flags"},
		},
	),
	Waitid: NewEvent(
		Waitid,
		Sys32waitid, // id32Bit
		"waitid",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_life",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "idtype"},
			{Type: "pid_t", Name: "id"},
			{Type: "struct siginfo*", Name: "infop"},
			{Type: "int", Name: "options"},
			{Type: "struct rusage*", Name: "rusage"},
		},
	),
	AddKey: NewEvent(
		AddKey,
		Sys32add_key, // id32Bit
		"add_key",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"system",
			"system_keys",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "type"},
			{Type: "const char*", Name: "description"},
			{Type: "const void*", Name: "payload"},
			{Type: "size_t", Name: "plen"},
			{Type: "key_serial_t", Name: "keyring"},
		},
	),
	RequestKey: NewEvent(
		RequestKey,
		Sys32request_key, // id32Bit
		"request_key",    // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"syscalls",
			"system",
			"system_keys",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "type"},
			{Type: "const char*", Name: "description"},
			{Type: "const char*", Name: "callout_info"},
			{Type: "key_serial_t", Name: "dest_keyring"},
		},
	),
	Keyctl: NewEvent(
		Keyctl,
		Sys32keyctl, // id32Bit
		"keyctl",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"system",
			"system_keys",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "operation"},
			{Type: "unsigned long", Name: "arg2"},
			{Type: "unsigned long", Name: "arg3"},
			{Type: "unsigned long", Name: "arg4"},
			{Type: "unsigned long", Name: "arg5"},
		},
	),
	IoprioSet: NewEvent(
		IoprioSet,
		Sys32ioprio_set, // id32Bit
		"ioprio_set",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_sched",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "which"},
			{Type: "int", Name: "who"},
			{Type: "int", Name: "ioprio"},
		},
	),
	IoprioGet: NewEvent(
		IoprioGet,
		Sys32ioprio_get, // id32Bit
		"ioprio_get",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_sched",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "which"},
			{Type: "int", Name: "who"},
		},
	),
	InotifyInit: NewEvent(
		InotifyInit,
		Sys32inotify_init, // id32Bit
		"inotify_init",    // name
		"",                // docPath
		false,             // internal
		true,              // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_monitor",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	InotifyAddWatch: NewEvent(
		InotifyAddWatch,
		Sys32inotify_add_watch, // id32Bit
		"inotify_add_watch",    // name
		"",                     // docPath
		false,                  // internal
		true,                   // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_monitor",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "u32", Name: "mask"},
		},
	),
	InotifyRmWatch: NewEvent(
		InotifyRmWatch,
		Sys32inotify_rm_watch, // id32Bit
		"inotify_rm_watch",    // name
		"",                    // docPath
		false,                 // internal
		true,                  // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_monitor",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "int", Name: "wd"},
		},
	),
	MigratePages: NewEvent(
		MigratePages,
		Sys32migrate_pages, // id32Bit
		"migrate_pages",    // name
		"",                 // docPath
		false,              // internal
		true,               // syscall
		[]string{
			"syscalls",
			"system",
			"system_numa",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "pid"},
			{Type: "unsigned long", Name: "maxnode"},
			{Type: "const unsigned long*", Name: "old_nodes"},
			{Type: "const unsigned long*", Name: "new_nodes"},
		},
	),
	Openat: NewEvent(
		Openat,
		Sys32openat, // id32Bit
		"openat",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "int", Name: "flags"},
			{Type: "mode_t", Name: "mode"},
		},
	),
	Mkdirat: NewEvent(
		Mkdirat,
		Sys32mkdirat, // id32Bit
		"mkdirat",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_dir_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "mode_t", Name: "mode"},
		},
	),
	Mknodat: NewEvent(
		Mknodat,
		Sys32mknodat, // id32Bit
		"mknodat",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "mode_t", Name: "mode"},
			{Type: "dev_t", Name: "dev"},
		},
	),
	Fchownat: NewEvent(
		Fchownat,
		Sys32fchownat, // id32Bit
		"fchownat",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"default",
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "uid_t", Name: "owner"},
			{Type: "gid_t", Name: "group"},
			{Type: "int", Name: "flags"},
		},
	),
	Futimesat: NewEvent(
		Futimesat,
		Sys32futimesat, // id32Bit
		"futimesat",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "struct timeval*", Name: "times"},
		},
	),
	Newfstatat: NewEvent(
		Newfstatat,
		Sys32fstatat64, // id32Bit
		"newfstatat",   // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "struct stat*", Name: "statbuf"},
			{Type: "int", Name: "flags"},
		},
	),
	Unlinkat: NewEvent(
		Unlinkat,
		Sys32unlinkat, // id32Bit
		"unlinkat",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_link_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "int", Name: "flags"},
		},
	),
	Renameat: NewEvent(
		Renameat,
		Sys32renameat, // id32Bit
		"renameat",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "olddirfd"},
			{Type: "const char*", Name: "oldpath"},
			{Type: "int", Name: "newdirfd"},
			{Type: "const char*", Name: "newpath"},
		},
	),
	Linkat: NewEvent(
		Linkat,
		Sys32linkat, // id32Bit
		"linkat",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_link_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "olddirfd"},
			{Type: "const char*", Name: "oldpath"},
			{Type: "int", Name: "newdirfd"},
			{Type: "const char*", Name: "newpath"},
			{Type: "unsigned int", Name: "flags"},
		},
	),
	Symlinkat: NewEvent(
		Symlinkat,
		Sys32symlinkat, // id32Bit
		"symlinkat",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_link_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "target"},
			{Type: "int", Name: "newdirfd"},
			{Type: "const char*", Name: "linkpath"},
		},
	),
	Readlinkat: NewEvent(
		Readlinkat,
		Sys32readlinkat, // id32Bit
		"readlinkat",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_link_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "char*", Name: "buf"},
			{Type: "int", Name: "bufsiz"},
		},
	),
	Fchmodat: NewEvent(
		Fchmodat,
		Sys32fchmodat, // id32Bit
		"fchmodat",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"default",
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "mode_t", Name: "mode"},
			{Type: "int", Name: "flags"},
		},
	),
	Faccessat: NewEvent(
		Faccessat,
		Sys32faccessat, // id32Bit
		"faccessat",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "int", Name: "mode"},
			{Type: "int", Name: "flags"},
		},
	),
	Pselect6: NewEvent(
		Pselect6,
		Sys32pselect6_time64, // id32Bit
		"pselect6",           // name
		"",                   // docPath
		false,                // internal
		true,                 // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_mux_io",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "nfds"},
			{Type: "fd_set*", Name: "readfds"},
			{Type: "fd_set*", Name: "writefds"},
			{Type: "fd_set*", Name: "exceptfds"},
			{Type: "struct timespec*", Name: "timeout"},
			{Type: "void*", Name: "sigmask"},
		},
	),
	Ppoll: NewEvent(
		Ppoll,
		Sys32ppoll_time64, // id32Bit
		"ppoll",           // name
		"",                // docPath
		false,             // internal
		true,              // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_mux_io",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "struct pollfd*", Name: "fds"},
			{Type: "unsigned int", Name: "nfds"},
			{Type: "struct timespec*", Name: "tmo_p"},
			{Type: "const sigset_t*", Name: "sigmask"},
			{Type: "size_t", Name: "sigsetsize"},
		},
	),
	Unshare: NewEvent(
		Unshare,
		Sys32unshare, // id32Bit
		"unshare",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"proc",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "flags"},
		},
	),
	SetRobustList: NewEvent(
		SetRobustList,
		Sys32set_robust_list, // id32Bit
		"set_robust_list",    // name
		"",                   // docPath
		false,                // internal
		true,                 // syscall
		[]string{
			"syscalls",
			"ipc",
			"ipc_futex",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "struct robust_list_head*", Name: "head"},
			{Type: "size_t", Name: "len"},
		},
	),
	GetRobustList: NewEvent(
		GetRobustList,
		Sys32get_robust_list, // id32Bit
		"get_robust_list",    // name
		"",                   // docPath
		false,                // internal
		true,                 // syscall
		[]string{
			"syscalls",
			"ipc",
			"ipc_futex",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "pid"},
			{Type: "struct robust_list_head**", Name: "head_ptr"},
			{Type: "size_t*", Name: "len_ptr"},
		},
	),
	Splice: NewEvent(
		Splice,
		Sys32splice, // id32Bit
		"splice",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"ipc",
			"ipc_pipe",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd_in"},
			{Type: "off_t*", Name: "off_in"},
			{Type: "int", Name: "fd_out"},
			{Type: "off_t*", Name: "off_out"},
			{Type: "size_t", Name: "len"},
			{Type: "unsigned int", Name: "flags"},
		},
	),
	Tee: NewEvent(
		Tee,
		Sys32tee, // id32Bit
		"tee",    // name
		"",       // docPath
		false,    // internal
		true,     // syscall
		[]string{
			"syscalls",
			"ipc",
			"ipc_pipe",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd_in"},
			{Type: "int", Name: "fd_out"},
			{Type: "size_t", Name: "len"},
			{Type: "unsigned int", Name: "flags"},
		},
	),
	SyncFileRange: NewEvent(
		SyncFileRange,
		Sys32sync_file_range, // id32Bit
		"sync_file_range",    // name
		"",                   // docPath
		false,                // internal
		true,                 // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_sync",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "off_t", Name: "offset"},
			{Type: "off_t", Name: "nbytes"},
			{Type: "unsigned int", Name: "flags"},
		},
	),
	Vmsplice: NewEvent(
		Vmsplice,
		Sys32vmsplice, // id32Bit
		"vmsplice",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"ipc",
			"ipc_pipe",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const struct iovec*", Name: "iov"},
			{Type: "unsigned long", Name: "nr_segs"},
			{Type: "unsigned int", Name: "flags"},
		},
	),
	MovePages: NewEvent(
		MovePages,
		Sys32move_pages, // id32Bit
		"move_pages",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"system",
			"system_numa",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "pid"},
			{Type: "unsigned long", Name: "count"},
			{Type: "const void**", Name: "pages"},
			{Type: "const int*", Name: "nodes"},
			{Type: "int*", Name: "status"},
			{Type: "int", Name: "flags"},
		},
	),
	Utimensat: NewEvent(
		Utimensat,
		Sys32utimensat_time64, // id32Bit
		"utimensat",           // name
		"",                    // docPath
		false,                 // internal
		true,                  // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "struct timespec*", Name: "times"},
			{Type: "int", Name: "flags"},
		},
	),
	EpollPwait: NewEvent(
		EpollPwait,
		Sys32epoll_pwait, // id32Bit
		"epoll_pwait",    // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_mux_io",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "epfd"},
			{Type: "struct epoll_event*", Name: "events"},
			{Type: "int", Name: "maxevents"},
			{Type: "int", Name: "timeout"},
			{Type: "const sigset_t*", Name: "sigmask"},
			{Type: "size_t", Name: "sigsetsize"},
		},
	),
	Signalfd: NewEvent(
		Signalfd,
		Sys32signalfd, // id32Bit
		"signalfd",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"signals",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "sigset_t*", Name: "mask"},
			{Type: "int", Name: "flags"},
		},
	),
	TimerfdCreate: NewEvent(
		TimerfdCreate,
		Sys32timerfd_create, // id32Bit
		"timerfd_create",    // name
		"",                  // docPath
		false,               // internal
		true,                // syscall
		[]string{
			"syscalls",
			"time",
			"time_timer",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "clockid"},
			{Type: "int", Name: "flags"},
		},
	),
	Eventfd: NewEvent(
		Eventfd,
		Sys32eventfd, // id32Bit
		"eventfd",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"signals",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned int", Name: "initval"},
			{Type: "int", Name: "flags"},
		},
	),
	Fallocate: NewEvent(
		Fallocate,
		Sys32fallocate, // id32Bit
		"fallocate",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "int", Name: "mode"},
			{Type: "off_t", Name: "offset"},
			{Type: "off_t", Name: "len"},
		},
	),
	TimerfdSettime: NewEvent(
		TimerfdSettime,
		Sys32timerfd_settime64, // id32Bit
		"timerfd_settime",      // name
		"",                     // docPath
		false,                  // internal
		true,                   // syscall
		[]string{
			"syscalls",
			"time",
			"time_timer",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "int", Name: "flags"},
			{Type: "const struct itimerspec*", Name: "new_value"},
			{Type: "struct itimerspec*", Name: "old_value"},
		},
	),
	TimerfdGettime: NewEvent(
		TimerfdGettime,
		Sys32timerfd_gettime64, // id32Bit
		"timerfd_gettime",      // name
		"",                     // docPath
		false,                  // internal
		true,                   // syscall
		[]string{
			"syscalls",
			"time",
			"time_timer",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "struct itimerspec*", Name: "curr_value"},
		},
	),
	Accept4: NewEvent(
		Accept4,
		Sys32accept4, // id32Bit
		"accept4",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"net",
			"net_sock",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct sockaddr*", Name: "addr"},
			{Type: "int*", Name: "addrlen"},
			{Type: "int", Name: "flags"},
		},
	),
	Signalfd4: NewEvent(
		Signalfd4,
		Sys32signalfd4, // id32Bit
		"signalfd4",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"signals",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const sigset_t*", Name: "mask"},
			{Type: "size_t", Name: "sizemask"},
			{Type: "int", Name: "flags"},
		},
	),
	Eventfd2: NewEvent(
		Eventfd2,
		Sys32eventfd2, // id32Bit
		"eventfd2",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"signals",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned int", Name: "initval"},
			{Type: "int", Name: "flags"},
		},
	),
	EpollCreate1: NewEvent(
		EpollCreate1,
		Sys32epoll_create1, // id32Bit
		"epoll_create1",    // name
		"",                 // docPath
		false,              // internal
		true,               // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_mux_io",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "flags"},
		},
	),
	Dup3: NewEvent(
		Dup3,
		Sys32dup3, // id32Bit
		"dup3",    // name
		"",        // docPath
		false,     // internal
		true,      // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_fd_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "oldfd"},
			{Type: "int", Name: "newfd"},
			{Type: "int", Name: "flags"},
		},
	),
	Pipe2: NewEvent(
		Pipe2,
		Sys32pipe2, // id32Bit
		"pipe2",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"ipc",
			"ipc_pipe",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int[2]", Name: "pipefd"},
			{Type: "int", Name: "flags"},
		},
	),
	InotifyInit1: NewEvent(
		InotifyInit1,
		Sys32inotify_init1, // id32Bit
		"inotify_init1",    // name
		"",                 // docPath
		false,              // internal
		true,               // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_monitor",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "flags"},
		},
	),
	Preadv: NewEvent(
		Preadv,
		Sys32preadv, // id32bit
		"preadv",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_read_write",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const struct iovec*", Name: "iov"},
			{Type: "unsigned long", Name: "iovcnt"},
			{Type: "unsigned long", Name: "pos_l"},
			{Type: "unsigned long", Name: "pos_h"},
		},
	),
	Pwritev: NewEvent(
		Pwritev,
		Sys32pwritev, // id32Bit
		"pwritev",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_read_write",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const struct iovec*", Name: "iov"},
			{Type: "unsigned long", Name: "iovcnt"},
			{Type: "unsigned long", Name: "pos_l"},
			{Type: "unsigned long", Name: "pos_h"},
		},
	),
	RtTgsigqueueinfo: NewEvent(
		RtTgsigqueueinfo,
		Sys32rt_tgsigqueueinfo, // id32Bit
		"rt_tgsigqueueinfo",    // name
		"",                     // docPath
		false,                  // internal
		true,                   // syscall
		[]string{
			"syscalls",
			"signals",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "pid_t", Name: "tgid"},
			{Type: "pid_t", Name: "tid"},
			{Type: "int", Name: "sig"},
			{Type: "siginfo_t*", Name: "info"},
		},
	),
	PerfEventOpen: NewEvent(
		PerfEventOpen,
		Sys32perf_event_open, // id32Bit
		"perf_event_open",    // name
		"",                   // docPath
		false,                // internal
		true,                 // syscall
		[]string{
			"syscalls",
			"system",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "struct perf_event_attr*", Name: "attr"},
			{Type: "pid_t", Name: "pid"},
			{Type: "int", Name: "cpu"},
			{Type: "int", Name: "group_fd"},
			{Type: "unsigned long", Name: "flags"},
		},
	),
	Recvmmsg: NewEvent(
		Recvmmsg,
		Sys32recvmmsg_time64, // id32Bit
		"recvmmsg",           // name
		"",                   // docPath
		false,                // internal
		true,                 // syscall
		[]string{
			"syscalls",
			"net",
			"net_snd_rcv",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct mmsghdr*", Name: "msgvec"},
			{Type: "unsigned int", Name: "vlen"},
			{Type: "int", Name: "flags"},
			{Type: "struct timespec*", Name: "timeout"},
		},
	),
	FanotifyInit: NewEvent(
		FanotifyInit,
		Sys32fanotify_init, // id32Bit
		"fanotify_init",    // name
		"",                 // docPath
		false,              // internal
		true,               // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_monitor",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned int", Name: "flags"},
			{Type: "unsigned int", Name: "event_f_flags"},
		},
	),
	FanotifyMark: NewEvent(
		FanotifyMark,
		Sys32fanotify_mark, // id32Bit
		"fanotify_mark",    // name
		"",                 // docPath
		false,              // internal
		true,               // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_monitor",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fanotify_fd"},
			{Type: "unsigned int", Name: "flags"},
			{Type: "u64", Name: "mask"},
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
		},
	),
	Prlimit64: NewEvent(
		Prlimit64,
		Sys32prlimit64, // id32Bit
		"prlimit64",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"proc",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "int", Name: "resource"},
			{Type: "const struct rlimit64*", Name: "new_limit"},
			{Type: "struct rlimit64*", Name: "old_limit"},
		},
	),
	NameToHandleAt: NewEvent(
		NameToHandleAt,
		Sys32name_to_handle_at, // id32Bit
		"name_to_handle_at",    // name
		"",                     // docPath
		false,                  // internal
		true,                   // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "struct file_handle*", Name: "handle"},
			{Type: "int*", Name: "mount_id"},
			{Type: "int", Name: "flags"},
		},
	),
	OpenByHandleAt: NewEvent(
		OpenByHandleAt,
		Sys32open_by_handle_at, // id32Bit
		"open_by_handle_at",    // name
		"",                     // docPath
		false,                  // internal
		true,                   // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "mount_fd"},
			{Type: "struct file_handle*", Name: "handle"},
			{Type: "int", Name: "flags"},
		},
	),
	ClockAdjtime: NewEvent(
		ClockAdjtime,
		Sys32clock_adjtime, // id32Bit
		"clock_adjtime",    // name
		"",                 // docPath
		false,              // internal
		true,               // syscall
		[]string{
			"syscalls",
			"time",
			"time_clock",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const clockid_t", Name: "clk_id"},
			{Type: "struct timex*", Name: "buf"},
		},
	),
	Syncfs: NewEvent(
		Syncfs,
		Sys32syncfs, // id32Bit
		"syncfs",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_sync",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
		},
	),
	Sendmmsg: NewEvent(
		Sendmmsg,
		Sys32sendmmsg, // id32Bit
		"sendmmsg",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"net",
			"net_snd_rcv",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct mmsghdr*", Name: "msgvec"},
			{Type: "unsigned int", Name: "vlen"},
			{Type: "int", Name: "flags"},
		},
	),
	Setns: NewEvent(
		Setns,
		Sys32setns, // id32Bit
		"setns",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"default",
			"syscalls",
			"proc",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "int", Name: "nstype"},
		},
	),
	Getcpu: NewEvent(
		Getcpu,
		Sys32getcpu, // id32Bit
		"getcpu",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"system",
			"system_numa",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned int*", Name: "cpu"},
			{Type: "unsigned int*", Name: "node"},
			{Type: "struct getcpu_cache*", Name: "tcache"},
		},
	),
	ProcessVmReadv: NewEvent(
		ProcessVmReadv,
		Sys32process_vm_readv, // id32Bit
		"process_vm_readv",    // name
		"",                    // docPath
		false,                 // internal
		true,                  // syscall
		[]string{
			"default",
			"syscalls",
			"proc",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "const struct iovec*", Name: "local_iov"},
			{Type: "unsigned long", Name: "liovcnt"},
			{Type: "const struct iovec*", Name: "remote_iov"},
			{Type: "unsigned long", Name: "riovcnt"},
			{Type: "unsigned long", Name: "flags"},
		},
	),
	ProcessVmWritev: NewEvent(
		ProcessVmWritev,
		Sys32process_vm_writev, // id32Bit
		"process_vm_writev",    // name
		"",                     // docPath
		false,                  // internal
		true,                   // syscall
		[]string{
			"default",
			"syscalls",
			"proc",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "const struct iovec*", Name: "local_iov"},
			{Type: "unsigned long", Name: "liovcnt"},
			{Type: "const struct iovec*", Name: "remote_iov"},
			{Type: "unsigned long", Name: "riovcnt"},
			{Type: "unsigned long", Name: "flags"},
		},
	),
	Kcmp: NewEvent(
		Kcmp,
		Sys32kcmp, // id32Bit
		"kcmp",    // name
		"",        // docPath
		false,     // internal
		true,      // syscall
		[]string{
			"syscalls",
			"proc",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "pid_t", Name: "pid1"},
			{Type: "pid_t", Name: "pid2"},
			{Type: "int", Name: "type"},
			{Type: "unsigned long", Name: "idx1"},
			{Type: "unsigned long", Name: "idx2"},
		},
	),
	FinitModule: NewEvent(
		FinitModule,
		Sys32finit_module, // id32Bit
		"finit_module",    // name
		"",                // docPath
		false,             // internal
		true,              // syscall
		[]string{
			"default",
			"syscalls",
			"system",
			"system_module",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const char*", Name: "param_values"},
			{Type: "int", Name: "flags"},
		},
	),
	SchedSetattr: NewEvent(
		SchedSetattr,
		Sys32sched_setattr, // id32Bit
		"sched_setattr",    // name
		"",                 // docPath
		false,              // internal
		true,               // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_sched",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "struct sched_attr*", Name: "attr"},
			{Type: "unsigned int", Name: "flags"},
		},
	),
	SchedGetattr: NewEvent(
		SchedGetattr,
		Sys32sched_getattr, // id32Bit
		"sched_getattr",    // name
		"",                 // docPath
		false,              // internal
		true,               // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_sched",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "struct sched_attr*", Name: "attr"},
			{Type: "unsigned int", Name: "size"},
			{Type: "unsigned int", Name: "flags"},
		},
	),
	Renameat2: NewEvent(
		Renameat2,
		Sys32renameat2, // id32Bit
		"renameat2",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "olddirfd"},
			{Type: "const char*", Name: "oldpath"},
			{Type: "int", Name: "newdirfd"},
			{Type: "const char*", Name: "newpath"},
			{Type: "unsigned int", Name: "flags"},
		},
	),
	Seccomp: NewEvent(
		Seccomp,
		Sys32seccomp, // id32Bit
		"seccomp",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"proc",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned int", Name: "operation"},
			{Type: "unsigned int", Name: "flags"},
			{Type: "const void*", Name: "args"},
		},
	),
	Getrandom: NewEvent(
		Getrandom,
		Sys32getrandom, // id32Bit
		"getrandom",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"fs",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "void*", Name: "buf"},
			{Type: "size_t", Name: "buflen"},
			{Type: "unsigned int", Name: "flags"},
		},
	),
	MemfdCreate: NewEvent(
		MemfdCreate,
		Sys32memfd_create, // id32Bit
		"memfd_create",    // name
		"",                // docPath
		false,             // internal
		true,              // syscall
		[]string{
			"default",
			"syscalls",
			"fs",
			"fs_file_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "name"},
			{Type: "unsigned int", Name: "flags"},
		},
	),
	KexecFileLoad: NewEvent(
		KexecFileLoad,
		Sys32Undefined,    // id32Bit
		"kexec_file_load", // name
		"",                // docPath
		false,             // internal
		true,              // syscall
		[]string{
			"syscalls",
			"system",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "kernel_fd"},
			{Type: "int", Name: "initrd_fd"},
			{Type: "unsigned long", Name: "cmdline_len"},
			{Type: "const char*", Name: "cmdline"},
			{Type: "unsigned long", Name: "flags"},
		},
	),
	Bpf: NewEvent(
		Bpf,
		Sys32bpf, // id32Bit
		"bpf",    // name
		"",       // docPath
		false,    // internal
		true,     // syscall
		[]string{
			"syscalls",
			"system",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "cmd"},
			{Type: "union bpf_attr*", Name: "attr"},
			{Type: "unsigned int", Name: "size"},
		},
	),
	Execveat: NewEvent(
		Execveat,
		Sys32execveat, // id32Bit
		"execveat",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_life",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{
				NewTailCall(
					"sys_enter_tails",
					"syscall__execveat",
					[]uint32{
						uint32(Execveat),
					},
				),
			},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "const char*const*", Name: "argv"},
			{Type: "const char*const*", Name: "envp"},
			{Type: "int", Name: "flags"},
		},
	),
	Userfaultfd: NewEvent(
		Userfaultfd,
		Sys32userfaultfd, // id32Bit
		"userfaultfd",    // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"syscalls",
			"system",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "flags"},
		},
	),
	Membarrier: NewEvent(
		Membarrier,
		Sys32membarrier, // id32Bit
		"membarrier",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_mem",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "cmd"},
			{Type: "int", Name: "flags"},
		},
	),
	Mlock2: NewEvent(
		Mlock2,
		Sys32mlock2, // id32Bit
		"mlock2",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_mem",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const void*", Name: "addr"},
			{Type: "size_t", Name: "len"},
			{Type: "int", Name: "flags"},
		},
	),
	CopyFileRange: NewEvent(
		CopyFileRange,
		Sys32copy_file_range, // id32Bit
		"copy_file_range",    // name
		"",                   // docPath
		false,                // internal
		true,                 // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_read_write",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd_in"},
			{Type: "off_t*", Name: "off_in"},
			{Type: "int", Name: "fd_out"},
			{Type: "off_t*", Name: "off_out"},
			{Type: "size_t", Name: "len"},
			{Type: "unsigned int", Name: "flags"},
		},
	),
	Preadv2: NewEvent(
		Preadv2,
		Sys32preadv2, // id32Bit
		"preadv2",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_read_write",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const struct iovec*", Name: "iov"},
			{Type: "unsigned long", Name: "iovcnt"},
			{Type: "unsigned long", Name: "pos_l"},
			{Type: "unsigned long", Name: "pos_h"},
			{Type: "int", Name: "flags"},
		},
	),
	Pwritev2: NewEvent(
		Pwritev2,
		Sys32pwritev2, // id32Bit
		"pwritev2",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_read_write",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const struct iovec*", Name: "iov"},
			{Type: "unsigned long", Name: "iovcnt"},
			{Type: "unsigned long", Name: "pos_l"},
			{Type: "unsigned long", Name: "pos_h"},
			{Type: "int", Name: "flags"},
		},
	),
	PkeyMprotect: NewEvent(
		PkeyMprotect,
		Sys32pkey_mprotect, // id32Bit
		"pkey_mprotect",    // name
		"",                 // docPath
		false,              // internal
		true,               // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_mem",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "void*", Name: "addr"},
			{Type: "size_t", Name: "len"},
			{Type: "int", Name: "prot"},
			{Type: "int", Name: "pkey"},
		},
	),
	PkeyAlloc: NewEvent(
		PkeyAlloc,
		Sys32pkey_alloc, // id32Bit
		"pkey_alloc",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_mem",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned int", Name: "flags"},
			{Type: "unsigned long", Name: "access_rights"},
		},
	),
	PkeyFree: NewEvent(
		PkeyFree,
		Sys32pkey_free, // id32Bit
		"pkey_free",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_mem",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "pkey"},
		},
	),
	Statx: NewEvent(
		Statx,
		Sys32statx, // id32Bit
		"statx",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "int", Name: "flags"},
			{Type: "unsigned int", Name: "mask"},
			{Type: "struct statx*", Name: "statxbuf"},
		},
	),
	IoPgetevents: NewEvent(
		IoPgetevents,
		Sys32io_pgetevents_time64, // id32Bit
		"io_pgetevents",           // name
		"",                        // docPath
		false,                     // internal
		true,                      // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_async_io",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "aio_context_t", Name: "ctx_id"},
			{Type: "long", Name: "min_nr"},
			{Type: "long", Name: "nr"},
			{Type: "struct io_event*", Name: "events"},
			{Type: "struct timespec*", Name: "timeout"},
			{Type: "const struct __aio_sigset*", Name: "usig"},
		},
	),
	Rseq: NewEvent(
		Rseq,
		Sys32rseq, // id32Bit
		"rseq",    // name
		"",        // docPath
		false,     // internal
		true,      // syscall
		[]string{
			"syscalls",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "struct rseq*", Name: "rseq"},
			{Type: "u32", Name: "rseq_len"},
			{Type: "int", Name: "flags"},
			{Type: "u32", Name: "sig"},
		},
	),
	PidfdSendSignal: NewEvent(
		PidfdSendSignal,
		Sys32pidfd_send_signal, // id32Bit
		"pidfd_send_signal",    // name
		"",                     // docPath
		false,                  // internal
		true,                   // syscall
		[]string{
			"syscalls",
			"signals",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "pidfd"},
			{Type: "int", Name: "sig"},
			{Type: "siginfo_t*", Name: "info"},
			{Type: "unsigned int", Name: "flags"},
		},
	),
	IoUringSetup: NewEvent(
		IoUringSetup,
		Sys32io_uring_setup, // id32Bit
		"io_uring_setup",    // name
		"",                  // docPath
		false,               // internal
		true,                // syscall
		[]string{
			"syscalls",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned int", Name: "entries"},
			{Type: "struct io_uring_params*", Name: "p"},
		},
	),
	IoUringEnter: NewEvent(
		IoUringEnter,
		Sys32io_uring_enter, // id32Bit
		"io_uring_enter",    // name
		"",                  // docPath
		false,               // internal
		true,                // syscall
		[]string{
			"syscalls",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned int", Name: "fd"},
			{Type: "unsigned int", Name: "to_submit"},
			{Type: "unsigned int", Name: "min_complete"},
			{Type: "unsigned int", Name: "flags"},
			{Type: "sigset_t*", Name: "sig"},
		},
	),
	IoUringRegister: NewEvent(
		IoUringRegister,
		Sys32io_uring_register, // id32Bit
		"io_uring_register",    // name
		"",                     // docPath
		false,                  // internal
		true,                   // syscall
		[]string{
			"syscalls",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned int", Name: "fd"},
			{Type: "unsigned int", Name: "opcode"},
			{Type: "void*", Name: "arg"},
			{Type: "unsigned int", Name: "nr_args"},
		},
	),
	OpenTree: NewEvent(
		OpenTree,
		Sys32open_tree, // id32Bit
		"open_tree",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "dfd"},
			{Type: "const char*", Name: "filename"},
			{Type: "unsigned int", Name: "flags"},
		},
	),
	MoveMount: NewEvent(
		MoveMount,
		Sys32move_mount, // id32Bit
		"move_mount",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"default",
			"syscalls",
			"fs",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "from_dfd"},
			{Type: "const char*", Name: "from_path"},
			{Type: "int", Name: "to_dfd"},
			{Type: "const char*", Name: "to_path"},
			{Type: "unsigned int", Name: "flags"},
		},
	),
	Fsopen: NewEvent(
		Fsopen,
		Sys32fsopen, // id32Bit
		"fsopen",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"fs",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "fsname"},
			{Type: "unsigned int", Name: "flags"},
		},
	),
	Fsconfig: NewEvent(
		Fsconfig,
		Sys32fsconfig, // id32Bit
		"fsconfig",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"fs",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int*", Name: "fs_fd"},
			{Type: "unsigned int", Name: "cmd"},
			{Type: "const char*", Name: "key"},
			{Type: "const void*", Name: "value"},
			{Type: "int", Name: "aux"},
		},
	),
	Fsmount: NewEvent(
		Fsmount,
		Sys32fsmount, // id32Bit
		"fsmount",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"fs",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fsfd"},
			{Type: "unsigned int", Name: "flags"},
			{Type: "unsigned int", Name: "ms_flags"},
		},
	),
	Fspick: NewEvent(
		Fspick,
		Sys32fspick, // id32Bit
		"fspick",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"fs",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "unsigned int", Name: "flags"},
		},
	),
	PidfdOpen: NewEvent(
		PidfdOpen,
		Sys32pidfd_open, // id32Bit
		"pidfd_open",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "unsigned int", Name: "flags"},
		},
	),
	Clone3: NewEvent(
		Clone3,
		Sys32clone3, // id32Bit
		"clone3",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"proc",
			"proc_life",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "struct clone_args*", Name: "cl_args"},
			{Type: "size_t", Name: "size"},
		},
	),
	CloseRange: NewEvent(
		CloseRange,
		Sys32close_range, // id32Bit
		"close_range",    // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned int", Name: "first"},
			{Type: "unsigned int", Name: "last"},
		},
	),
	Openat2: NewEvent(
		Openat2,
		Sys32openat2, // id32Bit
		"openat2",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "dirfd"},
			{Type: "const char*", Name: "pathname"},
			{Type: "struct open_how*", Name: "how"},
			{Type: "size_t", Name: "size"},
		},
	),
	PidfdGetfd: NewEvent(
		PidfdGetfd,
		Sys32pidfd_getfd, // id32Bit
		"pidfd_getfd",    // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"syscalls",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "pidfd"},
			{Type: "int", Name: "targetfd"},
			{Type: "unsigned int", Name: "flags"},
		},
	),
	Faccessat2: NewEvent(
		Faccessat2,
		Sys32faccessat2, // id32Bit
		"faccessat2",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_file_attr",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const char*", Name: "path"},
			{Type: "int", Name: "mode"},
			{Type: "int", Name: "flag"},
		},
	),
	ProcessMadvise: NewEvent(
		ProcessMadvise,
		Sys32process_madvise, // id32Bit
		"process_madvise",    // name
		"",                   // docPath
		false,                // internal
		true,                 // syscall
		[]string{
			"syscalls",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "pidfd"},
			{Type: "void*", Name: "addr"},
			{Type: "size_t", Name: "length"},
			{Type: "int", Name: "advice"},
			{Type: "unsigned long", Name: "flags"},
		},
	),
	EpollPwait2: NewEvent(
		EpollPwait2,
		Sys32epoll_pwait2, // id32Bit
		"epoll_pwait2",    // name
		"",                // docPath
		false,             // internal
		true,              // syscall
		[]string{
			"syscalls",
			"fs",
			"fs_mux_io",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "struct epoll_event*", Name: "events"},
			{Type: "int", Name: "maxevents"},
			{Type: "const struct timespec*", Name: "timeout"},
			{Type: "const sigset_t*", Name: "sigset"},
		},
	),
	MountSetatt: NewEvent(
		MountSetatt,
		Sys32mount_setattr,
		"mount_setattr",
		"",
		false,
		true,
		[]string{
			"syscalls",
			"fs",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "dfd"},
			{Type: "char*", Name: "path"},
			{Type: "unsigned int", Name: "flags"},
			{Type: "struct mount_attr*", Name: "uattr"},
			{Type: "size_t", Name: "usize"},
		},
	),
	QuotactlFd: NewEvent(
		QuotactlFd,
		Sys32quotactl_fd, // id32Bit
		"quotactl_fd",    // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"syscalls",
			"fs",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned int", Name: "fd"},
			{Type: "unsigned int", Name: "cmd"},
			{Type: "qid_t", Name: "id"},
			{Type: "void *", Name: "addr"},
		},
	),
	LandlockCreateRuleset: NewEvent(
		LandlockCreateRuleset,
		Sys32landlock_create_ruleset, // id32Bit
		"landlock_create_ruleset",    // name
		"",                           // docPath
		false,                        // internal
		true,                         // syscall
		[]string{
			"syscalls",
			"proc",
			"fs",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "struct landlock_ruleset_attr*", Name: "attr"},
			{Type: "size_t", Name: "size"},
			{Type: "u32", Name: "flags"},
		},
	),
	LandlockAddRule: NewEvent(
		LandlockAddRule,
		Sys32landlock_add_rule, // id32Bit
		"landlock_add_rule",    // name
		"",                     // docPath
		false,                  // internal
		true,                   // syscall
		[]string{
			"syscalls",
			"proc",
			"fs",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "ruleset_fd"},
			{Type: "landlock_rule_type", Name: "rule_type"},
			{Type: "void*", Name: "rule_attr"},
			{Type: "u32", Name: "flags"},
		},
	),
	LandloclRestrictSet: NewEvent(
		LandloclRestrictSet,
		Sys32landlock_restrict_self, // id32Bit
		"landlock_restrict_self",    // name
		"",                          // docPath
		false,                       // internal
		true,                        // syscall
		[]string{
			"syscalls",
			"proc",
			"fs",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "ruleset_fd"},
			{Type: "u32", Name: "flags"},
		},
	),
	MemfdSecret: NewEvent(
		MemfdSecret,
		Sys32memfd_secret, // id32Bit
		"memfd_secret",    // name
		"",                // docPath
		false,             // internal
		true,              // syscall
		[]string{
			"syscalls",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{{Type: "unsigned int", Name: "flags"}},
	),
	ProcessMrelease: NewEvent(
		ProcessMrelease,
		Sys32process_mrelease, // id32Bit
		"process_mrelease",    // name
		"",                    // docPath
		false,                 // internal
		true,                  // syscall
		[]string{
			"syscalls",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "pidfd"},
			{Type: "unsigned int", Name: "flags"},
		},
	),
	Waitpid: NewEvent(
		Waitpid,
		Sys32waitpid, // id32Bit
		"waitpid",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "int*", Name: "status"},
			{Type: "int", Name: "options"},
		},
	),
	Oldfstat: NewEvent(
		Oldfstat,
		Sys32oldfstat, // id32Bit
		"oldfstat",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Break: NewEvent(
		Break,
		Sys32break, // id32Bit
		"break",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Oldstat: NewEvent(
		Oldstat,
		Sys32oldstat, // id32Bit
		"oldstat",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "char*", Name: "filename"},
			{Type: "struct __old_kernel_stat*", Name: "statbuf"},
		},
	),
	Umount: NewEvent(
		Umount,
		Sys32umount, // id32Bit
		"umount",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "target"},
		},
	),
	Stime: NewEvent(
		Stime,
		Sys32stime, // id32Bit
		"stime",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const time_t*", Name: "t"},
		},
	),
	Stty: NewEvent(
		Stty,
		Sys32stty, // id32Bit
		"stty",    // name
		"",        // docPath
		false,     // internal
		true,      // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Gtty: NewEvent(
		Gtty,
		Sys32gtty, // id32Bit
		"gtty",    // name
		"",        // docPath
		false,     // internal
		true,      // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Nice: NewEvent(
		Nice,
		Sys32nice, // id32Bit
		"nice",    // name
		"",        // docPath
		false,     // internal
		true,      // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "inc"},
		},
	),
	Ftime: NewEvent(
		Ftime,
		Sys32ftime, // id32Bit
		"ftime",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Prof: NewEvent(
		Prof,
		Sys32prof, // id32Bit
		"prof",    // name
		"",        // docPath
		false,     // internal
		true,      // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Signal: NewEvent(
		Signal,
		Sys32signal, // id32Bit
		"signal",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "signum"},
			{Type: "sighandler_t", Name: "handler"},
		},
	),
	Lock: NewEvent(
		Lock,
		Sys32lock, // id32Bit
		"lock",    // name
		"",        // docPath
		false,     // internal
		true,      // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Mpx: NewEvent(
		Mpx,
		Sys32mpx, // id32Bit
		"mpx",    // name
		"",       // docPath
		false,    // internal
		true,     // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Ulimit: NewEvent(
		Ulimit,
		Sys32ulimit, // id32Bit
		"ulimit",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Oldolduname: NewEvent(
		Oldolduname,
		Sys32oldolduname, // id32Bit
		"oldolduname",    // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "struct oldold_utsname*", Name: "name"},
		},
	),
	Sigaction: NewEvent(
		Sigaction,
		Sys32sigaction, // id32Bit
		"sigaction",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "sig"},
			{Type: "const struct sigaction*", Name: "act"},
			{Type: "struct sigaction*", Name: "oact"},
		},
	),
	Sgetmask: NewEvent(
		Sgetmask,
		Sys32sgetmask, // id32Bit
		"sgetmask",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Ssetmask: NewEvent(
		Ssetmask,
		Sys32ssetmask, // id32Bit
		"ssetmask",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "long", Name: "newmask"},
		},
	),
	Sigsuspend: NewEvent(
		Sigsuspend,
		Sys32sigsuspend, // id32Bit
		"sigsuspend",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const sigset_t*", Name: "mask"},
		},
	),
	Sigpending: NewEvent(
		Sigpending,
		Sys32sigpending, // id32Bit
		"sigpending",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "sigset_t*", Name: "set"},
		},
	),
	Oldlstat: NewEvent(
		Oldlstat,
		Sys32oldlstat, // id32Bit
		"oldlstat",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "struct stat*", Name: "statbuf"},
		},
	),
	Readdir: NewEvent(
		Readdir,
		Sys32readdir, // id32Bit
		"readdir",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned int", Name: "fd"},
			{Type: "struct old_linux_dirent*", Name: "dirp"},
			{Type: "unsigned int", Name: "count"},
		},
	),
	Profil: NewEvent(
		Profil,
		Sys32profil, // id32Bit
		"profil",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Socketcall: NewEvent(
		Socketcall,
		Sys32socketcall, // id32Bit
		"socketcall",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "call"},
			{Type: "unsigned long*", Name: "args"},
		},
	),
	Olduname: NewEvent(
		Olduname,
		Sys32olduname, // id32Bit
		"olduname",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "struct utsname*", Name: "buf"},
		},
	),
	Idle: NewEvent(
		Idle,
		Sys32idle, // id32Bit
		"idle",    // name
		"",        // docPath
		false,     // internal
		true,      // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Vm86old: NewEvent(
		Vm86old,
		Sys32vm86old, // id32Bit
		"vm86old",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "struct vm86_struct*", Name: "info"},
		},
	),
	Ipc: NewEvent(
		Ipc,
		Sys32ipc, // id32Bit
		"ipc",    // name
		"",       // docPath
		false,    // internal
		true,     // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned int", Name: "call"},
			{Type: "int", Name: "first"},
			{Type: "unsigned long", Name: "second"},
			{Type: "unsigned long", Name: "third"},
			{Type: "void*", Name: "ptr"},
			{Type: "long", Name: "fifth"},
		},
	),
	Sigreturn: NewEvent(
		Sigreturn,
		Sys32sigreturn, // id32Bit
		"sigreturn",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Sigprocmask: NewEvent(
		Sigprocmask,
		Sys32sigprocmask, // id32Bit
		"sigprocmask",    // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "how"},
			{Type: "const sigset_t *restrict", Name: "set"},
			{Type: "sigset_t *restrict", Name: "oldset"},
		},
	),
	Bdflush: NewEvent(
		Bdflush,
		Sys32bdflush, // id32Bit
		"bdflush",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Afs_syscall: NewEvent(
		Afs_syscall,
		Sys32afs_syscall, // id32Bit
		"afs_syscall",    // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Llseek: NewEvent(
		Llseek,
		Sys32_llseek, // id32Bit
		"llseek",     // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned int", Name: "fd"},
			{Type: "unsigned long", Name: "offset_high"},
			{Type: "unsigned long", Name: "offset_low"},
			{Type: "loff_t*", Name: "result"},
			{Type: "unsigned int", Name: "whence"},
		},
	),
	OldSelect: NewEvent(
		OldSelect,
		Sys32select,  // id32Bit
		"old_select", // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "nfds"},
			{Type: "fd_set*", Name: "readfds"},
			{Type: "fd_set*", Name: "writefds"},
			{Type: "fd_set*", Name: "exceptfds"},
			{Type: "struct timeval*", Name: "timeout"},
		},
	),
	Vm86: NewEvent(
		Vm86,
		Sys32vm86, // id32Bit
		"vm86",    // name
		"",        // docPath
		false,     // internal
		true,      // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned long", Name: "fn"},
			{Type: "struct vm86plus_struct*", Name: "v86"},
		},
	),
	OldGetrlimit: NewEvent(
		OldGetrlimit,
		Sys32getrlimit,  // id32Bit
		"old_getrlimit", // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "resource"},
			{Type: "struct rlimit*", Name: "rlim"},
		},
	),
	Mmap2: NewEvent(
		Mmap2,
		Sys32mmap2, // id32Bit
		"mmap2",    // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned long", Name: "addr"},
			{Type: "unsigned long", Name: "length"},
			{Type: "unsigned long", Name: "prot"},
			{Type: "unsigned long", Name: "flags"},
			{Type: "unsigned long", Name: "fd"},
			{Type: "unsigned long", Name: "pgoffset"},
		},
	),
	Truncate64: NewEvent(
		Truncate64,
		Sys32truncate64, // id32Bit
		"truncate64",    // name
		"",              // docPath
		false,           // internal
		true,            // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "off_t", Name: "length"},
		},
	),
	Ftruncate64: NewEvent(
		Ftruncate64,
		Sys32ftruncate64, // id32Bit
		"ftruncate64",    // name
		"",               // docPath
		false,            // internal
		true,             // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "off_t", Name: "length"},
		},
	),
	Stat64: NewEvent(
		Stat64,
		Sys32stat64, // id32Bit
		"stat64",    // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "struct stat64*", Name: "statbuf"},
		},
	),
	Lstat64: NewEvent(
		Lstat64,
		Sys32lstat64, // id32Bit
		"lstat64",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "struct stat64*", Name: "statbuf"},
		},
	),
	Fstat64: NewEvent(
		Fstat64,
		Sys32fstat64, // id32Bit
		"fstat64",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "struct stat64*", Name: "statbuf"},
		},
	),
	Lchown16: NewEvent(
		Lchown16,
		Sys32lchown, // id32Bit
		"lchown16",  // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "old_uid_t", Name: "owner"},
			{Type: "old_gid_t", Name: "group"},
		},
	),
	Getuid16: NewEvent(
		Getuid16,
		Sys32getuid, // id32Bit
		"getuid16",  // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Getgid16: NewEvent(
		Getgid16,
		Sys32getgid, // id32Bit
		"getgid16",  // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Geteuid16: NewEvent(
		Geteuid16,
		Sys32geteuid, // id32Bit
		"geteuid16",  // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Getegid16: NewEvent(
		Getegid16,
		Sys32getegid, // id32Bit
		"getegid16",  // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	Setreuid16: NewEvent(
		Setreuid16,
		Sys32setreuid, // id32Bit
		"setreuid16",  // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "old_uid_t", Name: "ruid"},
			{Type: "old_uid_t", Name: "euid"},
		},
	),
	Setregid16: NewEvent(
		Setregid16,
		Sys32setregid, // id32Bit
		"setregid16",  // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "old_gid_t", Name: "rgid"},
			{Type: "old_gid_t", Name: "egid"},
		},
	),
	Getgroups16: NewEvent(
		Getgroups16,
		Sys32getgroups, // id32Bit
		"getgroups16",  // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "size"},
			{Type: "old_gid_t*", Name: "list"},
		},
	),
	Setgroups16: NewEvent(
		Setgroups16,
		Sys32setgroups, // id32Bit
		"setgroups16",  // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "size_t", Name: "size"},
			{Type: "const gid_t*", Name: "list"},
		},
	),
	Fchown16: NewEvent(
		Fchown16,
		Sys32fchown, // id32Bit
		"fchown16",  // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned int", Name: "fd"},
			{Type: "old_uid_t", Name: "user"},
			{Type: "old_gid_t", Name: "group"},
		},
	),
	Setresuid16: NewEvent(
		Setresuid16,
		Sys32setresuid, // id32Bit
		"setresuid16",  // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "old_uid_t", Name: "ruid"},
			{Type: "old_uid_t", Name: "euid"},
			{Type: "old_uid_t", Name: "suid"},
		},
	),
	Getresuid16: NewEvent(
		Getresuid16,
		Sys32getresuid, // id32Bit
		"getresuid16",  // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "old_uid_t*", Name: "ruid"},
			{Type: "old_uid_t*", Name: "euid"},
			{Type: "old_uid_t*", Name: "suid"},
		},
	),
	Setresgid16: NewEvent(
		Setresgid16,
		Sys32setresgid, // id32Bit
		"setresgid16",  // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "old_uid_t", Name: "rgid"},
			{Type: "old_uid_t", Name: "euid"},
			{Type: "old_uid_t", Name: "suid"},
		},
	),
	Getresgid16: NewEvent(
		Getresgid16,
		Sys32getresgid, // id32Bit
		"getresgid16",  // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "old_gid_t*", Name: "rgid"},
			{Type: "old_gid_t*", Name: "egid"},
			{Type: "old_gid_t*", Name: "sgid"},
		},
	),
	Chown16: NewEvent(
		Chown16,
		Sys32chown, // id32Bit
		"chown16",  // name
		"",         // docPath
		false,      // internal
		true,       // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "old_uid_t", Name: "owner"},
			{Type: "old_gid_t", Name: "group"},
		},
	),
	Setuid16: NewEvent(
		Setuid16,
		Sys32setuid, // id32Bit
		"setuid16",  // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "old_old_uid_t", Name: "uid"},
		},
	),
	Setgid16: NewEvent(
		Setgid16,
		Sys32setgid, // id32Bit
		"setgid16",  // name
		"",          // docPath
		false,       // internal
		true,        // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "old_gid_t", Name: "gid"},
		},
	),
	Setfsuid16: NewEvent(
		Setfsuid16,
		Sys32setfsuid, // id32Bit
		"setfsuid16",  // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "old_uid_t", Name: "fsuid"},
		},
	),
	Setfsgid16: NewEvent(
		Setfsgid16,
		Sys32setfsgid, // id32Bit
		"setfsgid16",  // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "old_gid_t", Name: "fsgid"},
		},
	),
	Fcntl64: NewEvent(
		Fcntl64,
		Sys32fcntl64, // id32Bit
		"fcntl64",    // name
		"",           // docPath
		false,        // internal
		true,         // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "int", Name: "cmd"},
			{Type: "unsigned long", Name: "arg"},
		},
	),
	Sendfile32: NewEvent(
		Sendfile32,
		Sys32sendfile, // id32Bit
		"sendfile32",  // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "out_fd"},
			{Type: "int", Name: "in_fd"},
			{Type: "off_t*", Name: "offset"},
			{Type: "size_t", Name: "count"},
		},
	),
	Statfs64: NewEvent(
		Statfs64,
		Sys32statfs64, // id32Bit
		"statfs64",    // name
		"",            // docPath
		false,         // internal
		true,          // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "size_t", Name: "sz"},
			{Type: "struct statfs64*", Name: "buf"},
		},
	),
	Fstatfs64: NewEvent(
		Fstatfs64,
		Sys32fstatfs64, // id32Bit
		"fstatfs64",    // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "size_t", Name: "sz"},
			{Type: "struct statfs64*", Name: "buf"},
		},
	),
	Fadvise64_64: NewEvent(
		Fadvise64_64,
		Sys32fadvise64_64, // id32Bit
		"fadvise64_64",    // name
		"",                // docPath
		false,             // internal
		true,              // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "loff_t", Name: "offset"},
			{Type: "loff_t", Name: "len"},
			{Type: "int", Name: "advice"},
		},
	),
	ClockGettime32: NewEvent(
		ClockGettime32,
		Sys32clock_gettime, // id32Bit
		"clock_gettime32",  // name
		"",                 // docPath
		false,              // internal
		true,               // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "clockid_t", Name: "which_clock"},
			{Type: "struct old_timespec32*", Name: "tp"},
		},
	),
	ClockSettime32: NewEvent(
		ClockSettime32,
		Sys32clock_settime, // id32Bit
		"clock_settime32",  // name
		"",                 // docPath
		false,              // internal
		true,               // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "clockid_t", Name: "which_clock"},
			{Type: "struct old_timespec32*", Name: "tp"},
		},
	),
	ClockAdjtime64: NewEvent(
		ClockAdjtime64,
		Sys32clock_adjtime64, // id32Bit
		"clock_adjtime64",    // name
		"",                   // docPath
		false,                // internal
		true,                 // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	ClockGetresTime32: NewEvent(
		ClockGetresTime32,
		Sys32clock_getres,     // id32Bit
		"clock_getres_time32", // name
		"",                    // docPath
		false,                 // internal
		true,                  // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "clockid_t", Name: "which_clock"},
			{Type: "struct old_timespec32*", Name: "tp"},
		},
	),
	ClockNanosleepTime32: NewEvent(
		ClockNanosleepTime32,
		Sys32clock_nanosleep,     // id32Bit
		"clock_nanosleep_time32", // name
		"",                       // docPath
		false,                    // internal
		true,                     // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "clockid_t", Name: "which_clock"},
			{Type: "int", Name: "flags"},
			{Type: "struct old_timespec32*", Name: "rqtp"},
			{Type: "struct old_timespec32*", Name: "rmtp"},
		},
	),
	TimerGettime32: NewEvent(
		TimerGettime32,
		Sys32timer_gettime, // id32Bit
		"timer_gettime32",  // name
		"",                 // docPath
		false,              // internal
		true,               // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "timer_t", Name: "timer_id"},
			{Type: "struct old_itimerspec32*", Name: "setting"},
		},
	),
	TimerSettime32: NewEvent(
		TimerSettime32,
		Sys32timer_settime, // id32Bit
		"timer_settime32",  // name
		"",                 // docPath
		false,              // internal
		true,               // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "timer_t", Name: "timer_id"},
			{Type: "int", Name: "flags"},
			{Type: "struct old_itimerspec32*", Name: "new"},
			{Type: "struct old_itimerspec32*", Name: "old"},
		},
	),
	TimerfdGettime32: NewEvent(
		TimerfdGettime32,
		Sys32timerfd_gettime, // id32Bit
		"timerfd_gettime32",  // name
		"",                   // docPath
		false,                // internal
		true,                 // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "ufd"},
			{Type: "struct old_itimerspec32*", Name: "otmr"},
		},
	),
	TimerfdSettime32: NewEvent(
		TimerfdSettime32,
		Sys32timerfd_settime, // id32Bit
		"timerfd_settime32",  // name
		"",                   // docPath
		false,                // internal
		true,                 // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "ufd"},
			{Type: "int", Name: "flags"},
			{Type: "struct old_itimerspec32*", Name: "utmr"},
			{Type: "struct old_itimerspec32*", Name: "otmr"},
		},
	),
	UtimensatTime32: NewEvent(
		UtimensatTime32,
		Sys32utimensat,     // id32Bit
		"utimensat_time32", // name
		"",                 // docPath
		false,              // internal
		true,               // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned int", Name: "dfd"},
			{Type: "char*", Name: "filename"},
			{Type: "struct old_timespec32*", Name: "t"},
			{Type: "int", Name: "flags"},
		},
	),
	Pselect6Time32: NewEvent(
		Pselect6Time32,
		Sys32pselect6,     // id32Bit
		"pselect6_time32", // name
		"",                // docPath
		false,             // internal
		true,              // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "n"},
			{Type: "fd_set*", Name: "inp"},
			{Type: "fd_set*", Name: "outp"},
			{Type: "fd_set*", Name: "exp"},
			{Type: "struct old_timespec32*", Name: "tsp"},
			{Type: "void*", Name: "sig"},
		},
	),
	PpollTime32: NewEvent(
		PpollTime32,
		Sys32ppoll,     // id32Bit
		"ppoll_time32", // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "struct pollfd*", Name: "ufds"},
			{Type: "unsigned int", Name: "nfds"},
			{Type: "struct old_timespec32*", Name: "tsp"},
			{Type: "sigset_t*", Name: "sigmask"},
			{Type: "size_t", Name: "sigsetsize"},
		},
	),
	IoPgeteventsTime32: NewEvent(
		IoPgeteventsTime32,
		Sys32io_pgetevents,     // id32Bit
		"io_pgetevents_time32", // name
		"",                     // docPath
		false,                  // internal
		true,                   // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	RecvmmsgTime32: NewEvent(
		RecvmmsgTime32,
		Sys32recvmmsg,     // id32Bit
		"recvmmsg_time32", // name
		"",                // docPath
		false,             // internal
		true,              // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "struct mmsghdr*", Name: "mmsg"},
			{Type: "unsigned int", Name: "vlen"},
			{Type: "unsigned int", Name: "flags"},
			{Type: "struct old_timespec32*", Name: "timeout"},
		},
	),
	MqTimedsendTime32: NewEvent(
		MqTimedsendTime32,
		Sys32mq_timedsend,     // id32Bit
		"mq_timedsend_time32", // name
		"",                    // docPath
		false,                 // internal
		true,                  // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "mqd_t", Name: "mqdes"},
			{Type: "char*", Name: "u_msg_ptr"},
			{Type: "unsigned int", Name: "msg_len"},
			{Type: "unsigned int", Name: "msg_prio"},
			{Type: "struct old_timespec32*", Name: "u_abs_timeout"},
		},
	),
	MqTimedreceiveTime32: NewEvent(
		MqTimedreceiveTime32,
		Sys32mq_timedreceive,     // id32Bit
		"mq_timedreceive_time32", // name
		"",                       // docPath
		false,                    // internal
		true,                     // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "mqd_t", Name: "mqdes"},
			{Type: "char*", Name: "u_msg_ptr"},
			{Type: "unsigned int", Name: "msg_len"},
			{Type: "unsigned int*", Name: "u_msg_prio"},
			{Type: "struct old_timespec32*", Name: "u_abs_timeout"},
		},
	),
	RtSigtimedwaitTime32: NewEvent(
		RtSigtimedwaitTime32,
		Sys32rt_sigtimedwait,     // id32Bit
		"rt_sigtimedwait_time32", // name
		"",                       // docPath
		false,                    // internal
		true,                     // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "sigset_t*", Name: "uthese"},
			{Type: "siginfo_t*", Name: "uinfo"},
			{Type: "struct old_timespec32*", Name: "uts"},
			{Type: "size_t", Name: "sigsetsize"},
		},
	),
	FutexTime32: NewEvent(
		FutexTime32,
		Sys32futex,     // id32Bit
		"futex_time32", // name
		"",             // docPath
		false,          // internal
		true,           // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "u32*", Name: "uaddr"},
			{Type: "int", Name: "op"},
			{Type: "u32", Name: "val"},
			{Type: "struct old_timespec32*", Name: "utime"},
			{Type: "u32*", Name: "uaddr2"},
			{Type: "u32", Name: "val3"},
		},
	),
	SchedRrGetInterval32: NewEvent(
		SchedRrGetInterval32,
		Sys32sched_rr_get_interval,     // id32Bit
		"sched_rr_get_interval_time32", // name
		"",                             // docPath
		false,                          // internal
		true,                           // syscall
		[]string{
			"syscalls",
			"32bit_unique",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "struct old_timespec32*", Name: "interval"},
		},
	),
	SysEnter: NewEvent(
		SysEnter,
		Sys32Undefined, // id32Bit
		"sys_enter",    // name
		"",             // docPath
		false,          // internal
		false,          // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SysEnter, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "syscall"},
		},
	),
	SysExit: NewEvent(
		SysExit,
		Sys32Undefined, // id32Bit
		"sys_exit",     // name
		"",             // docPath
		false,          // internal
		false,          // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SysExit, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "syscall"},
		},
	),
	SchedProcessFork: NewEvent(
		SchedProcessFork,
		Sys32Undefined,       // id32Bit
		"sched_process_fork", // name
		"",                   // docPath
		false,                // internal
		false,                // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SchedProcessFork, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "parent_tid"},
			{Type: "int", Name: "parent_ns_tid"},
			{Type: "int", Name: "parent_pid"},
			{Type: "int", Name: "parent_ns_pid"},
			{Type: "int", Name: "child_tid"},
			{Type: "int", Name: "child_ns_tid"},
			{Type: "int", Name: "child_pid"},
			{Type: "int", Name: "child_ns_pid"},
			{Type: "unsigned long", Name: "start_time"},
		},
	),
	SchedProcessExec: NewEvent(
		SchedProcessExec,
		Sys32Undefined,       // id32Bit
		"sched_process_exec", // name
		"",                   // docPath
		false,                // internal
		false,                // syscall
		[]string{
			"default",
			"proc",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SchedProcessExec, true),
				NewProbe(probes.LoadElfPhdrs, false),
			},
			[]*KSymbol{},
			[]*TailCall{
				NewTailCall(
					"prog_array_tp",
					"sched_process_exec_event_submit_tail",
					[]uint32{
						TailSchedProcessExecEventSubmit,
					},
				),
			},
			NewCapabilities(
				map[capabilities.RingType][]cap.Value{
					capabilities.Base: {
						// 1. set by processSchedProcessFork IF ExecHash enabled
						// 2. set by processSchedProcessExec by CaptureExec if needed
						// cap.SYS_PTRACE,
					},
				},
			),
		),
		[]trace.ArgMeta{
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
			{Type: "const char**", Name: "env"},
		},
	),
	SchedProcessExit: NewEvent(
		SchedProcessExit,
		Sys32Undefined,       // id32Bit
		"sched_process_exit", // name
		"",                   // docPath
		false,                // internal
		false,                // syscall
		[]string{
			"proc",
			"proc_life",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SchedProcessExit, true),
				NewProbe(probes.SchedProcessFree, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "long", Name: "exit_code"},
			// The field value represents that all threads exited at the event time.
			// Multiple exits of threads of the same process group at the same time could result that all threads exit
			// events would have 'true' value in this field altogether.
			{Type: "bool", Name: "process_group_exit"},
		},
	),
	SchedSwitch: NewEvent(
		SchedSwitch,
		Sys32Undefined, // id32Bit
		"sched_switch", // name
		"",             // docPath
		false,          // internal
		false,          // syscall
		[]string{},     // sets
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SchedSwitch, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "cpu"},
			{Type: "int", Name: "prev_tid"},
			{Type: "const char*", Name: "prev_comm"},
			{Type: "int", Name: "next_tid"},
			{Type: "const char*", Name: "next_comm"},
		},
	),
	DoExit: NewEvent(
		DoExit,
		Sys32Undefined, // id32Bit
		"do_exit",      // name
		"",             // docPath
		false,          // internal
		false,          // syscall
		[]string{
			"proc",
			"proc_life",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.DoExit, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	CapCapable: NewEvent(
		CapCapable,
		Sys32Undefined, // id32Bit
		"cap_capable",  // name
		"",             // docPath
		false,          // internal
		false,          // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.CapCapable, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "cap"},
		},
	),
	VfsWrite: NewEvent(
		VfsWrite,
		Sys32Undefined, // id32Bit
		"vfs_write",    // name
		"",             // docPath
		false,          // internal
		false,          // syscall
		[]string{},     // sets
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.VfsWrite, true),
				NewProbe(probes.VfsWriteRet, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "size_t", Name: "count"},
			{Type: "off_t", Name: "pos"},
		},
	),
	VfsWritev: NewEvent(
		VfsWritev,
		Sys32Undefined, // id32Bit
		"vfs_writev",   // name
		"",             // docPath
		false,          // internal
		false,          // syscall
		[]string{},     // sets
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.VfsWriteV, true),
				NewProbe(probes.VfsWriteVRet, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "unsigned long", Name: "vlen"},
			{Type: "off_t", Name: "pos"},
		},
	),
	MemProtAlert: NewEvent(
		MemProtAlert,
		Sys32Undefined,   // id32Bit
		"mem_prot_alert", // name
		"",               // docPath
		false,            // internal
		false,            // syscall
		[]string{},       // sets
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SecurityMmapAddr, true),
				NewProbe(probes.SecurityFileMProtect, true),
				NewProbe(probes.SyscallEnter__Internal, true),
			},
			[]*KSymbol{},
			[]*TailCall{
				NewTailCall(
					"sys_enter_init_tail",
					"sys_enter_init",
					[]uint32{
						uint32(Mmap),
						uint32(Mprotect),
						uint32(PkeyMprotect),
					},
				),
			},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
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
	),
	CommitCreds: NewEvent(
		CommitCreds,
		Sys32Undefined, // id32Bit
		"commit_creds", // name
		"",             // docPath
		false,          // internal
		false,          // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.CommitCreds, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "slim_cred_t", Name: "old_cred"},
			{Type: "slim_cred_t", Name: "new_cred"},
		},
	),
	SwitchTaskNS: NewEvent(
		SwitchTaskNS,
		Sys32Undefined,   // id32Bit
		"switch_task_ns", // name
		"",               // docPath
		false,            // internal
		false,            // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SwitchTaskNS, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			&Capabilities{}),
		[]trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "u32", Name: "new_mnt"},
			{Type: "u32", Name: "new_pid"},
			{Type: "u32", Name: "new_uts"},
			{Type: "u32", Name: "new_ipc"},
			{Type: "u32", Name: "new_net"},
			{Type: "u32", Name: "new_cgroup"},
		},
	),
	MagicWrite: NewEvent(
		MagicWrite,
		Sys32Undefined,                   // id32Bit
		"magic_write",                    // name
		"security_alerts/magic_write.md", // docPath
		false,                            // internal
		false,                            // syscall
		[]string{},                       // sets
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.VfsWrite, true),
				NewProbe(probes.VfsWriteRet, true),
				NewProbe(probes.VfsWriteV, false),
				NewProbe(probes.VfsWriteVRet, false),
				NewProbe(probes.KernelWrite, false),
				NewProbe(probes.KernelWriteRet, false),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "bytes", Name: "bytes"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
		},
	),
	CgroupAttachTask: NewEvent(
		CgroupAttachTask,
		Sys32Undefined,       // id32Bit
		"cgroup_attach_task", // name
		"",                   // docPath
		false,                // internal
		false,                // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.CgroupAttachTask, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "cgroup_path"},
			{Type: "const char*", Name: "comm"},
			{Type: "pid_t", Name: "pid"},
		},
	),
	CgroupMkdir: NewEvent(
		CgroupMkdir,
		Sys32Undefined, // id32Bit
		"cgroup_mkdir", // name
		"",             // docPath
		false,          // internal
		false,          // syscall
		[]string{},     // sets
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.CgroupMkdir, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "u64", Name: "cgroup_id"},
			{Type: "const char*", Name: "cgroup_path"},
			{Type: "u32", Name: "hierarchy_id"},
		},
	),
	CgroupRmdir: NewEvent(
		CgroupRmdir,
		Sys32Undefined, // id32Bit
		"cgroup_rmdir", // name
		"",             // docPath
		false,          // internal
		false,          // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.CgroupRmdir, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "u64", Name: "cgroup_id"},
			{Type: "const char*", Name: "cgroup_path"},
			{Type: "u32", Name: "hierarchy_id"},
		},
	),
	SecurityBprmCheck: NewEvent(
		SecurityBprmCheck,
		Sys32Undefined,        // id32Bit
		"security_bprm_check", // name
		"",                    // docPath
		false,                 // internal
		false,                 // syscall
		[]string{
			"lsm_hooks",
			"proc",
			"proc_life",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SecurityBPRMCheck, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
		},
	),
	SecurityFileOpen: NewEvent(
		SecurityFileOpen,
		Sys32Undefined,       // id32Bit
		"security_file_open", // name
		"",                   // docPath
		false,                // internal
		false,                // syscall
		[]string{
			"lsm_hooks",
			"fs",
			"fs_file_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SecurityFileOpen, true),
				NewProbe(probes.SyscallEnter__Internal, true),
			},
			[]*KSymbol{},
			[]*TailCall{
				NewTailCall(
					"sys_enter_init_tail",
					"sys_enter_init",
					[]uint32{
						uint32(Open),
						uint32(Openat),
						uint32(Openat2),
						uint32(OpenByHandleAt),
						uint32(Execve),
						uint32(Execveat),
					},
				),
			},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "int", Name: "flags"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "unsigned long", Name: "ctime"},
			{Type: "const char*", Name: "syscall_pathname"},
		},
	),
	SecurityInodeUnlink: NewEvent(
		SecurityInodeUnlink,
		Sys32Undefined,          // id32Bit
		"security_inode_unlink", // name
		"",                      // docPath
		false,                   // internal
		false,                   // syscall
		[]string{
			"default",
			"lsm_hooks",
			"fs",
			"fs_file_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SecurityInodeUnlink, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "dev_t", Name: "dev"},
			{Type: "u64", Name: "ctime"},
		},
	),
	SecuritySocketCreate: NewEvent(
		SecuritySocketCreate,
		Sys32Undefined,           // id32Bit
		"security_socket_create", // name
		"",                       // docPath
		false,                    // internal
		false,                    // syscall
		[]string{
			"lsm_hooks",
			"net",
			"net_sock",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SecuritySocketCreate, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "family"},
			{Type: "int", Name: "type"},
			{Type: "int", Name: "protocol"},
			{Type: "int", Name: "kern"},
		},
	),
	SecuritySocketListen: NewEvent(
		SecuritySocketListen,
		Sys32Undefined,           // id32Bit
		"security_socket_listen", // name
		"",                       // docPath
		false,                    // internal
		false,                    // syscall
		[]string{
			"lsm_hooks",
			"net",
			"net_sock",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SecuritySocketListen, true),
				NewProbe(probes.SyscallEnter__Internal, true),
			},
			[]*KSymbol{},
			[]*TailCall{
				NewTailCall(
					"sys_enter_init_tail",
					"sys_enter_init",
					[]uint32{
						uint32(Listen),
					},
				),
			},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct sockaddr*", Name: "local_addr"},
			{Type: "int", Name: "backlog"},
		},
	),
	SecuritySocketConnect: NewEvent(
		SecuritySocketConnect,
		Sys32Undefined,            // id32Bit
		"security_socket_connect", // name
		"",                        // docPath
		false,                     // internal
		false,                     // syscall
		[]string{
			"default",
			"lsm_hooks",
			"net",
			"net_sock",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SecuritySocketConnect, true),
				NewProbe(probes.SyscallEnter__Internal, true),
			},
			[]*KSymbol{},
			[]*TailCall{
				NewTailCall(
					"sys_enter_init_tail",
					"sys_enter_init",
					[]uint32{
						uint32(Connect),
					},
				),
			},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct sockaddr*", Name: "remote_addr"},
		},
	),
	SecuritySocketAccept: NewEvent(
		SecuritySocketAccept,
		Sys32Undefined,           // id32Bit
		"security_socket_accept", // name
		"",                       // docPath
		false,                    // internal
		true,                     // syscall
		[]string{
			"default",
			"lsm_hooks",
			"net",
			"net_sock",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SecuritySocketAccept, true),
				NewProbe(probes.SyscallEnter__Internal, true),
			},
			[]*KSymbol{},
			[]*TailCall{
				NewTailCall(
					"sys_enter_init_tail",
					"sys_enter_init",
					[]uint32{
						uint32(Accept),
						uint32(Accept4),
					},
				),
			},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct sockaddr*", Name: "local_addr"},
		},
	),
	SecuritySocketBind: NewEvent(
		SecuritySocketBind,
		Sys32Undefined,         // id32Bit
		"security_socket_bind", // name
		"",                     // docPath
		false,                  // internal
		false,                  // syscall
		[]string{
			"default",
			"lsm_hooks",
			"net",
			"net_sock",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SecuritySocketBind, true),
				NewProbe(probes.SyscallEnter__Internal, true),
			},
			[]*KSymbol{},
			[]*TailCall{
				NewTailCall(
					"sys_enter_init_tail",
					"sys_enter_init",
					[]uint32{
						uint32(Bind),
					},
				),
			},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct sockaddr*", Name: "local_addr"},
		},
	),
	SecuritySocketSetsockopt: NewEvent(
		SecuritySocketSetsockopt,
		Sys32Undefined,                            // id32Bit
		"security_socket_setsockopt",              // name
		"lsm_hooks/security_socket_setsockopt.md", // docPath
		false, // internal
		false, // syscall
		[]string{
			"lsm_hooks",
			"net",
			"net_sock",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SecuritySocketSetsockopt, true),
				NewProbe(probes.SyscallEnter__Internal, true),
			},
			[]*KSymbol{},
			[]*TailCall{
				NewTailCall(
					"sys_enter_init_tail",
					"sys_enter_init",
					[]uint32{
						uint32(Setsockopt),
					},
				),
			},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "int", Name: "level"},
			{Type: "int", Name: "optname"},
			{Type: "struct sockaddr*", Name: "local_addr"},
		},
	),
	SecuritySbMount: NewEvent(
		SecuritySbMount,
		Sys32Undefined,      // id32Bit
		"security_sb_mount", // name
		"",                  // docPath
		false,               // internal
		false,               // syscall
		[]string{
			"default",
			"lsm_hooks",
			"fs",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SecuritySbMount, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "dev_name"},
			{Type: "const char*", Name: "path"},
			{Type: "const char*", Name: "type"},
			{Type: "unsigned long", Name: "flags"},
		},
	),
	SecurityBPF: NewEvent(
		SecurityBPF,
		Sys32Undefined, // id32Bit
		"security_bpf", // name
		"",             // docPath
		false,          // internal
		false,          // syscall
		[]string{
			"lsm_hooks",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SecurityBPF, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "cmd"},
		},
	),
	SecurityBPFMap: NewEvent(
		SecurityBPFMap,
		Sys32Undefined,     // id32Bit
		"security_bpf_map", // name
		"",                 // docPath
		false,              // internal
		false,              // syscall
		[]string{
			"lsm_hooks",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SecurityBPFMap, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned int", Name: "map_id"},
			{Type: "const char*", Name: "map_name"},
		},
	),
	SecurityKernelReadFile: NewEvent(
		SecurityKernelReadFile,
		Sys32Undefined,              // id32Bit
		"security_kernel_read_file", // name
		"",                          // docPath
		false,                       // internal
		false,                       // syscall
		[]string{
			"lsm_hooks",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SecurityKernelReadFile, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "int", Name: "type"},
			{Type: "unsigned long", Name: "ctime"},
		},
	),
	SecurityPostReadFile: NewEvent(
		SecurityPostReadFile,
		Sys32Undefined,                   // id32Bit
		"security_kernel_post_read_file", // name
		"",                               // docPath
		false,                            // internal
		false,                            // syscall
		[]string{
			"lsm_hooks",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SecurityKernelPostReadFile, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "long", Name: "size"},
			{Type: "int", Name: "type"},
		},
	),
	SecurityInodeMknod: NewEvent(
		SecurityInodeMknod,
		Sys32Undefined,         // id32Bit
		"security_inode_mknod", // name
		"",                     // docPath
		false,                  // internal
		false,                  // syscall
		[]string{
			"lsm_hooks",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SecurityInodeMknod, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "file_name"},
			{Type: "umode_t", Name: "mode"},
			{Type: "dev_t", Name: "dev"},
		},
	),
	SecurityInodeSymlinkEventId: NewEvent(
		SecurityInodeSymlinkEventId,
		Sys32Undefined,           // id32Bit
		"security_inode_symlink", // name
		"",                       // docPath
		false,                    // internal
		false,                    // syscall
		[]string{
			"lsm_hooks",
			"fs",
			"fs_file_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SecurityInodeSymlink, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "linkpath"},
			{Type: "const char*", Name: "target"},
		},
	),
	SecurityMmapFile: NewEvent(
		SecurityMmapFile,
		Sys32Undefined,       // id32Bit
		"security_mmap_file", // name
		"",                   // docPath
		false,                // internal
		false,                // syscall
		[]string{
			"lsm_hooks",
			"fs",
			"fs_file_ops",
			"proc",
			"proc_mem",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SecurityMmapFile, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "int", Name: "flags"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "unsigned long", Name: "ctime"},
			{Type: "unsigned long", Name: "prot"},
			{Type: "unsigned long", Name: "mmap_flags"},
		},
	),
	DoMmap: NewEvent(
		DoMmap,
		Sys32Undefined, // id32Bit
		"do_mmap",      // name
		"",             // docPath
		false,          // internal
		false,          // syscall
		[]string{
			"fs",
			"fs_file_ops",
			"proc",
			"proc_mem",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.DoMmap, true),
				NewProbe(probes.DoMmapRet, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
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
	),
	SecurityFileMprotect: NewEvent(
		SecurityFileMprotect,
		Sys32Undefined,                        // id32Bit
		"security_file_mprotect",              // name
		"lsm_hooks/security_file_mprotect.md", // docPath
		false,                                 // internal
		false,                                 // syscall
		[]string{
			"lsm_hooks",
			"proc",
			"proc_mem",
			"fs",
			"fs_file_ops",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SecurityFileMProtect, true),
				NewProbe(probes.SyscallEnter__Internal, true),
			},
			[]*KSymbol{},
			[]*TailCall{
				NewTailCall(
					"sys_enter_init_tail",
					"sys_enter_init",
					[]uint32{
						uint32(Mprotect),
						uint32(PkeyMprotect),
					},
				),
			},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "int", Name: "prot"},
			{Type: "unsigned long", Name: "ctime"},
			{Type: "int", Name: "prev_prot"},
			{Type: "void*", Name: "addr"},
			{Type: "size_t", Name: "len"},
			{Type: "int", Name: "pkey"},
		},
	),
	InitNamespaces: NewEvent(
		InitNamespaces,
		Sys32Undefined,    // id32Bit
		"init_namespaces", // name
		"",                // docPath
		false,             // internal
		false,             // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(
				map[capabilities.RingType][]cap.Value{
					capabilities.Base: {
						cap.SYS_PTRACE,
					},
				},
			),
		),
		[]trace.ArgMeta{
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
	),
	SocketDup: NewEvent(
		SocketDup,
		Sys32Undefined, // id32Bit
		"socket_dup",   // name
		"",             // docPath
		false,          // internal
		false,          // syscall
		[]string{},     // sets
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{
				NewTailCall(
					"sys_enter_init_tail",
					"sys_enter_init",
					[]uint32{
						uint32(Dup),
						uint32(Dup2),
						uint32(Dup3),
					},
				),
				NewTailCall(
					"sys_exit_init_tail",
					"sys_exit_init",
					[]uint32{
						uint32(Dup),
						uint32(Dup2),
						uint32(Dup3),
					},
				),
				NewTailCall(
					"sys_exit_tails",
					"sys_dup_exit_tail",
					[]uint32{
						uint32(Dup),
						uint32(Dup2),
						uint32(Dup3),
					},
				),
			},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "oldfd"},
			{Type: "int", Name: "newfd"},
			{Type: "struct sockaddr*", Name: "remote_addr"},
		},
	),
	HiddenInodes: NewEvent(
		HiddenInodes,
		Sys32Undefined,  // id32Bit
		"hidden_inodes", // name
		"",              // docPath
		false,           // internal
		false,           // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.Filldir64, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "char*", Name: "hidden_process"},
		},
	),
	KernelWrite: NewEvent(
		KernelWrite,
		Sys32Undefined,   // id32Bit
		"__kernel_write", // name
		"",               // docPath
		false,            // internal
		false,            // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.KernelWrite, true),
				NewProbe(probes.KernelWriteRet, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "size_t", Name: "count"},
			{Type: "off_t", Name: "pos"},
		},
	),
	DirtyPipeSplice: NewEvent(
		DirtyPipeSplice,
		Sys32Undefined,      // id32Bit
		"dirty_pipe_splice", // name
		"",                  // docPath
		false,               // internal
		false,               // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.DoSplice, true),
				NewProbe(probes.DoSpliceRet, true),
			},
			[]*KSymbol{
				NewKSymbol("pipefifo_fops", true),
			},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned long", Name: "inode_in"},
			{Type: "umode_t", Name: "in_file_type"},
			{Type: "const char*", Name: "in_file_path"},
			{Type: "loff_t", Name: "exposed_data_start_offset"},
			{Type: "size_t", Name: "exposed_data_len"},
			{Type: "unsigned long", Name: "inode_out"},
			{Type: "unsigned int", Name: "out_pipe_last_buffer_flags"},
		},
	),
	ContainerCreate: NewEvent(
		ContainerCreate,
		Sys32Undefined,     // id32Bit
		"container_create", // name
		"",                 // docPath
		false,              // internal
		false,              // syscall
		[]string{
			"default",
			"containers",
		},
		NewDependencies(
			[]ID{
				CgroupMkdir,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
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
	),
	ContainerRemove: NewEvent(
		ContainerRemove,
		Sys32Undefined,     // id32Bit
		"container_remove", // name
		"",                 // docPath
		false,              // internal
		false,              // syscall
		[]string{
			"default",
			"containers",
		},
		NewDependencies(
			[]ID{
				CgroupRmdir,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "runtime"},
			{Type: "const char*", Name: "container_id"},
		},
	),
	ExistingContainer: NewEvent(
		ExistingContainer,
		Sys32Undefined,       // id32Bit
		"existing_container", // name
		"",                   // docPath
		false,                // internal
		false,                // syscall
		[]string{
			"containers",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
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
	),
	ProcCreate: NewEvent(
		ProcCreate,
		Sys32Undefined, // id32Bit
		"proc_create",  // name
		"",             // docPath
		false,          // internal
		false,          // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.ProcCreate, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "char*", Name: "name"},
			{Type: "void*", Name: "proc_ops_addr"},
		},
	),
	KprobeAttach: NewEvent(
		KprobeAttach,
		Sys32Undefined,  // id32Bit
		"kprobe_attach", // name
		"",              // docPath
		false,           // internal
		false,           // syscall
		[]string{},      // sets
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.RegisterKprobe, true),
				NewProbe(probes.RegisterKprobeRet, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "char*", Name: "symbol_name"},
			{Type: "void*", Name: "pre_handler_addr"},
			{Type: "void*", Name: "post_handler_addr"},
		},
	),
	CallUsermodeHelper: NewEvent(
		CallUsermodeHelper,
		Sys32Undefined,        // id32Bit
		"call_usermodehelper", // name
		"",                    // docPath
		false,                 // internal
		false,                 // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.CallUsermodeHelper, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "const char*const*", Name: "argv"},
			{Type: "const char*const*", Name: "envp"},
			{Type: "int", Name: "wait"},
		},
	),
	DebugfsCreateFile: NewEvent(
		DebugfsCreateFile,
		Sys32Undefined,        // id32Bit
		"debugfs_create_file", // name
		"",                    // docPath
		false,                 // internal
		false,                 // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.DebugfsCreateFile, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "file_name"},
			{Type: "const char*", Name: "path"},
			{Type: "mode_t", Name: "mode"},
			{Type: "void*", Name: "proc_ops_addr"},
		},
	),
	PrintSyscallTable: NewEvent(
		PrintSyscallTable,
		Sys32Undefined,        // id32Bit
		"print_syscall_table", // name
		"",                    // docPath
		true,                  // internal
		false,                 // syscall
		[]string{},            // sets
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.PrintSyscallTable, true),
			},
			[]*KSymbol{
				NewKSymbol("sys_call_table", true),
			},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned long[]", Name: "syscalls_addresses"},
			{Type: "unsigned long", Name: trigger.ContextArgName},
		},
	),
	HiddenKernelModule: NewEvent(
		HiddenKernelModule,
		Sys32Undefined,         // id32Bit
		"hidden_kernel_module", // name
		"",                     // docPath
		false,                  // internal
		false,                  // syscall
		[]string{},             // sets
		NewDependencies(
			[]ID{
				HiddenKernelModuleSeeker,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "address"},
			{Type: "const char*", Name: "name"},
			{Type: "const char*", Name: "srcversion"},
		},
	),
	HiddenKernelModuleSeeker: NewEvent(
		HiddenKernelModuleSeeker,
		Sys32Undefined,                // id32Bit
		"hidden_kernel_module_seeker", // name
		"",                            // docPath
		true,                          // internal
		false,                         // syscall
		[]string{},                    // sets
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.HiddenKernelModuleSeeker, true),
				NewProbe(probes.HiddenKernelModuleVerifier, true),
				NewProbe(probes.ModuleLoad, true),
				NewProbe(probes.ModuleFree, true),
				NewProbe(probes.DoInitModule, true),
				NewProbe(probes.DoInitModuleRet, true),
				NewProbe(probes.LayoutAndAllocate, true),
			},
			[]*KSymbol{
				NewKSymbol("modules", true),
				NewKSymbol("modules_kset", true),
				NewKSymbol("mod_tree", true),
			},
			[]*TailCall{
				NewTailCall(
					"prog_array",
					"lkm_seeker_proc_tail",
					[]uint32{
						TailHiddenKernelModuleProc,
					},
				),
				NewTailCall(
					"prog_array",
					"lkm_seeker_kset_tail",
					[]uint32{
						TailHiddenKernelModuleKset,
					},
				),
				NewTailCall(
					"prog_array",
					"lkm_seeker_mod_tree_tail",
					[]uint32{
						TailHiddenKernelModuleModTree,
					},
				),
				NewTailCall(
					"prog_array",
					"lkm_seeker_new_mod_only_tail",
					[]uint32{
						TailHiddenKernelModuleNewModOnly,
					},
				),
			},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned long", Name: "address"},
			{Type: "bytes", Name: "name"},
			{Type: "unsigned int", Name: "flags"},
			{Type: "bytes", Name: "srcversion"},
		},
	),
	HookedSyscalls: NewEvent(
		HookedSyscalls,
		Sys32Undefined,    // id32Bit
		"hooked_syscalls", // name
		"",                // docPath
		false,             // internal
		false,             // syscall
		[]string{},
		NewDependencies(
			[]ID{
				DoInitModule,
				PrintSyscallTable,
			},
			[]*Probe{},
			[]*KSymbol{
				NewKSymbol("_stext", true),
				NewKSymbol("_etext", true),
			},
			[]*TailCall{},
			NewCapabilities(
				map[capabilities.RingType][]cap.Value{
					capabilities.Base: {
						cap.SYSLOG, // read /proc/kallsyms
					},
				},
			),
		),
		[]trace.ArgMeta{
			{Type: "[]char*", Name: "check_syscalls"},
			{Type: "[]trace.HookedSymbolData", Name: "hooked_syscalls"},
		},
	),
	DebugfsCreateDir: NewEvent(
		DebugfsCreateDir,
		Sys32Undefined,       // id32Bit
		"debugfs_create_dir", // name
		"",                   // docPath
		false,                // internal
		false,                // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.DebugfsCreateDir, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "name"},
			{Type: "const char*", Name: "path"},
		},
	),
	DeviceAdd: NewEvent(
		DeviceAdd,
		Sys32Undefined, // id32Bit
		"device_add",   // name
		"",             // docPath
		false,          // internal
		false,          // syscall
		[]string{},     // sets
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.DeviceAdd, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "name"},
			{Type: "const char*", Name: "parent_name"},
		},
	),
	RegisterChrdev: NewEvent(
		RegisterChrdev,
		Sys32Undefined,    // id32Bit
		"register_chrdev", // name
		"",                // docPath
		false,             // internal
		false,             // syscall
		[]string{},        // sets
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.RegisterChrdev, true),
				NewProbe(probes.RegisterChrdevRet, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned int", Name: "requested_major_number"},
			{Type: "unsigned int", Name: "granted_major_number"},
			{Type: "const char*", Name: "char_device_name"},
			{Type: "struct file_operations *", Name: "char_device_fops"},
		},
	),
	SharedObjectLoaded: NewEvent(
		SharedObjectLoaded,
		Sys32Undefined,         // id32Bit
		"shared_object_loaded", // name
		"",                     // docPath
		false,                  // internal
		false,                  // syscall
		[]string{
			"lsm_hooks",
			"fs",
			"fs_file_ops",
			"proc",
			"proc_mem",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SecurityMmapFile, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(
				map[capabilities.RingType][]cap.Value{
					capabilities.Base: {
						cap.SYS_PTRACE, // loadSharedObjectDyanmicSymbols()
					},
				},
			),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "int", Name: "flags"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "unsigned long", Name: "ctime"},
		},
	),
	SymbolsLoaded: NewEvent(
		SymbolsLoaded,
		Sys32Undefined,                    // id32Bit
		"symbols_loaded",                  // name
		"security_alerts/symbols_load.md", // docPath
		false,                             // internal
		false,                             // syscall
		[]string{
			"derived",
			"fs",
			"security_alert",
		},
		NewDependencies(
			[]ID{
				SharedObjectLoaded,
				SchedProcessExec,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "library_path"},
			{Type: "const char*const*", Name: "symbols"},
		},
	),
	SymbolsCollision: NewEvent(
		SymbolsCollision,
		Sys32Undefined,                         // id32Bit
		"symbols_collision",                    // name
		"security_alerts/symbols_collision.md", // docPath
		false,                                  // internal
		false,                                  // syscall
		[]string{
			"lsm_hooks",
			"fs",
			"fs_file_ops",
			"proc",
			"proc_mem",
		},
		NewDependencies(
			[]ID{
				SharedObjectLoaded,
				SchedProcessExec,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "loaded_path"},
			{Type: "const char*", Name: "collision_path"},
			{Type: "const char*const*", Name: "symbols"},
		},
	),
	CaptureFileWrite: NewEvent(
		CaptureFileWrite,
		Sys32Undefined,       // id32Bit
		"capture_file_write", // name
		"",                   // docPath
		true,                 // internal
		false,                // syscall
		nil,                  // sets
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.VfsWrite, true),
				NewProbe(probes.VfsWriteRet, true),
				NewProbe(probes.VfsWriteV, false),
				NewProbe(probes.VfsWriteVRet, false),
				NewProbe(probes.KernelWrite, false),
				NewProbe(probes.KernelWriteRet, false),
			},
			[]*KSymbol{
				NewKSymbol("pipefifo_fops", true),
			},
			[]*TailCall{
				NewTailCall(
					"prog_array",
					"trace_ret_vfs_write_tail",
					[]uint32{
						TailVfsWrite,
					},
				),
				NewTailCall(
					"prog_array",
					"trace_ret_vfs_writev_tail",
					[]uint32{
						TailVfsWritev,
					},
				),
				NewTailCall(
					"prog_array",
					"trace_ret_kernel_write_tail",
					[]uint32{
						TailKernelWrite,
					},
				),
				NewTailCall(
					"prog_array",
					"send_bin",
					[]uint32{
						TailSendBin,
					},
				),
			},
			NewCapabilities(nil),
		),
		nil, // params
	),
	CaptureFileRead: NewEvent(
		CaptureFileRead,
		Sys32Undefined,      // id32bit
		"capture_file_read", // name
		"",                  // docPath
		true,                // internal
		false,               // syscall
		[]string{},          // tags
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.VfsRead, true),
				NewProbe(probes.VfsReadRet, true),
				NewProbe(probes.VfsReadV, false),
				NewProbe(probes.VfsReadVRet, false),
			},
			[]*KSymbol{
				NewKSymbol("pipefifo_fops", true),
			},
			[]*TailCall{
				NewTailCall(
					"prog_array",
					"trace_ret_vfs_read_tail",
					[]uint32{
						TailVfsRead,
					},
				),
				NewTailCall(
					"prog_array",
					"trace_ret_vfs_readv_tail",
					[]uint32{
						TailVfsReadv,
					},
				),
				NewTailCall(
					"prog_array",
					"send_bin",
					[]uint32{
						TailSendBin,
					},
				),
			},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	CaptureExec: NewEvent(
		CaptureExec,
		Sys32Undefined, // id32Bit
		"capture_exec", // name
		"",             // docPath
		true,           // internal
		false,          // syscall
		[]string{},
		NewDependencies(
			[]ID{
				SchedProcessExec,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(
				map[capabilities.RingType][]cap.Value{
					capabilities.Base: {
						cap.SYS_PTRACE, // processSchedProcessExec() performance
					},
				},
			),
		),
		[]trace.ArgMeta{},
	),
	CaptureModule: NewEvent(
		CaptureModule,
		Sys32Undefined,   // id32Bit
		"capture_module", // name
		"",               // docPath
		true,             // internal
		false,            // syscall
		[]string{},
		NewDependencies(
			[]ID{
				SchedProcessExec,
			},
			[]*Probe{
				NewProbe(probes.SyscallEnter__Internal, true),
				NewProbe(probes.SyscallExit__Internal, true),
				NewProbe(probes.SecurityKernelPostReadFile, true),
			},
			[]*KSymbol{},
			[]*TailCall{
				NewTailCall(
					"sys_enter_tails",
					"syscall__init_module",
					[]uint32{
						uint32(InitModule),
					},
				),
				NewTailCall(
					"prog_array_tp",
					"send_bin_tp",
					[]uint32{
						TailSendBinTP,
					},
				),
				NewTailCall(
					"prog_array",
					"send_bin",
					[]uint32{
						TailSendBin,
					},
				),
			},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	CaptureMem: NewEvent(
		CaptureMem,
		Sys32Undefined, // id32Bit
		"capture_mem",  // name
		"",             // docPath
		true,           // internal
		false,          // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{
				NewTailCall(
					"prog_array",
					"send_bin",
					[]uint32{
						TailSendBin,
					},
				),
			},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	CaptureBpf: NewEvent(
		CaptureBpf,
		Sys32Undefined, // id32Bit
		"capture_bpf",  // name
		"",             // docPath
		true,           // internal
		false,          // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SecurityBPF, true),
			},
			[]*KSymbol{},
			[]*TailCall{
				NewTailCall(
					"prog_array",
					"send_bin",
					[]uint32{
						TailSendBin,
					},
				),
			},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{},
	),
	DoInitModule: NewEvent(
		DoInitModule,
		Sys32Undefined,   // id32Bit
		"do_init_module", // name
		"",               // docPath
		false,            // internal
		false,            // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.DoInitModule, true),
				NewProbe(probes.DoInitModuleRet, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "name"},
			{Type: "const char*", Name: "version"},
			{Type: "const char*", Name: "src_version"},
		},
	),
	ModuleLoad: NewEvent(
		ModuleLoad,
		Sys32Undefined, // id32Bit
		"module_load",  // name
		"",             // docPath
		false,          // internal
		false,          // syscall
		[]string{},     // sets
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.ModuleLoad, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "name"},
			{Type: "const char*", Name: "version"},
			{Type: "const char*", Name: "src_version"},
		},
	),
	ModuleFree: NewEvent(
		ModuleFree,
		Sys32Undefined, // id32Bit
		"module_free",  // name
		"",             // docPath
		false,          // internal
		false,          // syscall
		[]string{},     // sets
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.ModuleFree, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "name"},
			{Type: "const char*", Name: "version"},
			{Type: "const char*", Name: "src_version"},
		},
	),
	SocketAccept: NewEvent(
		SocketAccept,
		Sys32Undefined,  // id32Bit
		"socket_accept", // name
		"",              // docPath
		false,           // internal
		false,           // syscall
		[]string{},
		NewDependencies(
			[]ID{
				SecuritySocketAccept,
			},
			[]*Probe{
				NewProbe(probes.SyscallEnter__Internal, true),
				NewProbe(probes.SyscallExit__Internal, true),
			},
			[]*KSymbol{},
			[]*TailCall{
				NewTailCall(
					"sys_exit_tails",
					"syscall__accept4",
					[]uint32{
						uint32(Accept),
						uint32(Accept4),
					},
				),
				NewTailCall(
					"sys_exit_init_tail",
					"sys_exit_init",
					[]uint32{
						uint32(Accept),
						uint32(Accept4),
					},
				),
			},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct sockaddr*", Name: "local_addr"},
			{Type: "struct sockaddr*", Name: "remote_addr"},
		},
	),
	LoadElfPhdrs: NewEvent(
		LoadElfPhdrs,
		Sys32Undefined,   // id32Bit
		"load_elf_phdrs", // name
		"",               // docPath
		false,            // internal
		false,            // syscall
		[]string{
			"proc",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.LoadElfPhdrs, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
		},
	),
	HookedProcFops: NewEvent(
		HookedProcFops,
		Sys32Undefined,     // id32Bit
		"hooked_proc_fops", // name
		"",                 // docPath
		false,              // internal
		false,              // syscall
		[]string{},         // interfaceSets
		NewDependencies(
			[]ID{
				DoInitModule,
			},
			[]*Probe{
				NewProbe(probes.SecurityFilePermission, true),
			},
			[]*KSymbol{
				NewKSymbol("_stext", true),
				NewKSymbol("_etext", true),
			},
			[]*TailCall{},
			NewCapabilities(
				map[capabilities.RingType][]cap.Value{
					capabilities.Base: {
						cap.SYSLOG, // read /proc/kallsyms
					},
				},
			),
		),
		[]trace.ArgMeta{
			{Type: "[]trace.HookedSymbolData", Name: "hooked_fops_pointers"},
		},
	),
	PrintNetSeqOps: NewEvent(
		PrintNetSeqOps,
		Sys32Undefined,      // id32Bit
		"print_net_seq_ops", // name
		"",                  // docPath
		true,                // internal
		false,               // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.PrintNetSeqOps, true),
			},
			[]*KSymbol{
				NewKSymbol("tcp4_seq_ops", true),
				NewKSymbol("tcp6_seq_ops", true),
				NewKSymbol("udp_seq_ops", true),
				NewKSymbol("udp6_seq_ops", true),
				NewKSymbol("raw_seq_ops", true),
				NewKSymbol("raw6_seq_ops", true),
			},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "unsigned long[]", Name: "net_seq_ops"},
			{Type: "unsigned long", Name: trigger.ContextArgName},
		},
	),
	HookedSeqOps: NewEvent(
		HookedSeqOps,
		Sys32Undefined,   // id32Bit
		"hooked_seq_ops", // name
		"",               // docPath
		false,            // internal
		false,            // syscall
		[]string{},
		NewDependencies(
			[]ID{
				PrintNetSeqOps,
				DoInitModule,
			},
			[]*Probe{},
			[]*KSymbol{
				NewKSymbol("_stext", true),
				NewKSymbol("_etext", true),
			},
			[]*TailCall{},
			NewCapabilities(
				map[capabilities.RingType][]cap.Value{
					capabilities.Base: {
						cap.SYSLOG, // read /proc/kallsyms
					},
				},
			),
		),
		[]trace.ArgMeta{
			{Type: "map[string]trace.HookedSymbolData", Name: "hooked_seq_ops"},
		},
	),
	TaskRename: NewEvent(
		TaskRename,
		Sys32Undefined, // id32Bit
		"task_rename",  // name
		"",             // docPath
		false,          // internal
		false,          // syscall
		[]string{"proc"},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.TaskRename, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "old_name"},
			{Type: "const char*", Name: "new_name"},
		},
	),
	SecurityInodeRename: NewEvent(
		SecurityInodeRename,
		Sys32Undefined,          // id32Bit
		"security_inode_rename", // name
		"",                      // docPath
		false,                   // internal
		false,                   // syscall
		[]string{},              // sets
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SecurityInodeRename, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "old_path"},
			{Type: "const char*", Name: "new_path"},
		},
	),
	DoSigaction: NewEvent(
		DoSigaction,
		Sys32Undefined, // id32Bit
		"do_sigaction", // name
		"",             // docPath
		false,          // internal
		false,          // syscall
		[]string{
			"proc",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.DoSigaction, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
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
	),
	BpfAttach: NewEvent(
		BpfAttach,
		Sys32Undefined, // id32Bit
		"bpf_attach",   // name
		"docs/events/builtin/extra/bpf_attach.md", // docPath
		false,      // internal
		false,      // syscall
		[]string{}, // sets
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SecurityFileIoctl, true),
				NewProbe(probes.SecurityBpfProg, true),
				NewProbe(probes.SecurityBPF, true),
				NewProbe(probes.TpProbeRegPrioMayExist, true),
				NewProbe(probes.CheckHelperCall, false),
				NewProbe(probes.CheckMapFuncCompatibility, false),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "prog_type"},
			{Type: "const char*", Name: "prog_name"},
			{Type: "u32", Name: "prog_id"},
			{Type: "unsigned long[]", Name: "prog_helpers"},
			{Type: "const char*", Name: "symbol_name"},
			{Type: "u64", Name: "symbol_addr"},
			{Type: "int", Name: "attach_type"},
		},
	),
	KallsymsLookupName: NewEvent(
		KallsymsLookupName,
		Sys32Undefined,                    // id32Bit
		"kallsyms_lookup_name",            // name
		"kprobes/kallsyms_lookup_name.md", // docPath
		false,                             // internal
		false,                             // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.KallsymsLookupName, true),
				NewProbe(probes.KallsymsLookupNameRet, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "symbol_name"},
			{Type: "void*", Name: "symbol_address"},
		},
	),
	PrintMemDump: NewEvent(
		PrintMemDump,
		Sys32Undefined,   // id32Bit
		"print_mem_dump", // name
		"",               // docPath
		false,            // internal
		false,            // syscall
		[]string{},       // sets
		NewDependencies(
			[]ID{
				DoInitModule,
			},
			[]*Probe{
				NewProbe(probes.PrintMemDump, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(map[capabilities.RingType][]cap.Value{
				capabilities.Base: {
					cap.SYSLOG, // read /proc/kallsyms
				}},
			),
		),
		[]trace.ArgMeta{
			{Type: "bytes", Name: "bytes"},
			{Type: "void*", Name: "address"},
			{Type: "u64", Name: "length"},
			{Type: "u64", Name: "caller_context_id"},
			{Type: "char*", Name: "arch"},
			{Type: "char*", Name: "symbol_name"},
			{Type: "char*", Name: "symbol_owner"},
		},
	),
	VfsRead: NewEvent(
		VfsRead,
		Sys32Undefined, // id32Bit
		"vfs_read",     // name
		"",             // docPath
		false,          // internal
		false,          // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.VfsRead, true),
				NewProbe(probes.VfsReadRet, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "size_t", Name: "count"},
			{Type: "off_t", Name: "pos"},
		},
	),
	VfsReadv: NewEvent(
		VfsReadv,
		Sys32Undefined, // id32Bit
		"vfs_readv",    // name
		"",             // docPath
		false,          // internal
		false,          // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.VfsReadV, true),
				NewProbe(probes.VfsReadVRet, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "unsigned long", Name: "vlen"},
			{Type: "off_t", Name: "pos"},
		},
	),
	VfsUtimes: NewEvent(
		VfsUtimes,
		Sys32Undefined, // id32bit
		"vfs_utimes",   // name
		"",             // docPath
		false,          // internal
		false,          // syscall
		[]string{},     // sets
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.VfsUtimes, false),    // this probe exits in kernels >= 5.9
				NewProbe(probes.UtimesCommon, false), // this probe exits in kernels < 5.9
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "u64", Name: "atime"},
			{Type: "u64", Name: "mtime"},
		},
	),
	DoTruncate: NewEvent(
		DoTruncate,
		Sys32Undefined, // id32Bit
		"do_truncate",  // name
		"",             // docPath
		false,          // internal
		false,          // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.DoTruncate, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "dev_t", Name: "dev"},
			{Type: "u64", Name: "length"},
		},
	),
	FileModification: NewEvent(
		FileModification,
		Sys32Undefined,                 // id32Bit
		"file_modification",            // name
		"kprobes/file_modification.md", // docPath
		false,                          // internal
		false,                          // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.FdInstall, true),
				NewProbe(probes.FilpClose, true),
				NewProbe(probes.FileUpdateTime, true),
				NewProbe(probes.FileUpdateTimeRet, true),
				NewProbe(probes.FileModified, false),    // not required because doesn't ...
				NewProbe(probes.FileModifiedRet, false), // ... exist in kernels < 5.3
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "file_path"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "unsigned long", Name: "old_ctime"},
			{Type: "unsigned long", Name: "new_ctime"},
		},
	),
	InotifyWatch: NewEvent(
		InotifyWatch,
		Sys32Undefined,  // id32Bit
		"inotify_watch", // name
		"",              // docPath
		false,           // internal
		false,           // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.InotifyFindInode, true),
				NewProbe(probes.InotifyFindInodeRet, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "dev_t", Name: "dev"},
		},
	),
	SecurityBpfProg: NewEvent(
		SecurityBpfProg,
		Sys32Undefined,      // id32Bit
		"security_bpf_prog", // name
		"docs/events/builtin/extra/security_bpf_prog.md", // docPath
		false, // internal
		false, // syscall
		[]string{},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.SecurityBpfProg, true),
				NewProbe(probes.BpfCheck, true),
				NewProbe(probes.CheckHelperCall, false),
				NewProbe(probes.CheckMapFuncCompatibility, false),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "int", Name: "type"},
			{Type: "const char*", Name: "name"},
			{Type: "unsigned long[]", Name: "helpers"},
			{Type: "u32", Name: "id"},
			{Type: "bool", Name: "load"},
		},
	),
	ProcessExecuteFailed: NewEvent(
		ProcessExecuteFailed,
		Sys32Undefined,           // id32Bit
		"process_execute_failed", // name
		"",                       // docPath
		false,                    // internal
		false,                    // syscall
		[]string{
			"proc",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.ExecBinprm, true),
				NewProbe(probes.ExecBinprmRet, true),
			},
			[]*KSymbol{},
			[]*TailCall{
				NewTailCall(
					"sys_enter_init_tail",
					"sys_enter_init",
					[]uint32{
						uint32(Execve),
						uint32(Execveat),
					},
				),
				NewTailCall(
					"prog_array",
					"trace_ret_exec_binprm1",
					[]uint32{
						TailExecBinprm1,
					},
				),
				NewTailCall(
					"prog_array",
					"trace_ret_exec_binprm2",
					[]uint32{
						TailExecBinprm2,
					},
				),
			},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "const char*", Name: "binary.path"},
			{Type: "dev_t", Name: "binary.device_id"},
			{Type: "unsigned long", Name: "binary.inode_number"},
			{Type: "unsigned long", Name: "binary.ctime"},
			{Type: "umode_t", Name: "binary.inode_mode"},
			{Type: "const char*", Name: "interpreter_path"},
			{Type: "umode_t", Name: "stdin_type"},
			{Type: "char*", Name: "stdin_path"},
			{Type: "int", Name: "kernel_invoked"},
			{Type: "const char*const*", Name: "binary.arguments"},
			{Type: "const char*const*", Name: "environment"},
		},
	),
	NetPacketBase: NewEvent(
		NetPacketBase,
		Sys32Undefined,    // id32Bit
		"net_packet_base", // name
		"",                // docPath
		true,              // internal
		false,             // syscall
		[]string{
			"network_events",
		},
		NewDependencies(
			[]ID{},
			[]*Probe{
				NewProbe(probes.CgroupSKBIngress, true),
				NewProbe(probes.CgroupSKBEgress, true),
				NewProbe(probes.SockAllocFile, true),
				NewProbe(probes.SockAllocFileRet, true),
				NewProbe(probes.CgroupBPFRunFilterSKB, true),
				NewProbe(probes.SecuritySocketRecvmsg, true),
				NewProbe(probes.SecuritySocketSendmsg, true),
				NewProbe(probes.SecuritySkClone, true),
			},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(
				map[capabilities.RingType][]cap.Value{
					capabilities.Base: {
						cap.NET_ADMIN, // needed by BPF_PROG_TYPE_CGROUP_SKB
					},
				},
			),
		),
		[]trace.ArgMeta{},
	),
	NetPacketIPBase: NewEvent(
		NetPacketIPBase,
		Sys32Undefined,       // id32Bit
		"net_packet_ip_base", // name
		"",                   // docPath
		true,                 // internal
		false,                // syscall
		[]string{"network_events"},
		NewDependencies(
			[]ID{
				NetPacketBase,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "bytes", Name: "payload"},
		},
	),
	NetPacketIPv4: NewEvent(
		NetPacketIPv4,
		Sys32Undefined,    // id32Bit
		"net_packet_ipv4", // name
		"",                // docPath
		false,             // internal
		false,             // syscall
		[]string{
			"network_events",
		},
		NewDependencies(
			[]ID{
				NetPacketIPBase,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "src"}, // TODO: remove after filter supports ProtoIPv4
			{Type: "const char*", Name: "dst"}, // TODO: remove after filter supports ProtoIPv4
			{Type: "trace.ProtoIPv4", Name: "proto_ipv4"},
		},
	),
	NetPacketIPv6: NewEvent(
		NetPacketIPv6,
		Sys32Undefined,    // id32Bit
		"net_packet_ipv6", // name
		"",                // docPath
		false,             // internal
		false,             // syscall
		[]string{"network_events"},
		NewDependencies(
			[]ID{
				NetPacketIPBase,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "src"}, // TODO: remove after filter supports ProtoIPv6
			{Type: "const char*", Name: "dst"}, // TODO: remove after filter supports ProtoIPv6
			{Type: "trace.ProtoIPv6", Name: "proto_ipv6"},
		},
	),
	NetPacketTCPBase: NewEvent(
		NetPacketTCPBase,
		Sys32Undefined,        // id32Bit
		"net_packet_tcp_base", // name
		"",                    // docPath
		true,                  // internal
		false,                 // syscall
		[]string{
			"network_events",
		},
		NewDependencies(
			[]ID{
				NetPacketBase,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "bytes", Name: "payload"},
		},
	),
	NetPacketTCP: NewEvent(
		NetPacketTCP,
		Sys32Undefined,   // id32Bit
		"net_packet_tcp", // name
		"",               // docPath
		false,            // internal
		false,            // syscall
		[]string{"network_events"},
		NewDependencies(
			[]ID{
				NetPacketTCPBase,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "src"},
			{Type: "const char*", Name: "dst"},
			{Type: "u16", Name: "src_port"}, // TODO: remove after filter supports ProtoTCP
			{Type: "u16", Name: "dst_port"}, // TODO: remove after filter supports ProtoTCP
			{Type: "trace.ProtoTCP", Name: "proto_tcp"},
		},
	),
	NetPacketUDPBase: NewEvent(
		NetPacketUDPBase,
		Sys32Undefined,             // id32Bit
		"net_packet_udp_base",      // name
		"",                         // docPath
		true,                       // internal
		false,                      // syscall
		[]string{"network_events"}, // sets
		NewDependencies(
			[]ID{
				NetPacketBase,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "bytes", Name: "payload"},
		},
	),
	NetPacketUDP: NewEvent(
		NetPacketUDP,
		Sys32Undefined,   // id32Bit
		"net_packet_udp", // name
		"",               // docPath
		false,            // internal
		false,            // syscall
		[]string{"network_events"},
		NewDependencies(
			[]ID{
				NetPacketUDPBase,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "src"},
			{Type: "const char*", Name: "dst"},
			{Type: "u16", Name: "src_port"}, // TODO: remove after filter supports ProtoUDP
			{Type: "u16", Name: "dst_port"}, // TODO: remove after filter supports ProtoUDP
			{Type: "trace.ProtoUDP", Name: "proto_udp"},
		},
	),
	NetPacketICMPBase: NewEvent(
		NetPacketICMPBase,
		Sys32Undefined,         // id32Bit
		"net_packet_icmp_base", // name
		"",                     // docPath
		true,                   // internal
		false,                  // syscall
		[]string{
			"network_events",
		},
		NewDependencies(
			[]ID{
				NetPacketBase,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "bytes", Name: "payload"},
		},
	),
	NetPacketICMP: NewEvent(
		NetPacketICMP,
		Sys32Undefined,    // id32Bit
		"net_packet_icmp", // name
		"",                // docPath
		false,             // internal
		false,             // syscall
		[]string{
			"default",
			"network_events",
		},
		NewDependencies(
			[]ID{
				NetPacketICMPBase,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "src"},
			{Type: "const char*", Name: "dst"},
			{Type: "trace.ProtoICMP", Name: "proto_icmp"},
		},
	),
	NetPacketICMPv6Base: NewEvent(
		NetPacketICMPv6Base,
		Sys32Undefined,           // id32Bit
		"net_packet_icmpv6_base", // name
		"",                       // docPath
		true,                     // internal
		false,                    // syscall
		[]string{
			"network_events",
		},
		NewDependencies(
			[]ID{
				NetPacketBase,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "bytes", Name: "payload"},
		},
	),
	NetPacketICMPv6: NewEvent(
		NetPacketICMPv6,
		Sys32Undefined,      // id32Bit
		"net_packet_icmpv6", // name
		"",                  // docPath
		false,               // internal
		false,               // syscall
		[]string{
			"default",
			"network_events",
		},
		NewDependencies(
			[]ID{
				NetPacketICMPv6Base,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "src"},
			{Type: "const char*", Name: "dst"},
			{Type: "trace.ProtoICMPv6", Name: "proto_icmpv6"},
		},
	),
	NetPacketDNSBase: NewEvent(
		NetPacketDNSBase,
		Sys32Undefined,        // id32Bit
		"net_packet_dns_base", // name
		"",                    // docPath
		true,                  // internal
		false,                 // syscall
		[]string{
			"network_events",
		},
		NewDependencies(
			[]ID{
				NetPacketBase,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "bytes", Name: "payload"},
		},
	),
	NetPacketDNS: NewEvent(
		NetPacketDNS,
		Sys32Undefined,   // id32Bit
		"net_packet_dns", // name
		"",               // docPath
		false,            // internal
		false,            // syscall
		[]string{
			"network_events",
		},
		NewDependencies(
			[]ID{
				NetPacketDNSBase,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "src"},
			{Type: "const char*", Name: "dst"},
			{Type: "u16", Name: "src_port"},
			{Type: "u16", Name: "dst_port"},
			{Type: "trace.ProtoDNS", Name: "proto_dns"},
		},
	),
	NetPacketDNSRequest: NewEvent(
		NetPacketDNSRequest,
		Sys32Undefined,           // id32Bit
		"net_packet_dns_request", // name
		"",                       // docPath
		false,                    // internal
		false,                    // syscall
		[]string{
			"default",
			"network_events",
		},
		NewDependencies(
			[]ID{
				NetPacketDNSBase,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "trace.PktMeta", Name: "metadata"},
			{Type: "[]trace.DnsQueryData", Name: "dns_questions"},
		},
	),
	NetPacketDNSResponse: NewEvent(
		NetPacketDNSResponse,
		Sys32Undefined,            // id32Bit
		"net_packet_dns_response", // name
		"",                        // docPath
		false,                     // internal
		false,                     // syscall
		[]string{
			"default",
			"network_events",
		},
		NewDependencies(
			[]ID{
				NetPacketDNSBase,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "trace.PktMeta", Name: "metadata"},
			{Type: "[]trace.DnsResponseData", Name: "dns_response"},
		},
	),
	NetPacketHTTPBase: NewEvent(
		NetPacketHTTPBase,
		Sys32Undefined,         // id32Bit
		"net_packet_http_base", // name
		"",                     // docPath
		true,                   // internal
		false,                  // syscall
		[]string{
			"network_events",
		},
		NewDependencies(
			[]ID{
				NetPacketBase,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "bytes", Name: "payload"},
		},
	),
	NetPacketHTTP: NewEvent(
		NetPacketHTTP,
		Sys32Undefined,    // id32Bit
		"net_packet_http", // name
		"",                // docPath
		false,             // internal
		false,             // syscall
		[]string{
			"network_events",
		},
		NewDependencies(
			[]ID{
				NetPacketHTTPBase,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "const char*", Name: "src"},
			{Type: "const char*", Name: "dst"},
			{Type: "u16", Name: "src_port"},
			{Type: "u16", Name: "dst_port"},
			{Type: "trace.ProtoHTTP", Name: "proto_http"},
		},
	),
	NetPacketHTTPRequest: NewEvent(
		NetPacketHTTPRequest,
		Sys32Undefined,            // id32Bit
		"net_packet_http_request", // name
		"",                        // docPath
		false,                     // internal
		false,                     // syscall
		[]string{
			"default",
			"network_events",
		},
		NewDependencies(
			[]ID{
				NetPacketHTTPBase,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "trace.PktMeta", Name: "metadata"},
			{Type: "trace.ProtoHTTPRequest", Name: "http_request"},
		},
	),
	NetPacketHTTPResponse: NewEvent(
		NetPacketHTTPResponse,
		Sys32Undefined,                        // id32Bit
		"net_packet_http_response",            // name
		"",                                    // docPath
		false,                                 // internal
		false,                                 // syscall
		[]string{"default", "network_events"}, // sets
		NewDependencies(
			[]ID{
				NetPacketHTTPBase,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "trace.PktMeta", Name: "metadata"},
			{Type: "trace.ProtoHTTPResponse", Name: "http_response"},
		},
	),
	NetPacketCapture: NewEvent(
		NetPacketCapture,
		Sys32Undefined,       // id32Bit
		"net_packet_capture", // name
		"",                   // docPath
		true,                 // internal
		false,                // syscall
		[]string{},
		NewDependencies(
			[]ID{
				NetPacketBase,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		[]trace.ArgMeta{
			{Type: "bytes", Name: "payload"},
		},
	),
	CaptureNetPacket: NewEvent(
		CaptureNetPacket,
		Sys32Undefined,       // id32Bit
		"capture_net_packet", // name
		"",                   // docPath
		true,                 // internal
		false,                // syscall
		nil,
		NewDependencies(
			[]ID{
				NetPacketCapture,
			},
			[]*Probe{},
			[]*KSymbol{},
			[]*TailCall{},
			NewCapabilities(nil),
		),
		nil,
	),
}
