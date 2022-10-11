package events

import (
	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
	"github.com/aquasecurity/tracee/pkg/events/trigger"
	"github.com/aquasecurity/tracee/types/trace"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

type dependencies struct {
	Events       []eventDependency // Events required to be loaded and/or submitted for the event to happen
	KSymbols     []string
	TailCalls    []TailCall
	Capabilities []cap.Value
}

type probeDependency struct {
	Handle   probes.Handle
	Required bool // should tracee fail if probe fails to attach
}

type eventDependency struct {
	EventID ID
}

type TailCall struct {
	MapName    string
	MapIndexes []uint32
	ProgName   string
}

func (tc *TailCall) AddIndex(i uint32) {
	tc.MapIndexes = append(tc.MapIndexes, i)
}

// an enum that specifies the index of a function to be used in a bpf tail call
// tail function indexes should match defined values in ebpf code for prog_array map
const (
	tailVfsWrite uint32 = iota
	tailVfsWritev
	tailSendBin
	tailSendBinTP
	tailKernelWrite
)

// Event is a struct describing an event configuration
type Event struct {
	ID32Bit      ID
	Name         string
	DocPath      string // Relative to the 'doc/events' directory
	Internal     bool
	Syscall      bool
	Probes       []probeDependency
	Dependencies dependencies
	Sets         []string
	Params       []trace.ArgMeta
}

type eventDefinitions struct {
	events map[ID]Event
}

// Get without checking for Event existance
func (e *eventDefinitions) Get(eventId ID) Event {
	evt := e.events[eventId]
	return evt
}

// GetSafe gets the Event and also returns bool to check for existance
func (e *eventDefinitions) GetSafe(eventId ID) (Event, bool) {
	evt, ok := e.events[eventId]
	return evt, ok
}

// Events returns the underlying Event definitions map
// Use at own risk and do not modify the map
func (e *eventDefinitions) Events() map[ID]Event {
	return e.events
}

func (e *eventDefinitions) Length() int {
	return len(e.events)
}

func (e *eventDefinitions) NamesToIDs() map[string]ID {
	namesToIds := make(map[string]ID, len(e.events))

	for id, evt := range e.events {
		namesToIds[evt.Name] = id
	}
	return namesToIds
}

type ID int32

// Common events (used by all architectures)
// events should match defined values in ebpf code
const (
	NetPacket ID = iota + 700
	DnsRequest
	DnsResponse
	MaxNetID
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
	MaxCommonID
)

// Events originated from user-space
const (
	InitNamespaces ID = iota + 2000
	ContainerCreate
	ContainerRemove
	ExistingContainer
	HookedSyscalls
	HookedSeqOps
	SymbolsLoaded
	MaxUserSpace
)

// Capture meta-events
const (
	CaptureFileWrite ID = iota + 4000
	CaptureExec
	CaptureModule
	CaptureMem
	CaptureProfile
	CapturePcap
)

const (
	CaptureIface int32 = 1 << iota
	TraceIface
)

var Definitions = eventDefinitions{
	events: map[ID]Event{
		Read: {
			ID32Bit: sys32read,
			Name:    "read",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_read_write"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "void*", Name: "buf"},
				{Type: "size_t", Name: "count"},
			},
		},
		Write: {
			ID32Bit: sys32write,
			Name:    "write",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_read_write"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "void*", Name: "buf"},
				{Type: "size_t", Name: "count"},
			},
		},
		Open: {
			ID32Bit: sys32open,
			Name:    "open",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_file_ops"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "int", Name: "flags"},
				{Type: "mode_t", Name: "mode"},
			},
		},
		Close: {
			ID32Bit: sys32close,
			Name:    "close",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_file_ops"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
			},
		},
		Stat: {
			ID32Bit: sys32stat,
			Name:    "stat",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "struct stat*", Name: "statbuf"},
			},
		},
		Fstat: {
			ID32Bit: sys32fstat,
			Name:    "fstat",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "struct stat*", Name: "statbuf"},
			},
		},
		Lstat: {
			ID32Bit: sys32lstat,
			Name:    "lstat",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "struct stat*", Name: "statbuf"},
			},
		},
		Poll: {
			ID32Bit: sys32poll,
			Name:    "poll",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_mux_io"},
			Params: []trace.ArgMeta{
				{Type: "struct pollfd*", Name: "fds"},
				{Type: "unsigned int", Name: "nfds"},
				{Type: "int", Name: "timeout"},
			},
		},
		Lseek: {
			ID32Bit: sys32lseek,
			Name:    "lseek",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_read_write"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "off_t", Name: "offset"},
				{Type: "unsigned int", Name: "whence"},
			},
		},
		Mmap: {
			ID32Bit: sys32mmap,
			Name:    "mmap",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_mem"},
			Params: []trace.ArgMeta{
				{Type: "void*", Name: "addr"},
				{Type: "size_t", Name: "length"},
				{Type: "int", Name: "prot"},
				{Type: "int", Name: "flags"},
				{Type: "int", Name: "fd"},
				{Type: "off_t", Name: "off"},
			},
		},
		Mprotect: {
			ID32Bit: sys32mprotect,
			Name:    "mprotect",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_mem"},
			Params: []trace.ArgMeta{
				{Type: "void*", Name: "addr"},
				{Type: "size_t", Name: "len"},
				{Type: "int", Name: "prot"},
			},
		},
		Munmap: {
			ID32Bit: sys32munmap,
			Name:    "munmap",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_mem"},
			Params: []trace.ArgMeta{
				{Type: "void*", Name: "addr"},
				{Type: "size_t", Name: "length"},
			},
		},
		Brk: {
			ID32Bit: sys32brk,
			Name:    "brk",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_mem"},
			Params: []trace.ArgMeta{
				{Type: "void*", Name: "addr"},
			},
		},
		RtSigaction: {
			ID32Bit: sys32rt_sigaction,
			Name:    "rt_sigaction",
			Syscall: true,
			Sets:    []string{"syscalls", "signals"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "signum"},
				{Type: "const struct sigaction*", Name: "act"},
				{Type: "struct sigaction*", Name: "oldact"},
				{Type: "size_t", Name: "sigsetsize"},
			},
		},
		RtSigprocmask: {
			ID32Bit: sys32rt_sigprocmask,
			Name:    "rt_sigprocmask",
			Syscall: true,
			Sets:    []string{"syscalls", "signals"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "how"},
				{Type: "sigset_t*", Name: "set"},
				{Type: "sigset_t*", Name: "oldset"},
				{Type: "size_t", Name: "sigsetsize"},
			},
		},
		RtSigreturn: {
			ID32Bit: sys32rt_sigreturn,
			Name:    "rt_sigreturn",
			Syscall: true,
			Sets:    []string{"syscalls", "signals"},
			Params:  []trace.ArgMeta{},
		},
		Ioctl: {
			ID32Bit: sys32ioctl,
			Name:    "ioctl",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_fd_ops"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "unsigned long", Name: "request"},
				{Type: "unsigned long", Name: "arg"},
			},
		},
		Pread64: {
			ID32Bit: sys32pread64,
			Name:    "pread64",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_read_write"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "void*", Name: "buf"},
				{Type: "size_t", Name: "count"},
				{Type: "off_t", Name: "offset"},
			},
		},
		Pwrite64: {
			ID32Bit: sys32pwrite64,
			Name:    "pwrite64",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_read_write"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const void*", Name: "buf"},
				{Type: "size_t", Name: "count"},
				{Type: "off_t", Name: "offset"},
			},
		},
		Readv: {
			ID32Bit: sys32readv,
			Name:    "readv",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_read_write"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const struct iovec*", Name: "iov"},
				{Type: "int", Name: "iovcnt"},
			},
		},
		Writev: {
			ID32Bit: sys32writev,
			Name:    "writev",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_read_write"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const struct iovec*", Name: "iov"},
				{Type: "int", Name: "iovcnt"},
			},
		},
		Access: {
			ID32Bit: sys32access,
			Name:    "access",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "int", Name: "mode"},
			},
		},
		Pipe: {
			ID32Bit: sys32pipe,
			Name:    "pipe",
			Syscall: true,
			Sets:    []string{"syscalls", "ipc", "ipc_pipe"},
			Params: []trace.ArgMeta{
				{Type: "int[2]", Name: "pipefd"},
			},
		},
		Select: {
			ID32Bit: sys32_newselect,
			Name:    "select",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_mux_io"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "nfds"},
				{Type: "fd_set*", Name: "readfds"},
				{Type: "fd_set*", Name: "writefds"},
				{Type: "fd_set*", Name: "exceptfds"},
				{Type: "struct timeval*", Name: "timeout"},
			},
		},
		SchedYield: {
			ID32Bit: sys32sched_yield,
			Name:    "sched_yield",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_sched"},
			Params:  []trace.ArgMeta{},
		},
		Mremap: {
			ID32Bit: sys32mremap,
			Name:    "mremap",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_mem"},
			Params: []trace.ArgMeta{
				{Type: "void*", Name: "old_address"},
				{Type: "size_t", Name: "old_size"},
				{Type: "size_t", Name: "new_size"},
				{Type: "int", Name: "flags"},
				{Type: "void*", Name: "new_address"},
			},
		},
		Msync: {
			ID32Bit: sys32msync,
			Name:    "msync",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_sync"},
			Params: []trace.ArgMeta{
				{Type: "void*", Name: "addr"},
				{Type: "size_t", Name: "length"},
				{Type: "int", Name: "flags"},
			},
		},
		Mincore: {
			ID32Bit: sys32mincore,
			Name:    "mincore",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_mem"},
			Params: []trace.ArgMeta{
				{Type: "void*", Name: "addr"},
				{Type: "size_t", Name: "length"},
				{Type: "unsigned char*", Name: "vec"},
			},
		},
		Madvise: {
			ID32Bit: sys32madvise,
			Name:    "madvise",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_mem"},
			Params: []trace.ArgMeta{
				{Type: "void*", Name: "addr"},
				{Type: "size_t", Name: "length"},
				{Type: "int", Name: "advice"},
			},
		},
		Shmget: {
			ID32Bit: sys32shmget,
			Name:    "shmget",
			Syscall: true,
			Sets:    []string{"syscalls", "ipc", "ipc_shm"},
			Params: []trace.ArgMeta{
				{Type: "key_t", Name: "key"},
				{Type: "size_t", Name: "size"},
				{Type: "int", Name: "shmflg"},
			},
		},
		Shmat: {
			ID32Bit: sys32shmat,
			Name:    "shmat",
			Syscall: true,
			Sets:    []string{"syscalls", "ipc", "ipc_shm"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "shmid"},
				{Type: "const void*", Name: "shmaddr"},
				{Type: "int", Name: "shmflg"},
			},
		},
		Shmctl: {
			ID32Bit: sys32shmctl,
			Name:    "shmctl",
			Syscall: true,
			Sets:    []string{"syscalls", "ipc", "ipc_shm"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "shmid"},
				{Type: "int", Name: "cmd"},
				{Type: "struct shmid_ds*", Name: "buf"},
			},
		},
		Dup: {
			ID32Bit: sys32dup,
			Name:    "dup",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_fd_ops"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "oldfd"},
			},
		},
		Dup2: {
			ID32Bit: sys32dup2,
			Name:    "dup2",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_fd_ops"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "oldfd"},
				{Type: "int", Name: "newfd"},
			},
		},
		Pause: {
			ID32Bit: sys32pause,
			Name:    "pause",
			Syscall: true,
			Sets:    []string{"syscalls", "signals"},
			Params:  []trace.ArgMeta{},
		},
		Nanosleep: {
			ID32Bit: sys32nanosleep,
			Name:    "nanosleep",
			Syscall: true,
			Sets:    []string{"syscalls", "time", "time_timer"},
			Params: []trace.ArgMeta{
				{Type: "const struct timespec*", Name: "req"},
				{Type: "struct timespec*", Name: "rem"},
			},
		},
		Getitimer: {
			ID32Bit: sys32getitimer,
			Name:    "getitimer",
			Syscall: true,
			Sets:    []string{"syscalls", "time", "time_timer"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "which"},
				{Type: "struct itimerval*", Name: "curr_value"},
			},
		},
		Alarm: {
			ID32Bit: sys32alarm,
			Name:    "alarm",
			Syscall: true,
			Sets:    []string{"syscalls", "time", "time_timer"},
			Params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "seconds"},
			},
		},
		Setitimer: {
			ID32Bit: sys32setitimer,
			Name:    "setitimer",
			Syscall: true,
			Sets:    []string{"syscalls", "time", "time_timer"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "which"},
				{Type: "struct itimerval*", Name: "new_value"},
				{Type: "struct itimerval*", Name: "old_value"},
			},
		},
		Getpid: {
			ID32Bit: sys32getpid,
			Name:    "getpid",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_ids"},
			Params:  []trace.ArgMeta{},
		},
		Sendfile: {
			ID32Bit: sys32sendfile64,
			Name:    "sendfile",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_read_write"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "out_fd"},
				{Type: "int", Name: "in_fd"},
				{Type: "off_t*", Name: "offset"},
				{Type: "size_t", Name: "count"},
			},
		},
		Socket: {
			ID32Bit: sys32socket,
			Name:    "socket",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "net", "net_sock"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "domain"},
				{Type: "int", Name: "type"},
				{Type: "int", Name: "protocol"},
			},
		},
		Connect: {
			ID32Bit: sys32connect,
			Name:    "connect",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "net", "net_sock"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct sockaddr*", Name: "addr"},
				{Type: "int", Name: "addrlen"},
			},
		},
		Accept: {
			ID32Bit: sys32undefined,
			Name:    "accept",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "net", "net_sock"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct sockaddr*", Name: "addr"},
				{Type: "int*", Name: "addrlen"},
			},
		},
		Sendto: {
			ID32Bit: sys32sendto,
			Name:    "sendto",
			Syscall: true,
			Sets:    []string{"syscalls", "net", "net_snd_rcv"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "void*", Name: "buf"},
				{Type: "size_t", Name: "len"},
				{Type: "int", Name: "flags"},
				{Type: "struct sockaddr*", Name: "dest_addr"},
				{Type: "int", Name: "addrlen"},
			},
		},
		Recvfrom: {
			ID32Bit: sys32recvfrom,
			Name:    "recvfrom",
			Syscall: true,
			Sets:    []string{"syscalls", "net", "net_snd_rcv"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "void*", Name: "buf"},
				{Type: "size_t", Name: "len"},
				{Type: "int", Name: "flags"},
				{Type: "struct sockaddr*", Name: "src_addr"},
				{Type: "int*", Name: "addrlen"},
			},
		},
		Sendmsg: {
			ID32Bit: sys32sendmsg,
			Name:    "sendmsg",
			Syscall: true,
			Sets:    []string{"syscalls", "net", "net_snd_rcv"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct msghdr*", Name: "msg"},
				{Type: "int", Name: "flags"},
			},
		},
		Recvmsg: {
			ID32Bit: sys32recvmsg,
			Name:    "recvmsg",
			Syscall: true,
			Sets:    []string{"syscalls", "net", "net_snd_rcv"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct msghdr*", Name: "msg"},
				{Type: "int", Name: "flags"},
			},
		},
		Shutdown: {
			ID32Bit: sys32shutdown,
			Name:    "shutdown",
			Syscall: true,
			Sets:    []string{"syscalls", "net", "net_sock"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "int", Name: "how"},
			},
		},
		Bind: {
			ID32Bit: sys32bind,
			Name:    "bind",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "net", "net_sock"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct sockaddr*", Name: "addr"},
				{Type: "int", Name: "addrlen"},
			},
		},
		Listen: {
			ID32Bit: sys32listen,
			Name:    "listen",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "net", "net_sock"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "int", Name: "backlog"},
			},
		},
		Getsockname: {
			ID32Bit: sys32getsockname,
			Name:    "getsockname",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "net", "net_sock"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct sockaddr*", Name: "addr"},
				{Type: "int*", Name: "addrlen"},
			},
		},
		Getpeername: {
			ID32Bit: sys32getpeername,
			Name:    "getpeername",
			Syscall: true,
			Sets:    []string{"syscalls", "net", "net_sock"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct sockaddr*", Name: "addr"},
				{Type: "int*", Name: "addrlen"},
			},
		},
		Socketpair: {
			ID32Bit: sys32socketpair,
			Name:    "socketpair",
			Syscall: true,
			Sets:    []string{"syscalls", "net", "net_sock"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "domain"},
				{Type: "int", Name: "type"},
				{Type: "int", Name: "protocol"},
				{Type: "int[2]", Name: "sv"},
			},
		},
		Setsockopt: {
			ID32Bit: sys32setsockopt,
			Name:    "setsockopt",
			Syscall: true,
			Sets:    []string{"syscalls", "net", "net_sock"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "int", Name: "level"},
				{Type: "int", Name: "optname"},
				{Type: "const void*", Name: "optval"},
				{Type: "int", Name: "optlen"},
			},
		},
		Getsockopt: {
			ID32Bit: sys32getsockopt,
			Name:    "getsockopt",
			Syscall: true,
			Sets:    []string{"syscalls", "net", "net_sock"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "int", Name: "level"},
				{Type: "int", Name: "optname"},
				{Type: "void*", Name: "optval"},
				{Type: "int*", Name: "optlen"},
			},
		},
		Clone: {
			ID32Bit: sys32clone,
			Name:    "clone",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "proc", "proc_life"},
			Params: []trace.ArgMeta{
				{Type: "unsigned long", Name: "flags"},
				{Type: "void*", Name: "stack"},
				{Type: "int*", Name: "parent_tid"},
				{Type: "int*", Name: "child_tid"},
				{Type: "unsigned long", Name: "tls"},
			},
		},
		Fork: {
			ID32Bit: sys32fork,
			Name:    "fork",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "proc", "proc_life"},
			Params:  []trace.ArgMeta{},
		},
		Vfork: {
			ID32Bit: sys32vfork,
			Name:    "vfork",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "proc", "proc_life"},
			Params:  []trace.ArgMeta{},
		},
		Execve: {
			ID32Bit: sys32execve,
			Name:    "execve",
			Syscall: true,
			Dependencies: dependencies{
				TailCalls: []TailCall{
					{MapName: "sys_enter_tails", MapIndexes: []uint32{uint32(Execve)}, ProgName: "syscall__execve"},
				},
			},
			Sets: []string{"default", "syscalls", "proc", "proc_life"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "const char*const*", Name: "argv"},
				{Type: "const char*const*", Name: "envp"},
			},
		},
		Exit: {
			ID32Bit: sys32exit,
			Name:    "exit",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_life"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "status"},
			},
		},
		Wait4: {
			ID32Bit: sys32wait4,
			Name:    "wait4",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_life"},
			Params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "int*", Name: "wstatus"},
				{Type: "int", Name: "options"},
				{Type: "struct rusage*", Name: "rusage"},
			},
		},
		Kill: {
			ID32Bit: sys32kill,
			Name:    "kill",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "signals"},
			Params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "int", Name: "sig"},
			},
		},
		Uname: {
			ID32Bit: sys32uname,
			Name:    "uname",
			Syscall: true,
			Sets:    []string{"syscalls", "system"},
			Params: []trace.ArgMeta{
				{Type: "struct utsname*", Name: "buf"},
			},
		},
		Semget: {
			ID32Bit: sys32semget,
			Name:    "semget",
			Syscall: true,
			Sets:    []string{"syscalls", "ipc", "ipc_sem"},
			Params: []trace.ArgMeta{
				{Type: "key_t", Name: "key"},
				{Type: "int", Name: "nsems"},
				{Type: "int", Name: "semflg"},
			},
		},
		Semop: {
			ID32Bit: sys32undefined,
			Name:    "semop",
			Syscall: true,
			Sets:    []string{"syscalls", "ipc", "ipc_sem"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "semid"},
				{Type: "struct sembuf*", Name: "sops"},
				{Type: "size_t", Name: "nsops"},
			},
		},
		Semctl: {
			ID32Bit: sys32semctl,
			Name:    "semctl",
			Syscall: true,
			Sets:    []string{"syscalls", "ipc", "ipc_sem"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "semid"},
				{Type: "int", Name: "semnum"},
				{Type: "int", Name: "cmd"},
				{Type: "unsigned long", Name: "arg"},
			},
		},
		Shmdt: {
			ID32Bit: sys32shmdt,
			Name:    "shmdt",
			Syscall: true,
			Sets:    []string{"syscalls", "ipc", "ipc_shm"},
			Params: []trace.ArgMeta{
				{Type: "const void*", Name: "shmaddr"},
			},
		},
		Msgget: {
			ID32Bit: sys32msgget,
			Name:    "msgget",
			Syscall: true,
			Sets:    []string{"syscalls", "ipc", "ipc_msgq"},
			Params: []trace.ArgMeta{
				{Type: "key_t", Name: "key"},
				{Type: "int", Name: "msgflg"},
			},
		},
		Msgsnd: {
			ID32Bit: sys32msgsnd,
			Name:    "msgsnd",
			Syscall: true,
			Sets:    []string{"syscalls", "ipc", "ipc_msgq"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "msqid"},
				{Type: "struct msgbuf*", Name: "msgp"},
				{Type: "size_t", Name: "msgsz"},
				{Type: "int", Name: "msgflg"},
			},
		},
		Msgrcv: {
			ID32Bit: sys32msgrcv,
			Name:    "msgrcv",
			Syscall: true,
			Sets:    []string{"syscalls", "ipc", "ipc_msgq"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "msqid"},
				{Type: "struct msgbuf*", Name: "msgp"},
				{Type: "size_t", Name: "msgsz"},
				{Type: "long", Name: "msgtyp"},
				{Type: "int", Name: "msgflg"},
			},
		},
		Msgctl: {
			ID32Bit: sys32msgctl,
			Name:    "msgctl",
			Syscall: true,
			Sets:    []string{"syscalls", "ipc", "ipc_msgq"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "msqid"},
				{Type: "int", Name: "cmd"},
				{Type: "struct msqid_ds*", Name: "buf"},
			},
		},
		Fcntl: {
			ID32Bit: sys32fcntl,
			Name:    "fcntl",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_fd_ops"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "int", Name: "cmd"},
				{Type: "unsigned long", Name: "arg"},
			},
		},
		Flock: {
			ID32Bit: sys32flock,
			Name:    "flock",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_fd_ops"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "int", Name: "operation"},
			},
		},
		Fsync: {
			ID32Bit: sys32fsync,
			Name:    "fsync",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_sync"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
			},
		},
		Fdatasync: {
			ID32Bit: sys32fdatasync,
			Name:    "fdatasync",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_sync"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
			},
		},
		Truncate: {
			ID32Bit: sys32truncate,
			Name:    "truncate",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_ops"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "off_t", Name: "length"},
			},
		},
		Ftruncate: {
			ID32Bit: sys32ftruncate,
			Name:    "ftruncate",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_ops"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "off_t", Name: "length"},
			},
		},
		Getdents: {
			ID32Bit: sys32getdents,
			Name:    "getdents",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_dir_ops"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "struct linux_dirent*", Name: "dirp"},
				{Type: "unsigned int", Name: "count"},
			},
		},
		Getcwd: {
			ID32Bit: sys32getcwd,
			Name:    "getcwd",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_dir_ops"},
			Params: []trace.ArgMeta{
				{Type: "char*", Name: "buf"},
				{Type: "size_t", Name: "size"},
			},
		},
		Chdir: {
			ID32Bit: sys32chdir,
			Name:    "chdir",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_dir_ops"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
			},
		},
		Fchdir: {
			ID32Bit: sys32fchdir,
			Name:    "fchdir",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_dir_ops"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
			},
		},
		Rename: {
			ID32Bit: sys32rename,
			Name:    "rename",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_ops"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "oldpath"},
				{Type: "const char*", Name: "newpath"},
			},
		},
		Mkdir: {
			ID32Bit: sys32mkdir,
			Name:    "mkdir",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_dir_ops"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "mode_t", Name: "mode"},
			},
		},
		Rmdir: {
			ID32Bit: sys32rmdir,
			Name:    "rmdir",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_dir_ops"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
			},
		},
		Creat: {
			ID32Bit: sys32creat,
			Name:    "creat",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_file_ops"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "mode_t", Name: "mode"},
			},
		},
		Link: {
			ID32Bit: sys32link,
			Name:    "link",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_link_ops"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "oldpath"},
				{Type: "const char*", Name: "newpath"},
			},
		},
		Unlink: {
			ID32Bit: sys32unlink,
			Name:    "unlink",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_link_ops"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
			},
		},
		Symlink: {
			ID32Bit: sys32symlink,
			Name:    "symlink",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_link_ops"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "target"},
				{Type: "const char*", Name: "linkpath"},
			},
		},
		Readlink: {
			ID32Bit: sys32readlink,
			Name:    "readlink",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_link_ops"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "char*", Name: "buf"},
				{Type: "size_t", Name: "bufsiz"},
			},
		},
		Chmod: {
			ID32Bit: sys32chmod,
			Name:    "chmod",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "mode_t", Name: "mode"},
			},
		},
		Fchmod: {
			ID32Bit: sys32fchmod,
			Name:    "fchmod",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "mode_t", Name: "mode"},
			},
		},
		Chown: {
			ID32Bit: sys32chown32,
			Name:    "chown",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "uid_t", Name: "owner"},
				{Type: "gid_t", Name: "group"},
			},
		},
		Fchown: {
			ID32Bit: sys32fchown32,
			Name:    "fchown",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "uid_t", Name: "owner"},
				{Type: "gid_t", Name: "group"},
			},
		},
		Lchown: {
			ID32Bit: sys32lchown32,
			Name:    "lchown",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "uid_t", Name: "owner"},
				{Type: "gid_t", Name: "group"},
			},
		},
		Umask: {
			ID32Bit: sys32umask,
			Name:    "umask",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "mode_t", Name: "mask"},
			},
		},
		Gettimeofday: {
			ID32Bit: sys32gettimeofday,
			Name:    "gettimeofday",
			Syscall: true,
			Sets:    []string{"syscalls", "time", "time_tod"},
			Params: []trace.ArgMeta{
				{Type: "struct timeval*", Name: "tv"},
				{Type: "struct timezone*", Name: "tz"},
			},
		},
		Getrlimit: {
			ID32Bit: sys32ugetrlimit,
			Name:    "getrlimit",
			Syscall: true,
			Sets:    []string{"syscalls", "proc"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "resource"},
				{Type: "struct rlimit*", Name: "rlim"},
			},
		},
		Getrusage: {
			ID32Bit: sys32getrusage,
			Name:    "getrusage",
			Syscall: true,
			Sets:    []string{"syscalls", "proc"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "who"},
				{Type: "struct rusage*", Name: "usage"},
			},
		},
		Sysinfo: {
			ID32Bit: sys32sysinfo,
			Name:    "sysinfo",
			Syscall: true,
			Sets:    []string{"syscalls", "system"},
			Params: []trace.ArgMeta{
				{Type: "struct sysinfo*", Name: "info"},
			},
		},
		Times: {
			ID32Bit: sys32times,
			Name:    "times",
			Syscall: true,
			Sets:    []string{"syscalls", "proc"},
			Params: []trace.ArgMeta{
				{Type: "struct tms*", Name: "buf"},
			},
		},
		Ptrace: {
			ID32Bit: sys32ptrace,
			Name:    "ptrace",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "proc"},
			Params: []trace.ArgMeta{
				{Type: "long", Name: "request"},
				{Type: "pid_t", Name: "pid"},
				{Type: "void*", Name: "addr"},
				{Type: "void*", Name: "data"},
			},
		},
		Getuid: {
			ID32Bit: sys32getuid32,
			Name:    "getuid",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_ids"},
			Params:  []trace.ArgMeta{},
		},
		Syslog: {
			ID32Bit: sys32syslog,
			Name:    "syslog",
			Syscall: true,
			Sets:    []string{"syscalls", "system"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "type"},
				{Type: "char*", Name: "bufp"},
				{Type: "int", Name: "len"},
			},
		},
		Getgid: {
			ID32Bit: sys32getgid32,
			Name:    "getgid",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_ids"},
			Params:  []trace.ArgMeta{},
		},
		Setuid: {
			ID32Bit: sys32setuid32,
			Name:    "setuid",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "proc", "proc_ids"},
			Params: []trace.ArgMeta{
				{Type: "uid_t", Name: "uid"},
			},
		},
		Setgid: {
			ID32Bit: sys32setgid32,
			Name:    "setgid",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "proc", "proc_ids"},
			Params: []trace.ArgMeta{
				{Type: "gid_t", Name: "gid"},
			},
		},
		Geteuid: {
			ID32Bit: sys32geteuid32,
			Name:    "geteuid",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_ids"},
			Params:  []trace.ArgMeta{},
		},
		Getegid: {
			ID32Bit: sys32getegid32,
			Name:    "getegid",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_ids"},
			Params:  []trace.ArgMeta{},
		},
		Setpgid: {
			ID32Bit: sys32setpgid,
			Name:    "setpgid",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_ids"},
			Params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "pid_t", Name: "pgid"},
			},
		},
		Getppid: {
			ID32Bit: sys32getppid,
			Name:    "getppid",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_ids"},
			Params:  []trace.ArgMeta{},
		},
		Getpgrp: {
			ID32Bit: sys32getpgrp,
			Name:    "getpgrp",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_ids"},
			Params:  []trace.ArgMeta{},
		},
		Setsid: {
			ID32Bit: sys32setsid,
			Name:    "setsid",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_ids"},
			Params:  []trace.ArgMeta{},
		},
		Setreuid: {
			ID32Bit: sys32setreuid32,
			Name:    "setreuid",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "proc", "proc_ids"},
			Params: []trace.ArgMeta{
				{Type: "uid_t", Name: "ruid"},
				{Type: "uid_t", Name: "euid"},
			},
		},
		Setregid: {
			ID32Bit: sys32setregid32,
			Name:    "setregid",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "proc", "proc_ids"},
			Params: []trace.ArgMeta{
				{Type: "gid_t", Name: "rgid"},
				{Type: "gid_t", Name: "egid"},
			},
		},
		Getgroups: {
			ID32Bit: sys32getgroups32,
			Name:    "getgroups",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_ids"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "size"},
				{Type: "gid_t*", Name: "list"},
			},
		},
		Setgroups: {
			ID32Bit: sys32setgroups32,
			Name:    "setgroups",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_ids"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "size"},
				{Type: "gid_t*", Name: "list"},
			},
		},
		Setresuid: {
			ID32Bit: sys32setresuid32,
			Name:    "setresuid",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_ids"},
			Params: []trace.ArgMeta{
				{Type: "uid_t", Name: "ruid"},
				{Type: "uid_t", Name: "euid"},
				{Type: "uid_t", Name: "suid"},
			},
		},
		Getresuid: {
			ID32Bit: sys32getresuid32,
			Name:    "getresuid",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_ids"},
			Params: []trace.ArgMeta{
				{Type: "uid_t*", Name: "ruid"},
				{Type: "uid_t*", Name: "euid"},
				{Type: "uid_t*", Name: "suid"},
			},
		},
		Setresgid: {
			ID32Bit: sys32setresgid32,
			Name:    "setresgid",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_ids"},
			Params: []trace.ArgMeta{
				{Type: "gid_t", Name: "rgid"},
				{Type: "gid_t", Name: "egid"},
				{Type: "gid_t", Name: "sgid"},
			},
		},
		Getresgid: {
			ID32Bit: sys32getresgid32,
			Name:    "getresgid",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_ids"},
			Params: []trace.ArgMeta{
				{Type: "gid_t*", Name: "rgid"},
				{Type: "gid_t*", Name: "egid"},
				{Type: "gid_t*", Name: "sgid"},
			},
		},
		Getpgid: {
			ID32Bit: sys32getpgid,
			Name:    "getpgid",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_ids"},
			Params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
			},
		},
		Setfsuid: {
			ID32Bit: sys32setfsuid32,
			Name:    "setfsuid",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "proc", "proc_ids"},
			Params: []trace.ArgMeta{
				{Type: "uid_t", Name: "fsuid"},
			},
		},
		Setfsgid: {
			ID32Bit: sys32setfsgid32,
			Name:    "setfsgid",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "proc", "proc_ids"},
			Params: []trace.ArgMeta{
				{Type: "gid_t", Name: "fsgid"},
			},
		},
		Getsid: {
			ID32Bit: sys32getsid,
			Name:    "getsid",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_ids"},
			Params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
			},
		},
		Capget: {
			ID32Bit: sys32capget,
			Name:    "capget",
			Syscall: true,
			Sets:    []string{"syscalls", "proc"},
			Params: []trace.ArgMeta{
				{Type: "cap_user_header_t", Name: "hdrp"},
				{Type: "cap_user_data_t", Name: "datap"},
			},
		},
		Capset: {
			ID32Bit: sys32capset,
			Name:    "capset",
			Syscall: true,
			Sets:    []string{"syscalls", "proc"},
			Params: []trace.ArgMeta{
				{Type: "cap_user_header_t", Name: "hdrp"},
				{Type: "const cap_user_data_t", Name: "datap"},
			},
		},
		RtSigpending: {
			ID32Bit: sys32rt_sigpending,
			Name:    "rt_sigpending",
			Syscall: true,
			Sets:    []string{"syscalls", "signals"},
			Params: []trace.ArgMeta{
				{Type: "sigset_t*", Name: "set"},
				{Type: "size_t", Name: "sigsetsize"},
			},
		},
		RtSigtimedwait: {
			ID32Bit: sys32rt_sigtimedwait_time64,
			Name:    "rt_sigtimedwait",
			Syscall: true,
			Sets:    []string{"syscalls", "signals"},
			Params: []trace.ArgMeta{
				{Type: "const sigset_t*", Name: "set"},
				{Type: "siginfo_t*", Name: "info"},
				{Type: "const struct timespec*", Name: "timeout"},
				{Type: "size_t", Name: "sigsetsize"},
			},
		},
		RtSigqueueinfo: {
			ID32Bit: sys32rt_sigqueueinfo,
			Name:    "rt_sigqueueinfo",
			Syscall: true,
			Sets:    []string{"syscalls", "signals"},
			Params: []trace.ArgMeta{
				{Type: "pid_t", Name: "tgid"},
				{Type: "int", Name: "sig"},
				{Type: "siginfo_t*", Name: "info"},
			},
		},
		RtSigsuspend: {
			ID32Bit: sys32rt_sigsuspend,
			Name:    "rt_sigsuspend",
			Syscall: true,
			Sets:    []string{"syscalls", "signals"},
			Params: []trace.ArgMeta{
				{Type: "sigset_t*", Name: "mask"},
				{Type: "size_t", Name: "sigsetsize"},
			},
		},
		Sigaltstack: {
			ID32Bit: sys32sigaltstack,
			Name:    "sigaltstack",
			Syscall: true,
			Sets:    []string{"syscalls", "signals"},
			Params: []trace.ArgMeta{
				{Type: "const stack_t*", Name: "ss"},
				{Type: "stack_t*", Name: "old_ss"},
			},
		},
		Utime: {
			ID32Bit: sys32utime,
			Name:    "utime",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "filename"},
				{Type: "const struct utimbuf*", Name: "times"},
			},
		},
		Mknod: {
			ID32Bit: sys32mknod,
			Name:    "mknod",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_file_ops"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "mode_t", Name: "mode"},
				{Type: "dev_t", Name: "dev"},
			},
		},
		Uselib: {
			ID32Bit: sys32uselib,
			Name:    "uselib",
			Syscall: true,
			Sets:    []string{"syscalls", "proc"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "library"},
			},
		},
		Personality: {
			ID32Bit: sys32personality,
			Name:    "personality",
			Syscall: true,
			Sets:    []string{"syscalls", "system"},
			Params: []trace.ArgMeta{
				{Type: "unsigned long", Name: "persona"},
			},
		},
		Ustat: {
			ID32Bit: sys32ustat,
			Name:    "ustat",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_info"},
			Params: []trace.ArgMeta{
				{Type: "dev_t", Name: "dev"},
				{Type: "struct ustat*", Name: "ubuf"},
			},
		},
		Statfs: {
			ID32Bit: sys32statfs,
			Name:    "statfs",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_info"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "struct statfs*", Name: "buf"},
			},
		},
		Fstatfs: {
			ID32Bit: sys32fstatfs,
			Name:    "fstatfs",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_info"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "struct statfs*", Name: "buf"},
			},
		},
		Sysfs: {
			ID32Bit: sys32sysfs,
			Name:    "sysfs",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_info"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "option"},
			},
		},
		Getpriority: {
			ID32Bit: sys32getpriority,
			Name:    "getpriority",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_sched"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "which"},
				{Type: "int", Name: "who"},
			},
		},
		Setpriority: {
			ID32Bit: sys32setpriority,
			Name:    "setpriority",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_sched"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "which"},
				{Type: "int", Name: "who"},
				{Type: "int", Name: "prio"},
			},
		},
		SchedSetparam: {
			ID32Bit: sys32sched_setparam,
			Name:    "sched_setparam",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_sched"},
			Params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "struct sched_param*", Name: "param"},
			},
		},
		SchedGetparam: {
			ID32Bit: sys32sched_getparam,
			Name:    "sched_getparam",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_sched"},
			Params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "struct sched_param*", Name: "param"},
			},
		},
		SchedSetscheduler: {
			ID32Bit: sys32sched_setscheduler,
			Name:    "sched_setscheduler",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_sched"},
			Params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "int", Name: "policy"},
				{Type: "struct sched_param*", Name: "param"},
			},
		},
		SchedGetscheduler: {
			ID32Bit: sys32sched_getscheduler,
			Name:    "sched_getscheduler",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_sched"},
			Params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
			},
		},
		SchedGetPriorityMax: {
			ID32Bit: sys32sched_get_priority_max,
			Name:    "sched_get_priority_max",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_sched"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "policy"},
			},
		},
		SchedGetPriorityMin: {
			ID32Bit: sys32sched_get_priority_min,
			Name:    "sched_get_priority_min",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_sched"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "policy"},
			},
		},
		SchedRrGetInterval: {
			ID32Bit: sys32sched_rr_get_interval_time64,
			Name:    "sched_rr_get_interval",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_sched"},
			Params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "struct timespec*", Name: "tp"},
			},
		},
		Mlock: {
			ID32Bit: sys32mlock,
			Name:    "mlock",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_mem"},
			Params: []trace.ArgMeta{
				{Type: "const void*", Name: "addr"},
				{Type: "size_t", Name: "len"},
			},
		},
		Munlock: {
			ID32Bit: sys32munlock,
			Name:    "munlock",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_mem"},
			Params: []trace.ArgMeta{
				{Type: "const void*", Name: "addr"},
				{Type: "size_t", Name: "len"},
			},
		},
		Mlockall: {
			ID32Bit: sys32mlockall,
			Name:    "mlockall",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_mem"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "flags"},
			},
		},
		Munlockall: {
			ID32Bit: sys32munlockall,
			Name:    "munlockall",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_mem"},
			Params:  []trace.ArgMeta{},
		},
		Vhangup: {
			ID32Bit: sys32vhangup,
			Name:    "vhangup",
			Syscall: true,
			Sets:    []string{"syscalls", "system"},
			Params:  []trace.ArgMeta{},
		},
		ModifyLdt: {
			ID32Bit: sys32modify_ldt,
			Name:    "modify_ldt",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_mem"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "func"},
				{Type: "void*", Name: "ptr"},
				{Type: "unsigned long", Name: "bytecount"},
			},
		},
		PivotRoot: {
			ID32Bit: sys32pivot_root,
			Name:    "pivot_root",
			Syscall: true,
			Sets:    []string{"syscalls", "fs"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "new_root"},
				{Type: "const char*", Name: "put_old"},
			},
		},
		Sysctl: {
			ID32Bit: sys32_sysctl,
			Name:    "sysctl",
			Syscall: true,
			Sets:    []string{"syscalls", "system"},
			Params: []trace.ArgMeta{
				{Type: "struct __sysctl_args*", Name: "args"},
			},
		},
		Prctl: {
			ID32Bit: sys32prctl,
			Name:    "prctl",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "proc"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "option"},
				{Type: "unsigned long", Name: "arg2"},
				{Type: "unsigned long", Name: "arg3"},
				{Type: "unsigned long", Name: "arg4"},
				{Type: "unsigned long", Name: "arg5"},
			},
		},
		ArchPrctl: {
			ID32Bit: sys32arch_prctl,
			Name:    "arch_prctl",
			Syscall: true,
			Sets:    []string{"syscalls", "proc"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "option"},
				{Type: "unsigned long", Name: "addr"},
			},
		},
		Adjtimex: {
			ID32Bit: sys32adjtimex,
			Name:    "adjtimex",
			Syscall: true,
			Sets:    []string{"syscalls", "time", "time_clock"},
			Params: []trace.ArgMeta{
				{Type: "struct timex*", Name: "buf"},
			},
		},
		Setrlimit: {
			ID32Bit: sys32setrlimit,
			Name:    "setrlimit",
			Syscall: true,
			Sets:    []string{"syscalls", "proc"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "resource"},
				{Type: "const struct rlimit*", Name: "rlim"},
			},
		},
		Chroot: {
			ID32Bit: sys32chroot,
			Name:    "chroot",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_dir_ops"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
			},
		},
		Sync: {
			ID32Bit: sys32sync,
			Name:    "sync",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_sync"},
			Params:  []trace.ArgMeta{},
		},
		Acct: {
			ID32Bit: sys32acct,
			Name:    "acct",
			Syscall: true,
			Sets:    []string{"syscalls", "system"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "filename"},
			},
		},
		Settimeofday: {
			ID32Bit: sys32settimeofday,
			Name:    "settimeofday",
			Syscall: true,
			Sets:    []string{"syscalls", "time", "time_tod"},
			Params: []trace.ArgMeta{
				{Type: "const struct timeval*", Name: "tv"},
				{Type: "const struct timezone*", Name: "tz"},
			},
		},
		Mount: {
			ID32Bit: sys32mount,
			Name:    "mount",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "source"},
				{Type: "const char*", Name: "target"},
				{Type: "const char*", Name: "filesystemtype"},
				{Type: "unsigned long", Name: "mountflags"},
				{Type: "const void*", Name: "data"},
			},
		},
		Umount2: {
			ID32Bit: sys32umount2,
			Name:    "umount2",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "target"},
				{Type: "int", Name: "flags"},
			},
		},
		Swapon: {
			ID32Bit: sys32swapon,
			Name:    "swapon",
			Syscall: true,
			Sets:    []string{"syscalls", "fs"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "int", Name: "swapflags"},
			},
		},
		Swapoff: {
			ID32Bit: sys32swapoff,
			Name:    "swapoff",
			Syscall: true,
			Sets:    []string{"syscalls", "fs"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
			},
		},
		Reboot: {
			ID32Bit: sys32reboot,
			Name:    "reboot",
			Syscall: true,
			Sets:    []string{"syscalls", "system"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "magic"},
				{Type: "int", Name: "magic2"},
				{Type: "int", Name: "cmd"},
				{Type: "void*", Name: "arg"},
			},
		},
		Sethostname: {
			ID32Bit: sys32sethostname,
			Name:    "sethostname",
			Syscall: true,
			Sets:    []string{"syscalls", "net"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "name"},
				{Type: "size_t", Name: "len"},
			},
		},
		Setdomainname: {
			ID32Bit: sys32setdomainname,
			Name:    "setdomainname",
			Syscall: true,
			Sets:    []string{"syscalls", "net"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "name"},
				{Type: "size_t", Name: "len"},
			},
		},
		Iopl: {
			ID32Bit: sys32iopl,
			Name:    "iopl",
			Syscall: true,
			Sets:    []string{"syscalls", "system"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "level"},
			},
		},
		Ioperm: {
			ID32Bit: sys32ioperm,
			Name:    "ioperm",
			Syscall: true,
			Sets:    []string{"syscalls", "system"},
			Params: []trace.ArgMeta{
				{Type: "unsigned long", Name: "from"},
				{Type: "unsigned long", Name: "num"},
				{Type: "int", Name: "turn_on"},
			},
		},
		CreateModule: {
			ID32Bit: sys32create_module,
			Name:    "create_module",
			Syscall: true,
			Sets:    []string{"syscalls", "system", "system_module"},
			Params:  []trace.ArgMeta{},
		},
		InitModule: {
			ID32Bit: sys32init_module,
			Name:    "init_module",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "system", "system_module"},
			Params: []trace.ArgMeta{
				{Type: "void*", Name: "module_image"},
				{Type: "unsigned long", Name: "len"},
				{Type: "const char*", Name: "param_values"},
			},
		},
		DeleteModule: {
			ID32Bit: sys32delete_module,
			Name:    "delete_module",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "system", "system_module"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "name"},
				{Type: "int", Name: "flags"},
			},
		},
		GetKernelSyms: {
			ID32Bit: sys32get_kernel_syms,
			Name:    "get_kernel_syms",
			Syscall: true,
			Sets:    []string{"syscalls", "system", "system_module"},
			Params:  []trace.ArgMeta{},
		},
		QueryModule: {
			ID32Bit: sys32query_module,
			Name:    "query_module",
			Syscall: true,
			Sets:    []string{"syscalls", "system", "system_module"},
			Params:  []trace.ArgMeta{},
		},
		Quotactl: {
			ID32Bit: sys32quotactl,
			Name:    "quotactl",
			Syscall: true,
			Sets:    []string{"syscalls", "system"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "cmd"},
				{Type: "const char*", Name: "special"},
				{Type: "int", Name: "id"},
				{Type: "void*", Name: "addr"},
			},
		},
		Nfsservctl: {
			ID32Bit: sys32nfsservctl,
			Name:    "nfsservctl",
			Syscall: true,
			Sets:    []string{"syscalls", "fs"},
			Params:  []trace.ArgMeta{},
		},
		Getpmsg: {
			ID32Bit: sys32getpmsg,
			Name:    "getpmsg",
			Syscall: true,
			Sets:    []string{"syscalls"},
			Params:  []trace.ArgMeta{},
		},
		Putpmsg: {
			ID32Bit: sys32putpmsg,
			Name:    "putpmsg",
			Syscall: true,
			Sets:    []string{"syscalls"},
			Params:  []trace.ArgMeta{},
		},
		Afs: {
			ID32Bit: sys32undefined,
			Name:    "afs",
			Syscall: true,
			Sets:    []string{"syscalls"},
			Params:  []trace.ArgMeta{},
		},
		Tuxcall: {
			ID32Bit: sys32undefined,
			Name:    "tuxcall",
			Syscall: true,
			Sets:    []string{"syscalls"},
			Params:  []trace.ArgMeta{},
		},
		Security: {
			ID32Bit: sys32undefined,
			Name:    "security",
			Syscall: true,
			Sets:    []string{"syscalls"},
			Params:  []trace.ArgMeta{},
		},
		Gettid: {
			ID32Bit: sys32gettid,
			Name:    "gettid",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_ids"},
			Params:  []trace.ArgMeta{},
		},
		Readahead: {
			ID32Bit: sys32readahead,
			Name:    "readahead",
			Syscall: true,
			Sets:    []string{"syscalls", "fs"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "off_t", Name: "offset"},
				{Type: "size_t", Name: "count"},
			},
		},
		Setxattr: {
			ID32Bit: sys32setxattr,
			Name:    "setxattr",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "const char*", Name: "name"},
				{Type: "const void*", Name: "value"},
				{Type: "size_t", Name: "size"},
				{Type: "int", Name: "flags"},
			},
		},
		Lsetxattr: {
			ID32Bit: sys32lsetxattr,
			Name:    "lsetxattr",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "const char*", Name: "name"},
				{Type: "const void*", Name: "value"},
				{Type: "size_t", Name: "size"},
				{Type: "int", Name: "flags"},
			},
		},
		Fsetxattr: {
			ID32Bit: sys32fsetxattr,
			Name:    "fsetxattr",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const char*", Name: "name"},
				{Type: "const void*", Name: "value"},
				{Type: "size_t", Name: "size"},
				{Type: "int", Name: "flags"},
			},
		},
		Getxattr: {
			ID32Bit: sys32getxattr,
			Name:    "getxattr",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "const char*", Name: "name"},
				{Type: "void*", Name: "value"},
				{Type: "size_t", Name: "size"},
			},
		},
		Lgetxattr: {
			ID32Bit: sys32lgetxattr,
			Name:    "lgetxattr",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "const char*", Name: "name"},
				{Type: "void*", Name: "value"},
				{Type: "size_t", Name: "size"},
			},
		},
		Fgetxattr: {
			ID32Bit: sys32fgetxattr,
			Name:    "fgetxattr",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const char*", Name: "name"},
				{Type: "void*", Name: "value"},
				{Type: "size_t", Name: "size"},
			},
		},
		Listxattr: {
			ID32Bit: sys32listxattr,
			Name:    "listxattr",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "char*", Name: "list"},
				{Type: "size_t", Name: "size"},
			},
		},
		Llistxattr: {
			ID32Bit: sys32llistxattr,
			Name:    "llistxattr",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "char*", Name: "list"},
				{Type: "size_t", Name: "size"},
			},
		},
		Flistxattr: {
			ID32Bit: sys32flistxattr,
			Name:    "flistxattr",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "char*", Name: "list"},
				{Type: "size_t", Name: "size"},
			},
		},
		Removexattr: {
			ID32Bit: sys32removexattr,
			Name:    "removexattr",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "const char*", Name: "name"},
			},
		},
		Lremovexattr: {
			ID32Bit: sys32lremovexattr,
			Name:    "lremovexattr",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "const char*", Name: "name"},
			},
		},
		Fremovexattr: {
			ID32Bit: sys32fremovexattr,
			Name:    "fremovexattr",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const char*", Name: "name"},
			},
		},
		Tkill: {
			ID32Bit: sys32tkill,
			Name:    "tkill",
			Syscall: true,
			Sets:    []string{"syscalls", "signals"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "tid"},
				{Type: "int", Name: "sig"},
			},
		},
		Time: {
			ID32Bit: sys32time,
			Name:    "time",
			Syscall: true,
			Sets:    []string{"syscalls", "time", "time_tod"},
			Params: []trace.ArgMeta{
				{Type: "time_t*", Name: "tloc"},
			},
		},
		Futex: {
			ID32Bit: sys32futex_time64,
			Name:    "futex",
			Syscall: true,
			Sets:    []string{"syscalls", "ipc", "ipc_futex"},
			Params: []trace.ArgMeta{
				{Type: "int*", Name: "uaddr"},
				{Type: "int", Name: "futex_op"},
				{Type: "int", Name: "val"},
				{Type: "const struct timespec*", Name: "timeout"},
				{Type: "int*", Name: "uaddr2"},
				{Type: "int", Name: "val3"},
			},
		},
		SchedSetaffinity: {
			ID32Bit: sys32sched_setaffinity,
			Name:    "sched_setaffinity",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_sched"},
			Params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "size_t", Name: "cpusetsize"},
				{Type: "unsigned long*", Name: "mask"},
			},
		},
		SchedGetaffinity: {
			ID32Bit: sys32sched_getaffinity,
			Name:    "sched_getaffinity",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_sched"},
			Params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "size_t", Name: "cpusetsize"},
				{Type: "unsigned long*", Name: "mask"},
			},
		},
		SetThreadArea: {
			ID32Bit: sys32set_thread_area,
			Name:    "set_thread_area",
			Syscall: true,
			Sets:    []string{"syscalls", "proc"},
			Params: []trace.ArgMeta{
				{Type: "struct user_desc*", Name: "u_info"},
			},
		},
		IoSetup: {
			ID32Bit: sys32io_setup,
			Name:    "io_setup",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_async_io"},
			Params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "nr_events"},
				{Type: "io_context_t*", Name: "ctx_idp"},
			},
		},
		IoDestroy: {
			ID32Bit: sys32io_destroy,
			Name:    "io_destroy",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_async_io"},
			Params: []trace.ArgMeta{
				{Type: "io_context_t", Name: "ctx_id"},
			},
		},
		IoGetevents: {
			ID32Bit: sys32io_getevents,
			Name:    "io_getevents",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_async_io"},
			Params: []trace.ArgMeta{
				{Type: "io_context_t", Name: "ctx_id"},
				{Type: "long", Name: "min_nr"},
				{Type: "long", Name: "nr"},
				{Type: "struct io_event*", Name: "events"},
				{Type: "struct timespec*", Name: "timeout"},
			},
		},
		IoSubmit: {
			ID32Bit: sys32io_submit,
			Name:    "io_submit",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_async_io"},
			Params: []trace.ArgMeta{
				{Type: "io_context_t", Name: "ctx_id"},
				{Type: "long", Name: "nr"},
				{Type: "struct iocb**", Name: "iocbpp"},
			},
		},
		IoCancel: {
			ID32Bit: sys32io_cancel,
			Name:    "io_cancel",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_async_io"},
			Params: []trace.ArgMeta{
				{Type: "io_context_t", Name: "ctx_id"},
				{Type: "struct iocb*", Name: "iocb"},
				{Type: "struct io_event*", Name: "result"},
			},
		},
		GetThreadArea: {
			ID32Bit: sys32get_thread_area,
			Name:    "get_thread_area",
			Syscall: true,
			Sets:    []string{"syscalls", "proc"},
			Params: []trace.ArgMeta{
				{Type: "struct user_desc*", Name: "u_info"},
			},
		},
		LookupDcookie: {
			ID32Bit: sys32lookup_dcookie,
			Name:    "lookup_dcookie",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_dir_ops"},
			Params: []trace.ArgMeta{
				{Type: "u64", Name: "cookie"},
				{Type: "char*", Name: "buffer"},
				{Type: "size_t", Name: "len"},
			},
		},
		EpollCreate: {
			ID32Bit: sys32epoll_create,
			Name:    "epoll_create",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_mux_io"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "size"},
			},
		},
		EpollCtlOld: {
			ID32Bit: sys32undefined,
			Name:    "epoll_ctl_old",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_mux_io"},
			Params:  []trace.ArgMeta{},
		},
		EpollWaitOld: {
			ID32Bit: sys32undefined,
			Name:    "epoll_wait_old",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_mux_io"},
			Params:  []trace.ArgMeta{},
		},
		RemapFilePages: {
			ID32Bit: sys32remap_file_pages,
			Name:    "remap_file_pages",
			Syscall: true,
			Sets:    []string{"syscalls"},
			Params: []trace.ArgMeta{
				{Type: "void*", Name: "addr"},
				{Type: "size_t", Name: "size"},
				{Type: "int", Name: "prot"},
				{Type: "size_t", Name: "pgoff"},
				{Type: "int", Name: "flags"},
			},
		},
		Getdents64: {
			ID32Bit: sys32getdents64,
			Name:    "getdents64",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_dir_ops"},
			Params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "fd"},
				{Type: "struct linux_dirent64*", Name: "dirp"},
				{Type: "unsigned int", Name: "count"},
			},
		},
		SetTidAddress: {
			ID32Bit: sys32set_tid_address,
			Name:    "set_tid_address",
			Syscall: true,
			Sets:    []string{"syscalls", "proc"},
			Params: []trace.ArgMeta{
				{Type: "int*", Name: "tidptr"},
			},
		},
		RestartSyscall: {
			ID32Bit: sys32restart_syscall,
			Name:    "restart_syscall",
			Syscall: true,
			Sets:    []string{"syscalls", "signals"},
			Params:  []trace.ArgMeta{},
		},
		Semtimedop: {
			ID32Bit: sys32semtimedop_time64,
			Name:    "semtimedop",
			Syscall: true,
			Sets:    []string{"syscalls", "ipc", "ipc_sem"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "semid"},
				{Type: "struct sembuf*", Name: "sops"},
				{Type: "size_t", Name: "nsops"},
				{Type: "const struct timespec*", Name: "timeout"},
			},
		},
		Fadvise64: {
			ID32Bit: sys32fadvise64,
			Name:    "fadvise64",
			Syscall: true,
			Sets:    []string{"syscalls", "fs"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "off_t", Name: "offset"},
				{Type: "size_t", Name: "len"},
				{Type: "int", Name: "advice"},
			},
		},
		TimerCreate: {
			ID32Bit: sys32timer_create,
			Name:    "timer_create",
			Syscall: true,
			Sets:    []string{"syscalls", "time", "time_timer"},
			Params: []trace.ArgMeta{
				{Type: "const clockid_t", Name: "clockid"},
				{Type: "struct sigevent*", Name: "sevp"},
				{Type: "timer_t*", Name: "timer_id"},
			},
		},
		TimerSettime: {
			ID32Bit: sys32timer_settime64,
			Name:    "timer_settime",
			Syscall: true,
			Sets:    []string{"syscalls", "time", "time_timer"},
			Params: []trace.ArgMeta{
				{Type: "timer_t", Name: "timer_id"},
				{Type: "int", Name: "flags"},
				{Type: "const struct itimerspec*", Name: "new_value"},
				{Type: "struct itimerspec*", Name: "old_value"},
			},
		},
		TimerGettime: {
			ID32Bit: sys32timer_gettime64,
			Name:    "timer_gettime",
			Syscall: true,
			Sets:    []string{"syscalls", "time", "time_timer"},
			Params: []trace.ArgMeta{
				{Type: "timer_t", Name: "timer_id"},
				{Type: "struct itimerspec*", Name: "curr_value"},
			},
		},
		TimerGetoverrun: {
			ID32Bit: sys32timer_getoverrun,
			Name:    "timer_getoverrun",
			Syscall: true,
			Sets:    []string{"syscalls", "time", "time_timer"},
			Params: []trace.ArgMeta{
				{Type: "timer_t", Name: "timer_id"},
			},
		},
		TimerDelete: {
			ID32Bit: sys32timer_delete,
			Name:    "timer_delete",
			Syscall: true,
			Sets:    []string{"syscalls", "time", "time_timer"},
			Params: []trace.ArgMeta{
				{Type: "timer_t", Name: "timer_id"},
			},
		},
		ClockSettime: {
			ID32Bit: sys32clock_settime64,
			Name:    "clock_settime",
			Syscall: true,
			Sets:    []string{"syscalls", "time", "time_clock"},
			Params: []trace.ArgMeta{
				{Type: "const clockid_t", Name: "clockid"},
				{Type: "const struct timespec*", Name: "tp"},
			},
		},
		ClockGettime: {
			ID32Bit: sys32clock_gettime64,
			Name:    "clock_gettime",
			Syscall: true,
			Sets:    []string{"syscalls", "time", "time_clock"},
			Params: []trace.ArgMeta{
				{Type: "const clockid_t", Name: "clockid"},
				{Type: "struct timespec*", Name: "tp"},
			},
		},
		ClockGetres: {
			ID32Bit: sys32clock_getres_time64,
			Name:    "clock_getres",
			Syscall: true,
			Sets:    []string{"syscalls", "time", "time_clock"},
			Params: []trace.ArgMeta{
				{Type: "const clockid_t", Name: "clockid"},
				{Type: "struct timespec*", Name: "res"},
			},
		},
		ClockNanosleep: {
			ID32Bit: sys32clock_nanosleep_time64,
			Name:    "clock_nanosleep",
			Syscall: true,
			Sets:    []string{"syscalls", "time", "time_clock"},
			Params: []trace.ArgMeta{
				{Type: "const clockid_t", Name: "clockid"},
				{Type: "int", Name: "flags"},
				{Type: "const struct timespec*", Name: "request"},
				{Type: "struct timespec*", Name: "remain"},
			},
		},
		ExitGroup: {
			ID32Bit: sys32exit_group,
			Name:    "exit_group",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_life"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "status"},
			},
		},
		EpollWait: {
			ID32Bit: sys32epoll_wait,
			Name:    "epoll_wait",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_mux_io"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "epfd"},
				{Type: "struct epoll_event*", Name: "events"},
				{Type: "int", Name: "maxevents"},
				{Type: "int", Name: "timeout"},
			},
		},
		EpollCtl: {
			ID32Bit: sys32epoll_ctl,
			Name:    "epoll_ctl",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_mux_io"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "epfd"},
				{Type: "int", Name: "op"},
				{Type: "int", Name: "fd"},
				{Type: "struct epoll_event*", Name: "event"},
			},
		},
		Tgkill: {
			ID32Bit: sys32tgkill,
			Name:    "tgkill",
			Syscall: true,
			Sets:    []string{"syscalls", "signals"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "tgid"},
				{Type: "int", Name: "tid"},
				{Type: "int", Name: "sig"},
			},
		},
		Utimes: {
			ID32Bit: sys32utimes,
			Name:    "utimes",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "char*", Name: "filename"},
				{Type: "struct timeval*", Name: "times"},
			},
		},
		Vserver: {
			ID32Bit: sys32vserver,
			Name:    "vserver",
			Syscall: true,
			Sets:    []string{"syscalls"},
			Params:  []trace.ArgMeta{},
		},
		Mbind: {
			ID32Bit: sys32mbind,
			Name:    "mbind",
			Syscall: true,
			Sets:    []string{"syscalls", "system", "system_numa"},
			Params: []trace.ArgMeta{
				{Type: "void*", Name: "addr"},
				{Type: "unsigned long", Name: "len"},
				{Type: "int", Name: "mode"},
				{Type: "const unsigned long*", Name: "nodemask"},
				{Type: "unsigned long", Name: "maxnode"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		SetMempolicy: {
			ID32Bit: sys32set_mempolicy,
			Name:    "set_mempolicy",
			Syscall: true,
			Sets:    []string{"syscalls", "system", "system_numa"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "mode"},
				{Type: "const unsigned long*", Name: "nodemask"},
				{Type: "unsigned long", Name: "maxnode"},
			},
		},
		GetMempolicy: {
			ID32Bit: sys32get_mempolicy,
			Name:    "get_mempolicy",
			Syscall: true,
			Sets:    []string{"syscalls", "system", "system_numa"},
			Params: []trace.ArgMeta{
				{Type: "int*", Name: "mode"},
				{Type: "unsigned long*", Name: "nodemask"},
				{Type: "unsigned long", Name: "maxnode"},
				{Type: "void*", Name: "addr"},
				{Type: "unsigned long", Name: "flags"},
			},
		},
		MqOpen: {
			ID32Bit: sys32mq_open,
			Name:    "mq_open",
			Syscall: true,
			Sets:    []string{"syscalls", "ipc", "ipc_msgq"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "name"},
				{Type: "int", Name: "oflag"},
				{Type: "mode_t", Name: "mode"},
				{Type: "struct mq_attr*", Name: "attr"},
			},
		},
		MqUnlink: {
			ID32Bit: sys32mq_unlink,
			Name:    "mq_unlink",
			Syscall: true,
			Sets:    []string{"syscalls", "ipc", "ipc_msgq"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "name"},
			},
		},
		MqTimedsend: {
			ID32Bit: sys32mq_timedsend_time64,
			Name:    "mq_timedsend",
			Syscall: true,
			Sets:    []string{"syscalls", "ipc", "ipc_msgq"},
			Params: []trace.ArgMeta{
				{Type: "mqd_t", Name: "mqdes"},
				{Type: "const char*", Name: "msg_ptr"},
				{Type: "size_t", Name: "msg_len"},
				{Type: "unsigned int", Name: "msg_prio"},
				{Type: "const struct timespec*", Name: "abs_timeout"},
			},
		},
		MqTimedreceive: {
			ID32Bit: sys32mq_timedreceive_time64,
			Name:    "mq_timedreceive",
			Syscall: true,
			Sets:    []string{"syscalls", "ipc", "ipc_msgq"},
			Params: []trace.ArgMeta{
				{Type: "mqd_t", Name: "mqdes"},
				{Type: "char*", Name: "msg_ptr"},
				{Type: "size_t", Name: "msg_len"},
				{Type: "unsigned int*", Name: "msg_prio"},
				{Type: "const struct timespec*", Name: "abs_timeout"},
			},
		},
		MqNotify: {
			ID32Bit: sys32mq_notify,
			Name:    "mq_notify",
			Syscall: true,
			Sets:    []string{"syscalls", "ipc", "ipc_msgq"},
			Params: []trace.ArgMeta{
				{Type: "mqd_t", Name: "mqdes"},
				{Type: "const struct sigevent*", Name: "sevp"},
			},
		},
		MqGetsetattr: {
			ID32Bit: sys32mq_getsetattr,
			Name:    "mq_getsetattr",
			Syscall: true,
			Sets:    []string{"syscalls", "ipc", "ipc_msgq"},
			Params: []trace.ArgMeta{
				{Type: "mqd_t", Name: "mqdes"},
				{Type: "const struct mq_attr*", Name: "newattr"},
				{Type: "struct mq_attr*", Name: "oldattr"},
			},
		},
		KexecLoad: {
			ID32Bit: sys32kexec_load,
			Name:    "kexec_load",
			Syscall: true,
			Sets:    []string{"syscalls", "system"},
			Params: []trace.ArgMeta{
				{Type: "unsigned long", Name: "entry"},
				{Type: "unsigned long", Name: "nr_segments"},
				{Type: "struct kexec_segment*", Name: "segments"},
				{Type: "unsigned long", Name: "flags"},
			},
		},
		Waitid: {
			ID32Bit: sys32waitid,
			Name:    "waitid",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_life"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "idtype"},
				{Type: "pid_t", Name: "id"},
				{Type: "struct siginfo*", Name: "infop"},
				{Type: "int", Name: "options"},
				{Type: "struct rusage*", Name: "rusage"},
			},
		},
		AddKey: {
			ID32Bit: sys32add_key,
			Name:    "add_key",
			Syscall: true,
			Sets:    []string{"syscalls", "system", "system_keys"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "type"},
				{Type: "const char*", Name: "description"},
				{Type: "const void*", Name: "payload"},
				{Type: "size_t", Name: "plen"},
				{Type: "key_serial_t", Name: "keyring"},
			},
		},
		RequestKey: {
			ID32Bit: sys32request_key,
			Name:    "request_key",
			Syscall: true,
			Sets:    []string{"syscalls", "system", "system_keys"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "type"},
				{Type: "const char*", Name: "description"},
				{Type: "const char*", Name: "callout_info"},
				{Type: "key_serial_t", Name: "dest_keyring"},
			},
		},
		Keyctl: {
			ID32Bit: sys32keyctl,
			Name:    "keyctl",
			Syscall: true,
			Sets:    []string{"syscalls", "system", "system_keys"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "operation"},
				{Type: "unsigned long", Name: "arg2"},
				{Type: "unsigned long", Name: "arg3"},
				{Type: "unsigned long", Name: "arg4"},
				{Type: "unsigned long", Name: "arg5"},
			},
		},
		IoprioSet: {
			ID32Bit: sys32ioprio_set,
			Name:    "ioprio_set",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_sched"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "which"},
				{Type: "int", Name: "who"},
				{Type: "int", Name: "ioprio"},
			},
		},
		IoprioGet: {
			ID32Bit: sys32ioprio_get,
			Name:    "ioprio_get",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_sched"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "which"},
				{Type: "int", Name: "who"},
			},
		},
		InotifyInit: {
			ID32Bit: sys32inotify_init,
			Name:    "inotify_init",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_monitor"},
			Params:  []trace.ArgMeta{},
		},
		InotifyAddWatch: {
			ID32Bit: sys32inotify_add_watch,
			Name:    "inotify_add_watch",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_monitor"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "u32", Name: "mask"},
			},
		},
		InotifyRmWatch: {
			ID32Bit: sys32inotify_rm_watch,
			Name:    "inotify_rm_watch",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_monitor"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "int", Name: "wd"},
			},
		},
		MigratePages: {
			ID32Bit: sys32migrate_pages,
			Name:    "migrate_pages",
			Syscall: true,
			Sets:    []string{"syscalls", "system", "system_numa"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "pid"},
				{Type: "unsigned long", Name: "maxnode"},
				{Type: "const unsigned long*", Name: "old_nodes"},
				{Type: "const unsigned long*", Name: "new_nodes"},
			},
		},
		Openat: {
			ID32Bit: sys32openat,
			Name:    "openat",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_file_ops"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "int", Name: "flags"},
				{Type: "mode_t", Name: "mode"},
			},
		},
		Mkdirat: {
			ID32Bit: sys32mkdirat,
			Name:    "mkdirat",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_dir_ops"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "mode_t", Name: "mode"},
			},
		},
		Mknodat: {
			ID32Bit: sys32mknodat,
			Name:    "mknodat",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_file_ops"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "mode_t", Name: "mode"},
				{Type: "dev_t", Name: "dev"},
			},
		},
		Fchownat: {
			ID32Bit: sys32fchownat,
			Name:    "fchownat",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "uid_t", Name: "owner"},
				{Type: "gid_t", Name: "group"},
				{Type: "int", Name: "flags"},
			},
		},
		Futimesat: {
			ID32Bit: sys32futimesat,
			Name:    "futimesat",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "struct timeval*", Name: "times"},
			},
		},
		Newfstatat: {
			ID32Bit: sys32fstatat64,
			Name:    "newfstatat",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "struct stat*", Name: "statbuf"},
				{Type: "int", Name: "flags"},
			},
		},
		Unlinkat: {
			ID32Bit: sys32unlinkat,
			Name:    "unlinkat",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_link_ops"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "int", Name: "flags"},
			},
		},
		Renameat: {
			ID32Bit: sys32renameat,
			Name:    "renameat",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_ops"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "olddirfd"},
				{Type: "const char*", Name: "oldpath"},
				{Type: "int", Name: "newdirfd"},
				{Type: "const char*", Name: "newpath"},
			},
		},
		Linkat: {
			ID32Bit: sys32linkat,
			Name:    "linkat",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_link_ops"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "olddirfd"},
				{Type: "const char*", Name: "oldpath"},
				{Type: "int", Name: "newdirfd"},
				{Type: "const char*", Name: "newpath"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		Symlinkat: {
			ID32Bit: sys32symlinkat,
			Name:    "symlinkat",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_link_ops"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "target"},
				{Type: "int", Name: "newdirfd"},
				{Type: "const char*", Name: "linkpath"},
			},
		},
		Readlinkat: {
			ID32Bit: sys32readlinkat,
			Name:    "readlinkat",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_link_ops"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "char*", Name: "buf"},
				{Type: "int", Name: "bufsiz"},
			},
		},
		Fchmodat: {
			ID32Bit: sys32fchmodat,
			Name:    "fchmodat",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "mode_t", Name: "mode"},
				{Type: "int", Name: "flags"},
			},
		},
		Faccessat: {
			ID32Bit: sys32faccessat,
			Name:    "faccessat",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "int", Name: "mode"},
				{Type: "int", Name: "flags"},
			},
		},
		Pselect6: {
			ID32Bit: sys32pselect6_time64,
			Name:    "pselect6",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_mux_io"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "nfds"},
				{Type: "fd_set*", Name: "readfds"},
				{Type: "fd_set*", Name: "writefds"},
				{Type: "fd_set*", Name: "exceptfds"},
				{Type: "struct timespec*", Name: "timeout"},
				{Type: "void*", Name: "sigmask"},
			},
		},
		Ppoll: {
			ID32Bit: sys32ppoll_time64,
			Name:    "ppoll",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_mux_io"},
			Params: []trace.ArgMeta{
				{Type: "struct pollfd*", Name: "fds"},
				{Type: "unsigned int", Name: "nfds"},
				{Type: "struct timespec*", Name: "tmo_p"},
				{Type: "const sigset_t*", Name: "sigmask"},
				{Type: "size_t", Name: "sigsetsize"},
			},
		},
		Unshare: {
			ID32Bit: sys32unshare,
			Name:    "unshare",
			Syscall: true,
			Sets:    []string{"syscalls", "proc"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "flags"},
			},
		},
		SetRobustList: {
			ID32Bit: sys32set_robust_list,
			Name:    "set_robust_list",
			Syscall: true,
			Sets:    []string{"syscalls", "ipc", "ipc_futex"},
			Params: []trace.ArgMeta{
				{Type: "struct robust_list_head*", Name: "head"},
				{Type: "size_t", Name: "len"},
			},
		},
		GetRobustList: {
			ID32Bit: sys32get_robust_list,
			Name:    "get_robust_list",
			Syscall: true,
			Sets:    []string{"syscalls", "ipc", "ipc_futex"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "pid"},
				{Type: "struct robust_list_head**", Name: "head_ptr"},
				{Type: "size_t*", Name: "len_ptr"},
			},
		},
		Splice: {
			ID32Bit: sys32splice,
			Name:    "splice",
			Syscall: true,
			Sets:    []string{"syscalls", "ipc", "ipc_pipe"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd_in"},
				{Type: "off_t*", Name: "off_in"},
				{Type: "int", Name: "fd_out"},
				{Type: "off_t*", Name: "off_out"},
				{Type: "size_t", Name: "len"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		Tee: {
			ID32Bit: sys32tee,
			Name:    "tee",
			Syscall: true,
			Sets:    []string{"syscalls", "ipc", "ipc_pipe"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd_in"},
				{Type: "int", Name: "fd_out"},
				{Type: "size_t", Name: "len"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		SyncFileRange: {
			ID32Bit: sys32sync_file_range,
			Name:    "sync_file_range",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_sync"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "off_t", Name: "offset"},
				{Type: "off_t", Name: "nbytes"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		Vmsplice: {
			ID32Bit: sys32vmsplice,
			Name:    "vmsplice",
			Syscall: true,
			Sets:    []string{"syscalls", "ipc", "ipc_pipe"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const struct iovec*", Name: "iov"},
				{Type: "unsigned long", Name: "nr_segs"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		MovePages: {
			ID32Bit: sys32move_pages,
			Name:    "move_pages",
			Syscall: true,
			Sets:    []string{"syscalls", "system", "system_numa"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "pid"},
				{Type: "unsigned long", Name: "count"},
				{Type: "const void**", Name: "pages"},
				{Type: "const int*", Name: "nodes"},
				{Type: "int*", Name: "status"},
				{Type: "int", Name: "flags"},
			},
		},
		Utimensat: {
			ID32Bit: sys32utimensat_time64,
			Name:    "utimensat",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "struct timespec*", Name: "times"},
				{Type: "int", Name: "flags"},
			},
		},
		EpollPwait: {
			ID32Bit: sys32epoll_pwait,
			Name:    "epoll_pwait",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_mux_io"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "epfd"},
				{Type: "struct epoll_event*", Name: "events"},
				{Type: "int", Name: "maxevents"},
				{Type: "int", Name: "timeout"},
				{Type: "const sigset_t*", Name: "sigmask"},
				{Type: "size_t", Name: "sigsetsize"},
			},
		},
		Signalfd: {
			ID32Bit: sys32signalfd,
			Name:    "signalfd",
			Syscall: true,
			Sets:    []string{"syscalls", "signals"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "sigset_t*", Name: "mask"},
				{Type: "int", Name: "flags"},
			},
		},
		TimerfdCreate: {
			ID32Bit: sys32timerfd_create,
			Name:    "timerfd_create",
			Syscall: true,
			Sets:    []string{"syscalls", "time", "time_timer"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "clockid"},
				{Type: "int", Name: "flags"},
			},
		},
		Eventfd: {
			ID32Bit: sys32eventfd,
			Name:    "eventfd",
			Syscall: true,
			Sets:    []string{"syscalls", "signals"},
			Params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "initval"},
				{Type: "int", Name: "flags"},
			},
		},
		Fallocate: {
			ID32Bit: sys32fallocate,
			Name:    "fallocate",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_ops"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "int", Name: "mode"},
				{Type: "off_t", Name: "offset"},
				{Type: "off_t", Name: "len"},
			},
		},
		TimerfdSettime: {
			ID32Bit: sys32timerfd_settime64,
			Name:    "timerfd_settime",
			Syscall: true,
			Sets:    []string{"syscalls", "time", "time_timer"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "int", Name: "flags"},
				{Type: "const struct itimerspec*", Name: "new_value"},
				{Type: "struct itimerspec*", Name: "old_value"},
			},
		},
		TimerfdGettime: {
			ID32Bit: sys32timerfd_gettime64,
			Name:    "timerfd_gettime",
			Syscall: true,
			Sets:    []string{"syscalls", "time", "time_timer"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "struct itimerspec*", Name: "curr_value"},
			},
		},
		Accept4: {
			ID32Bit: sys32accept4,
			Name:    "accept4",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "net", "net_sock"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct sockaddr*", Name: "addr"},
				{Type: "int*", Name: "addrlen"},
				{Type: "int", Name: "flags"},
			},
		},
		Signalfd4: {
			ID32Bit: sys32signalfd4,
			Name:    "signalfd4",
			Syscall: true,
			Sets:    []string{"syscalls", "signals"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const sigset_t*", Name: "mask"},
				{Type: "size_t", Name: "sizemask"},
				{Type: "int", Name: "flags"},
			},
		},
		Eventfd2: {
			ID32Bit: sys32eventfd2,
			Name:    "eventfd2",
			Syscall: true,
			Sets:    []string{"syscalls", "signals"},
			Params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "initval"},
				{Type: "int", Name: "flags"},
			},
		},
		EpollCreate1: {
			ID32Bit: sys32epoll_create1,
			Name:    "epoll_create1",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_mux_io"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "flags"},
			},
		},
		Dup3: {
			ID32Bit: sys32dup3,
			Name:    "dup3",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_fd_ops"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "oldfd"},
				{Type: "int", Name: "newfd"},
				{Type: "int", Name: "flags"},
			},
		},
		Pipe2: {
			ID32Bit: sys32pipe2,
			Name:    "pipe2",
			Syscall: true,
			Sets:    []string{"syscalls", "ipc", "ipc_pipe"},
			Params: []trace.ArgMeta{
				{Type: "int[2]", Name: "pipefd"},
				{Type: "int", Name: "flags"},
			},
		},
		InotifyInit1: {
			ID32Bit: sys32inotify_init1,
			Name:    "inotify_init1",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_monitor"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "flags"},
			},
		},
		Preadv: {
			ID32Bit: sys32preadv,
			Name:    "preadv",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_read_write"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const struct iovec*", Name: "iov"},
				{Type: "unsigned long", Name: "iovcnt"},
				{Type: "unsigned long", Name: "pos_l"},
				{Type: "unsigned long", Name: "pos_h"},
			},
		},
		Pwritev: {
			ID32Bit: sys32pwritev,
			Name:    "pwritev",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_read_write"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const struct iovec*", Name: "iov"},
				{Type: "unsigned long", Name: "iovcnt"},
				{Type: "unsigned long", Name: "pos_l"},
				{Type: "unsigned long", Name: "pos_h"},
			},
		},
		RtTgsigqueueinfo: {
			ID32Bit: sys32rt_tgsigqueueinfo,
			Name:    "rt_tgsigqueueinfo",
			Syscall: true,
			Sets:    []string{"syscalls", "signals"},
			Params: []trace.ArgMeta{
				{Type: "pid_t", Name: "tgid"},
				{Type: "pid_t", Name: "tid"},
				{Type: "int", Name: "sig"},
				{Type: "siginfo_t*", Name: "info"},
			},
		},
		PerfEventOpen: {
			ID32Bit: sys32perf_event_open,
			Name:    "perf_event_open",
			Syscall: true,
			Sets:    []string{"syscalls", "system"},
			Params: []trace.ArgMeta{
				{Type: "struct perf_event_attr*", Name: "attr"},
				{Type: "pid_t", Name: "pid"},
				{Type: "int", Name: "cpu"},
				{Type: "int", Name: "group_fd"},
				{Type: "unsigned long", Name: "flags"},
			},
		},
		Recvmmsg: {
			ID32Bit: sys32recvmmsg_time64,
			Name:    "recvmmsg",
			Syscall: true,
			Sets:    []string{"syscalls", "net", "net_snd_rcv"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct mmsghdr*", Name: "msgvec"},
				{Type: "unsigned int", Name: "vlen"},
				{Type: "int", Name: "flags"},
				{Type: "struct timespec*", Name: "timeout"},
			},
		},
		FanotifyInit: {
			ID32Bit: sys32fanotify_init,
			Name:    "fanotify_init",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_monitor"},
			Params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "flags"},
				{Type: "unsigned int", Name: "event_f_flags"},
			},
		},
		FanotifyMark: {
			ID32Bit: sys32fanotify_mark,
			Name:    "fanotify_mark",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_monitor"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fanotify_fd"},
				{Type: "unsigned int", Name: "flags"},
				{Type: "u64", Name: "mask"},
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
			},
		},
		Prlimit64: {
			ID32Bit: sys32prlimit64,
			Name:    "prlimit64",
			Syscall: true,
			Sets:    []string{"syscalls", "proc"},
			Params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "int", Name: "resource"},
				{Type: "const struct rlimit64*", Name: "new_limit"},
				{Type: "struct rlimit64*", Name: "old_limit"},
			},
		},
		NameToHandleAt: {
			ID32Bit: sys32name_to_handle_at,
			Name:    "name_to_handle_at",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_ops"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "struct file_handle*", Name: "handle"},
				{Type: "int*", Name: "mount_id"},
				{Type: "int", Name: "flags"},
			},
		},
		OpenByHandleAt: {
			ID32Bit: sys32open_by_handle_at,
			Name:    "open_by_handle_at",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_ops"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "mount_fd"},
				{Type: "struct file_handle*", Name: "handle"},
				{Type: "int", Name: "flags"},
			},
		},
		ClockAdjtime: {
			ID32Bit: sys32clock_adjtime,
			Name:    "clock_adjtime",
			Syscall: true,
			Sets:    []string{"syscalls", "time", "time_clock"},
			Params: []trace.ArgMeta{
				{Type: "const clockid_t", Name: "clk_id"},
				{Type: "struct timex*", Name: "buf"},
			},
		},
		Syncfs: {
			ID32Bit: sys32syncfs,
			Name:    "syncfs",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_sync"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
			},
		},
		Sendmmsg: {
			ID32Bit: sys32sendmmsg,
			Name:    "sendmmsg",
			Syscall: true,
			Sets:    []string{"syscalls", "net", "net_snd_rcv"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct mmsghdr*", Name: "msgvec"},
				{Type: "unsigned int", Name: "vlen"},
				{Type: "int", Name: "flags"},
			},
		},
		Setns: {
			ID32Bit: sys32setns,
			Name:    "setns",
			Syscall: true,
			Sets:    []string{"syscalls", "proc"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "int", Name: "nstype"},
			},
		},
		Getcpu: {
			ID32Bit: sys32getcpu,
			Name:    "getcpu",
			Syscall: true,
			Sets:    []string{"syscalls", "system", "system_numa"},
			Params: []trace.ArgMeta{
				{Type: "unsigned int*", Name: "cpu"},
				{Type: "unsigned int*", Name: "node"},
				{Type: "struct getcpu_cache*", Name: "tcache"},
			},
		},
		ProcessVmReadv: {
			ID32Bit: sys32process_vm_readv,
			Name:    "process_vm_readv",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "proc"},
			Params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "const struct iovec*", Name: "local_iov"},
				{Type: "unsigned long", Name: "liovcnt"},
				{Type: "const struct iovec*", Name: "remote_iov"},
				{Type: "unsigned long", Name: "riovcnt"},
				{Type: "unsigned long", Name: "flags"},
			},
		},
		ProcessVmWritev: {
			ID32Bit: sys32process_vm_writev,
			Name:    "process_vm_writev",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "proc"},
			Params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "const struct iovec*", Name: "local_iov"},
				{Type: "unsigned long", Name: "liovcnt"},
				{Type: "const struct iovec*", Name: "remote_iov"},
				{Type: "unsigned long", Name: "riovcnt"},
				{Type: "unsigned long", Name: "flags"},
			},
		},
		Kcmp: {
			ID32Bit: sys32kcmp,
			Name:    "kcmp",
			Syscall: true,
			Sets:    []string{"syscalls", "proc"},
			Params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid1"},
				{Type: "pid_t", Name: "pid2"},
				{Type: "int", Name: "type"},
				{Type: "unsigned long", Name: "idx1"},
				{Type: "unsigned long", Name: "idx2"},
			},
		},
		FinitModule: {
			ID32Bit: sys32finit_module,
			Name:    "finit_module",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "system", "system_module"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const char*", Name: "param_values"},
				{Type: "int", Name: "flags"},
			},
		},
		SchedSetattr: {
			ID32Bit: sys32sched_setattr,
			Name:    "sched_setattr",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_sched"},
			Params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "struct sched_attr*", Name: "attr"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		SchedGetattr: {
			ID32Bit: sys32sched_getattr,
			Name:    "sched_getattr",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_sched"},
			Params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "struct sched_attr*", Name: "attr"},
				{Type: "unsigned int", Name: "size"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		Renameat2: {
			ID32Bit: sys32renameat2,
			Name:    "renameat2",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_ops"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "olddirfd"},
				{Type: "const char*", Name: "oldpath"},
				{Type: "int", Name: "newdirfd"},
				{Type: "const char*", Name: "newpath"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		Seccomp: {
			ID32Bit: sys32seccomp,
			Name:    "seccomp",
			Syscall: true,
			Sets:    []string{"syscalls", "proc"},
			Params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "operation"},
				{Type: "unsigned int", Name: "flags"},
				{Type: "const void*", Name: "args"},
			},
		},
		Getrandom: {
			ID32Bit: sys32getrandom,
			Name:    "getrandom",
			Syscall: true,
			Sets:    []string{"syscalls", "fs"},
			Params: []trace.ArgMeta{
				{Type: "void*", Name: "buf"},
				{Type: "size_t", Name: "buflen"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		MemfdCreate: {
			ID32Bit: sys32memfd_create,
			Name:    "memfd_create",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_file_ops"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "name"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		KexecFileLoad: {
			ID32Bit: sys32undefined,
			Name:    "kexec_file_load",
			Syscall: true,
			Sets:    []string{"syscalls", "system"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "kernel_fd"},
				{Type: "int", Name: "initrd_fd"},
				{Type: "unsigned long", Name: "cmdline_len"},
				{Type: "const char*", Name: "cmdline"},
				{Type: "unsigned long", Name: "flags"},
			},
		},
		Bpf: {
			ID32Bit: sys32bpf,
			Name:    "bpf",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "system"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "cmd"},
				{Type: "union bpf_attr*", Name: "attr"},
				{Type: "unsigned int", Name: "size"},
			},
		},
		Execveat: {
			ID32Bit: sys32execveat,
			Name:    "execveat",
			Syscall: true,
			Dependencies: dependencies{
				TailCalls: []TailCall{
					{MapName: "sys_enter_tails", MapIndexes: []uint32{uint32(Execveat)}, ProgName: "syscall__execveat"},
				},
			},
			Sets: []string{"default", "syscalls", "proc", "proc_life"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "const char*const*", Name: "argv"},
				{Type: "const char*const*", Name: "envp"},
				{Type: "int", Name: "flags"},
			},
		},
		Userfaultfd: {
			ID32Bit: sys32userfaultfd,
			Name:    "userfaultfd",
			Syscall: true,
			Sets:    []string{"syscalls", "system"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "flags"},
			},
		},
		Membarrier: {
			ID32Bit: sys32membarrier,
			Name:    "membarrier",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_mem"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "cmd"},
				{Type: "int", Name: "flags"},
			},
		},
		Mlock2: {
			ID32Bit: sys32mlock2,
			Name:    "mlock2",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_mem"},
			Params: []trace.ArgMeta{
				{Type: "const void*", Name: "addr"},
				{Type: "size_t", Name: "len"},
				{Type: "int", Name: "flags"},
			},
		},
		CopyFileRange: {
			ID32Bit: sys32copy_file_range,
			Name:    "copy_file_range",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_read_write"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd_in"},
				{Type: "off_t*", Name: "off_in"},
				{Type: "int", Name: "fd_out"},
				{Type: "off_t*", Name: "off_out"},
				{Type: "size_t", Name: "len"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		Preadv2: {
			ID32Bit: sys32preadv2,
			Name:    "preadv2",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_read_write"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const struct iovec*", Name: "iov"},
				{Type: "unsigned long", Name: "iovcnt"},
				{Type: "unsigned long", Name: "pos_l"},
				{Type: "unsigned long", Name: "pos_h"},
				{Type: "int", Name: "flags"},
			},
		},
		Pwritev2: {
			ID32Bit: sys32pwritev2,
			Name:    "pwritev2",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_read_write"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const struct iovec*", Name: "iov"},
				{Type: "unsigned long", Name: "iovcnt"},
				{Type: "unsigned long", Name: "pos_l"},
				{Type: "unsigned long", Name: "pos_h"},
				{Type: "int", Name: "flags"},
			},
		},
		PkeyMprotect: {
			ID32Bit: sys32pkey_mprotect,
			Name:    "pkey_mprotect",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "proc", "proc_mem"},
			Params: []trace.ArgMeta{
				{Type: "void*", Name: "addr"},
				{Type: "size_t", Name: "len"},
				{Type: "int", Name: "prot"},
				{Type: "int", Name: "pkey"},
			},
		},
		PkeyAlloc: {
			ID32Bit: sys32pkey_alloc,
			Name:    "pkey_alloc",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_mem"},
			Params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "flags"},
				{Type: "unsigned long", Name: "access_rights"},
			},
		},
		PkeyFree: {
			ID32Bit: sys32pkey_free,
			Name:    "pkey_free",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "proc_mem"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "pkey"},
			},
		},
		Statx: {
			ID32Bit: sys32statx,
			Name:    "statx",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "int", Name: "flags"},
				{Type: "unsigned int", Name: "mask"},
				{Type: "struct statx*", Name: "statxbuf"},
			},
		},
		IoPgetevents: {
			ID32Bit: sys32io_pgetevents_time64,
			Name:    "io_pgetevents",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_async_io"},
			Params: []trace.ArgMeta{
				{Type: "aio_context_t", Name: "ctx_id"},
				{Type: "long", Name: "min_nr"},
				{Type: "long", Name: "nr"},
				{Type: "struct io_event*", Name: "events"},
				{Type: "struct timespec*", Name: "timeout"},
				{Type: "const struct __aio_sigset*", Name: "usig"},
			},
		},
		Rseq: {
			ID32Bit: sys32rseq,
			Name:    "rseq",
			Syscall: true,
			Sets:    []string{"syscalls"},
			Params: []trace.ArgMeta{
				{Type: "struct rseq*", Name: "rseq"},
				{Type: "u32", Name: "rseq_len"},
				{Type: "int", Name: "flags"},
				{Type: "u32", Name: "sig"},
			},
		},
		PidfdSendSignal: {
			ID32Bit: sys32pidfd_send_signal,
			Name:    "pidfd_send_signal",
			Syscall: true,
			Sets:    []string{"syscalls", "signals"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "pidfd"},
				{Type: "int", Name: "sig"},
				{Type: "siginfo_t*", Name: "info"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		IoUringSetup: {
			ID32Bit: sys32io_uring_setup,
			Name:    "io_uring_setup",
			Syscall: true,
			Sets:    []string{"syscalls"},
			Params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "entries"},
				{Type: "struct io_uring_params*", Name: "p"},
			},
		},
		IoUringEnter: {
			ID32Bit: sys32io_uring_enter,
			Name:    "io_uring_enter",
			Syscall: true,
			Sets:    []string{"syscalls"},
			Params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "fd"},
				{Type: "unsigned int", Name: "to_submit"},
				{Type: "unsigned int", Name: "min_complete"},
				{Type: "unsigned int", Name: "flags"},
				{Type: "sigset_t*", Name: "sig"},
			},
		},
		IoUringRegister: {
			ID32Bit: sys32io_uring_register,
			Name:    "io_uring_register",
			Syscall: true,
			Sets:    []string{"syscalls"},
			Params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "fd"},
				{Type: "unsigned int", Name: "opcode"},
				{Type: "void*", Name: "arg"},
				{Type: "unsigned int", Name: "nr_args"},
			},
		},
		OpenTree: {
			ID32Bit: sys32open_tree,
			Name:    "open_tree",
			Syscall: true,
			Sets:    []string{"syscalls"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "dfd"},
				{Type: "const char*", Name: "filename"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		MoveMount: {
			ID32Bit: sys32move_mount,
			Name:    "move_mount",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "from_dfd"},
				{Type: "const char*", Name: "from_path"},
				{Type: "int", Name: "to_dfd"},
				{Type: "const char*", Name: "to_path"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		Fsopen: {
			ID32Bit: sys32fsopen,
			Name:    "fsopen",
			Syscall: true,
			Sets:    []string{"syscalls", "fs"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "fsname"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		Fsconfig: {
			ID32Bit: sys32fsconfig,
			Name:    "fsconfig",
			Syscall: true,
			Sets:    []string{"syscalls", "fs"},
			Params: []trace.ArgMeta{
				{Type: "int*", Name: "fs_fd"},
				{Type: "unsigned int", Name: "cmd"},
				{Type: "const char*", Name: "key"},
				{Type: "const void*", Name: "value"},
				{Type: "int", Name: "aux"},
			},
		},
		Fsmount: {
			ID32Bit: sys32fsmount,
			Name:    "fsmount",
			Syscall: true,
			Sets:    []string{"syscalls", "fs"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fsfd"},
				{Type: "unsigned int", Name: "flags"},
				{Type: "unsigned int", Name: "ms_flags"},
			},
		},
		Fspick: {
			ID32Bit: sys32fspick,
			Name:    "fspick",
			Syscall: true,
			Sets:    []string{"syscalls", "fs"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		PidfdOpen: {
			ID32Bit: sys32pidfd_open,
			Name:    "pidfd_open",
			Syscall: true,
			Sets:    []string{"syscalls"},
			Params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		Clone3: {
			ID32Bit: sys32clone3,
			Name:    "clone3",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "proc", "proc_life"},
			Params: []trace.ArgMeta{
				{Type: "struct clone_args*", Name: "cl_args"},
				{Type: "size_t", Name: "size"},
			},
		},
		CloseRange: {
			ID32Bit: sys32close_range,
			Name:    "close_range",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_file_ops"},
			Params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "first"},
				{Type: "unsigned int", Name: "last"},
			},
		},
		Openat2: {
			ID32Bit: sys32openat2,
			Name:    "openat2",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_file_ops"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "struct open_how*", Name: "how"},
				{Type: "size_t", Name: "size"},
			},
		},
		PidfdGetfd: {
			ID32Bit: sys32pidfd_getfd,
			Name:    "pidfd_getfd",
			Syscall: true,
			Sets:    []string{"syscalls"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "pidfd"},
				{Type: "int", Name: "targetfd"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		Faccessat2: {
			ID32Bit: sys32faccessat2,
			Name:    "faccessat2",
			Syscall: true,
			Sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const char*", Name: "path"},
				{Type: "int", Name: "mode"},
				{Type: "int", Name: "flag"},
			},
		},
		ProcessMadvise: {
			ID32Bit: sys32process_madvise,
			Name:    "process_madvise",
			Syscall: true,
			Sets:    []string{"syscalls"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "pidfd"},
				{Type: "void*", Name: "addr"},
				{Type: "size_t", Name: "length"},
				{Type: "int", Name: "advice"},
				{Type: "unsigned long", Name: "flags"},
			},
		},
		EpollPwait2: {
			ID32Bit: sys32epoll_pwait2,
			Name:    "epoll_pwait2",
			Syscall: true,
			Sets:    []string{"syscalls", "fs", "fs_mux_io"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "struct epoll_event*", Name: "events"},
				{Type: "int", Name: "maxevents"},
				{Type: "const struct timespec*", Name: "timeout"},
				{Type: "const sigset_t*", Name: "sigset"},
			},
		},
		MountSetatt: {
			ID32Bit: sys32mount_setattr,
			Name:    "mount_setattr",
			Syscall: true,
			Sets:    []string{"syscalls", "fs"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "dfd"},
				{Type: "char*", Name: "path"},
				{Type: "unsigned int", Name: "flags"},
				{Type: "struct mount_attr*", Name: "uattr"},
				{Type: "size_t", Name: "usize"},
			},
		},
		QuotactlFd: {
			ID32Bit: sys32quotactl_fd,
			Name:    "quotactl_fd",
			Syscall: true,
			Sets:    []string{"syscalls", "fs"},
			Params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "fd"},
				{Type: "unsigned int", Name: "cmd"},
				{Type: "qid_t", Name: "id"},
				{Type: "void *", Name: "addr"},
			},
		},
		LandlockCreateRuleset: {
			ID32Bit: sys32landlock_create_ruleset,
			Name:    "landlock_create_ruleset",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "fs"},
			Params: []trace.ArgMeta{
				{Type: "struct landlock_ruleset_attr*", Name: "attr"},
				{Type: "size_t", Name: "size"},
				{Type: "u32", Name: "flags"},
			},
		},
		LandlockAddRule: {
			ID32Bit: sys32landlock_add_rule,
			Name:    "landlock_add_rule",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "fs"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "ruleset_fd"},
				{Type: "landlock_rule_type", Name: "rule_type"},
				{Type: "void*", Name: "rule_attr"},
				{Type: "u32", Name: "flags"},
			},
		},
		LandloclRestrictSet: {
			ID32Bit: sys32landlock_restrict_self,
			Name:    "landlock_restrict_self",
			Syscall: true,
			Sets:    []string{"syscalls", "proc", "fs"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "ruleset_fd"},
				{Type: "u32", Name: "flags"},
			},
		},
		MemfdSecret: {
			ID32Bit: sys32memfd_secret,
			Name:    "memfd_secret",
			Syscall: true,
			Sets:    []string{"syscalls"},
			Params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "flags"},
			},
		},
		ProcessMrelease: {
			ID32Bit: sys32process_mrelease,
			Name:    "process_mrelease",
			Syscall: true,
			Sets:    []string{"syscalls"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "pidfd"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		Waitpid: {
			ID32Bit: sys32waitpid,
			Name:    "waitpid",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "int*", Name: "status"},
				{Type: "int", Name: "options"},
			},
		},
		Oldfstat: {
			ID32Bit: sys32oldfstat,
			Name:    "oldfstat",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params:  []trace.ArgMeta{},
		},
		Break: {
			ID32Bit: sys32break,
			Name:    "break",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params:  []trace.ArgMeta{},
		},
		Oldstat: {
			ID32Bit: sys32oldstat,
			Name:    "oldstat",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "char*", Name: "filename"},
				{Type: "struct __old_kernel_stat*", Name: "statbuf"},
			},
		},
		Umount: {
			ID32Bit: sys32umount,
			Name:    "umount",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "target"},
			},
		},
		Stime: {
			ID32Bit: sys32stime,
			Name:    "stime",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "const time_t*", Name: "t"},
			},
		},
		Stty: {
			ID32Bit: sys32stty,
			Name:    "stty",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params:  []trace.ArgMeta{},
		},
		Gtty: {
			ID32Bit: sys32gtty,
			Name:    "gtty",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params:  []trace.ArgMeta{},
		},
		Nice: {
			ID32Bit: sys32nice,
			Name:    "nice",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "inc"},
			},
		},
		Ftime: {
			ID32Bit: sys32ftime,
			Name:    "ftime",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params:  []trace.ArgMeta{},
		},
		Prof: {
			ID32Bit: sys32prof,
			Name:    "prof",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params:  []trace.ArgMeta{},
		},
		Signal: {
			ID32Bit: sys32signal,
			Name:    "signal",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "signum"},
				{Type: "sighandler_t", Name: "handler"},
			},
		},
		Lock: {
			ID32Bit: sys32lock,
			Name:    "lock",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params:  []trace.ArgMeta{},
		},
		Mpx: {
			ID32Bit: sys32mpx,
			Name:    "mpx",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params:  []trace.ArgMeta{},
		},
		Ulimit: {
			ID32Bit: sys32ulimit,
			Name:    "ulimit",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params:  []trace.ArgMeta{},
		},
		Oldolduname: {
			ID32Bit: sys32oldolduname,
			Name:    "oldolduname",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "struct oldold_utsname*", Name: "name"},
			},
		},
		Sigaction: {
			ID32Bit: sys32sigaction,
			Name:    "sigaction",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "sig"},
				{Type: "const struct sigaction*", Name: "act"},
				{Type: "struct sigaction*", Name: "oact"},
			},
		},
		Sgetmask: {
			ID32Bit: sys32sgetmask,
			Name:    "sgetmask",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params:  []trace.ArgMeta{},
		},
		Ssetmask: {
			ID32Bit: sys32ssetmask,
			Name:    "ssetmask",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "long", Name: "newmask"},
			},
		},
		Sigsuspend: {
			ID32Bit: sys32sigsuspend,
			Name:    "sigsuspend",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "const sigset_t*", Name: "mask"},
			},
		},
		Sigpending: {
			ID32Bit: sys32sigpending,
			Name:    "sigpending",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "sigset_t*", Name: "set"},
			},
		},
		Oldlstat: {
			ID32Bit: sys32oldlstat,
			Name:    "oldlstat",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "struct stat*", Name: "statbuf"},
			},
		},
		Readdir: {
			ID32Bit: sys32readdir,
			Name:    "readdir",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "fd"},
				{Type: "struct old_linux_dirent*", Name: "dirp"},
				{Type: "unsigned int", Name: "count"},
			},
		},
		Profil: {
			ID32Bit: sys32profil,
			Name:    "profil",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params:  []trace.ArgMeta{},
		},
		Socketcall: {
			ID32Bit: sys32socketcall,
			Name:    "socketcall",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "call"},
				{Type: "unsigned long*", Name: "args"},
			},
		},
		Olduname: {
			ID32Bit: sys32olduname,
			Name:    "olduname",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "struct utsname*", Name: "buf"},
			},
		},
		Idle: {
			ID32Bit: sys32idle,
			Name:    "idle",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params:  []trace.ArgMeta{},
		},
		Vm86old: {
			ID32Bit: sys32vm86old,
			Name:    "vm86old",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "struct vm86_struct*", Name: "info"},
			},
		},
		Ipc: {
			ID32Bit: sys32ipc,
			Name:    "ipc",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "call"},
				{Type: "int", Name: "first"},
				{Type: "unsigned long", Name: "second"},
				{Type: "unsigned long", Name: "third"},
				{Type: "void*", Name: "ptr"},
				{Type: "long", Name: "fifth"},
			},
		},
		Sigreturn: {
			ID32Bit: sys32sigreturn,
			Name:    "sigreturn",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params:  []trace.ArgMeta{},
		},
		Sigprocmask: {
			ID32Bit: sys32sigprocmask,
			Name:    "sigprocmask",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "how"},
				{Type: "const sigset_t *restrict", Name: "set"},
				{Type: "sigset_t *restrict", Name: "oldset"},
			},
		},
		Bdflush: {
			ID32Bit: sys32bdflush,
			Name:    "bdflush",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params:  []trace.ArgMeta{},
		},
		Afs_syscall: {
			ID32Bit: sys32afs_syscall,
			Name:    "afs_syscall",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params:  []trace.ArgMeta{},
		},
		Llseek: {
			ID32Bit: sys32_llseek,
			Name:    "llseek",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "fd"},
				{Type: "unsigned long", Name: "offset_high"},
				{Type: "unsigned long", Name: "offset_low"},
				{Type: "loff_t*", Name: "result"},
				{Type: "unsigned int", Name: "whence"},
			},
		},
		OldSelect: {
			ID32Bit: sys32select,
			Name:    "old_select",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "nfds"},
				{Type: "fd_set*", Name: "readfds"},
				{Type: "fd_set*", Name: "writefds"},
				{Type: "fd_set*", Name: "exceptfds"},
				{Type: "struct timeval*", Name: "timeout"},
			},
		},
		Vm86: {
			ID32Bit: sys32vm86,
			Name:    "vm86",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "unsigned long", Name: "fn"},
				{Type: "struct vm86plus_struct*", Name: "v86"},
			},
		},
		OldGetrlimit: {
			ID32Bit: sys32getrlimit,
			Name:    "old_getrlimit",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "resource"},
				{Type: "struct rlimit*", Name: "rlim"},
			},
		},
		Mmap2: {
			ID32Bit: sys32mmap2,
			Name:    "mmap2",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "unsigned long", Name: "addr"},
				{Type: "unsigned long", Name: "length"},
				{Type: "unsigned long", Name: "prot"},
				{Type: "unsigned long", Name: "flags"},
				{Type: "unsigned long", Name: "fd"},
				{Type: "unsigned long", Name: "pgoffset"},
			},
		},
		Truncate64: {
			ID32Bit: sys32truncate64,
			Name:    "truncate64",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "off_t", Name: "length"},
			},
		},
		Ftruncate64: {
			ID32Bit: sys32ftruncate64,
			Name:    "ftruncate64",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "off_t", Name: "length"},
			},
		},
		Stat64: {
			ID32Bit: sys32stat64,
			Name:    "stat64",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "struct stat64*", Name: "statbuf"},
			},
		},
		Lstat64: {
			ID32Bit: sys32lstat64,
			Name:    "lstat64",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "struct stat64*", Name: "statbuf"},
			},
		},
		Fstat64: {
			ID32Bit: sys32fstat64,
			Name:    "fstat64",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "struct stat64*", Name: "statbuf"},
			},
		},
		Lchown16: {
			ID32Bit: sys32lchown,
			Name:    "lchown16",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "old_uid_t", Name: "owner"},
				{Type: "old_gid_t", Name: "group"},
			},
		},
		Getuid16: {
			ID32Bit: sys32getuid,
			Name:    "getuid16",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params:  []trace.ArgMeta{},
		},
		Getgid16: {
			ID32Bit: sys32getgid,
			Name:    "getgid16",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params:  []trace.ArgMeta{},
		},
		Geteuid16: {
			ID32Bit: sys32geteuid,
			Name:    "geteuid16",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params:  []trace.ArgMeta{},
		},
		Getegid16: {
			ID32Bit: sys32getegid,
			Name:    "getegid16",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params:  []trace.ArgMeta{},
		},
		Setreuid16: {
			ID32Bit: sys32setreuid,
			Name:    "setreuid16",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "old_uid_t", Name: "ruid"},
				{Type: "old_uid_t", Name: "euid"},
			},
		},
		Setregid16: {
			ID32Bit: sys32setregid,
			Name:    "setregid16",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "old_gid_t", Name: "rgid"},
				{Type: "old_gid_t", Name: "egid"},
			},
		},
		Getgroups16: {
			ID32Bit: sys32getgroups,
			Name:    "getgroups16",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "size"},
				{Type: "old_gid_t*", Name: "list"},
			},
		},
		Setgroups16: {
			ID32Bit: sys32setgroups,
			Name:    "setgroups16",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "size_t", Name: "size"},
				{Type: "const gid_t*", Name: "list"},
			},
		},
		Fchown16: {
			ID32Bit: sys32fchown,
			Name:    "fchown16",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "fd"},
				{Type: "old_uid_t", Name: "user"},
				{Type: "old_gid_t", Name: "group"},
			},
		},
		Setresuid16: {
			ID32Bit: sys32setresuid,
			Name:    "setresuid16",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "old_uid_t", Name: "ruid"},
				{Type: "old_uid_t", Name: "euid"},
				{Type: "old_uid_t", Name: "suid"},
			},
		},
		Getresuid16: {
			ID32Bit: sys32getresuid,
			Name:    "getresuid16",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "old_uid_t*", Name: "ruid"},
				{Type: "old_uid_t*", Name: "euid"},
				{Type: "old_uid_t*", Name: "suid"},
			},
		},
		Setresgid16: {
			ID32Bit: sys32setresgid,
			Name:    "setresgid16",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "old_uid_t", Name: "rgid"},
				{Type: "old_uid_t", Name: "euid"},
				{Type: "old_uid_t", Name: "suid"},
			},
		},
		Getresgid16: {
			ID32Bit: sys32getresgid,
			Name:    "getresgid16",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "old_gid_t*", Name: "rgid"},
				{Type: "old_gid_t*", Name: "egid"},
				{Type: "old_gid_t*", Name: "sgid"},
			},
		},
		Chown16: {
			ID32Bit: sys32chown,
			Name:    "chown16",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "old_uid_t", Name: "owner"},
				{Type: "old_gid_t", Name: "group"},
			},
		},
		Setuid16: {
			ID32Bit: sys32setuid,
			Name:    "setuid16",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "old_old_uid_t", Name: "uid"},
			},
		},
		Setgid16: {
			ID32Bit: sys32setgid,
			Name:    "setgid16",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "old_gid_t", Name: "gid"},
			},
		},
		Setfsuid16: {
			ID32Bit: sys32setfsuid,
			Name:    "setfsuid16",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "old_uid_t", Name: "fsuid"},
			},
		},
		Setfsgid16: {
			ID32Bit: sys32setfsgid,
			Name:    "setfsgid16",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "old_gid_t", Name: "fsgid"},
			},
		},
		Fcntl64: {
			ID32Bit: sys32fcntl64,
			Name:    "fcntl64",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "int", Name: "cmd"},
				{Type: "unsigned long", Name: "arg"},
			},
		},
		Sendfile32: {
			ID32Bit: sys32sendfile,
			Name:    "sendfile32",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "out_fd"},
				{Type: "int", Name: "in_fd"},
				{Type: "off_t*", Name: "offset"},
				{Type: "size_t", Name: "count"},
			},
		},
		Statfs64: {
			ID32Bit: sys32statfs64,
			Name:    "statfs64",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "size_t", Name: "sz"},
				{Type: "struct statfs64*", Name: "buf"},
			},
		},
		Fstatfs64: {
			ID32Bit: sys32fstatfs64,
			Name:    "fstatfs64",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "size_t", Name: "sz"},
				{Type: "struct statfs64*", Name: "buf"},
			},
		},
		Fadvise64_64: {
			ID32Bit: sys32fadvise64_64,
			Name:    "fadvise64_64",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "loff_t", Name: "offset"},
				{Type: "loff_t", Name: "len"},
				{Type: "int", Name: "advice"},
			},
		},
		ClockGettime32: {
			ID32Bit: sys32clock_gettime,
			Name:    "clock_gettime32",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "clockid_t", Name: "which_clock"},
				{Type: "struct old_timespec32*", Name: "tp"},
			},
		},
		ClockSettime32: {
			ID32Bit: sys32clock_settime,
			Name:    "clock_settime32",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "clockid_t", Name: "which_clock"},
				{Type: "struct old_timespec32*", Name: "tp"},
			},
		},
		ClockAdjtime64: {
			ID32Bit: sys32clock_adjtime64,
			Name:    "clock_adjtime64",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params:  []trace.ArgMeta{},
		},
		ClockGetresTime32: {
			ID32Bit: sys32clock_getres,
			Name:    "clock_getres_time32",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "clockid_t", Name: "which_clock"},
				{Type: "struct old_timespec32*", Name: "tp"},
			},
		},
		ClockNanosleepTime32: {
			ID32Bit: sys32clock_nanosleep,
			Name:    "clock_nanosleep_time32",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "clockid_t", Name: "which_clock"},
				{Type: "int", Name: "flags"},
				{Type: "struct old_timespec32*", Name: "rqtp"},
				{Type: "struct old_timespec32*", Name: "rmtp"},
			},
		},
		TimerGettime32: {
			ID32Bit: sys32timer_gettime,
			Name:    "timer_gettime32",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "timer_t", Name: "timer_id"},
				{Type: "struct old_itimerspec32*", Name: "setting"},
			},
		},
		TimerSettime32: {
			ID32Bit: sys32timer_settime,
			Name:    "timer_settime32",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "timer_t", Name: "timer_id"},
				{Type: "int", Name: "flags"},
				{Type: "struct old_itimerspec32*", Name: "new"},
				{Type: "struct old_itimerspec32*", Name: "old"},
			},
		},
		TimerfdGettime32: {
			ID32Bit: sys32timerfd_gettime,
			Name:    "timerfd_gettime32",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "ufd"},
				{Type: "struct old_itimerspec32*", Name: "otmr"},
			},
		},
		TimerfdSettime32: {
			ID32Bit: sys32timerfd_settime,
			Name:    "timerfd_settime32",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "ufd"},
				{Type: "int", Name: "flags"},
				{Type: "struct old_itimerspec32*", Name: "utmr"},
				{Type: "struct old_itimerspec32*", Name: "otmr"},
			},
		},
		UtimensatTime32: {
			ID32Bit: sys32utimensat,
			Name:    "utimensat_time32",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "dfd"},
				{Type: "char*", Name: "filename"},
				{Type: "struct old_timespec32*", Name: "t"},
				{Type: "int", Name: "flags"},
			},
		},
		Pselect6Time32: {
			ID32Bit: sys32pselect6,
			Name:    "pselect6_time32",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "n"},
				{Type: "fd_set*", Name: "inp"},
				{Type: "fd_set*", Name: "outp"},
				{Type: "fd_set*", Name: "exp"},
				{Type: "struct old_timespec32*", Name: "tsp"},
				{Type: "void*", Name: "sig"},
			},
		},
		PpollTime32: {
			ID32Bit: sys32ppoll,
			Name:    "ppoll_time32",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "struct pollfd*", Name: "ufds"},
				{Type: "unsigned int", Name: "nfds"},
				{Type: "struct old_timespec32*", Name: "tsp"},
				{Type: "sigset_t*", Name: "sigmask"},
				{Type: "size_t", Name: "sigsetsize"},
			},
		},
		IoPgeteventsTime32: {
			ID32Bit: sys32io_pgetevents,
			Name:    "io_pgetevents_time32",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params:  []trace.ArgMeta{},
		},
		RecvmmsgTime32: {
			ID32Bit: sys32recvmmsg,
			Name:    "recvmmsg_time32",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "struct mmsghdr*", Name: "mmsg"},
				{Type: "unsigned int", Name: "vlen"},
				{Type: "unsigned int", Name: "flags"},
				{Type: "struct old_timespec32*", Name: "timeout"},
			},
		},
		MqTimedsendTime32: {
			ID32Bit: sys32mq_timedsend,
			Name:    "mq_timedsend_time32",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "mqd_t", Name: "mqdes"},
				{Type: "char*", Name: "u_msg_ptr"},
				{Type: "unsigned int", Name: "msg_len"},
				{Type: "unsigned int", Name: "msg_prio"},
				{Type: "struct old_timespec32*", Name: "u_abs_timeout"},
			},
		},
		MqTimedreceiveTime32: {
			ID32Bit: sys32mq_timedreceive,
			Name:    "mq_timedreceive_time32",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "mqd_t", Name: "mqdes"},
				{Type: "char*", Name: "u_msg_ptr"},
				{Type: "unsigned int", Name: "msg_len"},
				{Type: "unsigned int*", Name: "u_msg_prio"},
				{Type: "struct old_timespec32*", Name: "u_abs_timeout"},
			},
		},
		RtSigtimedwaitTime32: {
			ID32Bit: sys32rt_sigtimedwait,
			Name:    "rt_sigtimedwait_time32",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "sigset_t*", Name: "uthese"},
				{Type: "siginfo_t*", Name: "uinfo"},
				{Type: "struct old_timespec32*", Name: "uts"},
				{Type: "size_t", Name: "sigsetsize"},
			},
		},
		FutexTime32: {
			ID32Bit: sys32futex,
			Name:    "futex_time32",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "u32*", Name: "uaddr"},
				{Type: "int", Name: "op"},
				{Type: "u32", Name: "val"},
				{Type: "struct old_timespec32*", Name: "utime"},
				{Type: "u32*", Name: "uaddr2"},
				{Type: "u32", Name: "val3"},
			},
		},
		SchedRrGetInterval32: {
			ID32Bit: sys32sched_rr_get_interval,
			Name:    "sched_rr_get_interval_time32",
			Syscall: true,
			Sets:    []string{"syscalls", "32bit_unique"},
			Params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "struct old_timespec32*", Name: "interval"},
			},
		},
		SysEnter: {
			ID32Bit: sys32undefined,
			Name:    "sys_enter",
			Probes: []probeDependency{
				{Handle: probes.SysEnter, Required: true},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "syscall"},
			},
		},
		SysExit: {
			ID32Bit: sys32undefined,
			Name:    "sys_exit",
			Probes: []probeDependency{
				{Handle: probes.SysExit, Required: true},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "syscall"},
			},
		},
		SchedProcessFork: {
			ID32Bit: sys32undefined,
			Name:    "sched_process_fork",
			Probes: []probeDependency{
				{Handle: probes.SchedProcessFork, Required: true},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
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
		},
		SchedProcessExec: {
			ID32Bit: sys32undefined,
			Name:    "sched_process_exec",
			Probes: []probeDependency{
				{Handle: probes.SchedProcessExec, Required: true},
				{Handle: probes.LoadElfPhdrs, Required: false},
			},
			Sets: []string{"default", "proc"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "cmdpath"},
				{Type: "const char*", Name: "pathname"},
				{Type: "const char**", Name: "argv"},
				{Type: "const char**", Name: "env"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
				{Type: "int", Name: "invoked_from_kernel"},
				{Type: "unsigned long", Name: "ctime"},
				{Type: "umode_t", Name: "stdin_type"},
				{Type: "umode_t", Name: "inode_mode"},
				{Type: "const char*", Name: "interp"},
				{Type: "const char*", Name: "interpreter_pathname"},
				{Type: "dev_t", Name: "interpreter_dev"},
				{Type: "unsigned long", Name: "interpreter_inode"},
				{Type: "unsigned long", Name: "interpreter_ctime"},
			},
		},
		SchedProcessExit: {
			ID32Bit: sys32undefined,
			Name:    "sched_process_exit",
			Probes: []probeDependency{
				{Handle: probes.SchedProcessExit, Required: true},
			},
			Sets: []string{"default", "proc", "proc_life"},
			Params: []trace.ArgMeta{
				{Type: "long", Name: "exit_code"},
				// The field value represents that all threads exited at the event time.
				// Multiple exits of threads of the same process group at the same time could result that all threads exit
				// events would have 'true' value in this field altogether.
				{Type: "bool", Name: "process_group_exit"},
			},
		},
		SchedSwitch: {
			ID32Bit: sys32undefined,
			Name:    "sched_switch",
			Probes: []probeDependency{
				{Handle: probes.SchedSwitch, Required: true},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "cpu"},
				{Type: "int", Name: "prev_tid"},
				{Type: "const char*", Name: "prev_comm"},
				{Type: "int", Name: "next_tid"},
				{Type: "const char*", Name: "next_comm"},
			},
		},
		DoExit: {
			ID32Bit: sys32undefined,
			Name:    "do_exit",
			Probes: []probeDependency{
				{Handle: probes.DoExit, Required: true},
			},
			Sets:   []string{"proc", "proc_life"},
			Params: []trace.ArgMeta{},
		},
		CapCapable: {
			ID32Bit: sys32undefined,
			Name:    "cap_capable",
			Probes: []probeDependency{
				{Handle: probes.CapCapable, Required: true},
			},
			Sets: []string{"default"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "cap"},
				{Type: "int", Name: "syscall"},
			},
		},
		VfsWrite: {
			ID32Bit: sys32undefined,
			Name:    "vfs_write",
			Probes: []probeDependency{
				{Handle: probes.VfsWrite, Required: true},
				{Handle: probes.VfsWriteRet, Required: true},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
				{Type: "size_t", Name: "count"},
				{Type: "off_t", Name: "pos"},
			},
		},
		VfsWritev: {
			ID32Bit: sys32undefined,
			Name:    "vfs_writev",
			Probes: []probeDependency{
				{Handle: probes.VfsWriteV, Required: true},
				{Handle: probes.VfsWriteVRet, Required: true},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
				{Type: "unsigned long", Name: "vlen"},
				{Type: "off_t", Name: "pos"},
			},
		},
		MemProtAlert: {
			ID32Bit: sys32undefined,
			Name:    "mem_prot_alert",
			Probes: []probeDependency{
				{Handle: probes.SecurityMmapAddr, Required: true},
				{Handle: probes.SecurityFileMProtect, Required: true},
				{Handle: probes.SyscallEnter__Internal, Required: true},
			},
			Dependencies: dependencies{
				TailCalls: []TailCall{
					{MapName: "sys_enter_init_tail", MapIndexes: []uint32{uint32(Mmap), uint32(Mprotect)}, ProgName: "sys_enter_init"},
				},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "u32", Name: "alert"},
			},
		},
		CommitCreds: {
			ID32Bit: sys32undefined,
			Name:    "commit_creds",
			Probes: []probeDependency{
				{Handle: probes.CommitCreds, Required: true},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "slim_cred_t", Name: "old_cred"},
				{Type: "slim_cred_t", Name: "new_cred"},
				{Type: "int", Name: "syscall"},
			},
		},
		SwitchTaskNS: {
			ID32Bit: sys32undefined,
			Name:    "switch_task_ns",
			Probes: []probeDependency{
				{Handle: probes.SwitchTaskNS, Required: true},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
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
			ID32Bit: sys32undefined,
			Name:    "magic_write",
			DocPath: "security_alerts/magic_write.md",
			Probes: []probeDependency{
				{Handle: probes.VfsWrite, Required: true},
				{Handle: probes.VfsWriteRet, Required: true},
				{Handle: probes.VfsWriteV, Required: false},
				{Handle: probes.VfsWriteVRet, Required: false},
				{Handle: probes.KernelWrite, Required: false},
				{Handle: probes.KernelWriteRet, Required: false},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "bytes", Name: "bytes"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
			},
		},
		CgroupAttachTask: {
			ID32Bit: sys32undefined,
			Name:    "cgroup_attach_task",
			Probes: []probeDependency{
				{Handle: probes.CgroupAttachTask, Required: true},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "cgroup_path"},
				{Type: "const char*", Name: "comm"},
				{Type: "pid_t", Name: "pid"},
			},
		},
		CgroupMkdir: {
			ID32Bit: sys32undefined,
			Name:    "cgroup_mkdir",
			Probes: []probeDependency{
				{Handle: probes.CgroupMkdir, Required: true},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "u64", Name: "cgroup_id"},
				{Type: "const char*", Name: "cgroup_path"},
				{Type: "u32", Name: "hierarchy_id"},
			},
		},
		CgroupRmdir: {
			ID32Bit: sys32undefined,
			Name:    "cgroup_rmdir",
			Probes: []probeDependency{
				{Handle: probes.CgroupRmdir, Required: true},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "u64", Name: "cgroup_id"},
				{Type: "const char*", Name: "cgroup_path"},
				{Type: "u32", Name: "hierarchy_id"},
			},
		},
		SecurityBprmCheck: {
			ID32Bit: sys32undefined,
			Name:    "security_bprm_check",
			Probes: []probeDependency{
				{Handle: probes.SecurityBPRMCheck, Required: true},
			},
			Sets: []string{"default", "lsm_hooks", "proc", "proc_life"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
			},
		},
		SecurityFileOpen: {
			ID32Bit: sys32undefined,
			Name:    "security_file_open",
			Probes: []probeDependency{
				{Handle: probes.SecurityFileOpen, Required: true},
				{Handle: probes.SyscallEnter__Internal, Required: true},
			},
			Dependencies: dependencies{
				TailCalls: []TailCall{
					{MapName: "sys_enter_init_tail", MapIndexes: []uint32{
						uint32(Open), uint32(Openat), uint32(Openat2), uint32(OpenByHandleAt),
						uint32(Execve), uint32(Execveat),
					}, ProgName: "sys_enter_init"},
				},
			},
			Sets: []string{"default", "lsm_hooks", "fs", "fs_file_ops"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "int", Name: "flags"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
				{Type: "unsigned long", Name: "ctime"},
				{Type: "const char*", Name: "syscall_pathname"},
				{Type: "int", Name: "syscall"},
			},
		},
		SecurityInodeUnlink: {
			ID32Bit: sys32undefined,
			Name:    "security_inode_unlink",
			Probes: []probeDependency{
				{Handle: probes.SecurityInodeUnlink, Required: true},
			},
			Sets: []string{"default", "lsm_hooks", "fs", "fs_file_ops"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "unsigned long", Name: "inode"},
				{Type: "dev_t", Name: "dev"},
				{Type: "u64", Name: "ctime"},
			},
		},
		SecuritySocketCreate: {
			ID32Bit: sys32undefined,
			Name:    "security_socket_create",
			Probes: []probeDependency{
				{Handle: probes.SecuritySocketCreate, Required: true},
			},
			Sets: []string{"default", "lsm_hooks", "net", "net_sock"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "family"},
				{Type: "int", Name: "type"},
				{Type: "int", Name: "protocol"},
				{Type: "int", Name: "kern"},
			},
		},
		SecuritySocketListen: {
			ID32Bit: sys32undefined,
			Name:    "security_socket_listen",
			Probes: []probeDependency{
				{Handle: probes.SecuritySocketListen, Required: true},
				{Handle: probes.SyscallEnter__Internal, Required: true},
			},
			Dependencies: dependencies{
				TailCalls: []TailCall{
					{MapName: "sys_enter_init_tail", MapIndexes: []uint32{uint32(Listen)}, ProgName: "sys_enter_init"},
				},
			},
			Sets: []string{"default", "lsm_hooks", "net", "net_sock"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct sockaddr*", Name: "local_addr"},
				{Type: "int", Name: "backlog"},
			},
		},
		SecuritySocketConnect: {
			ID32Bit: sys32undefined,
			Name:    "security_socket_connect",
			Probes: []probeDependency{
				{Handle: probes.SecuritySocketConnect, Required: true},
				{Handle: probes.SyscallEnter__Internal, Required: true},
			},
			Dependencies: dependencies{
				TailCalls: []TailCall{
					{MapName: "sys_enter_init_tail", MapIndexes: []uint32{uint32(Connect)}, ProgName: "sys_enter_init"},
				},
			},
			Sets: []string{"default", "lsm_hooks", "net", "net_sock"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct sockaddr*", Name: "remote_addr"},
			},
		},
		SecuritySocketAccept: {
			ID32Bit: sys32undefined,
			Name:    "security_socket_accept",
			Probes: []probeDependency{
				{Handle: probes.SecuritySocketAccept, Required: true},
				{Handle: probes.SyscallEnter__Internal, Required: true},
			},
			Dependencies: dependencies{
				TailCalls: []TailCall{
					{MapName: "sys_enter_init_tail", MapIndexes: []uint32{uint32(Accept), uint32(Accept4)}, ProgName: "sys_enter_init"},
				},
			},
			Sets: []string{"default", "lsm_hooks", "net", "net_sock"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct sockaddr*", Name: "local_addr"},
			},
		},
		SecuritySocketBind: {
			ID32Bit: sys32undefined,
			Name:    "security_socket_bind",
			Probes: []probeDependency{
				{Handle: probes.SecuritySocketBind, Required: true},
				{Handle: probes.SyscallEnter__Internal, Required: true},
			},
			Dependencies: dependencies{
				TailCalls: []TailCall{
					{MapName: "sys_enter_init_tail", MapIndexes: []uint32{uint32(Bind)}, ProgName: "sys_enter_init"},
				},
			},
			Sets: []string{"default", "lsm_hooks", "net", "net_sock"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct sockaddr*", Name: "local_addr"},
			},
		},
		SecuritySocketSetsockopt: {
			ID32Bit: sys32undefined,
			Name:    "security_socket_setsockopt",
			DocPath: "lsm_hooks/security_socket_setsockopt.md",
			Probes: []probeDependency{
				{Handle: probes.SecuritySocketSetsockopt, Required: true},
				{Handle: probes.SyscallEnter__Internal, Required: true},
			},
			Dependencies: dependencies{
				TailCalls: []TailCall{
					{MapName: "sys_enter_init_tail", MapIndexes: []uint32{uint32(Setsockopt)}, ProgName: "sys_enter_init"},
				},
			},
			Sets: []string{"default", "lsm_hooks", "net", "net_sock"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "int", Name: "level"},
				{Type: "int", Name: "optname"},
				{Type: "struct sockaddr*", Name: "local_addr"},
			},
		},
		SecuritySbMount: {
			ID32Bit: sys32undefined,
			Name:    "security_sb_mount",
			Probes: []probeDependency{
				{Handle: probes.SecuritySbMount, Required: true},
			},
			Sets: []string{"default", "lsm_hooks", "fs"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "dev_name"},
				{Type: "const char*", Name: "path"},
				{Type: "const char*", Name: "type"},
				{Type: "unsigned long", Name: "flags"},
			},
		},
		SecurityBPF: {
			ID32Bit: sys32undefined,
			Name:    "security_bpf",
			Probes: []probeDependency{
				{Handle: probes.SecurityBPF, Required: true},
			},
			Sets: []string{"lsm_hooks"},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "cmd"},
			},
		},
		SecurityBPFMap: {
			ID32Bit: sys32undefined,
			Name:    "security_bpf_map",
			Probes: []probeDependency{
				{Handle: probes.SecurityBPFMap, Required: true},
			},
			Sets: []string{"lsm_hooks"},
			Params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "map_id"},
				{Type: "const char*", Name: "map_name"},
			},
		},
		SecurityKernelReadFile: {
			ID32Bit: sys32undefined,
			Name:    "security_kernel_read_file",
			Probes: []probeDependency{
				{Handle: probes.SecurityKernelReadFile, Required: true},
			},
			Sets: []string{"lsm_hooks"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
				{Type: "int", Name: "type"},
				{Type: "unsigned long", Name: "ctime"},
			},
		},
		SecurityPostReadFile: {
			ID32Bit: sys32undefined,
			Name:    "security_kernel_post_read_file",
			Probes: []probeDependency{
				{Handle: probes.SecurityKernelPostReadFile, Required: true},
			},
			Sets: []string{"lsm_hooks"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "long", Name: "size"},
				{Type: "int", Name: "type"},
			},
		},
		SecurityInodeMknod: {
			ID32Bit: sys32undefined,
			Name:    "security_inode_mknod",
			Probes: []probeDependency{
				{Handle: probes.SecurityInodeMknod, Required: true},
			},
			Sets: []string{"lsm_hooks"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "file_name"},
				{Type: "umode_t", Name: "mode"},
				{Type: "dev_t", Name: "dev"},
			},
		},
		SecurityInodeSymlinkEventId: {
			ID32Bit: sys32undefined,
			Name:    "security_inode_symlink",
			Probes: []probeDependency{
				{Handle: probes.SecurityInodeSymlink, Required: true},
			},
			Sets: []string{"lsm_hooks", "fs", "fs_file_ops"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "linkpath"},
				{Type: "const char*", Name: "target"},
			},
		},
		SecurityMmapFile: {
			ID32Bit: sys32undefined,
			Name:    "security_mmap_file",
			Probes: []probeDependency{
				{Handle: probes.SecurityMmapFile, Required: true},
			},
			Sets: []string{"lsm_hooks", "fs", "fs_file_ops", "proc", "proc_mem"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "int", Name: "flags"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
				{Type: "unsigned long", Name: "ctime"},
				{Type: "int", Name: "prot"},
				{Type: "int", Name: "mmap_flags"},
				{Type: "int", Name: "syscall"},
			},
		},
		SecurityFileMprotect: {
			ID32Bit: sys32undefined,
			Name:    "security_file_mprotect",
			Probes: []probeDependency{
				{Handle: probes.SecurityFileMProtect, Required: true},
				{Handle: probes.SyscallEnter__Internal, Required: true},
			},
			Dependencies: dependencies{
				TailCalls: []TailCall{
					{MapName: "sys_enter_init_tail", MapIndexes: []uint32{uint32(Mprotect)}, ProgName: "sys_enter_init"},
				},
			},
			Sets: []string{"lsm_hooks", "proc", "proc_mem", "fs", "fs_file_ops"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "int", Name: "prot"},
				{Type: "unsigned long", Name: "ctime"},
			},
		},
		InitNamespaces: {
			ID32Bit: sys32undefined,
			Name:    "init_namespaces",
			Sets:    []string{},
			Dependencies: dependencies{
				Capabilities: []cap.Value{cap.SYS_PTRACE},
			},
			Params: []trace.ArgMeta{
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
		SocketDup: {
			ID32Bit: sys32undefined,
			Name:    "socket_dup",
			Dependencies: dependencies{
				TailCalls: []TailCall{
					{MapName: "sys_enter_init_tail", MapIndexes: []uint32{uint32(Dup), uint32(Dup2), uint32(Dup3)}, ProgName: "sys_enter_init"},
					{MapName: "sys_exit_init_tail", MapIndexes: []uint32{uint32(Dup), uint32(Dup2), uint32(Dup3)}, ProgName: "sys_exit_init"},
					{MapName: "sys_exit_tails", MapIndexes: []uint32{uint32(Dup), uint32(Dup2), uint32(Dup3)}, ProgName: "sys_dup_exit_tail"},
				},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "oldfd"},
				{Type: "int", Name: "newfd"},
				{Type: "struct sockaddr*", Name: "remote_addr"},
			},
		},
		HiddenInodes: {
			ID32Bit: sys32undefined,
			Name:    "hidden_inodes",
			Probes: []probeDependency{
				{Handle: probes.Filldir64, Required: true},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "char*", Name: "hidden_process"},
			},
		},
		KernelWrite: {
			ID32Bit: sys32undefined,
			Name:    "__kernel_write",
			Probes: []probeDependency{
				{Handle: probes.KernelWrite, Required: true},
				{Handle: probes.KernelWriteRet, Required: true},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
				{Type: "size_t", Name: "count"},
				{Type: "off_t", Name: "pos"},
			},
		},
		DirtyPipeSplice: {
			ID32Bit: sys32undefined,
			Name:    "dirty_pipe_splice",
			Probes: []probeDependency{
				{Handle: probes.DoSplice, Required: true},
				{Handle: probes.DoSpliceRet, Required: true},
			},
			Sets: []string{},
			Dependencies: dependencies{
				KSymbols: []string{"pipefifo_fops"},
			},
			Params: []trace.ArgMeta{
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
			ID32Bit: sys32undefined,
			Name:    "container_create",
			Dependencies: dependencies{
				Events: []eventDependency{{EventID: CgroupMkdir}},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "runtime"},
				{Type: "const char*", Name: "container_id"},
				{Type: "unsigned long", Name: "ctime"},
				{Type: "const char*", Name: "container_image"},
				{Type: "const char*", Name: "container_name"},
				{Type: "const char*", Name: "pod_name"},
				{Type: "const char*", Name: "pod_namespace"},
				{Type: "const char*", Name: "pod_uid"},
			},
		},
		ContainerRemove: {
			ID32Bit: sys32undefined,
			Name:    "container_remove",
			Dependencies: dependencies{
				Events: []eventDependency{{EventID: CgroupRmdir}},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "runtime"},
				{Type: "const char*", Name: "container_id"},
			},
		},
		ExistingContainer: {
			ID32Bit: sys32undefined,
			Name:    "existing_container",
			Sets:    []string{},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "runtime"},
				{Type: "const char*", Name: "container_id"},
				{Type: "unsigned long", Name: "ctime"},
				{Type: "const char*", Name: "container_image"},
				{Type: "const char*", Name: "container_name"},
				{Type: "const char*", Name: "pod_name"},
				{Type: "const char*", Name: "pod_namespace"},
				{Type: "const char*", Name: "pod_uid"},
			},
		},
		NetPacket: {
			ID32Bit: sys32undefined,
			Name:    "net_packet",
			Probes: []probeDependency{
				{Handle: probes.UDPSendmsg, Required: true},
				{Handle: probes.UDPDisconnect, Required: true},
				{Handle: probes.UDPDestroySock, Required: true},
				{Handle: probes.UDPv6DestroySock, Required: true},
				{Handle: probes.InetSockSetState, Required: true},
				{Handle: probes.TCPConnect, Required: true},
				{Handle: probes.ICMPRecv, Required: true},
				{Handle: probes.ICMPSend, Required: true},
				{Handle: probes.ICMPv6Recv, Required: true},
				{Handle: probes.ICMPv6Send, Required: true},
				{Handle: probes.Pingv4Sendmsg, Required: true},
				{Handle: probes.Pingv6Sendmsg, Required: true},
				{Handle: probes.SecuritySocketBind, Required: true},
			},
			Dependencies: dependencies{
				Capabilities: []cap.Value{cap.NET_ADMIN},
			},
			Sets: []string{"network_events"},
			Params: []trace.ArgMeta{
				{Type: "trace.PktMeta", Name: "metadata"},
			},
		},
		DnsRequest: {
			ID32Bit: sys32undefined,
			Name:    "dns_request",
			Probes: []probeDependency{
				{Handle: probes.UDPSendmsg, Required: true},
				{Handle: probes.UDPDisconnect, Required: true},
				{Handle: probes.UDPDestroySock, Required: true},
				{Handle: probes.UDPv6DestroySock, Required: true},
				{Handle: probes.InetSockSetState, Required: true},
				{Handle: probes.TCPConnect, Required: true},
			},
			Dependencies: dependencies{
				Capabilities: []cap.Value{cap.NET_ADMIN},
			},
			Sets: []string{"network_events"},
			Params: []trace.ArgMeta{
				{Type: "trace.PktMeta", Name: "metadata"},
				{Type: "[]trace.DnsQueryData", Name: "dns_questions"},
			},
		},
		DnsResponse: {
			ID32Bit: sys32undefined,
			Name:    "dns_response",
			Probes: []probeDependency{
				{Handle: probes.UDPSendmsg, Required: true},
				{Handle: probes.UDPDisconnect, Required: true},
				{Handle: probes.UDPDestroySock, Required: true},
				{Handle: probes.UDPv6DestroySock, Required: true},
				{Handle: probes.InetSockSetState, Required: true},
				{Handle: probes.TCPConnect, Required: true},
			},
			Dependencies: dependencies{
				Capabilities: []cap.Value{cap.NET_ADMIN},
			},
			Sets: []string{"network_events"},
			Params: []trace.ArgMeta{
				{Type: "trace.PktMeta", Name: "metadata"},
				{Type: "[]trace.DnsResponseData", Name: "dns_response"},
			},
		},
		ProcCreate: {
			ID32Bit: sys32undefined,
			Name:    "proc_create",
			Probes: []probeDependency{
				{Handle: probes.ProcCreate, Required: true},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "char*", Name: "name"},
				{Type: "void*", Name: "proc_ops_addr"},
			},
		},
		KprobeAttach: {
			ID32Bit: sys32undefined,
			Name:    "kprobe_attach",
			Probes: []probeDependency{
				{Handle: probes.RegisterKprobe, Required: true},
				{Handle: probes.RegisterKprobeRet, Required: true},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "char*", Name: "symbol_name"},
				{Type: "void*", Name: "pre_handler_addr"},
				{Type: "void*", Name: "post_handler_addr"},
			},
		},
		CallUsermodeHelper: {
			ID32Bit: sys32undefined,
			Name:    "call_usermodehelper",
			Probes: []probeDependency{
				{Handle: probes.CallUsermodeHelper, Required: true},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "const char*const*", Name: "argv"},
				{Type: "const char*const*", Name: "envp"},
				{Type: "int", Name: "wait"},
			},
		},
		DebugfsCreateFile: {
			ID32Bit: sys32undefined,
			Name:    "debugfs_create_file",
			Probes: []probeDependency{
				{Handle: probes.DebugfsCreateFile, Required: true},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "file_name"},
				{Type: "const char*", Name: "path"},
				{Type: "mode_t", Name: "mode"},
				{Type: "void*", Name: "proc_ops_addr"},
			},
			Dependencies: dependencies{
				Capabilities: []cap.Value{cap.NET_ADMIN},
			},
		},
		PrintSyscallTable: {
			ID32Bit:  sys32undefined,
			Name:     "print_syscall_table",
			Internal: true,
			Probes: []probeDependency{
				{Handle: probes.PrintSyscallTable, Required: true},
			},
			Dependencies: dependencies{
				KSymbols: []string{"sys_call_table"},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "unsigned long[]", Name: "syscalls_addresses"},
				{Type: "unsigned long", Name: trigger.ContextArgName},
			},
		},
		HookedSyscalls: {
			ID32Bit: sys32undefined,
			Name:    "hooked_syscalls",
			Dependencies: dependencies{
				Events: []eventDependency{
					{EventID: DoInitModule},
					{EventID: PrintSyscallTable},
				},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "[]trace.HookedSymbolData", Name: "hooked_syscalls"},
			},
		},
		DebugfsCreateDir: {
			ID32Bit: sys32undefined,
			Name:    "debugfs_create_dir",
			Probes: []probeDependency{
				{Handle: probes.DebugfsCreateDir, Required: true},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "name"},
				{Type: "const char*", Name: "path"},
			},
		},
		DeviceAdd: {
			ID32Bit: sys32undefined,
			Name:    "device_add",
			Probes: []probeDependency{
				{Handle: probes.DeviceAdd, Required: true},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "name"},
				{Type: "const char*", Name: "parent_name"},
			},
		},
		RegisterChrdev: {
			ID32Bit: sys32undefined,
			Name:    "register_chrdev",
			Probes: []probeDependency{
				{Handle: probes.RegisterChrdev, Required: true},
				{Handle: probes.RegisterChrdevRet, Required: true},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "requested_major_number"},
				{Type: "unsigned int", Name: "granted_major_number"},
				{Type: "const char*", Name: "char_device_name"},
				{Type: "struct file_operations *", Name: "char_device_fops"},
			},
		},
		SharedObjectLoaded: {
			ID32Bit: sys32undefined,
			Name:    "shared_object_loaded",
			Dependencies: dependencies{
				Events: []eventDependency{{EventID: SecurityMmapFile}},
			},
			Sets: []string{"lsm_hooks", "fs", "fs_file_ops", "proc", "proc_mem"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "int", Name: "flags"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
				{Type: "unsigned long", Name: "ctime"},
			},
		},
		SymbolsLoaded: {
			ID32Bit: sys32undefined,
			Name:    "symbols_loaded",
			DocPath: "security_alerts/symbols_load.md",
			Probes:  []probeDependency{},
			Dependencies: dependencies{
				Events: []eventDependency{
					{EventID: SharedObjectLoaded},
					{EventID: SchedProcessExec}, // Used to get mount namespace cache
				},
				Capabilities: []cap.Value{
					cap.SYS_PTRACE,   // Used to get host mount NS for bucket cache
					cap.DAC_OVERRIDE, // Used to open files across the system
				},
			},
			Sets: []string{"derived", "fs", "security_alert"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "library_path"},
				{Type: "const char*const*", Name: "symbols"},
			},
		},
		CaptureFileWrite: {
			ID32Bit:  sys32undefined,
			Name:     "capture_file_write",
			Internal: true,
			Probes: []probeDependency{
				{Handle: probes.VfsWrite, Required: true},
				{Handle: probes.VfsWriteRet, Required: true},
				{Handle: probes.VfsWriteV, Required: false},
				{Handle: probes.VfsWriteVRet, Required: false},
				{Handle: probes.KernelWrite, Required: false},
				{Handle: probes.KernelWriteRet, Required: false},
			},
			Dependencies: dependencies{
				TailCalls: []TailCall{
					{MapName: "prog_array", MapIndexes: []uint32{tailVfsWrite}, ProgName: "trace_ret_vfs_write_tail"},
					{MapName: "prog_array", MapIndexes: []uint32{tailVfsWritev}, ProgName: "trace_ret_vfs_writev_tail"},
					{MapName: "prog_array", MapIndexes: []uint32{tailKernelWrite}, ProgName: "trace_ret_kernel_write_tail"},
					{MapName: "prog_array", MapIndexes: []uint32{tailSendBin}, ProgName: "send_bin"},
				},
			},
		},
		CaptureExec: {
			ID32Bit:  sys32undefined,
			Name:     "capture_exec",
			Internal: true,
			Dependencies: dependencies{
				Events: []eventDependency{{EventID: SchedProcessExec}},
				Capabilities: []cap.Value{
					cap.SYS_PTRACE,
					cap.DAC_OVERRIDE,
				},
			},
		},
		CaptureModule: {
			ID32Bit:  sys32undefined,
			Name:     "capture_module",
			Internal: true,
			Probes: []probeDependency{
				{Handle: probes.SyscallEnter__Internal, Required: true},
				{Handle: probes.SyscallExit__Internal, Required: true},
				{Handle: probes.SecurityKernelPostReadFile, Required: true},
			},
			Dependencies: dependencies{
				Events: []eventDependency{{EventID: SchedProcessExec}},
				TailCalls: []TailCall{
					{MapName: "sys_enter_tails", MapIndexes: []uint32{uint32(InitModule)}, ProgName: "syscall__init_module"},
					{MapName: "prog_array_tp", MapIndexes: []uint32{tailSendBinTP}, ProgName: "send_bin_tp"},
					{MapName: "prog_array", MapIndexes: []uint32{tailSendBin}, ProgName: "send_bin"},
				},
			},
		},
		CaptureMem: {
			ID32Bit:  sys32undefined,
			Name:     "capture_mem",
			Internal: true,
			Dependencies: dependencies{
				TailCalls: []TailCall{
					{MapName: "prog_array", MapIndexes: []uint32{tailSendBin}, ProgName: "send_bin"},
				},
			},
		},
		CaptureProfile: {
			ID32Bit:  sys32undefined,
			Name:     "capture_profile",
			Internal: true,
			Dependencies: dependencies{
				Events: []eventDependency{{EventID: SchedProcessExec}},
			},
		},
		CapturePcap: {
			ID32Bit:  sys32undefined,
			Name:     "capture_pcap",
			Internal: true,
			Dependencies: dependencies{
				Events:       []eventDependency{{EventID: NetPacket}},
				Capabilities: []cap.Value{cap.NET_ADMIN},
			},
		},
		DoInitModule: {
			ID32Bit: sys32undefined,
			Name:    "do_init_module",
			Probes: []probeDependency{
				{Handle: probes.DoInitModule, Required: true},
				{Handle: probes.DoInitModuleRet, Required: true},
			},
			Dependencies: dependencies{},
			Sets:         []string{},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "name"},
				{Type: "const char*", Name: "version"},
				{Type: "const char*", Name: "src_version"},
				{Type: "void*", Name: "prev"},
				{Type: "void*", Name: "next"},
				{Type: "void*", Name: "prev_next"},
				{Type: "void*", Name: "next_prev"},
			},
		},
		SocketAccept: {
			ID32Bit:  sys32undefined,
			Name:     "socket_accept",
			Internal: false,
			Probes: []probeDependency{
				{Handle: probes.SyscallEnter__Internal, Required: true},
				{Handle: probes.SyscallExit__Internal, Required: true},
			},
			Dependencies: dependencies{
				Events: []eventDependency{{EventID: SecuritySocketAccept}},
				TailCalls: []TailCall{
					{MapName: "sys_exit_tails", MapIndexes: []uint32{uint32(Accept), uint32(Accept4)}, ProgName: "syscall__accept4"},
				},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct sockaddr*", Name: "local_addr"},
				{Type: "struct sockaddr*", Name: "remote_addr"}},
		},
		LoadElfPhdrs: {
			ID32Bit: sys32undefined,
			Name:    "load_elf_phdrs",
			Probes: []probeDependency{
				{Handle: probes.LoadElfPhdrs, Required: true},
			},
			Sets: []string{"proc"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
			},
		},
		HookedProcFops: {
			ID32Bit: sys32undefined,
			Name:    "hooked_proc_fops",
			Probes: []probeDependency{
				{Handle: probes.SecurityFilePermission, Required: true},
			},
			Dependencies: dependencies{
				KSymbols: []string{"_stext", "_etext"},
				Events: []eventDependency{
					{EventID: DoInitModule},
				},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "[]trace.HookedSymbolData", Name: "hooked_fops_pointers"},
			},
		},
		PrintNetSeqOps: {
			ID32Bit: sys32undefined,
			Name:    "print_net_seq_ops",
			Probes: []probeDependency{
				{Handle: probes.PrintNetSeqOps, Required: true},
			},
			Dependencies: dependencies{
				KSymbols: []string{
					"tcp4_seq_ops",
					"tcp6_seq_ops",
					"udp_seq_ops",
					"udp6_seq_ops",
					"raw_seq_ops",
					"raw6_seq_ops"},
			},
			Internal: true,
			Sets:     []string{},
			Params: []trace.ArgMeta{
				{Type: "unsigned long[]", Name: "net_seq_ops"},
				{Type: "unsigned long", Name: trigger.ContextArgName},
			},
		},
		HookedSeqOps: {
			ID32Bit: sys32undefined,
			Name:    "hooked_seq_ops",
			Dependencies: dependencies{
				Events: []eventDependency{
					{EventID: PrintNetSeqOps},
					{EventID: DoInitModule},
				},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "map[string]trace.HookedSymbolData", Name: "hooked_seq_ops"},
			},
		},
		TaskRename: {
			ID32Bit: sys32undefined,
			Name:    "task_rename",
			Probes: []probeDependency{
				{Handle: probes.TaskRename, Required: true},
			},
			Sets: []string{"proc"},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "old_name"},
				{Type: "const char*", Name: "new_name"},
				{Type: "int", Name: "syscall"},
			},
		},
		SecurityInodeRename: {
			ID32Bit: sys32undefined,
			Name:    "security_inode_rename",
			Probes: []probeDependency{
				{Handle: probes.SecurityInodeRename, Required: true},
			},
			Sets: []string{},
			Params: []trace.ArgMeta{
				{Type: "const char*", Name: "old_path"},
				{Type: "const char*", Name: "new_path"},
			},
		},
	},
}
