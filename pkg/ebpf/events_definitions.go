package ebpf

import "github.com/aquasecurity/tracee/types/trace"

// ProbeType is an enum that describes the mechanism used to attach the event
// Kprobes are explained here: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#1-kprobes
// Tracepoints are explained here: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#3-tracepoints
// Raw tracepoints are explained here: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#7-raw-tracepoints
type probeType uint8

const (
	kprobe = iota
	kretprobe
	tracepoint
	rawTracepoint
)

type probe struct {
	event  string
	attach probeType
	fn     string
}

type dependencies struct {
	events    []eventDependency // Events required to be loaded and/or submitted for the event to happen
	ksymbols  []string
	tailCalls []tailCall
}

type eventDependency struct {
	eventID int32
}

type tailCall struct {
	mapName  string
	mapIdx   uint32
	progName string
}

// EventDefinition is a struct describing an event configuration
type EventDefinition struct {
	ID32Bit      int32
	Name         string
	Internal     bool
	Syscall      bool
	Probes       []probe
	Dependencies dependencies
	Sets         []string
	Params       []trace.ArgMeta
}

// Common events (used by all architectures)
// events should match defined values in ebpf code
const (
	SysEnterEventID int32 = iota + 1000
	SysExitEventID
	SchedProcessForkEventID
	SchedProcessExecEventID
	SchedProcessExitEventID
	SchedSwitchEventID
	DoExitEventID
	CapCapableEventID
	VfsWriteEventID
	VfsWritevEventID
	MemProtAlertEventID
	CommitCredsEventID
	SwitchTaskNSEventID
	MagicWriteEventID
	CgroupAttachTaskEventID
	CgroupMkdirEventID
	CgroupRmdirEventID
	SecurityBprmCheckEventID
	SecurityFileOpenEventID
	SecurityInodeUnlinkEventID
	SecuritySocketCreateEventID
	SecuritySocketListenEventID
	SecuritySocketConnectEventID
	SecuritySocketAcceptEventID
	SecuritySocketBindEventID
	SecuritySbMountEventID
	SecurityBPFEventID
	SecurityBPFMapEventID
	SecurityKernelReadFileEventID
	SecurityInodeMknodEventID
	SecurityPostReadFileEventID
	SecurityInodeSymlinkEventId
	SecurityMmapFileEventID
	SecurityFileMprotectEventID
	SocketDupEventID
	HiddenInodesEventID
	__KernelWriteEventID
	ProcCreateEventID
	KprobeAttachEventID
	CallUsermodeHelperEventID
	DirtyPipeSpliceEventID
	DebugfsCreateFileEventID
	PrintSyscallTableEventID
	DebugfsCreateDirEventID
	DeviceAddEventID
	RegisterChrdevEventID
	SharedObjectLoadedEventID
	MaxCommonEventID
)

// Events originated from user-space
const (
	InitNamespacesEventID int32 = iota + 2000
	ContainerCreateEventID
	ContainerRemoveEventID
	ExistingContainerEventID
	DetectHookedSyscallsEventID
	MaxUserSpaceEventID
)

const Unique32BitSyscallsStartID = 3000

const (
	NetPacket int32 = iota + 4000
	DnsRequest
	DnsResponse
	MaxNetEventID
)

const (
	CaptureIface int32 = 1 << iota
	TraceIface
)

const (
	DebugNetSecurityBind int32 = iota + 5000
	DebugNetUdpSendmsg
	DebugNetUdpDisconnect
	DebugNetUdpDestroySock
	DebugNetUdpV6DestroySock
	DebugNetInetSockSetState
	DebugNetTcpConnect
)

const (
	CaptureFileWriteEventID int32 = iota + 6000
	CaptureExecEventID
	CaptureModuleEventID
	CaptureMemEventID
	CaptureProfileEventID
	CapturePcapEventID
)

var EventsDefinitions = map[int32]EventDefinition{
	ReadEventID: {
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
	WriteEventID: {
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
	OpenEventID: {
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
	CloseEventID: {
		ID32Bit: sys32close,
		Name:    "close",
		Syscall: true,
		Sets:    []string{"default", "syscalls", "fs", "fs_file_ops"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
		},
	},
	StatEventID: {
		ID32Bit: sys32stat,
		Name:    "stat",
		Syscall: true,
		Sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "struct stat*", Name: "statbuf"},
		},
	},
	FstatEventID: {
		ID32Bit: sys32fstat,
		Name:    "fstat",
		Syscall: true,
		Sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "struct stat*", Name: "statbuf"},
		},
	},
	LstatEventID: {
		ID32Bit: sys32lstat,
		Name:    "lstat",
		Syscall: true,
		Sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "struct stat*", Name: "statbuf"},
		},
	},
	PollEventID: {
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
	LseekEventID: {
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
	MmapEventID: {
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
	MprotectEventID: {
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
	MunmapEventID: {
		ID32Bit: sys32munmap,
		Name:    "munmap",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_mem"},
		Params: []trace.ArgMeta{
			{Type: "void*", Name: "addr"},
			{Type: "size_t", Name: "length"},
		},
	},
	BrkEventID: {
		ID32Bit: sys32brk,
		Name:    "brk",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_mem"},
		Params: []trace.ArgMeta{
			{Type: "void*", Name: "addr"},
		},
	},
	RtSigactionEventID: {
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
	RtSigprocmaskEventID: {
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
	RtSigreturnEventID: {
		ID32Bit: sys32rt_sigreturn,
		Name:    "rt_sigreturn",
		Syscall: true,
		Sets:    []string{"syscalls", "signals"},
		Params:  []trace.ArgMeta{},
	},
	IoctlEventID: {
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
	Pread64EventID: {
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
	Pwrite64EventID: {
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
	ReadvEventID: {
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
	WritevEventID: {
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
	AccessEventID: {
		ID32Bit: sys32access,
		Name:    "access",
		Syscall: true,
		Sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "int", Name: "mode"},
		},
	},
	PipeEventID: {
		ID32Bit: sys32pipe,
		Name:    "pipe",
		Syscall: true,
		Sets:    []string{"syscalls", "ipc", "ipc_pipe"},
		Params: []trace.ArgMeta{
			{Type: "int[2]", Name: "pipefd"},
		},
	},
	SelectEventID: {
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
	SchedYieldEventID: {
		ID32Bit: sys32sched_yield,
		Name:    "sched_yield",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_sched"},
		Params:  []trace.ArgMeta{},
	},
	MremapEventID: {
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
	MsyncEventID: {
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
	MincoreEventID: {
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
	MadviseEventID: {
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
	ShmgetEventID: {
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
	ShmatEventID: {
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
	ShmctlEventID: {
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
	DupEventID: {
		ID32Bit: sys32dup,
		Name:    "dup",
		Syscall: true,
		Sets:    []string{"default", "syscalls", "fs", "fs_fd_ops"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "oldfd"},
		},
	},
	Dup2EventID: {
		ID32Bit: sys32dup2,
		Name:    "dup2",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_fd_ops"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "oldfd"},
			{Type: "int", Name: "newfd"},
		},
	},
	PauseEventID: {
		ID32Bit: sys32pause,
		Name:    "pause",
		Syscall: true,
		Sets:    []string{"syscalls", "signals"},
		Params:  []trace.ArgMeta{},
	},
	NanosleepEventID: {
		ID32Bit: sys32nanosleep,
		Name:    "nanosleep",
		Syscall: true,
		Sets:    []string{"syscalls", "time", "time_timer"},
		Params: []trace.ArgMeta{
			{Type: "const struct timespec*", Name: "req"},
			{Type: "struct timespec*", Name: "rem"},
		},
	},
	GetitimerEventID: {
		ID32Bit: sys32getitimer,
		Name:    "getitimer",
		Syscall: true,
		Sets:    []string{"syscalls", "time", "time_timer"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "which"},
			{Type: "struct itimerval*", Name: "curr_value"},
		},
	},
	AlarmEventID: {
		ID32Bit: sys32alarm,
		Name:    "alarm",
		Syscall: true,
		Sets:    []string{"syscalls", "time", "time_timer"},
		Params: []trace.ArgMeta{
			{Type: "unsigned int", Name: "seconds"},
		},
	},
	SetitimerEventID: {
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
	GetpidEventID: {
		ID32Bit: sys32getpid,
		Name:    "getpid",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_ids"},
		Params:  []trace.ArgMeta{},
	},
	SendfileEventID: {
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
	SocketEventID: {
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
	ConnectEventID: {
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
	AcceptEventID: {
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
	SendtoEventID: {
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
	RecvfromEventID: {
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
	SendmsgEventID: {
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
	RecvmsgEventID: {
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
	ShutdownEventID: {
		ID32Bit: sys32shutdown,
		Name:    "shutdown",
		Syscall: true,
		Sets:    []string{"syscalls", "net", "net_sock"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "int", Name: "how"},
		},
	},
	BindEventID: {
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
	ListenEventID: {
		ID32Bit: sys32listen,
		Name:    "listen",
		Syscall: true,
		Sets:    []string{"default", "syscalls", "net", "net_sock"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "int", Name: "backlog"},
		},
	},
	GetsocknameEventID: {
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
	GetpeernameEventID: {
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
	SocketpairEventID: {
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
	SetsockoptEventID: {
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
	GetsockoptEventID: {
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
	CloneEventID: {
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
	ForkEventID: {
		ID32Bit: sys32fork,
		Name:    "fork",
		Syscall: true,
		Sets:    []string{"default", "syscalls", "proc", "proc_life"},
		Params:  []trace.ArgMeta{},
	},
	VforkEventID: {
		ID32Bit: sys32vfork,
		Name:    "vfork",
		Syscall: true,
		Sets:    []string{"default", "syscalls", "proc", "proc_life"},
		Params:  []trace.ArgMeta{},
	},
	ExecveEventID: {
		ID32Bit: sys32execve,
		Name:    "execve",
		Syscall: true,
		Dependencies: dependencies{
			tailCalls: []tailCall{
				{mapName: "sys_enter_tails", mapIdx: uint32(ExecveEventID), progName: "syscall__execve"},
			},
		},
		Sets: []string{"default", "syscalls", "proc", "proc_life"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "const char*const*", Name: "argv"},
			{Type: "const char*const*", Name: "envp"},
		},
	},
	ExitEventID: {
		ID32Bit: sys32exit,
		Name:    "exit",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_life"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "status"},
		},
	},
	Wait4EventID: {
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
	KillEventID: {
		ID32Bit: sys32kill,
		Name:    "kill",
		Syscall: true,
		Sets:    []string{"default", "syscalls", "signals"},
		Params: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "int", Name: "sig"},
		},
	},
	UnameEventID: {
		ID32Bit: sys32uname,
		Name:    "uname",
		Syscall: true,
		Sets:    []string{"syscalls", "system"},
		Params: []trace.ArgMeta{
			{Type: "struct utsname*", Name: "buf"},
		},
	},
	SemgetEventID: {
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
	SemopEventID: {
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
	SemctlEventID: {
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
	ShmdtEventID: {
		ID32Bit: sys32shmdt,
		Name:    "shmdt",
		Syscall: true,
		Sets:    []string{"syscalls", "ipc", "ipc_shm"},
		Params: []trace.ArgMeta{
			{Type: "const void*", Name: "shmaddr"},
		},
	},
	MsggetEventID: {
		ID32Bit: sys32msgget,
		Name:    "msgget",
		Syscall: true,
		Sets:    []string{"syscalls", "ipc", "ipc_msgq"},
		Params: []trace.ArgMeta{
			{Type: "key_t", Name: "key"},
			{Type: "int", Name: "msgflg"},
		},
	},
	MsgsndEventID: {
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
	MsgrcvEventID: {
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
	MsgctlEventID: {
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
	FcntlEventID: {
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
	FlockEventID: {
		ID32Bit: sys32flock,
		Name:    "flock",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_fd_ops"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "int", Name: "operation"},
		},
	},
	FsyncEventID: {
		ID32Bit: sys32fsync,
		Name:    "fsync",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_sync"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
		},
	},
	FdatasyncEventID: {
		ID32Bit: sys32fdatasync,
		Name:    "fdatasync",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_sync"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
		},
	},
	TruncateEventID: {
		ID32Bit: sys32truncate,
		Name:    "truncate",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_file_ops"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "off_t", Name: "length"},
		},
	},
	FtruncateEventID: {
		ID32Bit: sys32ftruncate,
		Name:    "ftruncate",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_file_ops"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "off_t", Name: "length"},
		},
	},
	GetdentsEventID: {
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
	GetcwdEventID: {
		ID32Bit: sys32getcwd,
		Name:    "getcwd",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_dir_ops"},
		Params: []trace.ArgMeta{
			{Type: "char*", Name: "buf"},
			{Type: "size_t", Name: "size"},
		},
	},
	ChdirEventID: {
		ID32Bit: sys32chdir,
		Name:    "chdir",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_dir_ops"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "path"},
		},
	},
	FchdirEventID: {
		ID32Bit: sys32fchdir,
		Name:    "fchdir",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_dir_ops"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
		},
	},
	RenameEventID: {
		ID32Bit: sys32rename,
		Name:    "rename",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_file_ops"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "oldpath"},
			{Type: "const char*", Name: "newpath"},
		},
	},
	MkdirEventID: {
		ID32Bit: sys32mkdir,
		Name:    "mkdir",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_dir_ops"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "mode_t", Name: "mode"},
		},
	},
	RmdirEventID: {
		ID32Bit: sys32rmdir,
		Name:    "rmdir",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_dir_ops"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
		},
	},
	CreatEventID: {
		ID32Bit: sys32creat,
		Name:    "creat",
		Syscall: true,
		Sets:    []string{"default", "syscalls", "fs", "fs_file_ops"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "mode_t", Name: "mode"},
		},
	},
	LinkEventID: {
		ID32Bit: sys32link,
		Name:    "link",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_link_ops"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "oldpath"},
			{Type: "const char*", Name: "newpath"},
		},
	},
	UnlinkEventID: {
		ID32Bit: sys32unlink,
		Name:    "unlink",
		Syscall: true,
		Sets:    []string{"default", "syscalls", "fs", "fs_link_ops"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
		},
	},
	SymlinkEventID: {
		ID32Bit: sys32symlink,
		Name:    "symlink",
		Syscall: true,
		Sets:    []string{"default", "syscalls", "fs", "fs_link_ops"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "target"},
			{Type: "const char*", Name: "linkpath"},
		},
	},
	ReadlinkEventID: {
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
	ChmodEventID: {
		ID32Bit: sys32chmod,
		Name:    "chmod",
		Syscall: true,
		Sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "mode_t", Name: "mode"},
		},
	},
	FchmodEventID: {
		ID32Bit: sys32fchmod,
		Name:    "fchmod",
		Syscall: true,
		Sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "mode_t", Name: "mode"},
		},
	},
	ChownEventID: {
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
	FchownEventID: {
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
	LchownEventID: {
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
	UmaskEventID: {
		ID32Bit: sys32umask,
		Name:    "umask",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_file_attr"},
		Params: []trace.ArgMeta{
			{Type: "mode_t", Name: "mask"},
		},
	},
	GettimeofdayEventID: {
		ID32Bit: sys32gettimeofday,
		Name:    "gettimeofday",
		Syscall: true,
		Sets:    []string{"syscalls", "time", "time_tod"},
		Params: []trace.ArgMeta{
			{Type: "struct timeval*", Name: "tv"},
			{Type: "struct timezone*", Name: "tz"},
		},
	},
	GetrlimitEventID: {
		ID32Bit: sys32ugetrlimit,
		Name:    "getrlimit",
		Syscall: true,
		Sets:    []string{"syscalls", "proc"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "resource"},
			{Type: "struct rlimit*", Name: "rlim"},
		},
	},
	GetrusageEventID: {
		ID32Bit: sys32getrusage,
		Name:    "getrusage",
		Syscall: true,
		Sets:    []string{"syscalls", "proc"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "who"},
			{Type: "struct rusage*", Name: "usage"},
		},
	},
	SysinfoEventID: {
		ID32Bit: sys32sysinfo,
		Name:    "sysinfo",
		Syscall: true,
		Sets:    []string{"syscalls", "system"},
		Params: []trace.ArgMeta{
			{Type: "struct sysinfo*", Name: "info"},
		},
	},
	TimesEventID: {
		ID32Bit: sys32times,
		Name:    "times",
		Syscall: true,
		Sets:    []string{"syscalls", "proc"},
		Params: []trace.ArgMeta{
			{Type: "struct tms*", Name: "buf"},
		},
	},
	PtraceEventID: {
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
	GetuidEventID: {
		ID32Bit: sys32getuid32,
		Name:    "getuid",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_ids"},
		Params:  []trace.ArgMeta{},
	},
	SyslogEventID: {
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
	GetgidEventID: {
		ID32Bit: sys32getgid32,
		Name:    "getgid",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_ids"},
		Params:  []trace.ArgMeta{},
	},
	SetuidEventID: {
		ID32Bit: sys32setuid32,
		Name:    "setuid",
		Syscall: true,
		Sets:    []string{"default", "syscalls", "proc", "proc_ids"},
		Params: []trace.ArgMeta{
			{Type: "uid_t", Name: "uid"},
		},
	},
	SetgidEventID: {
		ID32Bit: sys32setgid32,
		Name:    "setgid",
		Syscall: true,
		Sets:    []string{"default", "syscalls", "proc", "proc_ids"},
		Params: []trace.ArgMeta{
			{Type: "gid_t", Name: "gid"},
		},
	},
	GeteuidEventID: {
		ID32Bit: sys32geteuid32,
		Name:    "geteuid",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_ids"},
		Params:  []trace.ArgMeta{},
	},
	GetegidEventID: {
		ID32Bit: sys32getegid32,
		Name:    "getegid",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_ids"},
		Params:  []trace.ArgMeta{},
	},
	SetpgidEventID: {
		ID32Bit: sys32setpgid,
		Name:    "setpgid",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_ids"},
		Params: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "pid_t", Name: "pgid"},
		},
	},
	GetppidEventID: {
		ID32Bit: sys32getppid,
		Name:    "getppid",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_ids"},
		Params:  []trace.ArgMeta{},
	},
	GetpgrpEventID: {
		ID32Bit: sys32getpgrp,
		Name:    "getpgrp",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_ids"},
		Params:  []trace.ArgMeta{},
	},
	SetsidEventID: {
		ID32Bit: sys32setsid,
		Name:    "setsid",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_ids"},
		Params:  []trace.ArgMeta{},
	},
	SetreuidEventID: {
		ID32Bit: sys32setreuid32,
		Name:    "setreuid",
		Syscall: true,
		Sets:    []string{"default", "syscalls", "proc", "proc_ids"},
		Params: []trace.ArgMeta{
			{Type: "uid_t", Name: "ruid"},
			{Type: "uid_t", Name: "euid"},
		},
	},
	SetregidEventID: {
		ID32Bit: sys32setregid32,
		Name:    "setregid",
		Syscall: true,
		Sets:    []string{"default", "syscalls", "proc", "proc_ids"},
		Params: []trace.ArgMeta{
			{Type: "gid_t", Name: "rgid"},
			{Type: "gid_t", Name: "egid"},
		},
	},
	GetgroupsEventID: {
		ID32Bit: sys32getgroups32,
		Name:    "getgroups",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_ids"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "size"},
			{Type: "gid_t*", Name: "list"},
		},
	},
	SetgroupsEventID: {
		ID32Bit: sys32setgroups32,
		Name:    "setgroups",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_ids"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "size"},
			{Type: "gid_t*", Name: "list"},
		},
	},
	SetresuidEventID: {
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
	GetresuidEventID: {
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
	SetresgidEventID: {
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
	GetresgidEventID: {
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
	GetpgidEventID: {
		ID32Bit: sys32getpgid,
		Name:    "getpgid",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_ids"},
		Params: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
		},
	},
	SetfsuidEventID: {
		ID32Bit: sys32setfsuid32,
		Name:    "setfsuid",
		Syscall: true,
		Sets:    []string{"default", "syscalls", "proc", "proc_ids"},
		Params: []trace.ArgMeta{
			{Type: "uid_t", Name: "fsuid"},
		},
	},
	SetfsgidEventID: {
		ID32Bit: sys32setfsgid32,
		Name:    "setfsgid",
		Syscall: true,
		Sets:    []string{"default", "syscalls", "proc", "proc_ids"},
		Params: []trace.ArgMeta{
			{Type: "gid_t", Name: "fsgid"},
		},
	},
	GetsidEventID: {
		ID32Bit: sys32getsid,
		Name:    "getsid",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_ids"},
		Params: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
		},
	},
	CapgetEventID: {
		ID32Bit: sys32capget,
		Name:    "capget",
		Syscall: true,
		Sets:    []string{"syscalls", "proc"},
		Params: []trace.ArgMeta{
			{Type: "cap_user_header_t", Name: "hdrp"},
			{Type: "cap_user_data_t", Name: "datap"},
		},
	},
	CapsetEventID: {
		ID32Bit: sys32capset,
		Name:    "capset",
		Syscall: true,
		Sets:    []string{"syscalls", "proc"},
		Params: []trace.ArgMeta{
			{Type: "cap_user_header_t", Name: "hdrp"},
			{Type: "const cap_user_data_t", Name: "datap"},
		},
	},
	RtSigpendingEventID: {
		ID32Bit: sys32rt_sigpending,
		Name:    "rt_sigpending",
		Syscall: true,
		Sets:    []string{"syscalls", "signals"},
		Params: []trace.ArgMeta{
			{Type: "sigset_t*", Name: "set"},
			{Type: "size_t", Name: "sigsetsize"},
		},
	},
	RtSigtimedwaitEventID: {
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
	RtSigqueueinfoEventID: {
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
	RtSigsuspendEventID: {
		ID32Bit: sys32rt_sigsuspend,
		Name:    "rt_sigsuspend",
		Syscall: true,
		Sets:    []string{"syscalls", "signals"},
		Params: []trace.ArgMeta{
			{Type: "sigset_t*", Name: "mask"},
			{Type: "size_t", Name: "sigsetsize"},
		},
	},
	SigaltstackEventID: {
		ID32Bit: sys32sigaltstack,
		Name:    "sigaltstack",
		Syscall: true,
		Sets:    []string{"syscalls", "signals"},
		Params: []trace.ArgMeta{
			{Type: "const stack_t*", Name: "ss"},
			{Type: "stack_t*", Name: "old_ss"},
		},
	},
	UtimeEventID: {
		ID32Bit: sys32utime,
		Name:    "utime",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_file_attr"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "filename"},
			{Type: "const struct utimbuf*", Name: "times"},
		},
	},
	MknodEventID: {
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
	UselibEventID: {
		ID32Bit: sys32uselib,
		Name:    "uselib",
		Syscall: true,
		Sets:    []string{"syscalls", "proc"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "library"},
		},
	},
	PersonalityEventID: {
		ID32Bit: sys32personality,
		Name:    "personality",
		Syscall: true,
		Sets:    []string{"syscalls", "system"},
		Params: []trace.ArgMeta{
			{Type: "unsigned long", Name: "persona"},
		},
	},
	UstatEventID: {
		ID32Bit: sys32ustat,
		Name:    "ustat",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_info"},
		Params: []trace.ArgMeta{
			{Type: "dev_t", Name: "dev"},
			{Type: "struct ustat*", Name: "ubuf"},
		},
	},
	StatfsEventID: {
		ID32Bit: sys32statfs,
		Name:    "statfs",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_info"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "struct statfs*", Name: "buf"},
		},
	},
	FstatfsEventID: {
		ID32Bit: sys32fstatfs,
		Name:    "fstatfs",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_info"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "struct statfs*", Name: "buf"},
		},
	},
	SysfsEventID: {
		ID32Bit: sys32sysfs,
		Name:    "sysfs",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_info"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "option"},
		},
	},
	GetpriorityEventID: {
		ID32Bit: sys32getpriority,
		Name:    "getpriority",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_sched"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "which"},
			{Type: "int", Name: "who"},
		},
	},
	SetpriorityEventID: {
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
	SchedSetparamEventID: {
		ID32Bit: sys32sched_setparam,
		Name:    "sched_setparam",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_sched"},
		Params: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "struct sched_param*", Name: "param"},
		},
	},
	SchedGetparamEventID: {
		ID32Bit: sys32sched_getparam,
		Name:    "sched_getparam",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_sched"},
		Params: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "struct sched_param*", Name: "param"},
		},
	},
	SchedSetschedulerEventID: {
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
	SchedGetschedulerEventID: {
		ID32Bit: sys32sched_getscheduler,
		Name:    "sched_getscheduler",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_sched"},
		Params: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
		},
	},
	SchedGetPriorityMaxEventID: {
		ID32Bit: sys32sched_get_priority_max,
		Name:    "sched_get_priority_max",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_sched"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "policy"},
		},
	},
	SchedGetPriorityMinEventID: {
		ID32Bit: sys32sched_get_priority_min,
		Name:    "sched_get_priority_min",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_sched"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "policy"},
		},
	},
	SchedRrGetIntervalEventID: {
		ID32Bit: sys32sched_rr_get_interval_time64,
		Name:    "sched_rr_get_interval",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_sched"},
		Params: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "struct timespec*", Name: "tp"},
		},
	},
	MlockEventID: {
		ID32Bit: sys32mlock,
		Name:    "mlock",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_mem"},
		Params: []trace.ArgMeta{
			{Type: "const void*", Name: "addr"},
			{Type: "size_t", Name: "len"},
		},
	},
	MunlockEventID: {
		ID32Bit: sys32munlock,
		Name:    "munlock",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_mem"},
		Params: []trace.ArgMeta{
			{Type: "const void*", Name: "addr"},
			{Type: "size_t", Name: "len"},
		},
	},
	MlockallEventID: {
		ID32Bit: sys32mlockall,
		Name:    "mlockall",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_mem"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "flags"},
		},
	},
	MunlockallEventID: {
		ID32Bit: sys32munlockall,
		Name:    "munlockall",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_mem"},
		Params:  []trace.ArgMeta{},
	},
	VhangupEventID: {
		ID32Bit: sys32vhangup,
		Name:    "vhangup",
		Syscall: true,
		Sets:    []string{"syscalls", "system"},
		Params:  []trace.ArgMeta{},
	},
	ModifyLdtEventID: {
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
	PivotRootEventID: {
		ID32Bit: sys32pivot_root,
		Name:    "pivot_root",
		Syscall: true,
		Sets:    []string{"syscalls", "fs"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "new_root"},
			{Type: "const char*", Name: "put_old"},
		},
	},
	SysctlEventID: {
		ID32Bit: sys32_sysctl,
		Name:    "sysctl",
		Syscall: true,
		Sets:    []string{"syscalls", "system"},
		Params: []trace.ArgMeta{
			{Type: "struct __sysctl_args*", Name: "args"},
		},
	},
	PrctlEventID: {
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
	ArchPrctlEventID: {
		ID32Bit: sys32arch_prctl,
		Name:    "arch_prctl",
		Syscall: true,
		Sets:    []string{"syscalls", "proc"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "option"},
			{Type: "unsigned long", Name: "addr"},
		},
	},
	AdjtimexEventID: {
		ID32Bit: sys32adjtimex,
		Name:    "adjtimex",
		Syscall: true,
		Sets:    []string{"syscalls", "time", "time_clock"},
		Params: []trace.ArgMeta{
			{Type: "struct timex*", Name: "buf"},
		},
	},
	SetrlimitEventID: {
		ID32Bit: sys32setrlimit,
		Name:    "setrlimit",
		Syscall: true,
		Sets:    []string{"syscalls", "proc"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "resource"},
			{Type: "const struct rlimit*", Name: "rlim"},
		},
	},
	ChrootEventID: {
		ID32Bit: sys32chroot,
		Name:    "chroot",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_dir_ops"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "path"},
		},
	},
	SyncEventID: {
		ID32Bit: sys32sync,
		Name:    "sync",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_sync"},
		Params:  []trace.ArgMeta{},
	},
	AcctEventID: {
		ID32Bit: sys32acct,
		Name:    "acct",
		Syscall: true,
		Sets:    []string{"syscalls", "system"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "filename"},
		},
	},
	SettimeofdayEventID: {
		ID32Bit: sys32settimeofday,
		Name:    "settimeofday",
		Syscall: true,
		Sets:    []string{"syscalls", "time", "time_tod"},
		Params: []trace.ArgMeta{
			{Type: "const struct timeval*", Name: "tv"},
			{Type: "const struct timezone*", Name: "tz"},
		},
	},
	MountEventID: {
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
	Umount2EventID: {
		ID32Bit: sys32umount2,
		Name:    "umount2",
		Syscall: true,
		Sets:    []string{"default", "syscalls", "fs"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "target"},
			{Type: "int", Name: "flags"},
		},
	},
	SwaponEventID: {
		ID32Bit: sys32swapon,
		Name:    "swapon",
		Syscall: true,
		Sets:    []string{"syscalls", "fs"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "int", Name: "swapflags"},
		},
	},
	SwapoffEventID: {
		ID32Bit: sys32swapoff,
		Name:    "swapoff",
		Syscall: true,
		Sets:    []string{"syscalls", "fs"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "path"},
		},
	},
	RebootEventID: {
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
	SethostnameEventID: {
		ID32Bit: sys32sethostname,
		Name:    "sethostname",
		Syscall: true,
		Sets:    []string{"syscalls", "net"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "name"},
			{Type: "size_t", Name: "len"},
		},
	},
	SetdomainnameEventID: {
		ID32Bit: sys32setdomainname,
		Name:    "setdomainname",
		Syscall: true,
		Sets:    []string{"syscalls", "net"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "name"},
			{Type: "size_t", Name: "len"},
		},
	},
	IoplEventID: {
		ID32Bit: sys32iopl,
		Name:    "iopl",
		Syscall: true,
		Sets:    []string{"syscalls", "system"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "level"},
		},
	},
	IopermEventID: {
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
	CreateModuleEventID: {
		ID32Bit: sys32create_module,
		Name:    "create_module",
		Syscall: true,
		Sets:    []string{"syscalls", "system", "system_module"},
		Params:  []trace.ArgMeta{},
	},
	InitModuleEventID: {
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
	DeleteModuleEventID: {
		ID32Bit: sys32delete_module,
		Name:    "delete_module",
		Syscall: true,
		Sets:    []string{"default", "syscalls", "system", "system_module"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "name"},
			{Type: "int", Name: "flags"},
		},
	},
	GetKernelSymsEventID: {
		ID32Bit: sys32get_kernel_syms,
		Name:    "get_kernel_syms",
		Syscall: true,
		Sets:    []string{"syscalls", "system", "system_module"},
		Params:  []trace.ArgMeta{},
	},
	QueryModuleEventID: {
		ID32Bit: sys32query_module,
		Name:    "query_module",
		Syscall: true,
		Sets:    []string{"syscalls", "system", "system_module"},
		Params:  []trace.ArgMeta{},
	},
	QuotactlEventID: {
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
	NfsservctlEventID: {
		ID32Bit: sys32nfsservctl,
		Name:    "nfsservctl",
		Syscall: true,
		Sets:    []string{"syscalls", "fs"},
		Params:  []trace.ArgMeta{},
	},
	GetpmsgEventID: {
		ID32Bit: sys32getpmsg,
		Name:    "getpmsg",
		Syscall: true,
		Sets:    []string{"syscalls"},
		Params:  []trace.ArgMeta{},
	},
	PutpmsgEventID: {
		ID32Bit: sys32putpmsg,
		Name:    "putpmsg",
		Syscall: true,
		Sets:    []string{"syscalls"},
		Params:  []trace.ArgMeta{},
	},
	AfsEventID: {
		ID32Bit: sys32undefined,
		Name:    "afs",
		Syscall: true,
		Sets:    []string{"syscalls"},
		Params:  []trace.ArgMeta{},
	},
	TuxcallEventID: {
		ID32Bit: sys32undefined,
		Name:    "tuxcall",
		Syscall: true,
		Sets:    []string{"syscalls"},
		Params:  []trace.ArgMeta{},
	},
	SecurityEventID: {
		ID32Bit: sys32undefined,
		Name:    "security",
		Syscall: true,
		Sets:    []string{"syscalls"},
		Params:  []trace.ArgMeta{},
	},
	GettidEventID: {
		ID32Bit: sys32gettid,
		Name:    "gettid",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_ids"},
		Params:  []trace.ArgMeta{},
	},
	ReadaheadEventID: {
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
	SetxattrEventID: {
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
	LsetxattrEventID: {
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
	FsetxattrEventID: {
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
	GetxattrEventID: {
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
	LgetxattrEventID: {
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
	FgetxattrEventID: {
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
	ListxattrEventID: {
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
	LlistxattrEventID: {
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
	FlistxattrEventID: {
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
	RemovexattrEventID: {
		ID32Bit: sys32removexattr,
		Name:    "removexattr",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_file_attr"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "const char*", Name: "name"},
		},
	},
	LremovexattrEventID: {
		ID32Bit: sys32lremovexattr,
		Name:    "lremovexattr",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_file_attr"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "const char*", Name: "name"},
		},
	},
	FremovexattrEventID: {
		ID32Bit: sys32fremovexattr,
		Name:    "fremovexattr",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_file_attr"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "const char*", Name: "name"},
		},
	},
	TkillEventID: {
		ID32Bit: sys32tkill,
		Name:    "tkill",
		Syscall: true,
		Sets:    []string{"syscalls", "signals"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "tid"},
			{Type: "int", Name: "sig"},
		},
	},
	TimeEventID: {
		ID32Bit: sys32time,
		Name:    "time",
		Syscall: true,
		Sets:    []string{"syscalls", "time", "time_tod"},
		Params: []trace.ArgMeta{
			{Type: "time_t*", Name: "tloc"},
		},
	},
	FutexEventID: {
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
	SchedSetaffinityEventID: {
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
	SchedGetaffinityEventID: {
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
	SetThreadAreaEventID: {
		ID32Bit: sys32set_thread_area,
		Name:    "set_thread_area",
		Syscall: true,
		Sets:    []string{"syscalls", "proc"},
		Params: []trace.ArgMeta{
			{Type: "struct user_desc*", Name: "u_info"},
		},
	},
	IoSetupEventID: {
		ID32Bit: sys32io_setup,
		Name:    "io_setup",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_async_io"},
		Params: []trace.ArgMeta{
			{Type: "unsigned int", Name: "nr_events"},
			{Type: "io_context_t*", Name: "ctx_idp"},
		},
	},
	IoDestroyEventID: {
		ID32Bit: sys32io_destroy,
		Name:    "io_destroy",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_async_io"},
		Params: []trace.ArgMeta{
			{Type: "io_context_t", Name: "ctx_id"},
		},
	},
	IoGeteventsEventID: {
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
	IoSubmitEventID: {
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
	IoCancelEventID: {
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
	GetThreadAreaEventID: {
		ID32Bit: sys32get_thread_area,
		Name:    "get_thread_area",
		Syscall: true,
		Sets:    []string{"syscalls", "proc"},
		Params: []trace.ArgMeta{
			{Type: "struct user_desc*", Name: "u_info"},
		},
	},
	LookupDcookieEventID: {
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
	EpollCreateEventID: {
		ID32Bit: sys32epoll_create,
		Name:    "epoll_create",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_mux_io"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "size"},
		},
	},
	EpollCtlOldEventID: {
		ID32Bit: sys32undefined,
		Name:    "epoll_ctl_old",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_mux_io"},
		Params:  []trace.ArgMeta{},
	},
	EpollWaitOldEventID: {
		ID32Bit: sys32undefined,
		Name:    "epoll_wait_old",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_mux_io"},
		Params:  []trace.ArgMeta{},
	},
	RemapFilePagesEventID: {
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
	Getdents64EventID: {
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
	SetTidAddressEventID: {
		ID32Bit: sys32set_tid_address,
		Name:    "set_tid_address",
		Syscall: true,
		Sets:    []string{"syscalls", "proc"},
		Params: []trace.ArgMeta{
			{Type: "int*", Name: "tidptr"},
		},
	},
	RestartSyscallEventID: {
		ID32Bit: sys32restart_syscall,
		Name:    "restart_syscall",
		Syscall: true,
		Sets:    []string{"syscalls", "signals"},
		Params:  []trace.ArgMeta{},
	},
	SemtimedopEventID: {
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
	Fadvise64EventID: {
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
	TimerCreateEventID: {
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
	TimerSettimeEventID: {
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
	TimerGettimeEventID: {
		ID32Bit: sys32timer_gettime64,
		Name:    "timer_gettime",
		Syscall: true,
		Sets:    []string{"syscalls", "time", "time_timer"},
		Params: []trace.ArgMeta{
			{Type: "timer_t", Name: "timer_id"},
			{Type: "struct itimerspec*", Name: "curr_value"},
		},
	},
	TimerGetoverrunEventID: {
		ID32Bit: sys32timer_getoverrun,
		Name:    "timer_getoverrun",
		Syscall: true,
		Sets:    []string{"syscalls", "time", "time_timer"},
		Params: []trace.ArgMeta{
			{Type: "timer_t", Name: "timer_id"},
		},
	},
	TimerDeleteEventID: {
		ID32Bit: sys32timer_delete,
		Name:    "timer_delete",
		Syscall: true,
		Sets:    []string{"syscalls", "time", "time_timer"},
		Params: []trace.ArgMeta{
			{Type: "timer_t", Name: "timer_id"},
		},
	},
	ClockSettimeEventID: {
		ID32Bit: sys32clock_settime64,
		Name:    "clock_settime",
		Syscall: true,
		Sets:    []string{"syscalls", "time", "time_clock"},
		Params: []trace.ArgMeta{
			{Type: "const clockid_t", Name: "clockid"},
			{Type: "const struct timespec*", Name: "tp"},
		},
	},
	ClockGettimeEventID: {
		ID32Bit: sys32clock_gettime64,
		Name:    "clock_gettime",
		Syscall: true,
		Sets:    []string{"syscalls", "time", "time_clock"},
		Params: []trace.ArgMeta{
			{Type: "const clockid_t", Name: "clockid"},
			{Type: "struct timespec*", Name: "tp"},
		},
	},
	ClockGetresEventID: {
		ID32Bit: sys32clock_getres_time64,
		Name:    "clock_getres",
		Syscall: true,
		Sets:    []string{"syscalls", "time", "time_clock"},
		Params: []trace.ArgMeta{
			{Type: "const clockid_t", Name: "clockid"},
			{Type: "struct timespec*", Name: "res"},
		},
	},
	ClockNanosleepEventID: {
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
	ExitGroupEventID: {
		ID32Bit: sys32exit_group,
		Name:    "exit_group",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_life"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "status"},
		},
	},
	EpollWaitEventID: {
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
	EpollCtlEventID: {
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
	TgkillEventID: {
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
	UtimesEventID: {
		ID32Bit: sys32utimes,
		Name:    "utimes",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_file_attr"},
		Params: []trace.ArgMeta{
			{Type: "char*", Name: "filename"},
			{Type: "struct timeval*", Name: "times"},
		},
	},
	VserverEventID: {
		ID32Bit: sys32vserver,
		Name:    "vserver",
		Syscall: true,
		Sets:    []string{"syscalls"},
		Params:  []trace.ArgMeta{},
	},
	MbindEventID: {
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
	SetMempolicyEventID: {
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
	GetMempolicyEventID: {
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
	MqOpenEventID: {
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
	MqUnlinkEventID: {
		ID32Bit: sys32mq_unlink,
		Name:    "mq_unlink",
		Syscall: true,
		Sets:    []string{"syscalls", "ipc", "ipc_msgq"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "name"},
		},
	},
	MqTimedsendEventID: {
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
	MqTimedreceiveEventID: {
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
	MqNotifyEventID: {
		ID32Bit: sys32mq_notify,
		Name:    "mq_notify",
		Syscall: true,
		Sets:    []string{"syscalls", "ipc", "ipc_msgq"},
		Params: []trace.ArgMeta{
			{Type: "mqd_t", Name: "mqdes"},
			{Type: "const struct sigevent*", Name: "sevp"},
		},
	},
	MqGetsetattrEventID: {
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
	KexecLoadEventID: {
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
	WaitidEventID: {
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
	AddKeyEventID: {
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
	RequestKeyEventID: {
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
	KeyctlEventID: {
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
	IoprioSetEventID: {
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
	IoprioGetEventID: {
		ID32Bit: sys32ioprio_get,
		Name:    "ioprio_get",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_sched"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "which"},
			{Type: "int", Name: "who"},
		},
	},
	InotifyInitEventID: {
		ID32Bit: sys32inotify_init,
		Name:    "inotify_init",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_monitor"},
		Params:  []trace.ArgMeta{},
	},
	InotifyAddWatchEventID: {
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
	InotifyRmWatchEventID: {
		ID32Bit: sys32inotify_rm_watch,
		Name:    "inotify_rm_watch",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_monitor"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "int", Name: "wd"},
		},
	},
	MigratePagesEventID: {
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
	OpenatEventID: {
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
	MkdiratEventID: {
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
	MknodatEventID: {
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
	FchownatEventID: {
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
	FutimesatEventID: {
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
	NewfstatatEventID: {
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
	UnlinkatEventID: {
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
	RenameatEventID: {
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
	LinkatEventID: {
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
	SymlinkatEventID: {
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
	ReadlinkatEventID: {
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
	FchmodatEventID: {
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
	FaccessatEventID: {
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
	Pselect6EventID: {
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
	PpollEventID: {
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
	UnshareEventID: {
		ID32Bit: sys32unshare,
		Name:    "unshare",
		Syscall: true,
		Sets:    []string{"syscalls", "proc"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "flags"},
		},
	},
	SetRobustListEventID: {
		ID32Bit: sys32set_robust_list,
		Name:    "set_robust_list",
		Syscall: true,
		Sets:    []string{"syscalls", "ipc", "ipc_futex"},
		Params: []trace.ArgMeta{
			{Type: "struct robust_list_head*", Name: "head"},
			{Type: "size_t", Name: "len"},
		},
	},
	GetRobustListEventID: {
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
	SpliceEventID: {
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
	TeeEventID: {
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
	SyncFileRangeEventID: {
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
	VmspliceEventID: {
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
	MovePagesEventID: {
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
	UtimensatEventID: {
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
	EpollPwaitEventID: {
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
	SignalfdEventID: {
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
	TimerfdCreateEventID: {
		ID32Bit: sys32timerfd_create,
		Name:    "timerfd_create",
		Syscall: true,
		Sets:    []string{"syscalls", "time", "time_timer"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "clockid"},
			{Type: "int", Name: "flags"},
		},
	},
	EventfdEventID: {
		ID32Bit: sys32eventfd,
		Name:    "eventfd",
		Syscall: true,
		Sets:    []string{"syscalls", "signals"},
		Params: []trace.ArgMeta{
			{Type: "unsigned int", Name: "initval"},
			{Type: "int", Name: "flags"},
		},
	},
	FallocateEventID: {
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
	TimerfdSettimeEventID: {
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
	TimerfdGettimeEventID: {
		ID32Bit: sys32timerfd_gettime64,
		Name:    "timerfd_gettime",
		Syscall: true,
		Sets:    []string{"syscalls", "time", "time_timer"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "struct itimerspec*", Name: "curr_value"},
		},
	},
	Accept4EventID: {
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
	Signalfd4EventID: {
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
	Eventfd2EventID: {
		ID32Bit: sys32eventfd2,
		Name:    "eventfd2",
		Syscall: true,
		Sets:    []string{"syscalls", "signals"},
		Params: []trace.ArgMeta{
			{Type: "unsigned int", Name: "initval"},
			{Type: "int", Name: "flags"},
		},
	},
	EpollCreate1EventID: {
		ID32Bit: sys32epoll_create1,
		Name:    "epoll_create1",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_mux_io"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "flags"},
		},
	},
	Dup3EventID: {
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
	Pipe2EventID: {
		ID32Bit: sys32pipe2,
		Name:    "pipe2",
		Syscall: true,
		Sets:    []string{"syscalls", "ipc", "ipc_pipe"},
		Params: []trace.ArgMeta{
			{Type: "int[2]", Name: "pipefd"},
			{Type: "int", Name: "flags"},
		},
	},
	InotifyInit1EventID: {
		ID32Bit: sys32inotify_init1,
		Name:    "inotify_init1",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_monitor"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "flags"},
		},
	},
	PreadvEventID: {
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
	PwritevEventID: {
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
	RtTgsigqueueinfoEventID: {
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
	PerfEventOpenEventID: {
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
	RecvmmsgEventID: {
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
	FanotifyInitEventID: {
		ID32Bit: sys32fanotify_init,
		Name:    "fanotify_init",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_monitor"},
		Params: []trace.ArgMeta{
			{Type: "unsigned int", Name: "flags"},
			{Type: "unsigned int", Name: "event_f_flags"},
		},
	},
	FanotifyMarkEventID: {
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
	Prlimit64EventID: {
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
	NameToHandleAtEventID: {
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
	OpenByHandleAtEventID: {
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
	ClockAdjtimeEventID: {
		ID32Bit: sys32clock_adjtime,
		Name:    "clock_adjtime",
		Syscall: true,
		Sets:    []string{"syscalls", "time", "time_clock"},
		Params: []trace.ArgMeta{
			{Type: "const clockid_t", Name: "clk_id"},
			{Type: "struct timex*", Name: "buf"},
		},
	},
	SyncfsEventID: {
		ID32Bit: sys32syncfs,
		Name:    "syncfs",
		Syscall: true,
		Sets:    []string{"syscalls", "fs", "fs_sync"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
		},
	},
	SendmmsgEventID: {
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
	SetnsEventID: {
		ID32Bit: sys32setns,
		Name:    "setns",
		Syscall: true,
		Sets:    []string{"syscalls", "proc"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "int", Name: "nstype"},
		},
	},
	GetcpuEventID: {
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
	ProcessVmReadvEventID: {
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
	ProcessVmWritevEventID: {
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
	KcmpEventID: {
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
	FinitModuleEventID: {
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
	SchedSetattrEventID: {
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
	SchedGetattrEventID: {
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
	Renameat2EventID: {
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
	SeccompEventID: {
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
	GetrandomEventID: {
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
	MemfdCreateEventID: {
		ID32Bit: sys32memfd_create,
		Name:    "memfd_create",
		Syscall: true,
		Sets:    []string{"default", "syscalls", "fs", "fs_file_ops"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "name"},
			{Type: "unsigned int", Name: "flags"},
		},
	},
	KexecFileLoadEventID: {
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
	BpfEventID: {
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
	ExecveatEventID: {
		ID32Bit: sys32execveat,
		Name:    "execveat",
		Syscall: true,
		Dependencies: dependencies{
			tailCalls: []tailCall{
				{mapName: "sys_enter_tails", mapIdx: uint32(ExecveatEventID), progName: "syscall__execveat"},
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
	UserfaultfdEventID: {
		ID32Bit: sys32userfaultfd,
		Name:    "userfaultfd",
		Syscall: true,
		Sets:    []string{"syscalls", "system"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "flags"},
		},
	},
	MembarrierEventID: {
		ID32Bit: sys32membarrier,
		Name:    "membarrier",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_mem"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "cmd"},
			{Type: "int", Name: "flags"},
		},
	},
	Mlock2EventID: {
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
	CopyFileRangeEventID: {
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
	Preadv2EventID: {
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
	Pwritev2EventID: {
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
	PkeyMprotectEventID: {
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
	PkeyAllocEventID: {
		ID32Bit: sys32pkey_alloc,
		Name:    "pkey_alloc",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_mem"},
		Params: []trace.ArgMeta{
			{Type: "unsigned int", Name: "flags"},
			{Type: "unsigned long", Name: "access_rights"},
		},
	},
	PkeyFreeEventID: {
		ID32Bit: sys32pkey_free,
		Name:    "pkey_free",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "proc_mem"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "pkey"},
		},
	},
	StatxEventID: {
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
	IoPgeteventsEventID: {
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
	RseqEventID: {
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
	PidfdSendSignalEventID: {
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
	IoUringSetupEventID: {
		ID32Bit: sys32io_uring_setup,
		Name:    "io_uring_setup",
		Syscall: true,
		Sets:    []string{"syscalls"},
		Params: []trace.ArgMeta{
			{Type: "unsigned int", Name: "entries"},
			{Type: "struct io_uring_params*", Name: "p"},
		},
	},
	IoUringEnterEventID: {
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
	IoUringRegisterEventID: {
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
	OpenTreeEventID: {
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
	MoveMountEventID: {
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
	FsopenEventID: {
		ID32Bit: sys32fsopen,
		Name:    "fsopen",
		Syscall: true,
		Sets:    []string{"syscalls", "fs"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "fsname"},
			{Type: "unsigned int", Name: "flags"},
		},
	},
	FsconfigEventID: {
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
	FsmountEventID: {
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
	FspickEventID: {
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
	PidfdOpenEventID: {
		ID32Bit: sys32pidfd_open,
		Name:    "pidfd_open",
		Syscall: true,
		Sets:    []string{"syscalls"},
		Params: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "unsigned int", Name: "flags"},
		},
	},
	Clone3EventID: {
		ID32Bit: sys32clone3,
		Name:    "clone3",
		Syscall: true,
		Sets:    []string{"default", "syscalls", "proc", "proc_life"},
		Params: []trace.ArgMeta{
			{Type: "struct clone_args*", Name: "cl_args"},
			{Type: "size_t", Name: "size"},
		},
	},
	CloseRangeEventID: {
		ID32Bit: sys32close_range,
		Name:    "close_range",
		Syscall: true,
		Sets:    []string{"default", "syscalls", "fs", "fs_file_ops"},
		Params: []trace.ArgMeta{
			{Type: "unsigned int", Name: "first"},
			{Type: "unsigned int", Name: "last"},
		},
	},
	Openat2EventID: {
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
	PidfdGetfdEventID: {
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
	Faccessat2EventID: {
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
	ProcessMadviseEventID: {
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
	EpollPwait2EventID: {
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
	MountSetattEventID: {
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
	QuotactlFdEventID: {
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
	LandlockCreateRulesetEventID: {
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
	LandlockAddRuleEventID: {
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
	LandloclRestrictSetEventID: {
		ID32Bit: sys32landlock_restrict_self,
		Name:    "landlock_restrict_self",
		Syscall: true,
		Sets:    []string{"syscalls", "proc", "fs"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "ruleset_fd"},
			{Type: "u32", Name: "flags"},
		},
	},
	MemfdSecretEventID: {
		ID32Bit: sys32memfd_secret,
		Name:    "memfd_secret",
		Syscall: true,
		Sets:    []string{"syscalls"},
		Params: []trace.ArgMeta{
			{Type: "unsigned int", Name: "flags"},
		},
	},
	ProcessMreleaseEventID: {
		ID32Bit: sys32process_mrelease,
		Name:    "process_mrelease",
		Syscall: true,
		Sets:    []string{"syscalls"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "pidfd"},
			{Type: "unsigned int", Name: "flags"},
		},
	},
	WaitpidEventID: {
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
	OldfstatEventID: {
		ID32Bit: sys32oldfstat,
		Name:    "oldfstat",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params:  []trace.ArgMeta{},
	},
	BreakEventID: {
		ID32Bit: sys32break,
		Name:    "break",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params:  []trace.ArgMeta{},
	},
	OldstatEventID: {
		ID32Bit: sys32oldstat,
		Name:    "oldstat",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "char*", Name: "filename"},
			{Type: "struct __old_kernel_stat*", Name: "statbuf"},
		},
	},
	UmountEventID: {
		ID32Bit: sys32umount,
		Name:    "umount",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "target"},
		},
	},
	StimeEventID: {
		ID32Bit: sys32stime,
		Name:    "stime",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "const time_t*", Name: "t"},
		},
	},
	SttyEventID: {
		ID32Bit: sys32stty,
		Name:    "stty",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params:  []trace.ArgMeta{},
	},
	GttyEventID: {
		ID32Bit: sys32gtty,
		Name:    "gtty",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params:  []trace.ArgMeta{},
	},
	NiceEventID: {
		ID32Bit: sys32nice,
		Name:    "nice",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "inc"},
		},
	},
	FtimeEventID: {
		ID32Bit: sys32ftime,
		Name:    "ftime",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params:  []trace.ArgMeta{},
	},
	ProfEventID: {
		ID32Bit: sys32prof,
		Name:    "prof",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params:  []trace.ArgMeta{},
	},
	SignalEventID: {
		ID32Bit: sys32signal,
		Name:    "signal",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "signum"},
			{Type: "sighandler_t", Name: "handler"},
		},
	},
	LockEventID: {
		ID32Bit: sys32lock,
		Name:    "lock",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params:  []trace.ArgMeta{},
	},
	MpxEventID: {
		ID32Bit: sys32mpx,
		Name:    "mpx",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params:  []trace.ArgMeta{},
	},
	UlimitEventID: {
		ID32Bit: sys32ulimit,
		Name:    "ulimit",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params:  []trace.ArgMeta{},
	},
	OldoldunameEventID: {
		ID32Bit: sys32oldolduname,
		Name:    "oldolduname",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "struct oldold_utsname*", Name: "name"},
		},
	},
	SigactionEventID: {
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
	SgetmaskEventID: {
		ID32Bit: sys32sgetmask,
		Name:    "sgetmask",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params:  []trace.ArgMeta{},
	},
	SsetmaskEventID: {
		ID32Bit: sys32ssetmask,
		Name:    "ssetmask",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "long", Name: "newmask"},
		},
	},
	SigsuspendEventID: {
		ID32Bit: sys32sigsuspend,
		Name:    "sigsuspend",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "const sigset_t*", Name: "mask"},
		},
	},
	SigpendingEventID: {
		ID32Bit: sys32sigpending,
		Name:    "sigpending",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "sigset_t*", Name: "set"},
		},
	},
	OldlstatEventID: {
		ID32Bit: sys32oldlstat,
		Name:    "oldlstat",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "struct stat*", Name: "statbuf"},
		},
	},
	ReaddirEventID: {
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
	ProfilEventID: {
		ID32Bit: sys32profil,
		Name:    "profil",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params:  []trace.ArgMeta{},
	},
	SocketcallEventID: {
		ID32Bit: sys32socketcall,
		Name:    "socketcall",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "call"},
			{Type: "unsigned long*", Name: "args"},
		},
	},
	OldunameEventID: {
		ID32Bit: sys32olduname,
		Name:    "olduname",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "struct utsname*", Name: "buf"},
		},
	},
	IdleEventID: {
		ID32Bit: sys32idle,
		Name:    "idle",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params:  []trace.ArgMeta{},
	},
	Vm86oldEventID: {
		ID32Bit: sys32vm86old,
		Name:    "vm86old",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "struct vm86_struct*", Name: "info"},
		},
	},
	IpcEventID: {
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
	SigreturnEventID: {
		ID32Bit: sys32sigreturn,
		Name:    "sigreturn",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params:  []trace.ArgMeta{},
	},
	SigprocmaskEventID: {
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
	BdflushEventID: {
		ID32Bit: sys32bdflush,
		Name:    "bdflush",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params:  []trace.ArgMeta{},
	},
	Afs_syscallEventID: {
		ID32Bit: sys32afs_syscall,
		Name:    "afs_syscall",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params:  []trace.ArgMeta{},
	},
	LlseekEventID: {
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
	OldSelectEventID: {
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
	Vm86EventID: {
		ID32Bit: sys32vm86,
		Name:    "vm86",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "unsigned long", Name: "fn"},
			{Type: "struct vm86plus_struct*", Name: "v86"},
		},
	},
	OldGetrlimitEventID: {
		ID32Bit: sys32getrlimit,
		Name:    "old_getrlimit",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "resource"},
			{Type: "struct rlimit*", Name: "rlim"},
		},
	},
	Mmap2EventID: {
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
	Truncate64EventID: {
		ID32Bit: sys32truncate64,
		Name:    "truncate64",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "path"},
			{Type: "off_t", Name: "length"},
		},
	},
	Ftruncate64EventID: {
		ID32Bit: sys32ftruncate64,
		Name:    "ftruncate64",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "off_t", Name: "length"},
		},
	},
	Stat64EventID: {
		ID32Bit: sys32stat64,
		Name:    "stat64",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "struct stat64*", Name: "statbuf"},
		},
	},
	Lstat64EventID: {
		ID32Bit: sys32lstat64,
		Name:    "lstat64",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "struct stat64*", Name: "statbuf"},
		},
	},
	Fstat64EventID: {
		ID32Bit: sys32fstat64,
		Name:    "fstat64",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "fd"},
			{Type: "struct stat64*", Name: "statbuf"},
		},
	},
	Lchown16EventID: {
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
	Getuid16EventID: {
		ID32Bit: sys32getuid,
		Name:    "getuid16",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params:  []trace.ArgMeta{},
	},
	Getgid16EventID: {
		ID32Bit: sys32getgid,
		Name:    "getgid16",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params:  []trace.ArgMeta{},
	},
	Geteuid16EventID: {
		ID32Bit: sys32geteuid,
		Name:    "geteuid16",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params:  []trace.ArgMeta{},
	},
	Getegid16EventID: {
		ID32Bit: sys32getegid,
		Name:    "getegid16",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params:  []trace.ArgMeta{},
	},
	Setreuid16EventID: {
		ID32Bit: sys32setreuid,
		Name:    "setreuid16",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "old_uid_t", Name: "ruid"},
			{Type: "old_uid_t", Name: "euid"},
		},
	},
	Setregid16EventID: {
		ID32Bit: sys32setregid,
		Name:    "setregid16",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "old_gid_t", Name: "rgid"},
			{Type: "old_gid_t", Name: "egid"},
		},
	},
	Getgroups16EventID: {
		ID32Bit: sys32getgroups,
		Name:    "getgroups16",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "size"},
			{Type: "old_gid_t*", Name: "list"},
		},
	},
	Setgroups16EventID: {
		ID32Bit: sys32setgroups,
		Name:    "setgroups16",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "size_t", Name: "size"},
			{Type: "const gid_t*", Name: "list"},
		},
	},
	Fchown16EventID: {
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
	Setresuid16EventID: {
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
	Getresuid16EventID: {
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
	Setresgid16EventID: {
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
	Getresgid16EventID: {
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
	Chown16EventID: {
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
	Setuid16EventID: {
		ID32Bit: sys32setuid,
		Name:    "setuid16",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "old_old_uid_t", Name: "uid"},
		},
	},
	Setgid16EventID: {
		ID32Bit: sys32setgid,
		Name:    "setgid16",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "old_gid_t", Name: "gid"},
		},
	},
	Setfsuid16EventID: {
		ID32Bit: sys32setfsuid,
		Name:    "setfsuid16",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "old_uid_t", Name: "fsuid"},
		},
	},
	Setfsgid16EventID: {
		ID32Bit: sys32setfsgid,
		Name:    "setfsgid16",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "old_gid_t", Name: "fsgid"},
		},
	},
	Fcntl64EventID: {
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
	Sendfile32EventID: {
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
	Statfs64EventID: {
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
	Fstatfs64EventID: {
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
	Fadvise64_64EventID: {
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
	ClockGettime32EventID: {
		ID32Bit: sys32clock_gettime,
		Name:    "clock_gettime32",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "clockid_t", Name: "which_clock"},
			{Type: "struct old_timespec32*", Name: "tp"},
		},
	},
	ClockSettime32EventID: {
		ID32Bit: sys32clock_settime,
		Name:    "clock_settime32",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "clockid_t", Name: "which_clock"},
			{Type: "struct old_timespec32*", Name: "tp"},
		},
	},
	ClockAdjtime64EventID: {
		ID32Bit: sys32clock_adjtime64,
		Name:    "clock_adjtime64",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params:  []trace.ArgMeta{},
	},
	ClockGetresTime32EventID: {
		ID32Bit: sys32clock_getres,
		Name:    "clock_getres_time32",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "clockid_t", Name: "which_clock"},
			{Type: "struct old_timespec32*", Name: "tp"},
		},
	},
	ClockNanosleepTime32EventID: {
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
	TimerGettime32EventID: {
		ID32Bit: sys32timer_gettime,
		Name:    "timer_gettime32",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "timer_t", Name: "timer_id"},
			{Type: "struct old_itimerspec32*", Name: "setting"},
		},
	},
	TimerSettime32EventID: {
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
	TimerfdGettime32EventID: {
		ID32Bit: sys32timerfd_gettime,
		Name:    "timerfd_gettime32",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "ufd"},
			{Type: "struct old_itimerspec32*", Name: "otmr"},
		},
	},
	TimerfdSettime32EventID: {
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
	UtimensatTime32EventID: {
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
	Pselect6Time32EventID: {
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
	PpollTime32EventID: {
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
	IoPgeteventsTime32EventID: {
		ID32Bit: sys32io_pgetevents,
		Name:    "io_pgetevents_time32",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params:  []trace.ArgMeta{},
	},
	RecvmmsgTime32EventID: {
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
	MqTimedsendTime32EventID: {
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
	MqTimedreceiveTime32EventID: {
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
	RtSigtimedwaitTime32EventID: {
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
	FutexTime32EventID: {
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
	SchedRrGetInterval32EventID: {
		ID32Bit: sys32sched_rr_get_interval,
		Name:    "sched_rr_get_interval_time32",
		Syscall: true,
		Sets:    []string{"syscalls", "32bit_unique"},
		Params: []trace.ArgMeta{
			{Type: "pid_t", Name: "pid"},
			{Type: "struct old_timespec32*", Name: "interval"},
		},
	},
	SysEnterEventID: {
		ID32Bit: sys32undefined,
		Name:    "sys_enter",
		Probes: []probe{
			{event: "raw_syscalls:sys_enter", attach: rawTracepoint, fn: "tracepoint__raw_syscalls__sys_enter"},
		},
		Sets: []string{},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "syscall"},
		},
	},
	SysExitEventID: {
		ID32Bit: sys32undefined,
		Name:    "sys_exit",
		Probes: []probe{
			{event: "raw_syscalls:sys_exit", attach: rawTracepoint, fn: "tracepoint__raw_syscalls__sys_exit"},
		},
		Sets: []string{},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "syscall"},
		},
	},
	SchedProcessForkEventID: {
		ID32Bit: sys32undefined,
		Name:    "sched_process_fork",
		Probes: []probe{
			{event: "sched:sched_process_fork", attach: rawTracepoint, fn: "tracepoint__sched__sched_process_fork"},
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
	SchedProcessExecEventID: {
		ID32Bit: sys32undefined,
		Name:    "sched_process_exec",
		Probes: []probe{
			{event: "sched:sched_process_exec", attach: rawTracepoint, fn: "tracepoint__sched__sched_process_exec"},
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
		},
	},
	SchedProcessExitEventID: {
		ID32Bit: sys32undefined,
		Name:    "sched_process_exit",
		Probes: []probe{
			{event: "sched:sched_process_exit", attach: rawTracepoint, fn: "tracepoint__sched__sched_process_exit"},
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
	SchedSwitchEventID: {
		ID32Bit: sys32undefined,
		Name:    "sched_switch",
		Probes: []probe{
			{event: "sched:sched_switch", attach: rawTracepoint, fn: "tracepoint__sched__sched_switch"},
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
	DoExitEventID: {
		ID32Bit: sys32undefined,
		Name:    "do_exit",
		Probes: []probe{
			{event: "do_exit", attach: kprobe, fn: "trace_do_exit"},
		},
		Sets:   []string{"proc", "proc_life"},
		Params: []trace.ArgMeta{},
	},
	CapCapableEventID: {
		ID32Bit: sys32undefined,
		Name:    "cap_capable",
		Probes: []probe{
			{event: "cap_capable", attach: kprobe, fn: "trace_cap_capable"},
		},
		Sets: []string{"default"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "cap"},
			{Type: "int", Name: "syscall"},
		},
	},
	VfsWriteEventID: {
		ID32Bit: sys32undefined,
		Name:    "vfs_write",
		Probes: []probe{
			{event: "vfs_write", attach: kprobe, fn: "trace_vfs_write"},
			{event: "vfs_write", attach: kretprobe, fn: "trace_ret_vfs_write"},
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
	VfsWritevEventID: {
		ID32Bit: sys32undefined,
		Name:    "vfs_writev",
		Probes: []probe{
			{event: "vfs_writev", attach: kprobe, fn: "trace_vfs_writev"},
			{event: "vfs_writev", attach: kretprobe, fn: "trace_ret_vfs_writev"},
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
	MemProtAlertEventID: {
		ID32Bit: sys32undefined,
		Name:    "mem_prot_alert",
		Probes: []probe{
			{event: "security_mmap_addr", attach: kprobe, fn: "trace_mmap_alert"},
			{event: "security_file_mprotect", attach: kprobe, fn: "trace_security_file_mprotect"},
		},
		Sets: []string{},
		Params: []trace.ArgMeta{
			{Type: "u32", Name: "alert"},
		},
	},
	CommitCredsEventID: {
		ID32Bit: sys32undefined,
		Name:    "commit_creds",
		Probes: []probe{
			{event: "commit_creds", attach: kprobe, fn: "trace_commit_creds"},
		},
		Sets: []string{},
		Params: []trace.ArgMeta{
			{Type: "slim_cred_t", Name: "old_cred"},
			{Type: "slim_cred_t", Name: "new_cred"},
			{Type: "int", Name: "syscall"},
		},
	},
	SwitchTaskNSEventID: {
		ID32Bit: sys32undefined,
		Name:    "switch_task_ns",
		Probes: []probe{
			{event: "switch_task_namespaces", attach: kprobe, fn: "trace_switch_task_namespaces"},
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
	MagicWriteEventID: {
		ID32Bit: sys32undefined,
		Name:    "magic_write",
		Probes: []probe{
			{event: "vfs_write", attach: kprobe, fn: "trace_vfs_write"},
			{event: "vfs_write", attach: kretprobe, fn: "trace_ret_vfs_write"},
			{event: "vfs_writev", attach: kprobe, fn: "trace_vfs_writev"},
			{event: "vfs_writev", attach: kretprobe, fn: "trace_ret_vfs_writev"},
			{event: "__kernel_write", attach: kprobe, fn: "trace_kernel_write"},
			{event: "__kernel_write", attach: kretprobe, fn: "trace_ret_kernel_write"},
		},
		Sets: []string{},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "bytes", Name: "bytes"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
		},
	},
	CgroupAttachTaskEventID: {
		ID32Bit: sys32undefined,
		Name:    "cgroup_attach_task",
		Probes: []probe{
			{event: "cgroup:cgroup_attach_task", attach: rawTracepoint, fn: "tracepoint__cgroup__cgroup_attach_task"},
		},
		Sets: []string{},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "cgroup_path"},
			{Type: "const char*", Name: "comm"},
			{Type: "pid_t", Name: "pid"},
		},
	},
	CgroupMkdirEventID: {
		ID32Bit: sys32undefined,
		Name:    "cgroup_mkdir",
		Probes: []probe{
			{event: "cgroup:cgroup_mkdir", attach: rawTracepoint, fn: "tracepoint__cgroup__cgroup_mkdir"},
		},
		Sets: []string{},
		Params: []trace.ArgMeta{
			{Type: "u64", Name: "cgroup_id"},
			{Type: "const char*", Name: "cgroup_path"},
			{Type: "u32", Name: "hierarchy_id"},
		},
	},
	CgroupRmdirEventID: {
		ID32Bit: sys32undefined,
		Name:    "cgroup_rmdir",
		Probes: []probe{
			{event: "cgroup:cgroup_rmdir", attach: rawTracepoint, fn: "tracepoint__cgroup__cgroup_rmdir"},
		},
		Sets: []string{},
		Params: []trace.ArgMeta{
			{Type: "u64", Name: "cgroup_id"},
			{Type: "const char*", Name: "cgroup_path"},
			{Type: "u32", Name: "hierarchy_id"},
		},
	},
	SecurityBprmCheckEventID: {
		ID32Bit: sys32undefined,
		Name:    "security_bprm_check",
		Probes: []probe{
			{event: "security_bprm_check", attach: kprobe, fn: "trace_security_bprm_check"},
		},
		Sets: []string{"default", "lsm_hooks", "proc", "proc_life"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
		},
	},
	SecurityFileOpenEventID: {
		ID32Bit: sys32undefined,
		Name:    "security_file_open",
		Probes: []probe{
			{event: "security_file_open", attach: kprobe, fn: "trace_security_file_open"},
		},
		Sets: []string{"default", "lsm_hooks", "fs", "fs_file_ops"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "int", Name: "flags"},
			{Type: "dev_t", Name: "dev"},
			{Type: "unsigned long", Name: "inode"},
			{Type: "unsigned long", Name: "ctime"},
			{Type: "int", Name: "syscall"},
		},
	},
	SecurityInodeUnlinkEventID: {
		ID32Bit: sys32undefined,
		Name:    "security_inode_unlink",
		Probes: []probe{
			{event: "security_inode_unlink", attach: kprobe, fn: "trace_security_inode_unlink"},
		},
		Sets: []string{"default", "lsm_hooks", "fs", "fs_file_ops"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
		},
	},
	SecuritySocketCreateEventID: {
		ID32Bit: sys32undefined,
		Name:    "security_socket_create",
		Probes: []probe{
			{event: "security_socket_create", attach: kprobe, fn: "trace_security_socket_create"},
		},
		Sets: []string{"default", "lsm_hooks", "net", "net_sock"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "family"},
			{Type: "int", Name: "type"},
			{Type: "int", Name: "protocol"},
			{Type: "int", Name: "kern"},
		},
	},
	SecuritySocketListenEventID: {
		ID32Bit: sys32undefined,
		Name:    "security_socket_listen",
		Probes: []probe{
			{event: "security_socket_listen", attach: kprobe, fn: "trace_security_socket_listen"},
		},
		Sets: []string{"default", "lsm_hooks", "net", "net_sock"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct sockaddr*", Name: "local_addr"},
			{Type: "int", Name: "backlog"},
		},
	},
	SecuritySocketConnectEventID: {
		ID32Bit: sys32undefined,
		Name:    "security_socket_connect",
		Probes: []probe{
			{event: "security_socket_connect", attach: kprobe, fn: "trace_security_socket_connect"},
		},
		Sets: []string{"default", "lsm_hooks", "net", "net_sock"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct sockaddr*", Name: "remote_addr"},
		},
	},
	SecuritySocketAcceptEventID: {
		ID32Bit: sys32undefined,
		Name:    "security_socket_accept",
		Probes: []probe{
			{event: "security_socket_accept", attach: kprobe, fn: "trace_security_socket_accept"},
		},
		Sets: []string{"default", "lsm_hooks", "net", "net_sock"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct sockaddr*", Name: "local_addr"},
		},
	},
	SecuritySocketBindEventID: {
		ID32Bit: sys32undefined,
		Name:    "security_socket_bind",
		Probes: []probe{
			{event: "security_socket_bind", attach: kprobe, fn: "trace_security_socket_bind"},
		},
		Sets: []string{"default", "lsm_hooks", "net", "net_sock"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "sockfd"},
			{Type: "struct sockaddr*", Name: "local_addr"},
		},
	},
	SecuritySbMountEventID: {
		ID32Bit: sys32undefined,
		Name:    "security_sb_mount",
		Probes: []probe{
			{event: "security_sb_mount", attach: kprobe, fn: "trace_security_sb_mount"},
		},
		Sets: []string{"default", "lsm_hooks", "fs"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "dev_name"},
			{Type: "const char*", Name: "path"},
			{Type: "const char*", Name: "type"},
			{Type: "unsigned long", Name: "flags"},
		},
	},
	SecurityBPFEventID: {
		ID32Bit: sys32undefined,
		Name:    "security_bpf",
		Probes: []probe{
			{event: "security_bpf", attach: kprobe, fn: "trace_security_bpf"},
		},
		Sets: []string{"lsm_hooks"},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "cmd"},
		},
	},
	SecurityBPFMapEventID: {
		ID32Bit: sys32undefined,
		Name:    "security_bpf_map",
		Probes: []probe{
			{event: "security_bpf_map", attach: kprobe, fn: "trace_security_bpf_map"},
		},
		Sets: []string{"lsm_hooks"},
		Params: []trace.ArgMeta{
			{Type: "unsigned int", Name: "map_id"},
			{Type: "const char*", Name: "map_name"},
		},
	},
	SecurityKernelReadFileEventID: {
		ID32Bit: sys32undefined,
		Name:    "security_kernel_read_file",
		Probes: []probe{
			{event: "security_kernel_read_file", attach: kprobe, fn: "trace_security_kernel_read_file"},
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
	SecurityPostReadFileEventID: {
		ID32Bit: sys32undefined,
		Name:    "security_kernel_post_read_file",
		Probes: []probe{
			{event: "security_kernel_post_read_file", attach: kprobe, fn: "trace_security_kernel_post_read_file"},
		},
		Sets: []string{"lsm_hooks"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "long", Name: "size"},
			{Type: "int", Name: "type"},
		},
	},
	SecurityInodeMknodEventID: {
		ID32Bit: sys32undefined,
		Name:    "security_inode_mknod",
		Probes: []probe{
			{event: "security_inode_mknod", attach: kprobe, fn: "trace_security_inode_mknod"},
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
		Probes: []probe{
			{event: "security_inode_symlink", attach: kprobe, fn: "trace_security_inode_symlink"},
		},
		Sets: []string{"lsm_hooks", "fs", "fs_file_ops"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "linkpath"},
			{Type: "const char*", Name: "target"},
		},
	},
	SecurityMmapFileEventID: {
		ID32Bit: sys32undefined,
		Name:    "security_mmap_file",
		Probes: []probe{
			{event: "security_mmap_file", attach: kprobe, fn: "trace_security_mmap_file"},
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
	SecurityFileMprotectEventID: {
		ID32Bit: sys32undefined,
		Name:    "security_file_mprotect",
		Probes: []probe{
			{event: "security_file_mprotect", attach: kprobe, fn: "trace_security_file_mprotect"},
		},
		Sets: []string{"lsm_hooks", "proc", "proc_mem", "fs", "fs_file_ops"},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "int", Name: "prot"},
			{Type: "unsigned long", Name: "ctime"},
		},
	},
	InitNamespacesEventID: {
		ID32Bit: sys32undefined,
		Name:    "init_namespaces",
		Probes:  []probe{},
		Sets:    []string{},
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
	SocketDupEventID: {
		ID32Bit: sys32undefined,
		Name:    "socket_dup",
		Probes:  []probe{},
		Dependencies: dependencies{
			tailCalls: []tailCall{
				{mapName: "sys_exit_tails", mapIdx: uint32(DupEventID), progName: "sys_dup_exit_tail"},
				{mapName: "sys_exit_tails", mapIdx: uint32(Dup2EventID), progName: "sys_dup_exit_tail"},
				{mapName: "sys_exit_tails", mapIdx: uint32(Dup3EventID), progName: "sys_dup_exit_tail"},
			},
		},
		Sets: []string{},
		Params: []trace.ArgMeta{
			{Type: "int", Name: "oldfd"},
			{Type: "int", Name: "newfd"},
			{Type: "struct sockaddr*", Name: "remote_addr"},
		},
	},
	HiddenInodesEventID: {
		ID32Bit: sys32undefined,
		Name:    "hidden_inodes",
		Probes: []probe{
			{event: "filldir64", attach: kprobe, fn: "trace_filldir64"},
		},
		Sets: []string{},
		Params: []trace.ArgMeta{
			{Type: "char*", Name: "hidden_process"},
		},
	},
	__KernelWriteEventID: {
		ID32Bit: sys32undefined,
		Name:    "__kernel_write",
		Probes: []probe{
			{event: "__kernel_write", attach: kprobe, fn: "trace_kernel_write"},
			{event: "__kernel_write", attach: kretprobe, fn: "trace_ret_kernel_write"},
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
	DirtyPipeSpliceEventID: {
		ID32Bit: sys32undefined,
		Name:    "dirty_pipe_splice",
		Probes: []probe{
			{event: "do_splice", attach: kprobe, fn: "trace_do_splice"},
			{event: "do_splice", attach: kretprobe, fn: "trace_ret_do_splice"},
		},
		Sets: []string{},
		Dependencies: dependencies{
			ksymbols: []string{"pipefifo_fops"},
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
	ContainerCreateEventID: {
		ID32Bit: sys32undefined,
		Name:    "container_create",
		Probes:  []probe{},
		Dependencies: dependencies{
			events: []eventDependency{{eventID: CgroupMkdirEventID}},
		},
		Sets: []string{},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "runtime"},
			{Type: "const char*", Name: "container_id"},
			{Type: "unsigned long", Name: "ctime"},
		},
	},
	ContainerRemoveEventID: {
		ID32Bit: sys32undefined,
		Name:    "container_remove",
		Probes:  []probe{},
		Dependencies: dependencies{
			events: []eventDependency{{eventID: CgroupRmdirEventID}},
		},
		Sets: []string{},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "runtime"},
			{Type: "const char*", Name: "container_id"},
		},
	},
	ExistingContainerEventID: {
		ID32Bit: sys32undefined,
		Name:    "existing_container",
		Probes:  []probe{},
		Sets:    []string{},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "runtime"},
			{Type: "const char*", Name: "container_id"},
			{Type: "unsigned long", Name: "ctime"},
		},
	},
	NetPacket: {
		ID32Bit:      sys32undefined,
		Name:         "net_packet",
		Probes:       []probe{},
		Dependencies: dependencies{},
		Sets:         []string{"network_events"},
		Params: []trace.ArgMeta{
			{Type: "trace.PktMeta", Name: "metadata"},
		},
	},
	DnsRequest: {
		ID32Bit:      sys32undefined,
		Name:         "dns_request",
		Probes:       []probe{},
		Dependencies: dependencies{},
		Sets:         []string{"network_events"},
		Params: []trace.ArgMeta{
			{Type: "trace.PktMeta", Name: "metadata"},
			{Type: "[]bufferdecoder.DnsQueryData", Name: "dns_questions"},
		},
	},
	DnsResponse: {
		ID32Bit:      sys32undefined,
		Name:         "dns_response",
		Probes:       []probe{},
		Dependencies: dependencies{},
		Sets:         []string{"network_events"},
		Params: []trace.ArgMeta{
			{Type: "trace.PktMeta", Name: "metadata"},
			{Type: "[]bufferdecoder.DnsResponseData", Name: "dns_response"},
		},
	},
	ProcCreateEventID: {
		ID32Bit: sys32undefined,
		Name:    "proc_create",
		Probes: []probe{
			{event: "proc_create", attach: kprobe, fn: "trace_proc_create"},
		},
		Sets: []string{},
		Params: []trace.ArgMeta{
			{Type: "char*", Name: "name"},
			{Type: "u64", Name: "proc_ops_addr"},
		},
	},
	KprobeAttachEventID: {
		ID32Bit: sys32undefined,
		Name:    "kprobe_attach",
		Probes: []probe{
			{event: "arm_kprobe", attach: kprobe, fn: "trace_arm_kprobe"},
		},
		Sets: []string{},
		Params: []trace.ArgMeta{
			{Type: "char*", Name: "symbol_name"},
			{Type: "u64", Name: "pre_handler_addr"},
			{Type: "u64", Name: "post_handler_addr"},
		},
	},
	CallUsermodeHelperEventID: {
		ID32Bit: sys32undefined,
		Name:    "call_usermodehelper",
		Probes: []probe{
			{event: "call_usermodehelper", attach: kprobe, fn: "trace_call_usermodehelper"},
		},
		Sets: []string{},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "pathname"},
			{Type: "const char*const*", Name: "argv"},
			{Type: "const char*const*", Name: "envp"},
			{Type: "int", Name: "wait"},
		},
	},
	DebugfsCreateFileEventID: {
		ID32Bit: sys32undefined,
		Name:    "debugfs_create_file",
		Probes: []probe{
			{event: "debugfs_create_file", attach: kprobe, fn: "trace_debugfs_create_file"},
		},
		Sets: []string{},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "file_name"},
			{Type: "const char*", Name: "path"},
			{Type: "mode_t", Name: "mode"},
			{Type: "u64", Name: "proc_ops_addr"},
		},
	},
	PrintSyscallTableEventID: {
		ID32Bit:  sys32undefined,
		Name:     "print_syscall_table",
		Internal: true,
		Probes: []probe{
			{event: "security_file_ioctl", attach: kprobe, fn: "trace_tracee_trigger_event"},
		},
		Dependencies: dependencies{ksymbols: []string{"sys_call_table"}},
		Sets:         []string{},
		Params: []trace.ArgMeta{
			{Type: "unsigned long[]", Name: "syscalls_addresses"},
		},
	},
	DetectHookedSyscallsEventID: {
		ID32Bit: sys32undefined,
		Name:    "detect_hooked_syscalls",
		Dependencies: dependencies{
			events: []eventDependency{{eventID: FinitModuleEventID}, {eventID: PrintSyscallTableEventID}, {eventID: InitModuleEventID}},
		},
		Sets: []string{},
		Params: []trace.ArgMeta{
			{Type: "HookedSyscallData[]", Name: "hooked_syscalls"},
		},
	},
	DebugfsCreateDirEventID: {
		ID32Bit: sys32undefined,
		Name:    "debugfs_create_dir",
		Probes: []probe{
			{event: "debugfs_create_dir", attach: kprobe, fn: "trace_debugfs_create_dir"},
		},
		Sets: []string{},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "name"},
			{Type: "const char*", Name: "path"},
		},
	},
	DeviceAddEventID: {
		ID32Bit: sys32undefined,
		Name:    "device_add",
		Probes: []probe{
			{event: "device_add", attach: kprobe, fn: "trace_device_add"},
		},
		Sets: []string{},
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "name"},
			{Type: "const char*", Name: "parent_name"},
		},
	},
	RegisterChrdevEventID: {
		ID32Bit: sys32undefined,
		Name:    "register_chrdev",
		Probes: []probe{
			{event: "__register_chrdev", attach: kprobe, fn: "trace___register_chrdev"},
			{event: "__register_chrdev", attach: kretprobe, fn: "trace_ret__register_chrdev"},
		},
		Sets: []string{},
		Params: []trace.ArgMeta{
			{Type: "unsigned int", Name: "requested_major_number"},
			{Type: "unsigned int", Name: "granted_major_number"},
			{Type: "const char*", Name: "char_device_name"},
			{Type: "struct file_operations *", Name: "char_device_fops"},
		},
	},
	SharedObjectLoadedEventID: {
		ID32Bit: sys32undefined,
		Name:    "shared_object_loaded",
		Probes:  []probe{},
		Dependencies: dependencies{
			events: []eventDependency{{eventID: SecurityMmapFileEventID}},
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
	CaptureFileWriteEventID: {
		ID32Bit:  sys32undefined,
		Name:     "capture_file_write",
		Internal: true,
		Probes: []probe{
			{event: "vfs_write", attach: kprobe, fn: "trace_vfs_write"},
			{event: "vfs_write", attach: kretprobe, fn: "trace_ret_vfs_write"},
			{event: "vfs_writev", attach: kprobe, fn: "trace_vfs_writev"},
			{event: "vfs_writev", attach: kretprobe, fn: "trace_ret_vfs_writev"},
			{event: "__kernel_write", attach: kprobe, fn: "trace_kernel_write"},
			{event: "__kernel_write", attach: kretprobe, fn: "trace_ret_kernel_write"},
		},
		Dependencies: dependencies{
			tailCalls: []tailCall{
				{mapName: "prog_array", mapIdx: tailVfsWrite, progName: "trace_ret_vfs_write_tail"},
				{mapName: "prog_array", mapIdx: tailVfsWritev, progName: "trace_ret_vfs_writev_tail"},
				{mapName: "prog_array", mapIdx: tailKernelWrite, progName: "trace_ret_kernel_write_tail"},
				{mapName: "prog_array", mapIdx: tailSendBin, progName: "send_bin"},
			},
		},
	},
	CaptureExecEventID: {
		ID32Bit:  sys32undefined,
		Name:     "capture_exec",
		Internal: true,
		Probes:   []probe{},
		Dependencies: dependencies{
			events: []eventDependency{{eventID: SchedProcessExecEventID}},
		},
	},
	CaptureModuleEventID: {
		ID32Bit:  sys32undefined,
		Name:     "capture_module",
		Internal: true,
		Probes: []probe{
			{event: "raw_syscalls:sys_enter", attach: rawTracepoint, fn: "tracepoint__raw_syscalls__sys_enter"},
			{event: "raw_syscalls:sys_exit", attach: rawTracepoint, fn: "tracepoint__raw_syscalls__sys_exit"},
			{event: "security_kernel_post_read_file", attach: kprobe, fn: "trace_security_kernel_post_read_file"},
		},
		Dependencies: dependencies{
			events: []eventDependency{{eventID: SchedProcessExecEventID}},
			tailCalls: []tailCall{
				{mapName: "sys_enter_tails", mapIdx: uint32(InitModuleEventID), progName: "syscall__init_module"},
				{mapName: "prog_array_tp", mapIdx: tailSendBinTP, progName: "send_bin_tp"},
				{mapName: "prog_array", mapIdx: tailSendBin, progName: "send_bin"},
			},
		},
	},
	CaptureMemEventID: {
		ID32Bit:  sys32undefined,
		Name:     "capture_mem",
		Internal: true,
		Probes:   []probe{},
		Dependencies: dependencies{
			tailCalls: []tailCall{
				{mapName: "prog_array", mapIdx: tailSendBin, progName: "send_bin"},
			},
		},
	},
	CaptureProfileEventID: {
		ID32Bit:  sys32undefined,
		Name:     "capture_profile",
		Internal: true,
		Probes:   []probe{},
		Dependencies: dependencies{
			events: []eventDependency{{eventID: SchedProcessExecEventID}},
		},
	},
	CapturePcapEventID: {
		ID32Bit:  sys32undefined,
		Name:     "capture_pcap",
		Internal: true,
		Probes:   []probe{},
		Dependencies: dependencies{
			events: []eventDependency{{eventID: SecuritySocketBindEventID}},
		},
	},
}
