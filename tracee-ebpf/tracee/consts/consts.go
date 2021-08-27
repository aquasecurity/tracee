package consts

import (
	"math"

	"github.com/aquasecurity/tracee/tracee-ebpf/external"
)

// BpfConfig is an enum that include various configurations that can be passed to bpf code
// config should match defined values in ebpf code
type BpfConfig uint32

// Max depth of each stack trace to track
// Matches 'MAX_STACK_DEPTH' in eBPF code
const MaxStackDepth int = 20

const (
	ConfigDetectOrigSyscall BpfConfig = iota + 1
	ConfigExecEnv
	ConfigCaptureFiles
	ConfigExtractDynCode
	ConfigTraceePid
	ConfigStackAddresses
	ConfigUIDFilter
	ConfigMntNsFilter
	ConfigPidNsFilter
	ConfigUTSNsFilter
	ConfigCommFilter
	ConfigPidFilter
	ConfigContFilter
	ConfigFollowFilter
	ConfigNewPidFilter
	ConfigNewContFilter
	ConfigDebugNet
)

const (
	FilterNotEqual uint32 = iota
	FilterEqual
)

const (
	FilterIn  uint8 = 1
	FilterOut uint8 = 2
)

const (
	UidLess uint32 = iota
	UidGreater
	PidLess
	PidGreater
	MntNsLess
	MntNsGreater
	PidNsLess
	PidNsGreater
)

// Set default inequality values
// val<0 and val>math.MaxUint64 should never be used by the user as they give an empty set
const (
	LessNotSetUint    uint64 = 0
	GreaterNotSetUint uint64 = math.MaxUint64
	LessNotSetInt     int64  = math.MinInt64
	GreaterNotSetInt  int64  = math.MaxInt64
)

// an enum that specifies the index of a function to be used in a bpf tail call
// tail function indexes should match defined values in ebpf code
const (
	TailVfsWrite uint32 = iota
	TailVfsWritev
	TailSendBin
)

// BinType is an enum that specifies the type of binary data sent in the file perf map
// binary types should match defined values in ebpf code
type BinType uint8

const (
	SendVfsWrite BinType = iota + 1
	SendMprotect
)

// ArgType is an enum that encodes the argument types that the BPF program may write to the shared buffer
// argument types should match defined values in ebpf code
type ArgType uint8

const (
	NoneT ArgType = iota
	IntT
	UintT
	LongT
	UlongT
	OffT
	ModeT
	DevT
	SizeT
	PointerT
	StrT
	StrArrT
	SockAddrT
	AlertT
	BytesT
	U16T
	CredT
)

// ArgTag is an enum that encodes the argument types that the BPF program may write to the shared buffer
// argument tags should match defined values in ebpf code
type ArgTag uint8

// ProbeType is an enum that describes the mechanism used to attach the event
// Kprobes are explained here: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#1-kprobes
// Tracepoints are explained here: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#3-tracepoints
// Raw tracepoints are explained here: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#7-raw-tracepoints
type ProbeType uint8

const (
	SysCall ProbeType = iota
	Kprobe
	Kretprobe
	Tracepoint
	RawTracepoint
)

type Probe struct {
	Event  string
	Attach ProbeType
	Fn     string
}

// EventConfig is a struct describing an event configuration
type EventConfig struct {
	ID             int32
	ID32Bit        int32
	Name           string
	Probes         []Probe
	EssentialEvent bool
	Sets           []string
}

// Non syscalls events (used by all architectures)
// events should match defined values in ebpf code
const (
	SysEnterEventID int32 = iota + 1000
	SysExitEventID
	SchedProcessForkEventID
	SchedProcessExecEventID
	SchedProcessExitEventID
	DoExitEventID
	CapCapableEventID
	VfsWriteEventID
	VfsWritevEventID
	MemProtAlertEventID
	CommitCredsEventID
	SwitchTaskNSEventID
	MagicWriteEventID
	CgroupAttachTaskEventID
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
	SystemInfoEventID
	MaxEventID
)

const (
	NetPacket uint32 = iota
	DebugNetSecurityBind
	DebugNetUdpSendmsg
	DebugNetUdpDisconnect
	DebugNetUdpDestroySock
	DebugNetUdpV6DestroySock
	DebugNetInetSockSetState
	DebugNetTcpConnect
)

// EventsIDToEvent is list of supported events, indexed by their ID
var EventsIDToEvent = map[int32]EventConfig{
	ReadEventID:                   {ID: ReadEventID, ID32Bit: sys32read, Name: "read", Probes: []Probe{{Event: "read", Attach: SysCall, Fn: "read"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	WriteEventID:                  {ID: WriteEventID, ID32Bit: sys32write, Name: "write", Probes: []Probe{{Event: "write", Attach: SysCall, Fn: "write"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	OpenEventID:                   {ID: OpenEventID, ID32Bit: sys32open, Name: "open", Probes: []Probe{{Event: "open", Attach: SysCall, Fn: "open"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	CloseEventID:                  {ID: CloseEventID, ID32Bit: sys32close, Name: "close", Probes: []Probe{{Event: "close", Attach: SysCall, Fn: "close"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	StatEventID:                   {ID: StatEventID, ID32Bit: sys32stat, Name: "stat", Probes: []Probe{{Event: "newstat", Attach: SysCall, Fn: "newstat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	FstatEventID:                  {ID: FstatEventID, ID32Bit: sys32fstat, Name: "fstat", Probes: []Probe{{Event: "newfstat", Attach: SysCall, Fn: "newfstat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	LstatEventID:                  {ID: LstatEventID, ID32Bit: sys32lstat, Name: "lstat", Probes: []Probe{{Event: "newlstat", Attach: SysCall, Fn: "newlstat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	PollEventID:                   {ID: PollEventID, ID32Bit: sys32poll, Name: "poll", Probes: []Probe{{Event: "poll", Attach: SysCall, Fn: "poll"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	LseekEventID:                  {ID: LseekEventID, ID32Bit: sys32lseek, Name: "lseek", Probes: []Probe{{Event: "lseek", Attach: SysCall, Fn: "lseek"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	MmapEventID:                   {ID: MmapEventID, ID32Bit: sys32mmap, Name: "mmap", Probes: []Probe{{Event: "mmap", Attach: SysCall, Fn: "mmap"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	MprotectEventID:               {ID: MprotectEventID, ID32Bit: sys32mprotect, Name: "mprotect", Probes: []Probe{{Event: "mprotect", Attach: SysCall, Fn: "mprotect"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	MunmapEventID:                 {ID: MunmapEventID, ID32Bit: sys32munmap, Name: "munmap", Probes: []Probe{{Event: "munmap", Attach: SysCall, Fn: "munmap"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	BrkEventID:                    {ID: BrkEventID, ID32Bit: sys32brk, Name: "brk", Probes: []Probe{{Event: "brk", Attach: SysCall, Fn: "brk"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	RtSigactionEventID:            {ID: RtSigactionEventID, ID32Bit: sys32rt_sigaction, Name: "rt_sigaction", Probes: []Probe{{Event: "rt_sigaction", Attach: SysCall, Fn: "rt_sigaction"}}, Sets: []string{"syscalls", "signals"}},
	RtSigprocmaskEventID:          {ID: RtSigprocmaskEventID, ID32Bit: sys32rt_sigprocmask, Name: "rt_sigprocmask", Probes: []Probe{{Event: "rt_sigprocmask", Attach: SysCall, Fn: "rt_sigprocmask"}}, Sets: []string{"syscalls", "signals"}},
	RtSigreturnEventID:            {ID: RtSigreturnEventID, ID32Bit: sys32rt_sigreturn, Name: "rt_sigreturn", Probes: []Probe{{Event: "rt_sigreturn", Attach: SysCall, Fn: "rt_sigreturn"}}, Sets: []string{"syscalls", "signals"}},
	IoctlEventID:                  {ID: IoctlEventID, ID32Bit: sys32ioctl, Name: "ioctl", Probes: []Probe{{Event: "ioctl", Attach: SysCall, Fn: "ioctl"}}, Sets: []string{"syscalls", "fs", "fs_fd_ops"}},
	Pread64EventID:                {ID: Pread64EventID, ID32Bit: sys32pread64, Name: "pread64", Probes: []Probe{{Event: "pread64", Attach: SysCall, Fn: "pread64"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	Pwrite64EventID:               {ID: Pwrite64EventID, ID32Bit: sys32pwrite64, Name: "pwrite64", Probes: []Probe{{Event: "pwrite64", Attach: SysCall, Fn: "pwrite64"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	ReadvEventID:                  {ID: ReadvEventID, ID32Bit: sys32readv, Name: "readv", Probes: []Probe{{Event: "readv", Attach: SysCall, Fn: "readv"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	WritevEventID:                 {ID: WritevEventID, ID32Bit: sys32writev, Name: "writev", Probes: []Probe{{Event: "writev", Attach: SysCall, Fn: "writev"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	AccessEventID:                 {ID: AccessEventID, ID32Bit: sys32access, Name: "access", Probes: []Probe{{Event: "access", Attach: SysCall, Fn: "access"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	PipeEventID:                   {ID: PipeEventID, ID32Bit: sys32pipe, Name: "pipe", Probes: []Probe{{Event: "pipe", Attach: SysCall, Fn: "pipe"}}, Sets: []string{"syscalls", "ipc", "ipc_pipe"}},
	SelectEventID:                 {ID: SelectEventID, ID32Bit: sys32select, Name: "select", Probes: []Probe{{Event: "select", Attach: SysCall, Fn: "select"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	SchedYieldEventID:             {ID: SchedYieldEventID, ID32Bit: sys32sched_yield, Name: "sched_yield", Probes: []Probe{{Event: "sched_yield", Attach: SysCall, Fn: "sched_yield"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	MremapEventID:                 {ID: MremapEventID, ID32Bit: sys32mremap, Name: "mremap", Probes: []Probe{{Event: "mremap", Attach: SysCall, Fn: "mremap"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	MsyncEventID:                  {ID: MsyncEventID, ID32Bit: sys32msync, Name: "msync", Probes: []Probe{{Event: "msync", Attach: SysCall, Fn: "msync"}}, Sets: []string{"syscalls", "fs", "fs_sync"}},
	MincoreEventID:                {ID: MincoreEventID, ID32Bit: sys32mincore, Name: "mincore", Probes: []Probe{{Event: "mincore", Attach: SysCall, Fn: "mincore"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	MadviseEventID:                {ID: MadviseEventID, ID32Bit: sys32madvise, Name: "madvise", Probes: []Probe{{Event: "madvise", Attach: SysCall, Fn: "madvise"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	ShmgetEventID:                 {ID: ShmgetEventID, ID32Bit: sys32shmget, Name: "shmget", Probes: []Probe{{Event: "shmget", Attach: SysCall, Fn: "shmget"}}, Sets: []string{"syscalls", "ipc", "ipc_shm"}},
	ShmatEventID:                  {ID: ShmatEventID, ID32Bit: sys32shmat, Name: "shmat", Probes: []Probe{{Event: "shmat", Attach: SysCall, Fn: "shmat"}}, Sets: []string{"syscalls", "ipc", "ipc_shm"}},
	ShmctlEventID:                 {ID: ShmctlEventID, ID32Bit: sys32shmctl, Name: "shmctl", Probes: []Probe{{Event: "shmctl", Attach: SysCall, Fn: "shmctl"}}, Sets: []string{"syscalls", "ipc", "ipc_shm"}},
	DupEventID:                    {ID: DupEventID, ID32Bit: sys32dup, Name: "dup", Probes: []Probe{{Event: "dup", Attach: SysCall, Fn: "dup"}}, Sets: []string{"default", "syscalls", "fs", "fs_fd_ops"}},
	Dup2EventID:                   {ID: Dup2EventID, ID32Bit: sys32dup2, Name: "dup2", Probes: []Probe{{Event: "dup2", Attach: SysCall, Fn: "dup2"}}, Sets: []string{"default", "syscalls", "fs", "fs_fd_ops"}},
	PauseEventID:                  {ID: PauseEventID, ID32Bit: sys32pause, Name: "pause", Probes: []Probe{{Event: "pause", Attach: SysCall, Fn: "pause"}}, Sets: []string{"syscalls", "signals"}},
	NanosleepEventID:              {ID: NanosleepEventID, ID32Bit: sys32nanosleep, Name: "nanosleep", Probes: []Probe{{Event: "nanosleep", Attach: SysCall, Fn: "nanosleep"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	GetitimerEventID:              {ID: GetitimerEventID, ID32Bit: sys32getitimer, Name: "getitimer", Probes: []Probe{{Event: "getitimer", Attach: SysCall, Fn: "getitimer"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	AlarmEventID:                  {ID: AlarmEventID, ID32Bit: sys32alarm, Name: "alarm", Probes: []Probe{{Event: "alarm", Attach: SysCall, Fn: "alarm"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	SetitimerEventID:              {ID: SetitimerEventID, ID32Bit: sys32setitimer, Name: "setitimer", Probes: []Probe{{Event: "setitimer", Attach: SysCall, Fn: "setitimer"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	GetpidEventID:                 {ID: GetpidEventID, ID32Bit: sys32getpid, Name: "getpid", Probes: []Probe{{Event: "getpid", Attach: SysCall, Fn: "getpid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SendfileEventID:               {ID: SendfileEventID, ID32Bit: sys32sendfile, Name: "sendfile", Probes: []Probe{{Event: "sendfile", Attach: SysCall, Fn: "sendfile"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	SocketEventID:                 {ID: SocketEventID, ID32Bit: sys32socket, Name: "socket", Probes: []Probe{{Event: "socket", Attach: SysCall, Fn: "socket"}}, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	ConnectEventID:                {ID: ConnectEventID, ID32Bit: sys32connect, Name: "connect", Probes: []Probe{{Event: "connect", Attach: SysCall, Fn: "connect"}}, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	AcceptEventID:                 {ID: AcceptEventID, ID32Bit: sys32undefined, Name: "accept", Probes: []Probe{{Event: "accept", Attach: SysCall, Fn: "accept"}}, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	SendtoEventID:                 {ID: SendtoEventID, ID32Bit: sys32sendto, Name: "sendto", Probes: []Probe{{Event: "sendto", Attach: SysCall, Fn: "sendto"}}, Sets: []string{"syscalls", "net", "net_snd_rcv"}},
	RecvfromEventID:               {ID: RecvfromEventID, ID32Bit: sys32recvfrom, Name: "recvfrom", Probes: []Probe{{Event: "recvfrom", Attach: SysCall, Fn: "recvfrom"}}, Sets: []string{"syscalls", "net", "net_snd_rcv"}},
	SendmsgEventID:                {ID: SendmsgEventID, ID32Bit: sys32sendmsg, Name: "sendmsg", Probes: []Probe{{Event: "sendmsg", Attach: SysCall, Fn: "sendmsg"}}, Sets: []string{"syscalls", "net", "net_snd_rcv"}},
	RecvmsgEventID:                {ID: RecvmsgEventID, ID32Bit: sys32recvmsg, Name: "recvmsg", Probes: []Probe{{Event: "recvmsg", Attach: SysCall, Fn: "recvmsg"}}, Sets: []string{"syscalls", "net", "net_snd_rcv"}},
	ShutdownEventID:               {ID: ShutdownEventID, ID32Bit: sys32shutdown, Name: "shutdown", Probes: []Probe{{Event: "shutdown", Attach: SysCall, Fn: "shutdown"}}, Sets: []string{"syscalls", "net", "net_sock"}},
	BindEventID:                   {ID: BindEventID, ID32Bit: sys32bind, Name: "bind", Probes: []Probe{{Event: "bind", Attach: SysCall, Fn: "bind"}}, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	ListenEventID:                 {ID: ListenEventID, ID32Bit: sys32listen, Name: "listen", Probes: []Probe{{Event: "listen", Attach: SysCall, Fn: "listen"}}, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	GetsocknameEventID:            {ID: GetsocknameEventID, ID32Bit: sys32getsockname, Name: "getsockname", Probes: []Probe{{Event: "getsockname", Attach: SysCall, Fn: "getsockname"}}, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	GetpeernameEventID:            {ID: GetpeernameEventID, ID32Bit: sys32getpeername, Name: "getpeername", Probes: []Probe{{Event: "getpeername", Attach: SysCall, Fn: "getpeername"}}, Sets: []string{"syscalls", "net", "net_sock"}},
	SocketpairEventID:             {ID: SocketpairEventID, ID32Bit: sys32socketpair, Name: "socketpair", Probes: []Probe{{Event: "socketpair", Attach: SysCall, Fn: "socketpair"}}, Sets: []string{"syscalls", "net", "net_sock"}},
	SetsockoptEventID:             {ID: SetsockoptEventID, ID32Bit: sys32setsockopt, Name: "setsockopt", Probes: []Probe{{Event: "setsockopt", Attach: SysCall, Fn: "setsockopt"}}, Sets: []string{"syscalls", "net", "net_sock"}},
	GetsockoptEventID:             {ID: GetsockoptEventID, ID32Bit: sys32getsockopt, Name: "getsockopt", Probes: []Probe{{Event: "getsockopt", Attach: SysCall, Fn: "getsockopt"}}, Sets: []string{"syscalls", "net", "net_sock"}},
	CloneEventID:                  {ID: CloneEventID, ID32Bit: sys32clone, Name: "clone", Probes: []Probe{{Event: "clone", Attach: SysCall, Fn: "clone"}}, Sets: []string{"default", "syscalls", "proc", "proc_life"}},
	ForkEventID:                   {ID: ForkEventID, ID32Bit: sys32fork, Name: "fork", Probes: []Probe{{Event: "fork", Attach: SysCall, Fn: "fork"}}, Sets: []string{"default", "syscalls", "proc", "proc_life"}},
	VforkEventID:                  {ID: VforkEventID, ID32Bit: sys32vfork, Name: "vfork", Probes: []Probe{{Event: "vfork", Attach: SysCall, Fn: "vfork"}}, Sets: []string{"default", "syscalls", "proc", "proc_life"}},
	ExecveEventID:                 {ID: ExecveEventID, ID32Bit: sys32execve, Name: "execve", Probes: []Probe{{Event: "execve", Attach: SysCall, Fn: "execve"}}, Sets: []string{"default", "syscalls", "proc", "proc_life"}},
	ExitEventID:                   {ID: ExitEventID, ID32Bit: sys32exit, Name: "exit", Probes: []Probe{{Event: "exit", Attach: SysCall, Fn: "exit"}}, Sets: []string{"syscalls", "proc", "proc_life"}},
	Wait4EventID:                  {ID: Wait4EventID, ID32Bit: sys32wait4, Name: "wait4", Probes: []Probe{{Event: "wait4", Attach: SysCall, Fn: "wait4"}}, Sets: []string{"syscalls", "proc", "proc_life"}},
	KillEventID:                   {ID: KillEventID, ID32Bit: sys32kill, Name: "kill", Probes: []Probe{{Event: "kill", Attach: SysCall, Fn: "kill"}}, Sets: []string{"default", "syscalls", "signals"}},
	UnameEventID:                  {ID: UnameEventID, ID32Bit: sys32uname, Name: "uname", Probes: []Probe{{Event: "uname", Attach: SysCall, Fn: "uname"}}, Sets: []string{"syscalls", "system"}},
	SemgetEventID:                 {ID: SemgetEventID, ID32Bit: sys32semget, Name: "semget", Probes: []Probe{{Event: "semget", Attach: SysCall, Fn: "semget"}}, Sets: []string{"syscalls", "ipc", "ipc_sem"}},
	SemopEventID:                  {ID: SemopEventID, ID32Bit: sys32undefined, Name: "semop", Probes: []Probe{{Event: "semop", Attach: SysCall, Fn: "semop"}}, Sets: []string{"syscalls", "ipc", "ipc_sem"}},
	SemctlEventID:                 {ID: SemctlEventID, ID32Bit: sys32semctl, Name: "semctl", Probes: []Probe{{Event: "semctl", Attach: SysCall, Fn: "semctl"}}, Sets: []string{"syscalls", "ipc", "ipc_sem"}},
	ShmdtEventID:                  {ID: ShmdtEventID, ID32Bit: sys32shmdt, Name: "shmdt", Probes: []Probe{{Event: "shmdt", Attach: SysCall, Fn: "shmdt"}}, Sets: []string{"syscalls", "ipc", "ipc_shm"}},
	MsggetEventID:                 {ID: MsggetEventID, ID32Bit: sys32msgget, Name: "msgget", Probes: []Probe{{Event: "msgget", Attach: SysCall, Fn: "msgget"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	MsgsndEventID:                 {ID: MsgsndEventID, ID32Bit: sys32msgsnd, Name: "msgsnd", Probes: []Probe{{Event: "msgsnd", Attach: SysCall, Fn: "msgsnd"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	MsgrcvEventID:                 {ID: MsgrcvEventID, ID32Bit: sys32msgrcv, Name: "msgrcv", Probes: []Probe{{Event: "msgrcv", Attach: SysCall, Fn: "msgrcv"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	MsgctlEventID:                 {ID: MsgctlEventID, ID32Bit: sys32msgctl, Name: "msgctl", Probes: []Probe{{Event: "msgctl", Attach: SysCall, Fn: "msgctl"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	FcntlEventID:                  {ID: FcntlEventID, ID32Bit: sys32fcntl, Name: "fcntl", Probes: []Probe{{Event: "fcntl", Attach: SysCall, Fn: "fcntl"}}, Sets: []string{"syscalls", "fs", "fs_fd_ops"}},
	FlockEventID:                  {ID: FlockEventID, ID32Bit: sys32flock, Name: "flock", Probes: []Probe{{Event: "flock", Attach: SysCall, Fn: "flock"}}, Sets: []string{"syscalls", "fs", "fs_fd_ops"}},
	FsyncEventID:                  {ID: FsyncEventID, ID32Bit: sys32fsync, Name: "fsync", Probes: []Probe{{Event: "fsync", Attach: SysCall, Fn: "fsync"}}, Sets: []string{"syscalls", "fs", "fs_sync"}},
	FdatasyncEventID:              {ID: FdatasyncEventID, ID32Bit: sys32fdatasync, Name: "fdatasync", Probes: []Probe{{Event: "fdatasync", Attach: SysCall, Fn: "fdatasync"}}, Sets: []string{"syscalls", "fs", "fs_sync"}},
	TruncateEventID:               {ID: TruncateEventID, ID32Bit: sys32truncate, Name: "truncate", Probes: []Probe{{Event: "truncate", Attach: SysCall, Fn: "truncate"}}, Sets: []string{"syscalls", "fs", "fs_file_ops"}},
	FtruncateEventID:              {ID: FtruncateEventID, ID32Bit: sys32ftruncate, Name: "ftruncate", Probes: []Probe{{Event: "ftruncate", Attach: SysCall, Fn: "ftruncate"}}, Sets: []string{"syscalls", "fs", "fs_file_ops"}},
	GetdentsEventID:               {ID: GetdentsEventID, ID32Bit: sys32getdents, Name: "getdents", Probes: []Probe{{Event: "getdents", Attach: SysCall, Fn: "getdents"}}, Sets: []string{"default", "syscalls", "fs", "fs_dir_ops"}},
	GetcwdEventID:                 {ID: GetcwdEventID, ID32Bit: sys32getcwd, Name: "getcwd", Probes: []Probe{{Event: "getcwd", Attach: SysCall, Fn: "getcwd"}}, Sets: []string{"syscalls", "fs", "fs_dir_ops"}},
	ChdirEventID:                  {ID: ChdirEventID, ID32Bit: sys32chdir, Name: "chdir", Probes: []Probe{{Event: "chdir", Attach: SysCall, Fn: "chdir"}}, Sets: []string{"syscalls", "fs", "fs_dir_ops"}},
	FchdirEventID:                 {ID: FchdirEventID, ID32Bit: sys32fchdir, Name: "fchdir", Probes: []Probe{{Event: "fchdir", Attach: SysCall, Fn: "fchdir"}}, Sets: []string{"syscalls", "fs", "fs_dir_ops"}},
	RenameEventID:                 {ID: RenameEventID, ID32Bit: sys32rename, Name: "rename", Probes: []Probe{{Event: "rename", Attach: SysCall, Fn: "rename"}}, Sets: []string{"syscalls", "fs", "fs_file_ops"}},
	MkdirEventID:                  {ID: MkdirEventID, ID32Bit: sys32mkdir, Name: "mkdir", Probes: []Probe{{Event: "mkdir", Attach: SysCall, Fn: "mkdir"}}, Sets: []string{"syscalls", "fs", "fs_dir_ops"}},
	RmdirEventID:                  {ID: RmdirEventID, ID32Bit: sys32rmdir, Name: "rmdir", Probes: []Probe{{Event: "rmdir", Attach: SysCall, Fn: "rmdir"}}, Sets: []string{"syscalls", "fs", "fs_dir_ops"}},
	CreatEventID:                  {ID: CreatEventID, ID32Bit: sys32creat, Name: "creat", Probes: []Probe{{Event: "creat", Attach: SysCall, Fn: "creat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	LinkEventID:                   {ID: LinkEventID, ID32Bit: sys32link, Name: "link", Probes: []Probe{{Event: "link", Attach: SysCall, Fn: "link"}}, Sets: []string{"syscalls", "fs", "fs_link_ops"}},
	UnlinkEventID:                 {ID: UnlinkEventID, ID32Bit: sys32unlink, Name: "unlink", Probes: []Probe{{Event: "unlink", Attach: SysCall, Fn: "unlink"}}, Sets: []string{"default", "syscalls", "fs", "fs_link_ops"}},
	SymlinkEventID:                {ID: SymlinkEventID, ID32Bit: sys32symlink, Name: "symlink", Probes: []Probe{{Event: "symlink", Attach: SysCall, Fn: "symlink"}}, Sets: []string{"default", "syscalls", "fs", "fs_link_ops"}},
	ReadlinkEventID:               {ID: ReadlinkEventID, ID32Bit: sys32readlink, Name: "readlink", Probes: []Probe{{Event: "readlink", Attach: SysCall, Fn: "readlink"}}, Sets: []string{"syscalls", "fs", "fs_link_ops"}},
	ChmodEventID:                  {ID: ChmodEventID, ID32Bit: sys32chmod, Name: "chmod", Probes: []Probe{{Event: "chmod", Attach: SysCall, Fn: "chmod"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	FchmodEventID:                 {ID: FchmodEventID, ID32Bit: sys32fchmod, Name: "fchmod", Probes: []Probe{{Event: "fchmod", Attach: SysCall, Fn: "fchmod"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	ChownEventID:                  {ID: ChownEventID, ID32Bit: sys32chown, Name: "chown", Probes: []Probe{{Event: "chown", Attach: SysCall, Fn: "chown"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	FchownEventID:                 {ID: FchownEventID, ID32Bit: sys32fchown, Name: "fchown", Probes: []Probe{{Event: "fchown", Attach: SysCall, Fn: "fchown"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	LchownEventID:                 {ID: LchownEventID, ID32Bit: sys32lchown, Name: "lchown", Probes: []Probe{{Event: "lchown", Attach: SysCall, Fn: "lchown"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	UmaskEventID:                  {ID: UmaskEventID, ID32Bit: sys32umask, Name: "umask", Probes: []Probe{{Event: "umask", Attach: SysCall, Fn: "umask"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	GettimeofdayEventID:           {ID: GettimeofdayEventID, ID32Bit: sys32gettimeofday, Name: "gettimeofday", Probes: []Probe{{Event: "gettimeofday", Attach: SysCall, Fn: "gettimeofday"}}, Sets: []string{"syscalls", "time", "time_tod"}},
	GetrlimitEventID:              {ID: GetrlimitEventID, ID32Bit: sys32getrlimit, Name: "getrlimit", Probes: []Probe{{Event: "getrlimit", Attach: SysCall, Fn: "getrlimit"}}, Sets: []string{"syscalls", "proc"}},
	GetrusageEventID:              {ID: GetrusageEventID, ID32Bit: sys32getrusage, Name: "getrusage", Probes: []Probe{{Event: "getrusage", Attach: SysCall, Fn: "getrusage"}}, Sets: []string{"syscalls", "proc"}},
	SysinfoEventID:                {ID: SysinfoEventID, ID32Bit: sys32sysinfo, Name: "sysinfo", Probes: []Probe{{Event: "sysinfo", Attach: SysCall, Fn: "sysinfo"}}, Sets: []string{"syscalls", "system"}},
	TimesEventID:                  {ID: TimesEventID, ID32Bit: sys32times, Name: "times", Probes: []Probe{{Event: "times", Attach: SysCall, Fn: "times"}}, Sets: []string{"syscalls", "proc"}},
	PtraceEventID:                 {ID: PtraceEventID, ID32Bit: sys32ptrace, Name: "ptrace", Probes: []Probe{{Event: "ptrace", Attach: SysCall, Fn: "ptrace"}}, Sets: []string{"default", "syscalls", "proc"}},
	GetuidEventID:                 {ID: GetuidEventID, ID32Bit: sys32getuid, Name: "getuid", Probes: []Probe{{Event: "getuid", Attach: SysCall, Fn: "getuid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SyslogEventID:                 {ID: SyslogEventID, ID32Bit: sys32syslog, Name: "syslog", Probes: []Probe{{Event: "syslog", Attach: SysCall, Fn: "syslog"}}, Sets: []string{"syscalls", "system"}},
	GetgidEventID:                 {ID: GetgidEventID, ID32Bit: sys32getgid, Name: "getgid", Probes: []Probe{{Event: "getgid", Attach: SysCall, Fn: "getgid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SetuidEventID:                 {ID: SetuidEventID, ID32Bit: sys32setuid, Name: "setuid", Probes: []Probe{{Event: "setuid", Attach: SysCall, Fn: "setuid"}}, Sets: []string{"default", "syscalls", "proc", "proc_ids"}},
	SetgidEventID:                 {ID: SetgidEventID, ID32Bit: sys32setgid, Name: "setgid", Probes: []Probe{{Event: "setgid", Attach: SysCall, Fn: "setgid"}}, Sets: []string{"default", "syscalls", "proc", "proc_ids"}},
	GeteuidEventID:                {ID: GeteuidEventID, ID32Bit: sys32geteuid, Name: "geteuid", Probes: []Probe{{Event: "geteuid", Attach: SysCall, Fn: "geteuid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	GetegidEventID:                {ID: GetegidEventID, ID32Bit: sys32getegid, Name: "getegid", Probes: []Probe{{Event: "getegid", Attach: SysCall, Fn: "getegid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SetpgidEventID:                {ID: SetpgidEventID, ID32Bit: sys32setpgid, Name: "setpgid", Probes: []Probe{{Event: "setpgid", Attach: SysCall, Fn: "setpgid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	GetppidEventID:                {ID: GetppidEventID, ID32Bit: sys32getppid, Name: "getppid", Probes: []Probe{{Event: "getppid", Attach: SysCall, Fn: "getppid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	GetpgrpEventID:                {ID: GetpgrpEventID, ID32Bit: sys32getpgrp, Name: "getpgrp", Probes: []Probe{{Event: "getpgrp", Attach: SysCall, Fn: "getpgrp"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SetsidEventID:                 {ID: SetsidEventID, ID32Bit: sys32setsid, Name: "setsid", Probes: []Probe{{Event: "setsid", Attach: SysCall, Fn: "setsid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SetreuidEventID:               {ID: SetreuidEventID, ID32Bit: sys32setreuid, Name: "setreuid", Probes: []Probe{{Event: "setreuid", Attach: SysCall, Fn: "setreuid"}}, Sets: []string{"default", "syscalls", "proc", "proc_ids"}},
	SetregidEventID:               {ID: SetregidEventID, ID32Bit: sys32setregid, Name: "setregid", Probes: []Probe{{Event: "setregid", Attach: SysCall, Fn: "setregid"}}, Sets: []string{"default", "syscalls", "proc", "proc_ids"}},
	GetgroupsEventID:              {ID: GetgroupsEventID, ID32Bit: sys32getgroups, Name: "getgroups", Probes: []Probe{{Event: "getgroups", Attach: SysCall, Fn: "getgroups"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SetgroupsEventID:              {ID: SetgroupsEventID, ID32Bit: sys32setgroups, Name: "setgroups", Probes: []Probe{{Event: "setgroups", Attach: SysCall, Fn: "setgroups"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SetresuidEventID:              {ID: SetresuidEventID, ID32Bit: sys32setresuid, Name: "setresuid", Probes: []Probe{{Event: "setresuid", Attach: SysCall, Fn: "setresuid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	GetresuidEventID:              {ID: GetresuidEventID, ID32Bit: sys32getresuid, Name: "getresuid", Probes: []Probe{{Event: "getresuid", Attach: SysCall, Fn: "getresuid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SetresgidEventID:              {ID: SetresgidEventID, ID32Bit: sys32setresgid, Name: "setresgid", Probes: []Probe{{Event: "setresgid", Attach: SysCall, Fn: "setresgid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	GetresgidEventID:              {ID: GetresgidEventID, ID32Bit: sys32getresgid, Name: "getresgid", Probes: []Probe{{Event: "getresgid", Attach: SysCall, Fn: "getresgid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	GetpgidEventID:                {ID: GetpgidEventID, ID32Bit: sys32getpgid, Name: "getpgid", Probes: []Probe{{Event: "getpgid", Attach: SysCall, Fn: "getpgid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SetfsuidEventID:               {ID: SetfsuidEventID, ID32Bit: sys32setfsuid, Name: "setfsuid", Probes: []Probe{{Event: "setfsuid", Attach: SysCall, Fn: "setfsuid"}}, Sets: []string{"default", "syscalls", "proc", "proc_ids"}},
	SetfsgidEventID:               {ID: SetfsgidEventID, ID32Bit: sys32setfsgid, Name: "setfsgid", Probes: []Probe{{Event: "setfsgid", Attach: SysCall, Fn: "setfsgid"}}, Sets: []string{"default", "syscalls", "proc", "proc_ids"}},
	GetsidEventID:                 {ID: GetsidEventID, ID32Bit: sys32getsid, Name: "getsid", Probes: []Probe{{Event: "getsid", Attach: SysCall, Fn: "getsid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	CapgetEventID:                 {ID: CapgetEventID, ID32Bit: sys32capget, Name: "capget", Probes: []Probe{{Event: "capget", Attach: SysCall, Fn: "capget"}}, Sets: []string{"syscalls", "proc"}},
	CapsetEventID:                 {ID: CapsetEventID, ID32Bit: sys32capset, Name: "capset", Probes: []Probe{{Event: "capset", Attach: SysCall, Fn: "capset"}}, Sets: []string{"syscalls", "proc"}},
	RtSigpendingEventID:           {ID: RtSigpendingEventID, ID32Bit: sys32rt_sigpending, Name: "rt_sigpending", Probes: []Probe{{Event: "rt_sigpending", Attach: SysCall, Fn: "rt_sigpending"}}, Sets: []string{"syscalls", "signals"}},
	RtSigtimedwaitEventID:         {ID: RtSigtimedwaitEventID, ID32Bit: sys32rt_sigtimedwait, Name: "rt_sigtimedwait", Probes: []Probe{{Event: "rt_sigtimedwait", Attach: SysCall, Fn: "rt_sigtimedwait"}}, Sets: []string{"syscalls", "signals"}},
	RtSigqueueinfoEventID:         {ID: RtSigqueueinfoEventID, ID32Bit: sys32rt_sigqueueinfo, Name: "rt_sigqueueinfo", Probes: []Probe{{Event: "rt_sigqueueinfo", Attach: SysCall, Fn: "rt_sigqueueinfo"}}, Sets: []string{"syscalls", "signals"}},
	RtSigsuspendEventID:           {ID: RtSigsuspendEventID, ID32Bit: sys32rt_sigsuspend, Name: "rt_sigsuspend", Probes: []Probe{{Event: "rt_sigsuspend", Attach: SysCall, Fn: "rt_sigsuspend"}}, Sets: []string{"syscalls", "signals"}},
	SigaltstackEventID:            {ID: SigaltstackEventID, ID32Bit: sys32sigaltstack, Name: "sigaltstack", Probes: []Probe{{Event: "sigaltstack", Attach: SysCall, Fn: "sigaltstack"}}, Sets: []string{"syscalls", "signals"}},
	UtimeEventID:                  {ID: UtimeEventID, ID32Bit: sys32utime, Name: "utime", Probes: []Probe{{Event: "utime", Attach: SysCall, Fn: "utime"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	MknodEventID:                  {ID: MknodEventID, ID32Bit: sys32mknod, Name: "mknod", Probes: []Probe{{Event: "mknod", Attach: SysCall, Fn: "mknod"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	UselibEventID:                 {ID: UselibEventID, ID32Bit: sys32uselib, Name: "uselib", Probes: []Probe{{Event: "uselib", Attach: SysCall, Fn: "uselib"}}, Sets: []string{"syscalls", "proc"}},
	PersonalityEventID:            {ID: PersonalityEventID, ID32Bit: sys32personality, Name: "personality", Probes: []Probe{{Event: "personality", Attach: SysCall, Fn: "personality"}}, Sets: []string{"syscalls", "system"}},
	UstatEventID:                  {ID: UstatEventID, ID32Bit: sys32ustat, Name: "ustat", Probes: []Probe{{Event: "ustat", Attach: SysCall, Fn: "ustat"}}, Sets: []string{"syscalls", "fs", "fs_info"}},
	StatfsEventID:                 {ID: StatfsEventID, ID32Bit: sys32statfs, Name: "statfs", Probes: []Probe{{Event: "statfs", Attach: SysCall, Fn: "statfs"}}, Sets: []string{"syscalls", "fs", "fs_info"}},
	FstatfsEventID:                {ID: FstatfsEventID, ID32Bit: sys32fstatfs, Name: "fstatfs", Probes: []Probe{{Event: "fstatfs", Attach: SysCall, Fn: "fstatfs"}}, Sets: []string{"syscalls", "fs", "fs_info"}},
	SysfsEventID:                  {ID: SysfsEventID, ID32Bit: sys32sysfs, Name: "sysfs", Probes: []Probe{{Event: "sysfs", Attach: SysCall, Fn: "sysfs"}}, Sets: []string{"syscalls", "fs", "fs_info"}},
	GetpriorityEventID:            {ID: GetpriorityEventID, ID32Bit: sys32getpriority, Name: "getpriority", Probes: []Probe{{Event: "getpriority", Attach: SysCall, Fn: "getpriority"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SetpriorityEventID:            {ID: SetpriorityEventID, ID32Bit: sys32setpriority, Name: "setpriority", Probes: []Probe{{Event: "setpriority", Attach: SysCall, Fn: "setpriority"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedSetparamEventID:          {ID: SchedSetparamEventID, ID32Bit: sys32sched_setparam, Name: "sched_setparam", Probes: []Probe{{Event: "sched_setparam", Attach: SysCall, Fn: "sched_setparam"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedGetparamEventID:          {ID: SchedGetparamEventID, ID32Bit: sys32sched_getparam, Name: "sched_getparam", Probes: []Probe{{Event: "sched_getparam", Attach: SysCall, Fn: "sched_getparam"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedSetschedulerEventID:      {ID: SchedSetschedulerEventID, ID32Bit: sys32sched_setscheduler, Name: "sched_setscheduler", Probes: []Probe{{Event: "sched_setscheduler", Attach: SysCall, Fn: "sched_setscheduler"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedGetschedulerEventID:      {ID: SchedGetschedulerEventID, ID32Bit: sys32sched_getscheduler, Name: "sched_getscheduler", Probes: []Probe{{Event: "sched_getscheduler", Attach: SysCall, Fn: "sched_getscheduler"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedGetPriorityMaxEventID:    {ID: SchedGetPriorityMaxEventID, ID32Bit: sys32sched_get_priority_max, Name: "sched_get_priority_max", Probes: []Probe{{Event: "sched_get_priority_max", Attach: SysCall, Fn: "sched_get_priority_max"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedGetPriorityMinEventID:    {ID: SchedGetPriorityMinEventID, ID32Bit: sys32sched_get_priority_min, Name: "sched_get_priority_min", Probes: []Probe{{Event: "sched_get_priority_min", Attach: SysCall, Fn: "sched_get_priority_min"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedRrGetIntervalEventID:     {ID: SchedRrGetIntervalEventID, ID32Bit: sys32sched_rr_get_interval, Name: "sched_rr_get_interval", Probes: []Probe{{Event: "sched_rr_get_interval", Attach: SysCall, Fn: "sched_rr_get_interval"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	MlockEventID:                  {ID: MlockEventID, ID32Bit: sys32mlock, Name: "mlock", Probes: []Probe{{Event: "mlock", Attach: SysCall, Fn: "mlock"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	MunlockEventID:                {ID: MunlockEventID, ID32Bit: sys32munlock, Name: "munlock", Probes: []Probe{{Event: "munlock", Attach: SysCall, Fn: "munlock"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	MlockallEventID:               {ID: MlockallEventID, ID32Bit: sys32mlockall, Name: "mlockall", Probes: []Probe{{Event: "mlockall", Attach: SysCall, Fn: "mlockall"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	MunlockallEventID:             {ID: MunlockallEventID, ID32Bit: sys32munlockall, Name: "munlockall", Probes: []Probe{{Event: "munlockall", Attach: SysCall, Fn: "munlockall"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	VhangupEventID:                {ID: VhangupEventID, ID32Bit: sys32vhangup, Name: "vhangup", Probes: []Probe{{Event: "vhangup", Attach: SysCall, Fn: "vhangup"}}, Sets: []string{"syscalls", "system"}},
	ModifyLdtEventID:              {ID: ModifyLdtEventID, ID32Bit: sys32modify_ldt, Name: "modify_ldt", Probes: []Probe{{Event: "modify_ldt", Attach: SysCall, Fn: "modify_ldt"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	PivotRootEventID:              {ID: PivotRootEventID, ID32Bit: sys32pivot_root, Name: "pivot_root", Probes: []Probe{{Event: "pivot_root", Attach: SysCall, Fn: "pivot_root"}}, Sets: []string{"syscalls", "fs"}},
	SysctlEventID:                 {ID: SysctlEventID, ID32Bit: sys32undefined, Name: "sysctl", Probes: []Probe{{Event: "sysctl", Attach: SysCall, Fn: "sysctl"}}, Sets: []string{"syscalls", "system"}},
	PrctlEventID:                  {ID: PrctlEventID, ID32Bit: sys32prctl, Name: "prctl", Probes: []Probe{{Event: "prctl", Attach: SysCall, Fn: "prctl"}}, Sets: []string{"default", "syscalls", "proc"}},
	ArchPrctlEventID:              {ID: ArchPrctlEventID, ID32Bit: sys32arch_prctl, Name: "arch_prctl", Probes: []Probe{{Event: "arch_prctl", Attach: SysCall, Fn: "arch_prctl"}}, Sets: []string{"syscalls", "proc"}},
	AdjtimexEventID:               {ID: AdjtimexEventID, ID32Bit: sys32adjtimex, Name: "adjtimex", Probes: []Probe{{Event: "adjtimex", Attach: SysCall, Fn: "adjtimex"}}, Sets: []string{"syscalls", "time", "time_clock"}},
	SetrlimitEventID:              {ID: SetrlimitEventID, ID32Bit: sys32setrlimit, Name: "setrlimit", Probes: []Probe{{Event: "setrlimit", Attach: SysCall, Fn: "setrlimit"}}, Sets: []string{"syscalls", "proc"}},
	ChrootEventID:                 {ID: ChrootEventID, ID32Bit: sys32chroot, Name: "chroot", Probes: []Probe{{Event: "chroot", Attach: SysCall, Fn: "chroot"}}, Sets: []string{"syscalls", "fs", "fs_dir_ops"}},
	SyncEventID:                   {ID: SyncEventID, ID32Bit: sys32sync, Name: "sync", Probes: []Probe{{Event: "sync", Attach: SysCall, Fn: "sync"}}, Sets: []string{"syscalls", "fs", "fs_sync"}},
	AcctEventID:                   {ID: AcctEventID, ID32Bit: sys32acct, Name: "acct", Probes: []Probe{{Event: "acct", Attach: SysCall, Fn: "acct"}}, Sets: []string{"syscalls", "system"}},
	SettimeofdayEventID:           {ID: SettimeofdayEventID, ID32Bit: sys32settimeofday, Name: "settimeofday", Probes: []Probe{{Event: "settimeofday", Attach: SysCall, Fn: "settimeofday"}}, Sets: []string{"syscalls", "time", "time_tod"}},
	MountEventID:                  {ID: MountEventID, ID32Bit: sys32mount, Name: "mount", Probes: []Probe{{Event: "mount", Attach: SysCall, Fn: "mount"}}, Sets: []string{"default", "syscalls", "fs"}},
	UmountEventID:                 {ID: UmountEventID, ID32Bit: sys32umount, Name: "umount", Probes: []Probe{{Event: "umount", Attach: SysCall, Fn: "umount"}}, Sets: []string{"default", "syscalls", "fs"}},
	SwaponEventID:                 {ID: SwaponEventID, ID32Bit: sys32swapon, Name: "swapon", Probes: []Probe{{Event: "swapon", Attach: SysCall, Fn: "swapon"}}, Sets: []string{"syscalls", "fs"}},
	SwapoffEventID:                {ID: SwapoffEventID, ID32Bit: sys32swapoff, Name: "swapoff", Probes: []Probe{{Event: "swapoff", Attach: SysCall, Fn: "swapoff"}}, Sets: []string{"syscalls", "fs"}},
	RebootEventID:                 {ID: RebootEventID, ID32Bit: sys32reboot, Name: "reboot", Probes: []Probe{{Event: "reboot", Attach: SysCall, Fn: "reboot"}}, Sets: []string{"syscalls", "system"}},
	SethostnameEventID:            {ID: SethostnameEventID, ID32Bit: sys32sethostname, Name: "sethostname", Probes: []Probe{{Event: "sethostname", Attach: SysCall, Fn: "sethostname"}}, Sets: []string{"syscalls", "net"}},
	SetdomainnameEventID:          {ID: SetdomainnameEventID, ID32Bit: sys32setdomainname, Name: "setdomainname", Probes: []Probe{{Event: "setdomainname", Attach: SysCall, Fn: "setdomainname"}}, Sets: []string{"syscalls", "net"}},
	IoplEventID:                   {ID: IoplEventID, ID32Bit: sys32iopl, Name: "iopl", Probes: []Probe{{Event: "iopl", Attach: SysCall, Fn: "iopl"}}, Sets: []string{"syscalls", "system"}},
	IopermEventID:                 {ID: IopermEventID, ID32Bit: sys32ioperm, Name: "ioperm", Probes: []Probe{{Event: "ioperm", Attach: SysCall, Fn: "ioperm"}}, Sets: []string{"syscalls", "system"}},
	CreateModuleEventID:           {ID: CreateModuleEventID, ID32Bit: sys32create_module, Name: "create_module", Probes: []Probe{{Event: "create_module", Attach: SysCall, Fn: "create_module"}}, Sets: []string{"syscalls", "system", "system_module"}},
	InitModuleEventID:             {ID: InitModuleEventID, ID32Bit: sys32init_module, Name: "init_module", Probes: []Probe{{Event: "init_module", Attach: SysCall, Fn: "init_module"}}, Sets: []string{"default", "syscalls", "system", "system_module"}},
	DeleteModuleEventID:           {ID: DeleteModuleEventID, ID32Bit: sys32delete_module, Name: "delete_module", Probes: []Probe{{Event: "delete_module", Attach: SysCall, Fn: "delete_module"}}, Sets: []string{"default", "syscalls", "system", "system_module"}},
	GetKernelSymsEventID:          {ID: GetKernelSymsEventID, ID32Bit: sys32get_kernel_syms, Name: "get_kernel_syms", Probes: []Probe{{Event: "get_kernel_syms", Attach: SysCall, Fn: "get_kernel_syms"}}, Sets: []string{"syscalls", "system", "system_module"}},
	QueryModuleEventID:            {ID: QueryModuleEventID, ID32Bit: sys32query_module, Name: "query_module", Probes: []Probe{{Event: "query_module", Attach: SysCall, Fn: "query_module"}}, Sets: []string{"syscalls", "system", "system_module"}},
	QuotactlEventID:               {ID: QuotactlEventID, ID32Bit: sys32quotactl, Name: "quotactl", Probes: []Probe{{Event: "quotactl", Attach: SysCall, Fn: "quotactl"}}, Sets: []string{"syscalls", "system"}},
	NfsservctlEventID:             {ID: NfsservctlEventID, ID32Bit: sys32nfsservctl, Name: "nfsservctl", Probes: []Probe{{Event: "nfsservctl", Attach: SysCall, Fn: "nfsservctl"}}, Sets: []string{"syscalls", "fs"}},
	GetpmsgEventID:                {ID: GetpmsgEventID, ID32Bit: sys32getpmsg, Name: "getpmsg", Probes: []Probe{{Event: "getpmsg", Attach: SysCall, Fn: "getpmsg"}}, Sets: []string{"syscalls"}},
	PutpmsgEventID:                {ID: PutpmsgEventID, ID32Bit: sys32putpmsg, Name: "putpmsg", Probes: []Probe{{Event: "putpmsg", Attach: SysCall, Fn: "putpmsg"}}, Sets: []string{"syscalls"}},
	AfsEventID:                    {ID: AfsEventID, ID32Bit: sys32undefined, Name: "afs", Probes: []Probe{{Event: "afs", Attach: SysCall, Fn: "afs"}}, Sets: []string{"syscalls"}},
	TuxcallEventID:                {ID: TuxcallEventID, ID32Bit: sys32undefined, Name: "tuxcall", Probes: []Probe{{Event: "tuxcall", Attach: SysCall, Fn: "tuxcall"}}, Sets: []string{"syscalls"}},
	SecurityEventID:               {ID: SecurityEventID, ID32Bit: sys32undefined, Name: "security", Probes: []Probe{{Event: "security", Attach: SysCall, Fn: "security"}}, Sets: []string{"syscalls"}},
	GettidEventID:                 {ID: GettidEventID, ID32Bit: sys32gettid, Name: "gettid", Probes: []Probe{{Event: "gettid", Attach: SysCall, Fn: "gettid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	ReadaheadEventID:              {ID: ReadaheadEventID, ID32Bit: sys32readahead, Name: "readahead", Probes: []Probe{{Event: "readahead", Attach: SysCall, Fn: "readahead"}}, Sets: []string{"syscalls", "fs"}},
	SetxattrEventID:               {ID: SetxattrEventID, ID32Bit: sys32setxattr, Name: "setxattr", Probes: []Probe{{Event: "setxattr", Attach: SysCall, Fn: "setxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	LsetxattrEventID:              {ID: LsetxattrEventID, ID32Bit: sys32lsetxattr, Name: "lsetxattr", Probes: []Probe{{Event: "lsetxattr", Attach: SysCall, Fn: "lsetxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	FsetxattrEventID:              {ID: FsetxattrEventID, ID32Bit: sys32fsetxattr, Name: "fsetxattr", Probes: []Probe{{Event: "fsetxattr", Attach: SysCall, Fn: "fsetxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	GetxattrEventID:               {ID: GetxattrEventID, ID32Bit: sys32getxattr, Name: "getxattr", Probes: []Probe{{Event: "getxattr", Attach: SysCall, Fn: "getxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	LgetxattrEventID:              {ID: LgetxattrEventID, ID32Bit: sys32lgetxattr, Name: "lgetxattr", Probes: []Probe{{Event: "lgetxattr", Attach: SysCall, Fn: "lgetxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	FgetxattrEventID:              {ID: FgetxattrEventID, ID32Bit: sys32fgetxattr, Name: "fgetxattr", Probes: []Probe{{Event: "fgetxattr", Attach: SysCall, Fn: "fgetxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	ListxattrEventID:              {ID: ListxattrEventID, ID32Bit: sys32listxattr, Name: "listxattr", Probes: []Probe{{Event: "listxattr", Attach: SysCall, Fn: "listxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	LlistxattrEventID:             {ID: LlistxattrEventID, ID32Bit: sys32llistxattr, Name: "llistxattr", Probes: []Probe{{Event: "llistxattr", Attach: SysCall, Fn: "llistxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	FlistxattrEventID:             {ID: FlistxattrEventID, ID32Bit: sys32flistxattr, Name: "flistxattr", Probes: []Probe{{Event: "flistxattr", Attach: SysCall, Fn: "flistxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	RemovexattrEventID:            {ID: RemovexattrEventID, ID32Bit: sys32removexattr, Name: "removexattr", Probes: []Probe{{Event: "removexattr", Attach: SysCall, Fn: "removexattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	LremovexattrEventID:           {ID: LremovexattrEventID, ID32Bit: sys32lremovexattr, Name: "lremovexattr", Probes: []Probe{{Event: "lremovexattr", Attach: SysCall, Fn: "lremovexattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	FremovexattrEventID:           {ID: FremovexattrEventID, ID32Bit: sys32fremovexattr, Name: "fremovexattr", Probes: []Probe{{Event: "fremovexattr", Attach: SysCall, Fn: "fremovexattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	TkillEventID:                  {ID: TkillEventID, ID32Bit: sys32tkill, Name: "tkill", Probes: []Probe{{Event: "tkill", Attach: SysCall, Fn: "tkill"}}, Sets: []string{"syscalls", "signals"}},
	TimeEventID:                   {ID: TimeEventID, ID32Bit: sys32time, Name: "time", Probes: []Probe{{Event: "time", Attach: SysCall, Fn: "time"}}, Sets: []string{"syscalls", "time", "time_tod"}},
	FutexEventID:                  {ID: FutexEventID, ID32Bit: sys32futex, Name: "futex", Probes: []Probe{{Event: "futex", Attach: SysCall, Fn: "futex"}}, Sets: []string{"syscalls", "ipc", "ipc_futex"}},
	SchedSetaffinityEventID:       {ID: SchedSetaffinityEventID, ID32Bit: sys32sched_setaffinity, Name: "sched_setaffinity", Probes: []Probe{{Event: "sched_setaffinity", Attach: SysCall, Fn: "sched_setaffinity"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedGetaffinityEventID:       {ID: SchedGetaffinityEventID, ID32Bit: sys32sched_getaffinity, Name: "sched_getaffinity", Probes: []Probe{{Event: "sched_getaffinity", Attach: SysCall, Fn: "sched_getaffinity"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SetThreadAreaEventID:          {ID: SetThreadAreaEventID, ID32Bit: sys32set_thread_area, Name: "set_thread_area", Probes: []Probe{{Event: "set_thread_area", Attach: SysCall, Fn: "set_thread_area"}}, Sets: []string{"syscalls", "proc"}},
	IoSetupEventID:                {ID: IoSetupEventID, ID32Bit: sys32io_setup, Name: "io_setup", Probes: []Probe{{Event: "io_setup", Attach: SysCall, Fn: "io_setup"}}, Sets: []string{"syscalls", "fs", "fs_async_io"}},
	IoDestroyEventID:              {ID: IoDestroyEventID, ID32Bit: sys32io_destroy, Name: "io_destroy", Probes: []Probe{{Event: "io_destroy", Attach: SysCall, Fn: "io_destroy"}}, Sets: []string{"syscalls", "fs", "fs_async_io"}},
	IoGeteventsEventID:            {ID: IoGeteventsEventID, ID32Bit: sys32io_getevents, Name: "io_getevents", Probes: []Probe{{Event: "io_getevents", Attach: SysCall, Fn: "io_getevents"}}, Sets: []string{"syscalls", "fs", "fs_async_io"}},
	IoSubmitEventID:               {ID: IoSubmitEventID, ID32Bit: sys32io_submit, Name: "io_submit", Probes: []Probe{{Event: "io_submit", Attach: SysCall, Fn: "io_submit"}}, Sets: []string{"syscalls", "fs", "fs_async_io"}},
	IoCancelEventID:               {ID: IoCancelEventID, ID32Bit: sys32io_cancel, Name: "io_cancel", Probes: []Probe{{Event: "io_cancel", Attach: SysCall, Fn: "io_cancel"}}, Sets: []string{"syscalls", "fs", "fs_async_io"}},
	GetThreadAreaEventID:          {ID: GetThreadAreaEventID, ID32Bit: sys32get_thread_area, Name: "get_thread_area", Probes: []Probe{{Event: "get_thread_area", Attach: SysCall, Fn: "get_thread_area"}}, Sets: []string{"syscalls", "proc"}},
	LookupDcookieEventID:          {ID: LookupDcookieEventID, ID32Bit: sys32lookup_dcookie, Name: "lookup_dcookie", Probes: []Probe{{Event: "lookup_dcookie", Attach: SysCall, Fn: "lookup_dcookie"}}, Sets: []string{"syscalls", "fs", "fs_dir_ops"}},
	EpollCreateEventID:            {ID: EpollCreateEventID, ID32Bit: sys32epoll_create, Name: "epoll_create", Probes: []Probe{{Event: "epoll_create", Attach: SysCall, Fn: "epoll_create"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	EpollCtlOldEventID:            {ID: EpollCtlOldEventID, ID32Bit: sys32undefined, Name: "epoll_ctl_old", Probes: []Probe{{Event: "epoll_ctl_old", Attach: SysCall, Fn: "epoll_ctl_old"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	EpollWaitOldEventID:           {ID: EpollWaitOldEventID, ID32Bit: sys32undefined, Name: "epoll_wait_old", Probes: []Probe{{Event: "epoll_wait_old", Attach: SysCall, Fn: "epoll_wait_old"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	RemapFilePagesEventID:         {ID: RemapFilePagesEventID, ID32Bit: sys32remap_file_pages, Name: "remap_file_pages", Probes: []Probe{{Event: "remap_file_pages", Attach: SysCall, Fn: "remap_file_pages"}}, Sets: []string{"syscalls"}},
	Getdents64EventID:             {ID: Getdents64EventID, ID32Bit: sys32getdents64, Name: "getdents64", Probes: []Probe{{Event: "getdents64", Attach: SysCall, Fn: "getdents64"}}, Sets: []string{"default", "syscalls", "fs", "fs_dir_ops"}},
	SetTidAddressEventID:          {ID: SetTidAddressEventID, ID32Bit: sys32set_tid_address, Name: "set_tid_address", Probes: []Probe{{Event: "set_tid_address", Attach: SysCall, Fn: "set_tid_address"}}, Sets: []string{"syscalls", "proc"}},
	RestartSyscallEventID:         {ID: RestartSyscallEventID, ID32Bit: sys32restart_syscall, Name: "restart_syscall", Probes: []Probe{{Event: "restart_syscall", Attach: SysCall, Fn: "restart_syscall"}}, Sets: []string{"syscalls", "signals"}},
	SemtimedopEventID:             {ID: SemtimedopEventID, ID32Bit: sys32semtimedop_time64, Name: "semtimedop", Probes: []Probe{{Event: "semtimedop", Attach: SysCall, Fn: "semtimedop"}}, Sets: []string{"syscalls", "ipc", "ipc_sem"}},
	Fadvise64EventID:              {ID: Fadvise64EventID, ID32Bit: sys32fadvise64, Name: "fadvise64", Probes: []Probe{{Event: "fadvise64", Attach: SysCall, Fn: "fadvise64"}}, Sets: []string{"syscalls", "fs"}},
	TimerCreateEventID:            {ID: TimerCreateEventID, ID32Bit: sys32timer_create, Name: "timer_create", Probes: []Probe{{Event: "timer_create", Attach: SysCall, Fn: "timer_create"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	TimerSettimeEventID:           {ID: TimerSettimeEventID, ID32Bit: sys32timer_settime, Name: "timer_settime", Probes: []Probe{{Event: "timer_settime", Attach: SysCall, Fn: "timer_settime"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	TimerGettimeEventID:           {ID: TimerGettimeEventID, ID32Bit: sys32timer_gettime, Name: "timer_gettime", Probes: []Probe{{Event: "timer_gettime", Attach: SysCall, Fn: "timer_gettime"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	TimerGetoverrunEventID:        {ID: TimerGetoverrunEventID, ID32Bit: sys32timer_getoverrun, Name: "timer_getoverrun", Probes: []Probe{{Event: "timer_getoverrun", Attach: SysCall, Fn: "timer_getoverrun"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	TimerDeleteEventID:            {ID: TimerDeleteEventID, ID32Bit: sys32timer_delete, Name: "timer_delete", Probes: []Probe{{Event: "timer_delete", Attach: SysCall, Fn: "timer_delete"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	ClockSettimeEventID:           {ID: ClockSettimeEventID, ID32Bit: sys32clock_settime, Name: "clock_settime", Probes: []Probe{{Event: "clock_settime", Attach: SysCall, Fn: "clock_settime"}}, Sets: []string{"syscalls", "time", "time_clock"}},
	ClockGettimeEventID:           {ID: ClockGettimeEventID, ID32Bit: sys32clock_gettime, Name: "clock_gettime", Probes: []Probe{{Event: "clock_gettime", Attach: SysCall, Fn: "clock_gettime"}}, Sets: []string{"syscalls", "time", "time_clock"}},
	ClockGetresEventID:            {ID: ClockGetresEventID, ID32Bit: sys32clock_getres, Name: "clock_getres", Probes: []Probe{{Event: "clock_getres", Attach: SysCall, Fn: "clock_getres"}}, Sets: []string{"syscalls", "time", "time_clock"}},
	ClockNanosleepEventID:         {ID: ClockNanosleepEventID, ID32Bit: sys32clock_nanosleep, Name: "clock_nanosleep", Probes: []Probe{{Event: "clock_nanosleep", Attach: SysCall, Fn: "clock_nanosleep"}}, Sets: []string{"syscalls", "time", "time_clock"}},
	ExitGroupEventID:              {ID: ExitGroupEventID, ID32Bit: sys32exit_group, Name: "exit_group", Probes: []Probe{{Event: "exit_group", Attach: SysCall, Fn: "exit_group"}}, Sets: []string{"syscalls", "proc", "proc_life"}},
	EpollWaitEventID:              {ID: EpollWaitEventID, ID32Bit: sys32epoll_wait, Name: "epoll_wait", Probes: []Probe{{Event: "epoll_wait", Attach: SysCall, Fn: "epoll_wait"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	EpollCtlEventID:               {ID: EpollCtlEventID, ID32Bit: sys32epoll_ctl, Name: "epoll_ctl", Probes: []Probe{{Event: "epoll_ctl", Attach: SysCall, Fn: "epoll_ctl"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	TgkillEventID:                 {ID: TgkillEventID, ID32Bit: sys32tgkill, Name: "tgkill", Probes: []Probe{{Event: "tgkill", Attach: SysCall, Fn: "tgkill"}}, Sets: []string{"syscalls", "signals"}},
	UtimesEventID:                 {ID: UtimesEventID, ID32Bit: sys32utimes, Name: "utimes", Probes: []Probe{{Event: "utimes", Attach: SysCall, Fn: "utimes"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	VserverEventID:                {ID: VserverEventID, ID32Bit: sys32vserver, Name: "vserver", Probes: []Probe{{Event: "vserver", Attach: SysCall, Fn: "vserver"}}, Sets: []string{"syscalls"}},
	MbindEventID:                  {ID: MbindEventID, ID32Bit: sys32mbind, Name: "mbind", Probes: []Probe{{Event: "mbind", Attach: SysCall, Fn: "mbind"}}, Sets: []string{"syscalls", "system", "system_numa"}},
	SetMempolicyEventID:           {ID: SetMempolicyEventID, ID32Bit: sys32set_mempolicy, Name: "set_mempolicy", Probes: []Probe{{Event: "set_mempolicy", Attach: SysCall, Fn: "set_mempolicy"}}, Sets: []string{"syscalls", "system", "system_numa"}},
	GetMempolicyEventID:           {ID: GetMempolicyEventID, ID32Bit: sys32get_mempolicy, Name: "get_mempolicy", Probes: []Probe{{Event: "get_mempolicy", Attach: SysCall, Fn: "get_mempolicy"}}, Sets: []string{"syscalls", "system", "system_numa"}},
	MqOpenEventID:                 {ID: MqOpenEventID, ID32Bit: sys32mq_open, Name: "mq_open", Probes: []Probe{{Event: "mq_open", Attach: SysCall, Fn: "mq_open"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	MqUnlinkEventID:               {ID: MqUnlinkEventID, ID32Bit: sys32mq_unlink, Name: "mq_unlink", Probes: []Probe{{Event: "mq_unlink", Attach: SysCall, Fn: "mq_unlink"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	MqTimedsendEventID:            {ID: MqTimedsendEventID, ID32Bit: sys32mq_timedsend, Name: "mq_timedsend", Probes: []Probe{{Event: "mq_timedsend", Attach: SysCall, Fn: "mq_timedsend"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	MqTimedreceiveEventID:         {ID: MqTimedreceiveEventID, ID32Bit: sys32mq_timedreceive, Name: "mq_timedreceive", Probes: []Probe{{Event: "mq_timedreceive", Attach: SysCall, Fn: "mq_timedreceive"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	MqNotifyEventID:               {ID: MqNotifyEventID, ID32Bit: sys32mq_notify, Name: "mq_notify", Probes: []Probe{{Event: "mq_notify", Attach: SysCall, Fn: "mq_notify"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	MqGetsetattrEventID:           {ID: MqGetsetattrEventID, ID32Bit: sys32mq_getsetattr, Name: "mq_getsetattr", Probes: []Probe{{Event: "mq_getsetattr", Attach: SysCall, Fn: "mq_getsetattr"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	KexecLoadEventID:              {ID: KexecLoadEventID, ID32Bit: sys32kexec_load, Name: "kexec_load", Probes: []Probe{{Event: "kexec_load", Attach: SysCall, Fn: "kexec_load"}}, Sets: []string{"syscalls", "system"}},
	WaitidEventID:                 {ID: WaitidEventID, ID32Bit: sys32waitid, Name: "waitid", Probes: []Probe{{Event: "waitid", Attach: SysCall, Fn: "waitid"}}, Sets: []string{"syscalls", "proc", "proc_life"}},
	AddKeyEventID:                 {ID: AddKeyEventID, ID32Bit: sys32add_key, Name: "add_key", Probes: []Probe{{Event: "add_key", Attach: SysCall, Fn: "add_key"}}, Sets: []string{"syscalls", "system", "system_keys"}},
	RequestKeyEventID:             {ID: RequestKeyEventID, ID32Bit: sys32request_key, Name: "request_key", Probes: []Probe{{Event: "request_key", Attach: SysCall, Fn: "request_key"}}, Sets: []string{"syscalls", "system", "system_keys"}},
	KeyctlEventID:                 {ID: KeyctlEventID, ID32Bit: sys32keyctl, Name: "keyctl", Probes: []Probe{{Event: "keyctl", Attach: SysCall, Fn: "keyctl"}}, Sets: []string{"syscalls", "system", "system_keys"}},
	IoprioSetEventID:              {ID: IoprioSetEventID, ID32Bit: sys32ioprio_set, Name: "ioprio_set", Probes: []Probe{{Event: "ioprio_set", Attach: SysCall, Fn: "ioprio_set"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	IoprioGetEventID:              {ID: IoprioGetEventID, ID32Bit: sys32ioprio_get, Name: "ioprio_get", Probes: []Probe{{Event: "ioprio_get", Attach: SysCall, Fn: "ioprio_get"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	InotifyInitEventID:            {ID: InotifyInitEventID, ID32Bit: sys32inotify_init, Name: "inotify_init", Probes: []Probe{{Event: "inotify_init", Attach: SysCall, Fn: "inotify_init"}}, Sets: []string{"syscalls", "fs", "fs_monitor"}},
	InotifyAddWatchEventID:        {ID: InotifyAddWatchEventID, ID32Bit: sys32inotify_add_watch, Name: "inotify_add_watch", Probes: []Probe{{Event: "inotify_add_watch", Attach: SysCall, Fn: "inotify_add_watch"}}, Sets: []string{"syscalls", "fs", "fs_monitor"}},
	InotifyRmWatchEventID:         {ID: InotifyRmWatchEventID, ID32Bit: sys32inotify_rm_watch, Name: "inotify_rm_watch", Probes: []Probe{{Event: "inotify_rm_watch", Attach: SysCall, Fn: "inotify_rm_watch"}}, Sets: []string{"syscalls", "fs", "fs_monitor"}},
	MigratePagesEventID:           {ID: MigratePagesEventID, ID32Bit: sys32migrate_pages, Name: "migrate_pages", Probes: []Probe{{Event: "migrate_pages", Attach: SysCall, Fn: "migrate_pages"}}, Sets: []string{"syscalls", "system", "system_numa"}},
	OpenatEventID:                 {ID: OpenatEventID, ID32Bit: sys32openat, Name: "openat", Probes: []Probe{{Event: "openat", Attach: SysCall, Fn: "openat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	MkdiratEventID:                {ID: MkdiratEventID, ID32Bit: sys32mkdirat, Name: "mkdirat", Probes: []Probe{{Event: "mkdirat", Attach: SysCall, Fn: "mkdirat"}}, Sets: []string{"syscalls", "fs", "fs_dir_ops"}},
	MknodatEventID:                {ID: MknodatEventID, ID32Bit: sys32mknodat, Name: "mknodat", Probes: []Probe{{Event: "mknodat", Attach: SysCall, Fn: "mknodat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	FchownatEventID:               {ID: FchownatEventID, ID32Bit: sys32fchownat, Name: "fchownat", Probes: []Probe{{Event: "fchownat", Attach: SysCall, Fn: "fchownat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	FutimesatEventID:              {ID: FutimesatEventID, ID32Bit: sys32futimesat, Name: "futimesat", Probes: []Probe{{Event: "futimesat", Attach: SysCall, Fn: "futimesat"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	NewfstatatEventID:             {ID: NewfstatatEventID, ID32Bit: sys32fstatat64, Name: "newfstatat", Probes: []Probe{{Event: "newfstatat", Attach: SysCall, Fn: "newfstatat"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	UnlinkatEventID:               {ID: UnlinkatEventID, ID32Bit: sys32unlinkat, Name: "unlinkat", Probes: []Probe{{Event: "unlinkat", Attach: SysCall, Fn: "unlinkat"}}, Sets: []string{"default", "syscalls", "fs", "fs_link_ops"}},
	RenameatEventID:               {ID: RenameatEventID, ID32Bit: sys32renameat, Name: "renameat", Probes: []Probe{{Event: "renameat", Attach: SysCall, Fn: "renameat"}}, Sets: []string{"syscalls", "fs", "fs_file_ops"}},
	LinkatEventID:                 {ID: LinkatEventID, ID32Bit: sys32linkat, Name: "linkat", Probes: []Probe{{Event: "linkat", Attach: SysCall, Fn: "linkat"}}, Sets: []string{"syscalls", "fs", "fs_link_ops"}},
	SymlinkatEventID:              {ID: SymlinkatEventID, ID32Bit: sys32symlinkat, Name: "symlinkat", Probes: []Probe{{Event: "symlinkat", Attach: SysCall, Fn: "symlinkat"}}, Sets: []string{"default", "syscalls", "fs", "fs_link_ops"}},
	ReadlinkatEventID:             {ID: ReadlinkatEventID, ID32Bit: sys32readlinkat, Name: "readlinkat", Probes: []Probe{{Event: "readlinkat", Attach: SysCall, Fn: "readlinkat"}}, Sets: []string{"syscalls", "fs", "fs_link_ops"}},
	FchmodatEventID:               {ID: FchmodatEventID, ID32Bit: sys32fchmodat, Name: "fchmodat", Probes: []Probe{{Event: "fchmodat", Attach: SysCall, Fn: "fchmodat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	FaccessatEventID:              {ID: FaccessatEventID, ID32Bit: sys32faccessat, Name: "faccessat", Probes: []Probe{{Event: "faccessat", Attach: SysCall, Fn: "faccessat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	Pselect6EventID:               {ID: Pselect6EventID, ID32Bit: sys32pselect6, Name: "pselect6", Probes: []Probe{{Event: "pselect6", Attach: SysCall, Fn: "pselect6"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	PpollEventID:                  {ID: PpollEventID, ID32Bit: sys32ppoll, Name: "ppoll", Probes: []Probe{{Event: "ppoll", Attach: SysCall, Fn: "ppoll"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	UnshareEventID:                {ID: UnshareEventID, ID32Bit: sys32unshare, Name: "unshare", Probes: []Probe{{Event: "unshare", Attach: SysCall, Fn: "unshare"}}, Sets: []string{"syscalls", "proc"}},
	SetRobustListEventID:          {ID: SetRobustListEventID, ID32Bit: sys32set_robust_list, Name: "set_robust_list", Probes: []Probe{{Event: "set_robust_list", Attach: SysCall, Fn: "set_robust_list"}}, Sets: []string{"syscalls", "ipc", "ipc_futex"}},
	GetRobustListEventID:          {ID: GetRobustListEventID, ID32Bit: sys32get_robust_list, Name: "get_robust_list", Probes: []Probe{{Event: "get_robust_list", Attach: SysCall, Fn: "get_robust_list"}}, Sets: []string{"syscalls", "ipc", "ipc_futex"}},
	SpliceEventID:                 {ID: SpliceEventID, ID32Bit: sys32splice, Name: "splice", Probes: []Probe{{Event: "splice", Attach: SysCall, Fn: "splice"}}, Sets: []string{"syscalls", "ipc", "ipc_pipe"}},
	TeeEventID:                    {ID: TeeEventID, ID32Bit: sys32tee, Name: "tee", Probes: []Probe{{Event: "tee", Attach: SysCall, Fn: "tee"}}, Sets: []string{"syscalls", "ipc", "ipc_pipe"}},
	SyncFileRangeEventID:          {ID: SyncFileRangeEventID, ID32Bit: sys32sync_file_range, Name: "sync_file_range", Probes: []Probe{{Event: "sync_file_range", Attach: SysCall, Fn: "sync_file_range"}}, Sets: []string{"syscalls", "fs", "fs_sync"}},
	VmspliceEventID:               {ID: VmspliceEventID, ID32Bit: sys32vmsplice, Name: "vmsplice", Probes: []Probe{{Event: "vmsplice", Attach: SysCall, Fn: "vmsplice"}}, Sets: []string{"syscalls", "ipc", "ipc_pipe"}},
	MovePagesEventID:              {ID: MovePagesEventID, ID32Bit: sys32move_pages, Name: "move_pages", Probes: []Probe{{Event: "move_pages", Attach: SysCall, Fn: "move_pages"}}, Sets: []string{"syscalls", "system", "system_numa"}},
	UtimensatEventID:              {ID: UtimensatEventID, ID32Bit: sys32utimensat, Name: "utimensat", Probes: []Probe{{Event: "utimensat", Attach: SysCall, Fn: "utimensat"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	EpollPwaitEventID:             {ID: EpollPwaitEventID, ID32Bit: sys32epoll_pwait, Name: "epoll_pwait", Probes: []Probe{{Event: "epoll_pwait", Attach: SysCall, Fn: "epoll_pwait"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	SignalfdEventID:               {ID: SignalfdEventID, ID32Bit: sys32signalfd, Name: "signalfd", Probes: []Probe{{Event: "signalfd", Attach: SysCall, Fn: "signalfd"}}, Sets: []string{"syscalls", "signals"}},
	TimerfdCreateEventID:          {ID: TimerfdCreateEventID, ID32Bit: sys32timerfd_create, Name: "timerfd_create", Probes: []Probe{{Event: "timerfd_create", Attach: SysCall, Fn: "timerfd_create"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	EventfdEventID:                {ID: EventfdEventID, ID32Bit: sys32eventfd, Name: "eventfd", Probes: []Probe{{Event: "eventfd", Attach: SysCall, Fn: "eventfd"}}, Sets: []string{"syscalls", "signals"}},
	FallocateEventID:              {ID: FallocateEventID, ID32Bit: sys32fallocate, Name: "fallocate", Probes: []Probe{{Event: "fallocate", Attach: SysCall, Fn: "fallocate"}}, Sets: []string{"syscalls", "fs", "fs_file_ops"}},
	TimerfdSettimeEventID:         {ID: TimerfdSettimeEventID, ID32Bit: sys32timerfd_settime, Name: "timerfd_settime", Probes: []Probe{{Event: "timerfd_settime", Attach: SysCall, Fn: "timerfd_settime"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	TimerfdGettimeEventID:         {ID: TimerfdGettimeEventID, ID32Bit: sys32timerfd_gettime, Name: "timerfd_gettime", Probes: []Probe{{Event: "timerfd_gettime", Attach: SysCall, Fn: "timerfd_gettime"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	Accept4EventID:                {ID: Accept4EventID, ID32Bit: sys32accept4, Name: "accept4", Probes: []Probe{{Event: "accept4", Attach: SysCall, Fn: "accept4"}}, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	Signalfd4EventID:              {ID: Signalfd4EventID, ID32Bit: sys32signalfd4, Name: "signalfd4", Probes: []Probe{{Event: "signalfd4", Attach: SysCall, Fn: "signalfd4"}}, Sets: []string{"syscalls", "signals"}},
	Eventfd2EventID:               {ID: Eventfd2EventID, ID32Bit: sys32eventfd2, Name: "eventfd2", Probes: []Probe{{Event: "eventfd2", Attach: SysCall, Fn: "eventfd2"}}, Sets: []string{"syscalls", "signals"}},
	EpollCreate1EventID:           {ID: EpollCreate1EventID, ID32Bit: sys32epoll_create1, Name: "epoll_create1", Probes: []Probe{{Event: "epoll_create1", Attach: SysCall, Fn: "epoll_create1"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	Dup3EventID:                   {ID: Dup3EventID, ID32Bit: sys32dup3, Name: "dup3", Probes: []Probe{{Event: "dup3", Attach: SysCall, Fn: "dup3"}}, Sets: []string{"default", "syscalls", "fs", "fs_fd_ops"}},
	Pipe2EventID:                  {ID: Pipe2EventID, ID32Bit: sys32pipe2, Name: "pipe2", Probes: []Probe{{Event: "pipe2", Attach: SysCall, Fn: "pipe2"}}, Sets: []string{"syscalls", "ipc", "ipc_pipe"}},
	InotifyInit1EventID:           {ID: InotifyInit1EventID, ID32Bit: sys32inotify_init1, Name: "inotify_init1", Probes: []Probe{{Event: "inotify_init1", Attach: SysCall, Fn: "inotify_init1"}}, Sets: []string{"syscalls", "fs", "fs_monitor"}},
	PreadvEventID:                 {ID: PreadvEventID, ID32Bit: sys32preadv, Name: "preadv", Probes: []Probe{{Event: "preadv", Attach: SysCall, Fn: "preadv"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	PwritevEventID:                {ID: PwritevEventID, ID32Bit: sys32pwritev, Name: "pwritev", Probes: []Probe{{Event: "pwritev", Attach: SysCall, Fn: "pwritev"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	RtTgsigqueueinfoEventID:       {ID: RtTgsigqueueinfoEventID, ID32Bit: sys32rt_tgsigqueueinfo, Name: "rt_tgsigqueueinfo", Probes: []Probe{{Event: "rt_tgsigqueueinfo", Attach: SysCall, Fn: "rt_tgsigqueueinfo"}}, Sets: []string{"syscalls", "signals"}},
	PerfEventOpenEventID:          {ID: PerfEventOpenEventID, ID32Bit: sys32perf_event_open, Name: "perf_event_open", Probes: []Probe{{Event: "perf_event_open", Attach: SysCall, Fn: "perf_event_open"}}, Sets: []string{"syscalls", "system"}},
	RecvmmsgEventID:               {ID: RecvmmsgEventID, ID32Bit: sys32recvmmsg, Name: "recvmmsg", Probes: []Probe{{Event: "recvmmsg", Attach: SysCall, Fn: "recvmmsg"}}, Sets: []string{"syscalls", "net", "net_snd_rcv"}},
	FanotifyInitEventID:           {ID: FanotifyInitEventID, ID32Bit: sys32fanotify_init, Name: "fanotify_init", Probes: []Probe{{Event: "fanotify_init", Attach: SysCall, Fn: "fanotify_init"}}, Sets: []string{"syscalls", "fs", "fs_monitor"}},
	FanotifyMarkEventID:           {ID: FanotifyMarkEventID, ID32Bit: sys32fanotify_mark, Name: "fanotify_mark", Probes: []Probe{{Event: "fanotify_mark", Attach: SysCall, Fn: "fanotify_mark"}}, Sets: []string{"syscalls", "fs", "fs_monitor"}},
	Prlimit64EventID:              {ID: Prlimit64EventID, ID32Bit: sys32prlimit64, Name: "prlimit64", Probes: []Probe{{Event: "prlimit64", Attach: SysCall, Fn: "prlimit64"}}, Sets: []string{"syscalls", "proc"}},
	NameToHandleAtEventID:         {ID: NameToHandleAtEventID, ID32Bit: sys32name_to_handle_at, Name: "name_to_handle_at", Probes: []Probe{{Event: "name_to_handle_at", Attach: SysCall, Fn: "name_to_handle_at"}}, Sets: []string{"syscalls", "fs", "fs_file_ops"}},
	OpenByHandleAtEventID:         {ID: OpenByHandleAtEventID, ID32Bit: sys32open_by_handle_at, Name: "open_by_handle_at", Probes: []Probe{{Event: "open_by_handle_at", Attach: SysCall, Fn: "open_by_handle_at"}}, Sets: []string{"syscalls", "fs", "fs_file_ops"}},
	ClockAdjtimeEventID:           {ID: ClockAdjtimeEventID, ID32Bit: sys32clock_adjtime, Name: "clock_adjtime", Probes: []Probe{{Event: "clock_adjtime", Attach: SysCall, Fn: "clock_adjtime"}}, Sets: []string{"syscalls", "time", "time_clock"}},
	SyncfsEventID:                 {ID: SyncfsEventID, ID32Bit: sys32syncfs, Name: "syncfs", Probes: []Probe{{Event: "syncfs", Attach: SysCall, Fn: "syncfs"}}, Sets: []string{"syscalls", "fs", "fs_sync"}},
	SendmmsgEventID:               {ID: SendmmsgEventID, ID32Bit: sys32sendmmsg, Name: "sendmmsg", Probes: []Probe{{Event: "sendmmsg", Attach: SysCall, Fn: "sendmmsg"}}, Sets: []string{"syscalls", "net", "net_snd_rcv"}},
	SetnsEventID:                  {ID: SetnsEventID, ID32Bit: sys32setns, Name: "setns", Probes: []Probe{{Event: "setns", Attach: SysCall, Fn: "setns"}}, Sets: []string{"syscalls", "proc"}},
	GetcpuEventID:                 {ID: GetcpuEventID, ID32Bit: sys32getcpu, Name: "getcpu", Probes: []Probe{{Event: "getcpu", Attach: SysCall, Fn: "getcpu"}}, Sets: []string{"syscalls", "system", "system_numa"}},
	ProcessVmReadvEventID:         {ID: ProcessVmReadvEventID, ID32Bit: sys32process_vm_readv, Name: "process_vm_readv", Probes: []Probe{{Event: "process_vm_readv", Attach: SysCall, Fn: "process_vm_readv"}}, Sets: []string{"default", "syscalls", "proc"}},
	ProcessVmWritevEventID:        {ID: ProcessVmWritevEventID, ID32Bit: sys32process_vm_writev, Name: "process_vm_writev", Probes: []Probe{{Event: "process_vm_writev", Attach: SysCall, Fn: "process_vm_writev"}}, Sets: []string{"default", "syscalls", "proc"}},
	KcmpEventID:                   {ID: KcmpEventID, ID32Bit: sys32kcmp, Name: "kcmp", Probes: []Probe{{Event: "kcmp", Attach: SysCall, Fn: "kcmp"}}, Sets: []string{"syscalls", "proc"}},
	FinitModuleEventID:            {ID: FinitModuleEventID, ID32Bit: sys32finit_module, Name: "finit_module", Probes: []Probe{{Event: "finit_module", Attach: SysCall, Fn: "finit_module"}}, Sets: []string{"default", "syscalls", "system", "system_module"}},
	SchedSetattrEventID:           {ID: SchedSetattrEventID, ID32Bit: sys32sched_setattr, Name: "sched_setattr", Probes: []Probe{{Event: "sched_setattr", Attach: SysCall, Fn: "sched_setattr"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedGetattrEventID:           {ID: SchedGetattrEventID, ID32Bit: sys32sched_getattr, Name: "sched_getattr", Probes: []Probe{{Event: "sched_getattr", Attach: SysCall, Fn: "sched_getattr"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	Renameat2EventID:              {ID: Renameat2EventID, ID32Bit: sys32renameat2, Name: "renameat2", Probes: []Probe{{Event: "renameat2", Attach: SysCall, Fn: "renameat2"}}, Sets: []string{"syscalls", "fs", "fs_file_ops"}},
	SeccompEventID:                {ID: SeccompEventID, ID32Bit: sys32seccomp, Name: "seccomp", Probes: []Probe{{Event: "seccomp", Attach: SysCall, Fn: "seccomp"}}, Sets: []string{"syscalls", "proc"}},
	GetrandomEventID:              {ID: GetrandomEventID, ID32Bit: sys32getrandom, Name: "getrandom", Probes: []Probe{{Event: "getrandom", Attach: SysCall, Fn: "getrandom"}}, Sets: []string{"syscalls", "fs"}},
	MemfdCreateEventID:            {ID: MemfdCreateEventID, ID32Bit: sys32memfd_create, Name: "memfd_create", Probes: []Probe{{Event: "memfd_create", Attach: SysCall, Fn: "memfd_create"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	KexecFileLoadEventID:          {ID: KexecFileLoadEventID, ID32Bit: sys32undefined, Name: "kexec_file_load", Probes: []Probe{{Event: "kexec_file_load", Attach: SysCall, Fn: "kexec_file_load"}}, Sets: []string{"syscalls", "system"}},
	BpfEventID:                    {ID: BpfEventID, ID32Bit: sys32bpf, Name: "bpf", Probes: []Probe{{Event: "bpf", Attach: SysCall, Fn: "bpf"}}, Sets: []string{"default", "syscalls", "system"}},
	ExecveatEventID:               {ID: ExecveatEventID, ID32Bit: sys32execveat, Name: "execveat", Probes: []Probe{{Event: "execveat", Attach: SysCall, Fn: "execveat"}}, Sets: []string{"default", "syscalls", "proc", "proc_life"}},
	UserfaultfdEventID:            {ID: UserfaultfdEventID, ID32Bit: sys32userfaultfd, Name: "userfaultfd", Probes: []Probe{{Event: "userfaultfd", Attach: SysCall, Fn: "userfaultfd"}}, Sets: []string{"syscalls", "system"}},
	MembarrierEventID:             {ID: MembarrierEventID, ID32Bit: sys32membarrier, Name: "membarrier", Probes: []Probe{{Event: "membarrier", Attach: SysCall, Fn: "membarrier"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	Mlock2EventID:                 {ID: Mlock2EventID, ID32Bit: sys32mlock2, Name: "mlock2", Probes: []Probe{{Event: "mlock2", Attach: SysCall, Fn: "mlock2"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	CopyFileRangeEventID:          {ID: CopyFileRangeEventID, ID32Bit: sys32copy_file_range, Name: "copy_file_range", Probes: []Probe{{Event: "copy_file_range", Attach: SysCall, Fn: "copy_file_range"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	Preadv2EventID:                {ID: Preadv2EventID, ID32Bit: sys32preadv2, Name: "preadv2", Probes: []Probe{{Event: "preadv2", Attach: SysCall, Fn: "preadv2"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	Pwritev2EventID:               {ID: Pwritev2EventID, ID32Bit: sys32pwritev2, Name: "pwritev2", Probes: []Probe{{Event: "pwritev2", Attach: SysCall, Fn: "pwritev2"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	PkeyMprotectEventID:           {ID: PkeyMprotectEventID, ID32Bit: sys32pkey_mprotect, Name: "pkey_mprotect", Probes: []Probe{{Event: "pkey_mprotect", Attach: SysCall, Fn: "pkey_mprotect"}}, Sets: []string{"default", "syscalls", "proc", "proc_mem"}},
	PkeyAllocEventID:              {ID: PkeyAllocEventID, ID32Bit: sys32pkey_alloc, Name: "pkey_alloc", Probes: []Probe{{Event: "pkey_alloc", Attach: SysCall, Fn: "pkey_alloc"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	PkeyFreeEventID:               {ID: PkeyFreeEventID, ID32Bit: sys32pkey_free, Name: "pkey_free", Probes: []Probe{{Event: "pkey_free", Attach: SysCall, Fn: "pkey_free"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	StatxEventID:                  {ID: StatxEventID, ID32Bit: sys32statx, Name: "statx", Probes: []Probe{{Event: "statx", Attach: SysCall, Fn: "statx"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	IoPgeteventsEventID:           {ID: IoPgeteventsEventID, ID32Bit: sys32io_pgetevents, Name: "io_pgetevents", Probes: []Probe{{Event: "io_pgetevents", Attach: SysCall, Fn: "io_pgetevents"}}, Sets: []string{"syscalls", "fs", "fs_async_io"}},
	RseqEventID:                   {ID: RseqEventID, ID32Bit: sys32rseq, Name: "rseq", Probes: []Probe{{Event: "rseq", Attach: SysCall, Fn: "rseq"}}, Sets: []string{"syscalls"}},
	PidfdSendSignalEventID:        {ID: PidfdSendSignalEventID, ID32Bit: sys32pidfd_send_signal, Name: "pidfd_send_signal", Probes: []Probe{{Event: "pidfd_send_signal", Attach: SysCall, Fn: "pidfd_send_signal"}}, Sets: []string{"syscalls", "signals"}},
	IoUringSetupEventID:           {ID: IoUringSetupEventID, ID32Bit: sys32io_uring_setup, Name: "io_uring_setup", Probes: []Probe{{Event: "io_uring_setup", Attach: SysCall, Fn: "io_uring_setup"}}, Sets: []string{"syscalls"}},
	IoUringEnterEventID:           {ID: IoUringEnterEventID, ID32Bit: sys32io_uring_enter, Name: "io_uring_enter", Probes: []Probe{{Event: "io_uring_enter", Attach: SysCall, Fn: "io_uring_enter"}}, Sets: []string{"syscalls"}},
	IoUringRegisterEventID:        {ID: IoUringRegisterEventID, ID32Bit: sys32io_uring_register, Name: "io_uring_register", Probes: []Probe{{Event: "io_uring_register", Attach: SysCall, Fn: "io_uring_register"}}, Sets: []string{"syscalls"}},
	OpenTreeEventID:               {ID: OpenTreeEventID, ID32Bit: sys32open_tree, Name: "open_tree", Probes: []Probe{{Event: "open_tree", Attach: SysCall, Fn: "open_tree"}}, Sets: []string{"syscalls"}},
	MoveMountEventID:              {ID: MoveMountEventID, ID32Bit: sys32move_mount, Name: "move_mount", Probes: []Probe{{Event: "move_mount", Attach: SysCall, Fn: "move_mount"}}, Sets: []string{"default", "syscalls", "fs"}},
	FsopenEventID:                 {ID: FsopenEventID, ID32Bit: sys32fsopen, Name: "fsopen", Probes: []Probe{{Event: "fsopen", Attach: SysCall, Fn: "fsopen"}}, Sets: []string{"syscalls", "fs"}},
	FsconfigEventID:               {ID: FsconfigEventID, ID32Bit: sys32fsconfig, Name: "fsconfig", Probes: []Probe{{Event: "fsconfig", Attach: SysCall, Fn: "fsconfig"}}, Sets: []string{"syscalls", "fs"}},
	FsmountEventID:                {ID: FsmountEventID, ID32Bit: sys32fsmount, Name: "fsmount", Probes: []Probe{{Event: "fsmount", Attach: SysCall, Fn: "fsmount"}}, Sets: []string{"syscalls", "fs"}},
	FspickEventID:                 {ID: FspickEventID, ID32Bit: sys32fspick, Name: "fspick", Probes: []Probe{{Event: "fspick", Attach: SysCall, Fn: "fspick"}}, Sets: []string{"syscalls", "fs"}},
	PidfdOpenEventID:              {ID: PidfdOpenEventID, ID32Bit: sys32pidfd_open, Name: "pidfd_open", Probes: []Probe{{Event: "pidfd_open", Attach: SysCall, Fn: "pidfd_open"}}, Sets: []string{"syscalls"}},
	Clone3EventID:                 {ID: Clone3EventID, ID32Bit: sys32clone3, Name: "clone3", Probes: []Probe{{Event: "clone3", Attach: SysCall, Fn: "clone3"}}, Sets: []string{"default", "syscalls", "proc", "proc_life"}},
	CloseRangeEventID:             {ID: CloseRangeEventID, ID32Bit: sys32close_range, Name: "close_range", Probes: []Probe{{Event: "close_range", Attach: SysCall, Fn: "close_range"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	Openat2EventID:                {ID: Openat2EventID, ID32Bit: sys32openat2, Name: "openat2", Probes: []Probe{{Event: "openat2", Attach: SysCall, Fn: "openat2"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	PidfdGetfdEventID:             {ID: PidfdGetfdEventID, ID32Bit: sys32pidfd_getfd, Name: "pidfd_getfd", Probes: []Probe{{Event: "pidfd_getfd", Attach: SysCall, Fn: "pidfd_getfd"}}, Sets: []string{"syscalls"}},
	Faccessat2EventID:             {ID: Faccessat2EventID, ID32Bit: sys32faccessat2, Name: "faccessat2", Probes: []Probe{{Event: "faccessat2", Attach: SysCall, Fn: "faccessat2"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	ProcessMadviseEventID:         {ID: ProcessMadviseEventID, ID32Bit: sys32process_madvise, Name: "process_madvise", Probes: []Probe{{Event: "process_madvise", Attach: SysCall, Fn: "process_madvise"}}, Sets: []string{"syscalls"}},
	EpollPwait2EventID:            {ID: EpollPwait2EventID, ID32Bit: sys32epoll_pwait2, Name: "epoll_pwait2", Probes: []Probe{{Event: "epoll_pwait2", Attach: SysCall, Fn: "epoll_pwait2"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	SysEnterEventID:               {ID: SysEnterEventID, ID32Bit: sys32undefined, Name: "sys_enter", Probes: []Probe{{Event: "raw_syscalls:sys_enter", Attach: RawTracepoint, Fn: "tracepoint__raw_syscalls__sys_enter"}}, EssentialEvent: true, Sets: []string{}},
	SysExitEventID:                {ID: SysExitEventID, ID32Bit: sys32undefined, Name: "sys_exit", Probes: []Probe{{Event: "raw_syscalls:sys_exit", Attach: RawTracepoint, Fn: "tracepoint__raw_syscalls__sys_exit"}}, EssentialEvent: true, Sets: []string{}},
	SchedProcessForkEventID:       {ID: SchedProcessForkEventID, ID32Bit: sys32undefined, Name: "sched_process_fork", Probes: []Probe{{Event: "sched:sched_process_fork", Attach: RawTracepoint, Fn: "tracepoint__sched__sched_process_fork"}}, EssentialEvent: true, Sets: []string{}},
	SchedProcessExecEventID:       {ID: SchedProcessExecEventID, ID32Bit: sys32undefined, Name: "sched_process_exec", Probes: []Probe{{Event: "sched:sched_process_exec", Attach: RawTracepoint, Fn: "tracepoint__sched__sched_process_exec"}}, Sets: []string{"proc"}},
	SchedProcessExitEventID:       {ID: SchedProcessExitEventID, ID32Bit: sys32undefined, Name: "sched_process_exit", Probes: []Probe{{Event: "sched:sched_process_exit", Attach: RawTracepoint, Fn: "tracepoint__sched__sched_process_exit"}}, EssentialEvent: true, Sets: []string{"default", "proc", "proc_life"}},
	DoExitEventID:                 {ID: DoExitEventID, ID32Bit: sys32undefined, Name: "do_exit", Probes: []Probe{{Event: "do_exit", Attach: Kprobe, Fn: "trace_do_exit"}}, Sets: []string{"proc", "proc_life"}},
	CapCapableEventID:             {ID: CapCapableEventID, ID32Bit: sys32undefined, Name: "cap_capable", Probes: []Probe{{Event: "cap_capable", Attach: Kprobe, Fn: "trace_cap_capable"}}, Sets: []string{"default"}},
	VfsWriteEventID:               {ID: VfsWriteEventID, ID32Bit: sys32undefined, Name: "vfs_write", Probes: []Probe{{Event: "vfs_write", Attach: Kprobe, Fn: "trace_vfs_write"}, {Event: "vfs_write", Attach: Kretprobe, Fn: "trace_ret_vfs_write"}}, Sets: []string{}},
	VfsWritevEventID:              {ID: VfsWritevEventID, ID32Bit: sys32undefined, Name: "vfs_writev", Probes: []Probe{{Event: "vfs_writev", Attach: Kprobe, Fn: "trace_vfs_writev"}, {Event: "vfs_writev", Attach: Kretprobe, Fn: "trace_ret_vfs_writev"}}, Sets: []string{}},
	MemProtAlertEventID:           {ID: MemProtAlertEventID, ID32Bit: sys32undefined, Name: "mem_prot_alert", Probes: []Probe{{Event: "security_mmap_addr", Attach: Kprobe, Fn: "trace_mmap_alert"}, {Event: "security_file_mprotect", Attach: Kprobe, Fn: "trace_mprotect_alert"}}, Sets: []string{}},
	CommitCredsEventID:            {ID: CommitCredsEventID, ID32Bit: sys32undefined, Name: "commit_creds", Probes: []Probe{{Event: "commit_creds", Attach: Kprobe, Fn: "trace_commit_creds"}}, Sets: []string{}},
	SwitchTaskNSEventID:           {ID: SwitchTaskNSEventID, ID32Bit: sys32undefined, Name: "switch_task_ns", Probes: []Probe{{Event: "switch_task_namespaces", Attach: Kprobe, Fn: "trace_switch_task_namespaces"}}, Sets: []string{}},
	MagicWriteEventID:             {ID: MagicWriteEventID, ID32Bit: sys32undefined, Name: "magic_write", Probes: []Probe{}, Sets: []string{}},
	CgroupAttachTaskEventID:       {ID: CgroupAttachTaskEventID, ID32Bit: sys32undefined, Name: "cgroup_attach_task", Probes: []Probe{{Event: "cgroup:cgroup_attach_task", Attach: RawTracepoint, Fn: "tracepoint__cgroup__cgroup_attach_task"}}, EssentialEvent: true, Sets: []string{}},
	SecurityBprmCheckEventID:      {ID: SecurityBprmCheckEventID, ID32Bit: sys32undefined, Name: "security_bprm_check", Probes: []Probe{{Event: "security_bprm_check", Attach: Kprobe, Fn: "trace_security_bprm_check"}}, Sets: []string{"default", "lsm_hooks", "proc", "proc_life"}},
	SecurityFileOpenEventID:       {ID: SecurityFileOpenEventID, ID32Bit: sys32undefined, Name: "security_file_open", Probes: []Probe{{Event: "security_file_open", Attach: Kprobe, Fn: "trace_security_file_open"}}, Sets: []string{"default", "lsm_hooks", "fs", "fs_file_ops"}},
	SecurityInodeUnlinkEventID:    {ID: SecurityInodeUnlinkEventID, ID32Bit: sys32undefined, Name: "security_inode_unlink", Probes: []Probe{{Event: "security_inode_unlink", Attach: Kprobe, Fn: "trace_security_inode_unlink"}}, Sets: []string{"default", "lsm_hooks", "fs", "fs_file_ops"}},
	SecuritySocketCreateEventID:   {ID: SecuritySocketCreateEventID, ID32Bit: sys32undefined, Name: "security_socket_create", Probes: []Probe{{Event: "security_socket_create", Attach: Kprobe, Fn: "trace_security_socket_create"}}, Sets: []string{"default", "lsm_hooks", "net", "net_sock"}},
	SecuritySocketListenEventID:   {ID: SecuritySocketListenEventID, ID32Bit: sys32undefined, Name: "security_socket_listen", Probes: []Probe{{Event: "security_socket_listen", Attach: Kprobe, Fn: "trace_security_socket_listen"}}, Sets: []string{"default", "lsm_hooks", "net", "net_sock"}},
	SecuritySocketConnectEventID:  {ID: SecuritySocketConnectEventID, ID32Bit: sys32undefined, Name: "security_socket_connect", Probes: []Probe{{Event: "security_socket_connect", Attach: Kprobe, Fn: "trace_security_socket_connect"}}, Sets: []string{"default", "lsm_hooks", "net", "net_sock"}},
	SecuritySocketAcceptEventID:   {ID: SecuritySocketAcceptEventID, ID32Bit: sys32undefined, Name: "security_socket_accept", Probes: []Probe{{Event: "security_socket_accept", Attach: Kprobe, Fn: "trace_security_socket_accept"}}, Sets: []string{"default", "lsm_hooks", "net", "net_sock"}},
	SecuritySocketBindEventID:     {ID: SecuritySocketBindEventID, ID32Bit: sys32undefined, Name: "security_socket_bind", Probes: []Probe{{Event: "security_socket_bind", Attach: Kprobe, Fn: "trace_security_socket_bind"}}, Sets: []string{"default", "lsm_hooks", "net", "net_sock"}},
	SecuritySbMountEventID:        {ID: SecuritySbMountEventID, ID32Bit: sys32undefined, Name: "security_sb_mount", Probes: []Probe{{Event: "security_sb_mount", Attach: Kprobe, Fn: "trace_security_sb_mount"}}, Sets: []string{"default", "lsm_hooks", "fs"}},
	SecurityBPFEventID:            {ID: SecurityBPFEventID, ID32Bit: sys32undefined, Name: "security_bpf", Probes: []Probe{{Event: "security_bpf", Attach: Kprobe, Fn: "trace_security_bpf"}}, Sets: []string{"lsm_hooks"}},
	SecurityBPFMapEventID:         {ID: SecurityBPFMapEventID, ID32Bit: sys32undefined, Name: "security_bpf_map", Probes: []Probe{{Event: "security_bpf_map", Attach: Kprobe, Fn: "trace_security_bpf_map"}}, Sets: []string{"lsm_hooks"}},
	SecurityKernelReadFileEventID: {ID: SecurityKernelReadFileEventID, ID32Bit: sys32undefined, Name: "security_kernel_read_file", Probes: []Probe{{Event: "security_kernel_read_file", Attach: Kprobe, Fn: "trace_security_kernel_read_file"}}, Sets: []string{"lsm_hooks"}},
	SystemInfoEventID:             {ID: SystemInfoEventID, ID32Bit: sys32undefined, Name: "system_info_fetch", Probes: []Probe{}, Sets: []string{"default"}},
}

// EventsIDToParams is list of the parameters (name and type) used by the events
var EventsIDToParams = map[int32][]external.ArgMeta{
	ReadEventID:                   {{Type: "int", Name: "fd"}, {Type: "void*", Name: "buf"}, {Type: "size_t", Name: "count"}},
	WriteEventID:                  {{Type: "int", Name: "fd"}, {Type: "void*", Name: "buf"}, {Type: "size_t", Name: "count"}},
	OpenEventID:                   {{Type: "const char*", Name: "pathname"}, {Type: "int", Name: "flags"}, {Type: "mode_t", Name: "mode"}},
	CloseEventID:                  {{Type: "int", Name: "fd"}},
	StatEventID:                   {{Type: "const char*", Name: "pathname"}, {Type: "struct stat*", Name: "statbuf"}},
	FstatEventID:                  {{Type: "int", Name: "fd"}, {Type: "struct stat*", Name: "statbuf"}},
	LstatEventID:                  {{Type: "const char*", Name: "pathname"}, {Type: "struct stat*", Name: "statbuf"}},
	PollEventID:                   {{Type: "struct pollfd*", Name: "fds"}, {Type: "unsigned int", Name: "nfds"}, {Type: "int", Name: "timeout"}},
	LseekEventID:                  {{Type: "int", Name: "fd"}, {Type: "off_t", Name: "offset"}, {Type: "unsigned int", Name: "whence"}},
	MmapEventID:                   {{Type: "void*", Name: "addr"}, {Type: "size_t", Name: "length"}, {Type: "int", Name: "prot"}, {Type: "int", Name: "flags"}, {Type: "int", Name: "fd"}, {Type: "off_t", Name: "off"}},
	MprotectEventID:               {{Type: "void*", Name: "addr"}, {Type: "size_t", Name: "len"}, {Type: "int", Name: "prot"}},
	MunmapEventID:                 {{Type: "void*", Name: "addr"}, {Type: "size_t", Name: "length"}},
	BrkEventID:                    {{Type: "void*", Name: "addr"}},
	RtSigactionEventID:            {{Type: "int", Name: "signum"}, {Type: "const struct sigaction*", Name: "act"}, {Type: "struct sigaction*", Name: "oldact"}, {Type: "size_t", Name: "sigsetsize"}},
	RtSigprocmaskEventID:          {{Type: "int", Name: "how"}, {Type: "sigset_t*", Name: "set"}, {Type: "sigset_t*", Name: "oldset"}, {Type: "size_t", Name: "sigsetsize"}},
	RtSigreturnEventID:            {},
	IoctlEventID:                  {{Type: "int", Name: "fd"}, {Type: "unsigned long", Name: "request"}, {Type: "unsigned long", Name: "arg"}},
	Pread64EventID:                {{Type: "int", Name: "fd"}, {Type: "void*", Name: "buf"}, {Type: "size_t", Name: "count"}, {Type: "off_t", Name: "offset"}},
	Pwrite64EventID:               {{Type: "int", Name: "fd"}, {Type: "const void*", Name: "buf"}, {Type: "size_t", Name: "count"}, {Type: "off_t", Name: "offset"}},
	ReadvEventID:                  {{Type: "int", Name: "fd"}, {Type: "const struct iovec*", Name: "iov"}, {Type: "int", Name: "iovcnt"}},
	WritevEventID:                 {{Type: "int", Name: "fd"}, {Type: "const struct iovec*", Name: "iov"}, {Type: "int", Name: "iovcnt"}},
	AccessEventID:                 {{Type: "const char*", Name: "pathname"}, {Type: "int", Name: "mode"}},
	PipeEventID:                   {{Type: "int[2]", Name: "pipefd"}},
	SelectEventID:                 {{Type: "int", Name: "nfds"}, {Type: "fd_set*", Name: "readfds"}, {Type: "fd_set*", Name: "writefds"}, {Type: "fd_set*", Name: "exceptfds"}, {Type: "struct timeval*", Name: "timeout"}},
	SchedYieldEventID:             {},
	MremapEventID:                 {{Type: "void*", Name: "old_address"}, {Type: "size_t", Name: "old_size"}, {Type: "size_t", Name: "new_size"}, {Type: "int", Name: "flags"}, {Type: "void*", Name: "new_address"}},
	MsyncEventID:                  {{Type: "void*", Name: "addr"}, {Type: "size_t", Name: "length"}, {Type: "int", Name: "flags"}},
	MincoreEventID:                {{Type: "void*", Name: "addr"}, {Type: "size_t", Name: "length"}, {Type: "unsigned char*", Name: "vec"}},
	MadviseEventID:                {{Type: "void*", Name: "addr"}, {Type: "size_t", Name: "length"}, {Type: "int", Name: "advice"}},
	ShmgetEventID:                 {{Type: "key_t", Name: "key"}, {Type: "size_t", Name: "size"}, {Type: "int", Name: "shmflg"}},
	ShmatEventID:                  {{Type: "int", Name: "shmid"}, {Type: "const void*", Name: "shmaddr"}, {Type: "int", Name: "shmflg"}},
	ShmctlEventID:                 {{Type: "int", Name: "shmid"}, {Type: "int", Name: "cmd"}, {Type: "struct shmid_ds*", Name: "buf"}},
	DupEventID:                    {{Type: "int", Name: "oldfd"}},
	Dup2EventID:                   {{Type: "int", Name: "oldfd"}, {Type: "int", Name: "newfd"}},
	PauseEventID:                  {},
	NanosleepEventID:              {{Type: "const struct timespec*", Name: "req"}, {Type: "struct timespec*", Name: "rem"}},
	GetitimerEventID:              {{Type: "int", Name: "which"}, {Type: "struct itimerval*", Name: "curr_value"}},
	AlarmEventID:                  {{Type: "unsigned int", Name: "seconds"}},
	SetitimerEventID:              {{Type: "int", Name: "which"}, {Type: "struct itimerval*", Name: "new_value"}, {Type: "struct itimerval*", Name: "old_value"}},
	GetpidEventID:                 {},
	SendfileEventID:               {{Type: "int", Name: "out_fd"}, {Type: "int", Name: "in_fd"}, {Type: "off_t*", Name: "offset"}, {Type: "size_t", Name: "count"}},
	SocketEventID:                 {{Type: "int", Name: "domain"}, {Type: "int", Name: "type"}, {Type: "int", Name: "protocol"}},
	ConnectEventID:                {{Type: "int", Name: "sockfd"}, {Type: "struct sockaddr*", Name: "addr"}, {Type: "int", Name: "addrlen"}},
	AcceptEventID:                 {{Type: "int", Name: "sockfd"}, {Type: "struct sockaddr*", Name: "addr"}, {Type: "int*", Name: "addrlen"}},
	SendtoEventID:                 {{Type: "int", Name: "sockfd"}, {Type: "void*", Name: "buf"}, {Type: "size_t", Name: "len"}, {Type: "int", Name: "flags"}, {Type: "struct sockaddr*", Name: "dest_addr"}, {Type: "int", Name: "addrlen"}},
	RecvfromEventID:               {{Type: "int", Name: "sockfd"}, {Type: "void*", Name: "buf"}, {Type: "size_t", Name: "len"}, {Type: "int", Name: "flags"}, {Type: "struct sockaddr*", Name: "src_addr"}, {Type: "int*", Name: "addrlen"}},
	SendmsgEventID:                {{Type: "int", Name: "sockfd"}, {Type: "struct msghdr*", Name: "msg"}, {Type: "int", Name: "flags"}},
	RecvmsgEventID:                {{Type: "int", Name: "sockfd"}, {Type: "struct msghdr*", Name: "msg"}, {Type: "int", Name: "flags"}},
	ShutdownEventID:               {{Type: "int", Name: "sockfd"}, {Type: "int", Name: "how"}},
	BindEventID:                   {{Type: "int", Name: "sockfd"}, {Type: "struct sockaddr*", Name: "addr"}, {Type: "int", Name: "addrlen"}},
	ListenEventID:                 {{Type: "int", Name: "sockfd"}, {Type: "int", Name: "backlog"}},
	GetsocknameEventID:            {{Type: "int", Name: "sockfd"}, {Type: "struct sockaddr*", Name: "addr"}, {Type: "int*", Name: "addrlen"}},
	GetpeernameEventID:            {{Type: "int", Name: "sockfd"}, {Type: "struct sockaddr*", Name: "addr"}, {Type: "int*", Name: "addrlen"}},
	SocketpairEventID:             {{Type: "int", Name: "domain"}, {Type: "int", Name: "type"}, {Type: "int", Name: "protocol"}, {Type: "int[2]", Name: "sv"}},
	SetsockoptEventID:             {{Type: "int", Name: "sockfd"}, {Type: "int", Name: "level"}, {Type: "int", Name: "optname"}, {Type: "const void*", Name: "optval"}, {Type: "int", Name: "optlen"}},
	GetsockoptEventID:             {{Type: "int", Name: "sockfd"}, {Type: "int", Name: "level"}, {Type: "int", Name: "optname"}, {Type: "void*", Name: "optval"}, {Type: "int*", Name: "optlen"}},
	CloneEventID:                  {{Type: "unsigned long", Name: "flags"}, {Type: "void*", Name: "stack"}, {Type: "int*", Name: "parent_tid"}, {Type: "int*", Name: "child_tid"}, {Type: "unsigned long", Name: "tls"}},
	ForkEventID:                   {},
	VforkEventID:                  {},
	ExecveEventID:                 {{Type: "const char*", Name: "pathname"}, {Type: "const char*const*", Name: "argv"}, {Type: "const char*const*", Name: "envp"}},
	ExitEventID:                   {{Type: "int", Name: "status"}},
	Wait4EventID:                  {{Type: "pid_t", Name: "pid"}, {Type: "int*", Name: "wstatus"}, {Type: "int", Name: "options"}, {Type: "struct rusage*", Name: "rusage"}},
	KillEventID:                   {{Type: "pid_t", Name: "pid"}, {Type: "int", Name: "sig"}},
	UnameEventID:                  {{Type: "struct utsname*", Name: "buf"}},
	SemgetEventID:                 {{Type: "key_t", Name: "key"}, {Type: "int", Name: "nsems"}, {Type: "int", Name: "semflg"}},
	SemopEventID:                  {{Type: "int", Name: "semid"}, {Type: "struct sembuf*", Name: "sops"}, {Type: "size_t", Name: "nsops"}},
	SemctlEventID:                 {{Type: "int", Name: "semid"}, {Type: "int", Name: "semnum"}, {Type: "int", Name: "cmd"}, {Type: "unsigned long", Name: "arg"}},
	ShmdtEventID:                  {{Type: "const void*", Name: "shmaddr"}},
	MsggetEventID:                 {{Type: "key_t", Name: "key"}, {Type: "int", Name: "msgflg"}},
	MsgsndEventID:                 {{Type: "int", Name: "msqid"}, {Type: "struct msgbuf*", Name: "msgp"}, {Type: "size_t", Name: "msgsz"}, {Type: "int", Name: "msgflg"}},
	MsgrcvEventID:                 {{Type: "int", Name: "msqid"}, {Type: "struct msgbuf*", Name: "msgp"}, {Type: "size_t", Name: "msgsz"}, {Type: "long", Name: "msgtyp"}, {Type: "int", Name: "msgflg"}},
	MsgctlEventID:                 {{Type: "int", Name: "msqid"}, {Type: "int", Name: "cmd"}, {Type: "struct msqid_ds*", Name: "buf"}},
	FcntlEventID:                  {{Type: "int", Name: "fd"}, {Type: "int", Name: "cmd"}, {Type: "unsigned long", Name: "arg"}},
	FlockEventID:                  {{Type: "int", Name: "fd"}, {Type: "int", Name: "operation"}},
	FsyncEventID:                  {{Type: "int", Name: "fd"}},
	FdatasyncEventID:              {{Type: "int", Name: "fd"}},
	TruncateEventID:               {{Type: "const char*", Name: "path"}, {Type: "off_t", Name: "length"}},
	FtruncateEventID:              {{Type: "int", Name: "fd"}, {Type: "off_t", Name: "length"}},
	GetdentsEventID:               {{Type: "int", Name: "fd"}, {Type: "struct linux_dirent*", Name: "dirp"}, {Type: "unsigned int", Name: "count"}},
	GetcwdEventID:                 {{Type: "char*", Name: "buf"}, {Type: "size_t", Name: "size"}},
	ChdirEventID:                  {{Type: "const char*", Name: "path"}},
	FchdirEventID:                 {{Type: "int", Name: "fd"}},
	RenameEventID:                 {{Type: "const char*", Name: "oldpath"}, {Type: "const char*", Name: "newpath"}},
	MkdirEventID:                  {{Type: "const char*", Name: "pathname"}, {Type: "mode_t", Name: "mode"}},
	RmdirEventID:                  {{Type: "const char*", Name: "pathname"}},
	CreatEventID:                  {{Type: "const char*", Name: "pathname"}, {Type: "mode_t", Name: "mode"}},
	LinkEventID:                   {{Type: "const char*", Name: "oldpath"}, {Type: "const char*", Name: "newpath"}},
	UnlinkEventID:                 {{Type: "const char*", Name: "pathname"}},
	SymlinkEventID:                {{Type: "const char*", Name: "target"}, {Type: "const char*", Name: "linkpath"}},
	ReadlinkEventID:               {{Type: "const char*", Name: "pathname"}, {Type: "char*", Name: "buf"}, {Type: "size_t", Name: "bufsiz"}},
	ChmodEventID:                  {{Type: "const char*", Name: "pathname"}, {Type: "mode_t", Name: "mode"}},
	FchmodEventID:                 {{Type: "int", Name: "fd"}, {Type: "mode_t", Name: "mode"}},
	ChownEventID:                  {{Type: "const char*", Name: "pathname"}, {Type: "uid_t", Name: "owner"}, {Type: "gid_t", Name: "group"}},
	FchownEventID:                 {{Type: "int", Name: "fd"}, {Type: "uid_t", Name: "owner"}, {Type: "gid_t", Name: "group"}},
	LchownEventID:                 {{Type: "const char*", Name: "pathname"}, {Type: "uid_t", Name: "owner"}, {Type: "gid_t", Name: "group"}},
	UmaskEventID:                  {{Type: "mode_t", Name: "mask"}},
	GettimeofdayEventID:           {{Type: "struct timeval*", Name: "tv"}, {Type: "struct timezone*", Name: "tz"}},
	GetrlimitEventID:              {{Type: "int", Name: "resource"}, {Type: "struct rlimit*", Name: "rlim"}},
	GetrusageEventID:              {{Type: "int", Name: "who"}, {Type: "struct rusage*", Name: "usage"}},
	SysinfoEventID:                {{Type: "struct sysinfo*", Name: "info"}},
	TimesEventID:                  {{Type: "struct tms*", Name: "buf"}},
	PtraceEventID:                 {{Type: "long", Name: "request"}, {Type: "pid_t", Name: "pid"}, {Type: "void*", Name: "addr"}, {Type: "void*", Name: "data"}},
	GetuidEventID:                 {},
	SyslogEventID:                 {{Type: "int", Name: "type"}, {Type: "char*", Name: "bufp"}, {Type: "int", Name: "len"}},
	GetgidEventID:                 {},
	SetuidEventID:                 {{Type: "uid_t", Name: "uid"}},
	SetgidEventID:                 {{Type: "gid_t", Name: "gid"}},
	GeteuidEventID:                {},
	GetegidEventID:                {},
	SetpgidEventID:                {{Type: "pid_t", Name: "pid"}, {Type: "pid_t", Name: "pgid"}},
	GetppidEventID:                {},
	GetpgrpEventID:                {},
	SetsidEventID:                 {},
	SetreuidEventID:               {{Type: "uid_t", Name: "ruid"}, {Type: "uid_t", Name: "euid"}},
	SetregidEventID:               {{Type: "gid_t", Name: "rgid"}, {Type: "gid_t", Name: "egid"}},
	GetgroupsEventID:              {{Type: "int", Name: "size"}, {Type: "gid_t*", Name: "list"}},
	SetgroupsEventID:              {{Type: "int", Name: "size"}, {Type: "gid_t*", Name: "list"}},
	SetresuidEventID:              {{Type: "uid_t", Name: "ruid"}, {Type: "uid_t", Name: "euid"}, {Type: "uid_t", Name: "suid"}},
	GetresuidEventID:              {{Type: "uid_t*", Name: "ruid"}, {Type: "uid_t*", Name: "euid"}, {Type: "uid_t*", Name: "suid"}},
	SetresgidEventID:              {{Type: "gid_t", Name: "rgid"}, {Type: "gid_t", Name: "egid"}, {Type: "gid_t", Name: "sgid"}},
	GetresgidEventID:              {{Type: "gid_t*", Name: "rgid"}, {Type: "gid_t*", Name: "egid"}, {Type: "gid_t*", Name: "sgid"}},
	GetpgidEventID:                {{Type: "pid_t", Name: "pid"}},
	SetfsuidEventID:               {{Type: "uid_t", Name: "fsuid"}},
	SetfsgidEventID:               {{Type: "gid_t", Name: "fsgid"}},
	GetsidEventID:                 {{Type: "pid_t", Name: "pid"}},
	CapgetEventID:                 {{Type: "cap_user_header_t", Name: "hdrp"}, {Type: "cap_user_data_t", Name: "datap"}},
	CapsetEventID:                 {{Type: "cap_user_header_t", Name: "hdrp"}, {Type: "const cap_user_data_t", Name: "datap"}},
	RtSigpendingEventID:           {{Type: "sigset_t*", Name: "set"}, {Type: "size_t", Name: "sigsetsize"}},
	RtSigtimedwaitEventID:         {{Type: "const sigset_t*", Name: "set"}, {Type: "siginfo_t*", Name: "info"}, {Type: "const struct timespec*", Name: "timeout"}, {Type: "size_t", Name: "sigsetsize"}},
	RtSigqueueinfoEventID:         {{Type: "pid_t", Name: "tgid"}, {Type: "int", Name: "sig"}, {Type: "siginfo_t*", Name: "info"}},
	RtSigsuspendEventID:           {{Type: "sigset_t*", Name: "mask"}, {Type: "size_t", Name: "sigsetsize"}},
	SigaltstackEventID:            {{Type: "const stack_t*", Name: "ss"}, {Type: "stack_t*", Name: "old_ss"}},
	UtimeEventID:                  {{Type: "const char*", Name: "filename"}, {Type: "const struct utimbuf*", Name: "times"}},
	MknodEventID:                  {{Type: "const char*", Name: "pathname"}, {Type: "mode_t", Name: "mode"}, {Type: "dev_t", Name: "dev"}},
	UselibEventID:                 {{Type: "const char*", Name: "library"}},
	PersonalityEventID:            {{Type: "unsigned long", Name: "persona"}},
	UstatEventID:                  {{Type: "dev_t", Name: "dev"}, {Type: "struct ustat*", Name: "ubuf"}},
	StatfsEventID:                 {{Type: "const char*", Name: "path"}, {Type: "struct statfs*", Name: "buf"}},
	FstatfsEventID:                {{Type: "int", Name: "fd"}, {Type: "struct statfs*", Name: "buf"}},
	SysfsEventID:                  {{Type: "int", Name: "option"}},
	GetpriorityEventID:            {{Type: "int", Name: "which"}, {Type: "int", Name: "who"}},
	SetpriorityEventID:            {{Type: "int", Name: "which"}, {Type: "int", Name: "who"}, {Type: "int", Name: "prio"}},
	SchedSetparamEventID:          {{Type: "pid_t", Name: "pid"}, {Type: "struct sched_param*", Name: "param"}},
	SchedGetparamEventID:          {{Type: "pid_t", Name: "pid"}, {Type: "struct sched_param*", Name: "param"}},
	SchedSetschedulerEventID:      {{Type: "pid_t", Name: "pid"}, {Type: "int", Name: "policy"}, {Type: "struct sched_param*", Name: "param"}},
	SchedGetschedulerEventID:      {{Type: "pid_t", Name: "pid"}},
	SchedGetPriorityMaxEventID:    {{Type: "int", Name: "policy"}},
	SchedGetPriorityMinEventID:    {{Type: "int", Name: "policy"}},
	SchedRrGetIntervalEventID:     {{Type: "pid_t", Name: "pid"}, {Type: "struct timespec*", Name: "tp"}},
	MlockEventID:                  {{Type: "const void*", Name: "addr"}, {Type: "size_t", Name: "len"}},
	MunlockEventID:                {{Type: "const void*", Name: "addr"}, {Type: "size_t", Name: "len"}},
	MlockallEventID:               {{Type: "int", Name: "flags"}},
	MunlockallEventID:             {},
	VhangupEventID:                {},
	ModifyLdtEventID:              {{Type: "int", Name: "func"}, {Type: "void*", Name: "ptr"}, {Type: "unsigned long", Name: "bytecount"}},
	PivotRootEventID:              {{Type: "const char*", Name: "new_root"}, {Type: "const char*", Name: "put_old"}},
	SysctlEventID:                 {{Type: "struct __sysctl_args*", Name: "args"}},
	PrctlEventID:                  {{Type: "int", Name: "option"}, {Type: "unsigned long", Name: "arg2"}, {Type: "unsigned long", Name: "arg3"}, {Type: "unsigned long", Name: "arg4"}, {Type: "unsigned long", Name: "arg5"}},
	ArchPrctlEventID:              {{Type: "int", Name: "option"}, {Type: "unsigned long", Name: "addr"}},
	AdjtimexEventID:               {{Type: "struct timex*", Name: "buf"}},
	SetrlimitEventID:              {{Type: "int", Name: "resource"}, {Type: "const struct rlimit*", Name: "rlim"}},
	ChrootEventID:                 {{Type: "const char*", Name: "path"}},
	SyncEventID:                   {},
	AcctEventID:                   {{Type: "const char*", Name: "filename"}},
	SettimeofdayEventID:           {{Type: "const struct timeval*", Name: "tv"}, {Type: "const struct timezone*", Name: "tz"}},
	MountEventID:                  {{Type: "const char*", Name: "source"}, {Type: "const char*", Name: "target"}, {Type: "const char*", Name: "filesystemtype"}, {Type: "unsigned long", Name: "mountflags"}, {Type: "const void*", Name: "data"}},
	UmountEventID:                 {{Type: "const char*", Name: "target"}, {Type: "int", Name: "flags"}},
	SwaponEventID:                 {{Type: "const char*", Name: "path"}, {Type: "int", Name: "swapflags"}},
	SwapoffEventID:                {{Type: "const char*", Name: "path"}},
	RebootEventID:                 {{Type: "int", Name: "magic"}, {Type: "int", Name: "magic2"}, {Type: "int", Name: "cmd"}, {Type: "void*", Name: "arg"}},
	SethostnameEventID:            {{Type: "const char*", Name: "name"}, {Type: "size_t", Name: "len"}},
	SetdomainnameEventID:          {{Type: "const char*", Name: "name"}, {Type: "size_t", Name: "len"}},
	IoplEventID:                   {{Type: "int", Name: "level"}},
	IopermEventID:                 {{Type: "unsigned long", Name: "from"}, {Type: "unsigned long", Name: "num"}, {Type: "int", Name: "turn_on"}},
	InitModuleEventID:             {{Type: "void*", Name: "module_image"}, {Type: "unsigned long", Name: "len"}, {Type: "const char*", Name: "param_values"}},
	DeleteModuleEventID:           {{Type: "const char*", Name: "name"}, {Type: "int", Name: "flags"}},
	QuotactlEventID:               {{Type: "int", Name: "cmd"}, {Type: "const char*", Name: "special"}, {Type: "int", Name: "id"}, {Type: "void*", Name: "addr"}},
	GettidEventID:                 {},
	ReadaheadEventID:              {{Type: "int", Name: "fd"}, {Type: "off_t", Name: "offset"}, {Type: "size_t", Name: "count"}},
	SetxattrEventID:               {{Type: "const char*", Name: "path"}, {Type: "const char*", Name: "name"}, {Type: "const void*", Name: "value"}, {Type: "size_t", Name: "size"}, {Type: "int", Name: "flags"}},
	LsetxattrEventID:              {{Type: "const char*", Name: "path"}, {Type: "const char*", Name: "name"}, {Type: "const void*", Name: "value"}, {Type: "size_t", Name: "size"}, {Type: "int", Name: "flags"}},
	FsetxattrEventID:              {{Type: "int", Name: "fd"}, {Type: "const char*", Name: "name"}, {Type: "const void*", Name: "value"}, {Type: "size_t", Name: "size"}, {Type: "int", Name: "flags"}},
	GetxattrEventID:               {{Type: "const char*", Name: "path"}, {Type: "const char*", Name: "name"}, {Type: "void*", Name: "value"}, {Type: "size_t", Name: "size"}},
	LgetxattrEventID:              {{Type: "const char*", Name: "path"}, {Type: "const char*", Name: "name"}, {Type: "void*", Name: "value"}, {Type: "size_t", Name: "size"}},
	FgetxattrEventID:              {{Type: "int", Name: "fd"}, {Type: "const char*", Name: "name"}, {Type: "void*", Name: "value"}, {Type: "size_t", Name: "size"}},
	ListxattrEventID:              {{Type: "const char*", Name: "path"}, {Type: "char*", Name: "list"}, {Type: "size_t", Name: "size"}},
	LlistxattrEventID:             {{Type: "const char*", Name: "path"}, {Type: "char*", Name: "list"}, {Type: "size_t", Name: "size"}},
	FlistxattrEventID:             {{Type: "int", Name: "fd"}, {Type: "char*", Name: "list"}, {Type: "size_t", Name: "size"}},
	RemovexattrEventID:            {{Type: "const char*", Name: "path"}, {Type: "const char*", Name: "name"}},
	LremovexattrEventID:           {{Type: "const char*", Name: "path"}, {Type: "const char*", Name: "name"}},
	FremovexattrEventID:           {{Type: "int", Name: "fd"}, {Type: "const char*", Name: "name"}},
	TkillEventID:                  {{Type: "int", Name: "tid"}, {Type: "int", Name: "sig"}},
	TimeEventID:                   {{Type: "time_t*", Name: "tloc"}},
	FutexEventID:                  {{Type: "int*", Name: "uaddr"}, {Type: "int", Name: "futex_op"}, {Type: "int", Name: "val"}, {Type: "const struct timespec*", Name: "timeout"}, {Type: "int*", Name: "uaddr2"}, {Type: "int", Name: "val3"}},
	SchedSetaffinityEventID:       {{Type: "pid_t", Name: "pid"}, {Type: "size_t", Name: "cpusetsize"}, {Type: "unsigned long*", Name: "mask"}},
	SchedGetaffinityEventID:       {{Type: "pid_t", Name: "pid"}, {Type: "size_t", Name: "cpusetsize"}, {Type: "unsigned long*", Name: "mask"}},
	SetThreadAreaEventID:          {{Type: "struct user_desc*", Name: "u_info"}},
	IoSetupEventID:                {{Type: "unsigned int", Name: "nr_events"}, {Type: "io_context_t*", Name: "ctx_idp"}},
	IoDestroyEventID:              {{Type: "io_context_t", Name: "ctx_id"}},
	IoGeteventsEventID:            {{Type: "io_context_t", Name: "ctx_id"}, {Type: "long", Name: "min_nr"}, {Type: "long", Name: "nr"}, {Type: "struct io_event*", Name: "events"}, {Type: "struct timespec*", Name: "timeout"}},
	IoSubmitEventID:               {{Type: "io_context_t", Name: "ctx_id"}, {Type: "long", Name: "nr"}, {Type: "struct iocb**", Name: "iocbpp"}},
	IoCancelEventID:               {{Type: "io_context_t", Name: "ctx_id"}, {Type: "struct iocb*", Name: "iocb"}, {Type: "struct io_event*", Name: "result"}},
	GetThreadAreaEventID:          {{Type: "struct user_desc*", Name: "u_info"}},
	LookupDcookieEventID:          {{Type: "u64", Name: "cookie"}, {Type: "char*", Name: "buffer"}, {Type: "size_t", Name: "len"}},
	EpollCreateEventID:            {{Type: "int", Name: "size"}},
	RemapFilePagesEventID:         {{Type: "void*", Name: "addr"}, {Type: "size_t", Name: "size"}, {Type: "int", Name: "prot"}, {Type: "size_t", Name: "pgoff"}, {Type: "int", Name: "flags"}},
	Getdents64EventID:             {{Type: "unsigned int", Name: "fd"}, {Type: "struct linux_dirent64*", Name: "dirp"}, {Type: "unsigned int", Name: "count"}},
	SetTidAddressEventID:          {{Type: "int*", Name: "tidptr"}},
	RestartSyscallEventID:         {},
	SemtimedopEventID:             {{Type: "int", Name: "semid"}, {Type: "struct sembuf*", Name: "sops"}, {Type: "size_t", Name: "nsops"}, {Type: "const struct timespec*", Name: "timeout"}},
	Fadvise64EventID:              {{Type: "int", Name: "fd"}, {Type: "off_t", Name: "offset"}, {Type: "size_t", Name: "len"}, {Type: "int", Name: "advice"}},
	TimerCreateEventID:            {{Type: "const clockid_t", Name: "clockid"}, {Type: "struct sigevent*", Name: "sevp"}, {Type: "timer_t*", Name: "timer_id"}},
	TimerSettimeEventID:           {{Type: "timer_t", Name: "timer_id"}, {Type: "int", Name: "flags"}, {Type: "const struct itimerspec*", Name: "new_value"}, {Type: "struct itimerspec*", Name: "old_value"}},
	TimerGettimeEventID:           {{Type: "timer_t", Name: "timer_id"}, {Type: "struct itimerspec*", Name: "curr_value"}},
	TimerGetoverrunEventID:        {{Type: "timer_t", Name: "timer_id"}},
	TimerDeleteEventID:            {{Type: "timer_t", Name: "timer_id"}},
	ClockSettimeEventID:           {{Type: "const clockid_t", Name: "clockid"}, {Type: "const struct timespec*", Name: "tp"}},
	ClockGettimeEventID:           {{Type: "const clockid_t", Name: "clockid"}, {Type: "struct timespec*", Name: "tp"}},
	ClockGetresEventID:            {{Type: "const clockid_t", Name: "clockid"}, {Type: "struct timespec*", Name: "res"}},
	ClockNanosleepEventID:         {{Type: "const clockid_t", Name: "clockid"}, {Type: "int", Name: "flags"}, {Type: "const struct timespec*", Name: "request"}, {Type: "struct timespec*", Name: "remain"}},
	ExitGroupEventID:              {{Type: "int", Name: "status"}},
	EpollWaitEventID:              {{Type: "int", Name: "epfd"}, {Type: "struct epoll_event*", Name: "events"}, {Type: "int", Name: "maxevents"}, {Type: "int", Name: "timeout"}},
	EpollCtlEventID:               {{Type: "int", Name: "epfd"}, {Type: "int", Name: "op"}, {Type: "int", Name: "fd"}, {Type: "struct epoll_event*", Name: "event"}},
	TgkillEventID:                 {{Type: "int", Name: "tgid"}, {Type: "int", Name: "tid"}, {Type: "int", Name: "sig"}},
	UtimesEventID:                 {{Type: "char*", Name: "filename"}, {Type: "struct timeval*", Name: "times"}},
	MbindEventID:                  {{Type: "void*", Name: "addr"}, {Type: "unsigned long", Name: "len"}, {Type: "int", Name: "mode"}, {Type: "const unsigned long*", Name: "nodemask"}, {Type: "unsigned long", Name: "maxnode"}, {Type: "unsigned int", Name: "flags"}},
	SetMempolicyEventID:           {{Type: "int", Name: "mode"}, {Type: "const unsigned long*", Name: "nodemask"}, {Type: "unsigned long", Name: "maxnode"}},
	GetMempolicyEventID:           {{Type: "int*", Name: "mode"}, {Type: "unsigned long*", Name: "nodemask"}, {Type: "unsigned long", Name: "maxnode"}, {Type: "void*", Name: "addr"}, {Type: "unsigned long", Name: "flags"}},
	MqOpenEventID:                 {{Type: "const char*", Name: "name"}, {Type: "int", Name: "oflag"}, {Type: "mode_t", Name: "mode"}, {Type: "struct mq_attr*", Name: "attr"}},
	MqUnlinkEventID:               {{Type: "const char*", Name: "name"}},
	MqTimedsendEventID:            {{Type: "mqd_t", Name: "mqdes"}, {Type: "const char*", Name: "msg_ptr"}, {Type: "size_t", Name: "msg_len"}, {Type: "unsigned int", Name: "msg_prio"}, {Type: "const struct timespec*", Name: "abs_timeout"}},
	MqTimedreceiveEventID:         {{Type: "mqd_t", Name: "mqdes"}, {Type: "char*", Name: "msg_ptr"}, {Type: "size_t", Name: "msg_len"}, {Type: "unsigned int*", Name: "msg_prio"}, {Type: "const struct timespec*", Name: "abs_timeout"}},
	MqNotifyEventID:               {{Type: "mqd_t", Name: "mqdes"}, {Type: "const struct sigevent*", Name: "sevp"}},
	MqGetsetattrEventID:           {{Type: "mqd_t", Name: "mqdes"}, {Type: "const struct mq_attr*", Name: "newattr"}, {Type: "struct mq_attr*", Name: "oldattr"}},
	KexecLoadEventID:              {{Type: "unsigned long", Name: "entry"}, {Type: "unsigned long", Name: "nr_segments"}, {Type: "struct kexec_segment*", Name: "segments"}, {Type: "unsigned long", Name: "flags"}},
	WaitidEventID:                 {{Type: "int", Name: "idtype"}, {Type: "pid_t", Name: "id"}, {Type: "struct siginfo*", Name: "infop"}, {Type: "int", Name: "options"}, {Type: "struct rusage*", Name: "rusage"}},
	AddKeyEventID:                 {{Type: "const char*", Name: "type"}, {Type: "const char*", Name: "description"}, {Type: "const void*", Name: "payload"}, {Type: "size_t", Name: "plen"}, {Type: "key_serial_t", Name: "keyring"}},
	RequestKeyEventID:             {{Type: "const char*", Name: "type"}, {Type: "const char*", Name: "description"}, {Type: "const char*", Name: "callout_info"}, {Type: "key_serial_t", Name: "dest_keyring"}},
	KeyctlEventID:                 {{Type: "int", Name: "operation"}, {Type: "unsigned long", Name: "arg2"}, {Type: "unsigned long", Name: "arg3"}, {Type: "unsigned long", Name: "arg4"}, {Type: "unsigned long", Name: "arg5"}},
	IoprioSetEventID:              {{Type: "int", Name: "which"}, {Type: "int", Name: "who"}, {Type: "int", Name: "ioprio"}},
	IoprioGetEventID:              {{Type: "int", Name: "which"}, {Type: "int", Name: "who"}},
	InotifyInitEventID:            {},
	InotifyAddWatchEventID:        {{Type: "int", Name: "fd"}, {Type: "const char*", Name: "pathname"}, {Type: "u32", Name: "mask"}},
	InotifyRmWatchEventID:         {{Type: "int", Name: "fd"}, {Type: "int", Name: "wd"}},
	MigratePagesEventID:           {{Type: "int", Name: "pid"}, {Type: "unsigned long", Name: "maxnode"}, {Type: "const unsigned long*", Name: "old_nodes"}, {Type: "const unsigned long*", Name: "new_nodes"}},
	OpenatEventID:                 {{Type: "int", Name: "dirfd"}, {Type: "const char*", Name: "pathname"}, {Type: "int", Name: "flags"}, {Type: "mode_t", Name: "mode"}},
	MkdiratEventID:                {{Type: "int", Name: "dirfd"}, {Type: "const char*", Name: "pathname"}, {Type: "mode_t", Name: "mode"}},
	MknodatEventID:                {{Type: "int", Name: "dirfd"}, {Type: "const char*", Name: "pathname"}, {Type: "mode_t", Name: "mode"}, {Type: "dev_t", Name: "dev"}},
	FchownatEventID:               {{Type: "int", Name: "dirfd"}, {Type: "const char*", Name: "pathname"}, {Type: "uid_t", Name: "owner"}, {Type: "gid_t", Name: "group"}, {Type: "int", Name: "flags"}},
	FutimesatEventID:              {{Type: "int", Name: "dirfd"}, {Type: "const char*", Name: "pathname"}, {Type: "struct timeval*", Name: "times"}},
	NewfstatatEventID:             {{Type: "int", Name: "dirfd"}, {Type: "const char*", Name: "pathname"}, {Type: "struct stat*", Name: "statbuf"}, {Type: "int", Name: "flags"}},
	UnlinkatEventID:               {{Type: "int", Name: "dirfd"}, {Type: "const char*", Name: "pathname"}, {Type: "int", Name: "flags"}},
	RenameatEventID:               {{Type: "int", Name: "olddirfd"}, {Type: "const char*", Name: "oldpath"}, {Type: "int", Name: "newdirfd"}, {Type: "const char*", Name: "newpath"}},
	LinkatEventID:                 {{Type: "int", Name: "olddirfd"}, {Type: "const char*", Name: "oldpath"}, {Type: "int", Name: "newdirfd"}, {Type: "const char*", Name: "newpath"}, {Type: "unsigned int", Name: "flags"}},
	SymlinkatEventID:              {{Type: "const char*", Name: "target"}, {Type: "int", Name: "newdirfd"}, {Type: "const char*", Name: "linkpath"}},
	ReadlinkatEventID:             {{Type: "int", Name: "dirfd"}, {Type: "const char*", Name: "pathname"}, {Type: "char*", Name: "buf"}, {Type: "int", Name: "bufsiz"}},
	FchmodatEventID:               {{Type: "int", Name: "dirfd"}, {Type: "const char*", Name: "pathname"}, {Type: "mode_t", Name: "mode"}, {Type: "int", Name: "flags"}},
	FaccessatEventID:              {{Type: "int", Name: "dirfd"}, {Type: "const char*", Name: "pathname"}, {Type: "int", Name: "mode"}, {Type: "int", Name: "flags"}},
	Pselect6EventID:               {{Type: "int", Name: "nfds"}, {Type: "fd_set*", Name: "readfds"}, {Type: "fd_set*", Name: "writefds"}, {Type: "fd_set*", Name: "exceptfds"}, {Type: "struct timespec*", Name: "timeout"}, {Type: "void*", Name: "sigmask"}},
	PpollEventID:                  {{Type: "struct pollfd*", Name: "fds"}, {Type: "unsigned int", Name: "nfds"}, {Type: "struct timespec*", Name: "tmo_p"}, {Type: "const sigset_t*", Name: "sigmask"}, {Type: "size_t", Name: "sigsetsize"}},
	UnshareEventID:                {{Type: "int", Name: "flags"}},
	SetRobustListEventID:          {{Type: "struct robust_list_head*", Name: "head"}, {Type: "size_t", Name: "len"}},
	GetRobustListEventID:          {{Type: "int", Name: "pid"}, {Type: "struct robust_list_head**", Name: "head_ptr"}, {Type: "size_t*", Name: "len_ptr"}},
	SpliceEventID:                 {{Type: "int", Name: "fd_in"}, {Type: "off_t*", Name: "off_in"}, {Type: "int", Name: "fd_out"}, {Type: "off_t*", Name: "off_out"}, {Type: "size_t", Name: "len"}, {Type: "unsigned int", Name: "flags"}},
	TeeEventID:                    {{Type: "int", Name: "fd_in"}, {Type: "int", Name: "fd_out"}, {Type: "size_t", Name: "len"}, {Type: "unsigned int", Name: "flags"}},
	SyncFileRangeEventID:          {{Type: "int", Name: "fd"}, {Type: "off_t", Name: "offset"}, {Type: "off_t", Name: "nbytes"}, {Type: "unsigned int", Name: "flags"}},
	VmspliceEventID:               {{Type: "int", Name: "fd"}, {Type: "const struct iovec*", Name: "iov"}, {Type: "unsigned long", Name: "nr_segs"}, {Type: "unsigned int", Name: "flags"}},
	MovePagesEventID:              {{Type: "int", Name: "pid"}, {Type: "unsigned long", Name: "count"}, {Type: "const void**", Name: "pages"}, {Type: "const int*", Name: "nodes"}, {Type: "int*", Name: "status"}, {Type: "int", Name: "flags"}},
	UtimensatEventID:              {{Type: "int", Name: "dirfd"}, {Type: "const char*", Name: "pathname"}, {Type: "struct timespec*", Name: "times"}, {Type: "int", Name: "flags"}},
	EpollPwaitEventID:             {{Type: "int", Name: "epfd"}, {Type: "struct epoll_event*", Name: "events"}, {Type: "int", Name: "maxevents"}, {Type: "int", Name: "timeout"}, {Type: "const sigset_t*", Name: "sigmask"}, {Type: "size_t", Name: "sigsetsize"}},
	SignalfdEventID:               {{Type: "int", Name: "fd"}, {Type: "sigset_t*", Name: "mask"}, {Type: "int", Name: "flags"}},
	TimerfdCreateEventID:          {{Type: "int", Name: "clockid"}, {Type: "int", Name: "flags"}},
	EventfdEventID:                {{Type: "unsigned int", Name: "initval"}, {Type: "int", Name: "flags"}},
	FallocateEventID:              {{Type: "int", Name: "fd"}, {Type: "int", Name: "mode"}, {Type: "off_t", Name: "offset"}, {Type: "off_t", Name: "len"}},
	TimerfdSettimeEventID:         {{Type: "int", Name: "fd"}, {Type: "int", Name: "flags"}, {Type: "const struct itimerspec*", Name: "new_value"}, {Type: "struct itimerspec*", Name: "old_value"}},
	TimerfdGettimeEventID:         {{Type: "int", Name: "fd"}, {Type: "struct itimerspec*", Name: "curr_value"}},
	Accept4EventID:                {{Type: "int", Name: "sockfd"}, {Type: "struct sockaddr*", Name: "addr"}, {Type: "int*", Name: "addrlen"}, {Type: "int", Name: "flags"}},
	Signalfd4EventID:              {{Type: "int", Name: "fd"}, {Type: "const sigset_t*", Name: "mask"}, {Type: "size_t", Name: "sizemask"}, {Type: "int", Name: "flags"}},
	Eventfd2EventID:               {{Type: "unsigned int", Name: "initval"}, {Type: "int", Name: "flags"}},
	EpollCreate1EventID:           {{Type: "int", Name: "flags"}},
	Dup3EventID:                   {{Type: "int", Name: "oldfd"}, {Type: "int", Name: "newfd"}, {Type: "int", Name: "flags"}},
	Pipe2EventID:                  {{Type: "int*", Name: "pipefd"}, {Type: "int", Name: "flags"}},
	InotifyInit1EventID:           {{Type: "int", Name: "flags"}},
	PreadvEventID:                 {{Type: "int", Name: "fd"}, {Type: "const struct iovec*", Name: "iov"}, {Type: "unsigned long", Name: "iovcnt"}, {Type: "unsigned long", Name: "pos_l"}, {Type: "unsigned long", Name: "pos_h"}},
	PwritevEventID:                {{Type: "int", Name: "fd"}, {Type: "const struct iovec*", Name: "iov"}, {Type: "unsigned long", Name: "iovcnt"}, {Type: "unsigned long", Name: "pos_l"}, {Type: "unsigned long", Name: "pos_h"}},
	RtTgsigqueueinfoEventID:       {{Type: "pid_t", Name: "tgid"}, {Type: "pid_t", Name: "tid"}, {Type: "int", Name: "sig"}, {Type: "siginfo_t*", Name: "info"}},
	PerfEventOpenEventID:          {{Type: "struct perf_event_attr*", Name: "attr"}, {Type: "pid_t", Name: "pid"}, {Type: "int", Name: "cpu"}, {Type: "int", Name: "group_fd"}, {Type: "unsigned long", Name: "flags"}},
	RecvmmsgEventID:               {{Type: "int", Name: "sockfd"}, {Type: "struct mmsghdr*", Name: "msgvec"}, {Type: "unsigned int", Name: "vlen"}, {Type: "int", Name: "flags"}, {Type: "struct timespec*", Name: "timeout"}},
	FanotifyInitEventID:           {{Type: "unsigned int", Name: "flags"}, {Type: "unsigned int", Name: "event_f_flags"}},
	FanotifyMarkEventID:           {{Type: "int", Name: "fanotify_fd"}, {Type: "unsigned int", Name: "flags"}, {Type: "u64", Name: "mask"}, {Type: "int", Name: "dirfd"}, {Type: "const char*", Name: "pathname"}},
	Prlimit64EventID:              {{Type: "pid_t", Name: "pid"}, {Type: "int", Name: "resource"}, {Type: "const struct rlimit64*", Name: "new_limit"}, {Type: "struct rlimit64*", Name: "old_limit"}},
	NameToHandleAtEventID:         {{Type: "int", Name: "dirfd"}, {Type: "const char*", Name: "pathname"}, {Type: "struct file_handle*", Name: "handle"}, {Type: "int*", Name: "mount_id"}, {Type: "int", Name: "flags"}},
	OpenByHandleAtEventID:         {{Type: "int", Name: "mount_fd"}, {Type: "struct file_handle*", Name: "handle"}, {Type: "int", Name: "flags"}},
	ClockAdjtimeEventID:           {{Type: "const clockid_t", Name: "clk_id"}, {Type: "struct timex*", Name: "buf"}},
	SyncfsEventID:                 {{Type: "int", Name: "fd"}},
	SendmmsgEventID:               {{Type: "int", Name: "sockfd"}, {Type: "struct mmsghdr*", Name: "msgvec"}, {Type: "unsigned int", Name: "vlen"}, {Type: "int", Name: "flags"}},
	SetnsEventID:                  {{Type: "int", Name: "fd"}, {Type: "int", Name: "nstype"}},
	GetcpuEventID:                 {{Type: "unsigned int*", Name: "cpu"}, {Type: "unsigned int*", Name: "node"}, {Type: "struct getcpu_cache*", Name: "tcache"}},
	ProcessVmReadvEventID:         {{Type: "pid_t", Name: "pid"}, {Type: "const struct iovec*", Name: "local_iov"}, {Type: "unsigned long", Name: "liovcnt"}, {Type: "const struct iovec*", Name: "remote_iov"}, {Type: "unsigned long", Name: "riovcnt"}, {Type: "unsigned long", Name: "flags"}},
	ProcessVmWritevEventID:        {{Type: "pid_t", Name: "pid"}, {Type: "const struct iovec*", Name: "local_iov"}, {Type: "unsigned long", Name: "liovcnt"}, {Type: "const struct iovec*", Name: "remote_iov"}, {Type: "unsigned long", Name: "riovcnt"}, {Type: "unsigned long", Name: "flags"}},
	KcmpEventID:                   {{Type: "pid_t", Name: "pid1"}, {Type: "pid_t", Name: "pid2"}, {Type: "int", Name: "type"}, {Type: "unsigned long", Name: "idx1"}, {Type: "unsigned long", Name: "idx2"}},
	FinitModuleEventID:            {{Type: "int", Name: "fd"}, {Type: "const char*", Name: "param_values"}, {Type: "int", Name: "flags"}},
	SchedSetattrEventID:           {{Type: "pid_t", Name: "pid"}, {Type: "struct sched_attr*", Name: "attr"}, {Type: "unsigned int", Name: "flags"}},
	SchedGetattrEventID:           {{Type: "pid_t", Name: "pid"}, {Type: "struct sched_attr*", Name: "attr"}, {Type: "unsigned int", Name: "size"}, {Type: "unsigned int", Name: "flags"}},
	Renameat2EventID:              {{Type: "int", Name: "olddirfd"}, {Type: "const char*", Name: "oldpath"}, {Type: "int", Name: "newdirfd"}, {Type: "const char*", Name: "newpath"}, {Type: "unsigned int", Name: "flags"}},
	SeccompEventID:                {{Type: "unsigned int", Name: "operation"}, {Type: "unsigned int", Name: "flags"}, {Type: "const void*", Name: "args"}},
	GetrandomEventID:              {{Type: "void*", Name: "buf"}, {Type: "size_t", Name: "buflen"}, {Type: "unsigned int", Name: "flags"}},
	MemfdCreateEventID:            {{Type: "const char*", Name: "name"}, {Type: "unsigned int", Name: "flags"}},
	KexecFileLoadEventID:          {{Type: "int", Name: "kernel_fd"}, {Type: "int", Name: "initrd_fd"}, {Type: "unsigned long", Name: "cmdline_len"}, {Type: "const char*", Name: "cmdline"}, {Type: "unsigned long", Name: "flags"}},
	BpfEventID:                    {{Type: "int", Name: "cmd"}, {Type: "union bpf_attr*", Name: "attr"}, {Type: "unsigned int", Name: "size"}},
	ExecveatEventID:               {{Type: "int", Name: "dirfd"}, {Type: "const char*", Name: "pathname"}, {Type: "const char*const*", Name: "argv"}, {Type: "const char*const*", Name: "envp"}, {Type: "int", Name: "flags"}},
	UserfaultfdEventID:            {{Type: "int", Name: "flags"}},
	MembarrierEventID:             {{Type: "int", Name: "cmd"}, {Type: "int", Name: "flags"}},
	Mlock2EventID:                 {{Type: "const void*", Name: "addr"}, {Type: "size_t", Name: "len"}, {Type: "int", Name: "flags"}},
	CopyFileRangeEventID:          {{Type: "int", Name: "fd_in"}, {Type: "off_t*", Name: "off_in"}, {Type: "int", Name: "fd_out"}, {Type: "off_t*", Name: "off_out"}, {Type: "size_t", Name: "len"}, {Type: "unsigned int", Name: "flags"}},
	Preadv2EventID:                {{Type: "int", Name: "fd"}, {Type: "const struct iovec*", Name: "iov"}, {Type: "unsigned long", Name: "iovcnt"}, {Type: "unsigned long", Name: "pos_l"}, {Type: "unsigned long", Name: "pos_h"}, {Type: "int", Name: "flags"}},
	Pwritev2EventID:               {{Type: "int", Name: "fd"}, {Type: "const struct iovec*", Name: "iov"}, {Type: "unsigned long", Name: "iovcnt"}, {Type: "unsigned long", Name: "pos_l"}, {Type: "unsigned long", Name: "pos_h"}, {Type: "int", Name: "flags"}},
	PkeyMprotectEventID:           {{Type: "void*", Name: "addr"}, {Type: "size_t", Name: "len"}, {Type: "int", Name: "prot"}, {Type: "int", Name: "pkey"}},
	PkeyAllocEventID:              {{Type: "unsigned int", Name: "flags"}, {Type: "unsigned long", Name: "access_rights"}},
	PkeyFreeEventID:               {{Type: "int", Name: "pkey"}},
	StatxEventID:                  {{Type: "int", Name: "dirfd"}, {Type: "const char*", Name: "pathname"}, {Type: "int", Name: "flags"}, {Type: "unsigned int", Name: "mask"}, {Type: "struct statx*", Name: "statxbuf"}},
	IoPgeteventsEventID:           {{Type: "aio_context_t", Name: "ctx_id"}, {Type: "long", Name: "min_nr"}, {Type: "long", Name: "nr"}, {Type: "struct io_event*", Name: "events"}, {Type: "struct timespec*", Name: "timeout"}, {Type: "const struct __aio_sigset*", Name: "usig"}},
	RseqEventID:                   {{Type: "struct rseq*", Name: "rseq"}, {Type: "u32", Name: "rseq_len"}, {Type: "int", Name: "flags"}, {Type: "u32", Name: "sig"}},
	PidfdSendSignalEventID:        {{Type: "int", Name: "pidfd"}, {Type: "int", Name: "sig"}, {Type: "siginfo_t*", Name: "info"}, {Type: "unsigned int", Name: "flags"}},
	IoUringSetupEventID:           {{Type: "unsigned int", Name: "entries"}, {Type: "struct io_uring_params*", Name: "p"}},
	IoUringEnterEventID:           {{Type: "unsigned int", Name: "fd"}, {Type: "unsigned int", Name: "to_submit"}, {Type: "unsigned int", Name: "min_complete"}, {Type: "unsigned int", Name: "flags"}, {Type: "sigset_t*", Name: "sig"}},
	IoUringRegisterEventID:        {{Type: "unsigned int", Name: "fd"}, {Type: "unsigned int", Name: "opcode"}, {Type: "void*", Name: "arg"}, {Type: "unsigned int", Name: "nr_args"}},
	OpenTreeEventID:               {{Type: "int", Name: "dfd"}, {Type: "const char*", Name: "filename"}, {Type: "unsigned int", Name: "flags"}},
	MoveMountEventID:              {{Type: "int", Name: "from_dfd"}, {Type: "const char*", Name: "from_path"}, {Type: "int", Name: "to_dfd"}, {Type: "const char*", Name: "to_path"}, {Type: "unsigned int", Name: "flags"}},
	FsopenEventID:                 {{Type: "const char*", Name: "fsname"}, {Type: "unsigned int", Name: "flags"}},
	FsconfigEventID:               {{Type: "int*", Name: "fs_fd"}, {Type: "unsigned int", Name: "cmd"}, {Type: "const char*", Name: "key"}, {Type: "const void*", Name: "value"}, {Type: "int", Name: "aux"}},
	FsmountEventID:                {{Type: "int", Name: "fsfd"}, {Type: "unsigned int", Name: "flags"}, {Type: "unsigned int", Name: "ms_flags"}},
	FspickEventID:                 {{Type: "int", Name: "dirfd"}, {Type: "const char*", Name: "pathname"}, {Type: "unsigned int", Name: "flags"}},
	PidfdOpenEventID:              {{Type: "pid_t", Name: "pid"}, {Type: "unsigned int", Name: "flags"}},
	Clone3EventID:                 {{Type: "struct clone_args*", Name: "cl_args"}, {Type: "size_t", Name: "size"}},
	CloseRangeEventID:             {{Type: "unsigned int", Name: "first"}, {Type: "unsigned int", Name: "last"}},
	Openat2EventID:                {{Type: "int", Name: "dirfd"}, {Type: "const char*", Name: "pathname"}, {Type: "struct open_how*", Name: "how"}, {Type: "size_t", Name: "size"}},
	PidfdGetfdEventID:             {{Type: "int", Name: "pidfd"}, {Type: "int", Name: "targetfd"}, {Type: "unsigned int", Name: "flags"}},
	Faccessat2EventID:             {{Type: "int", Name: "fd"}, {Type: "const char*", Name: "path"}, {Type: "int", Name: "mode"}, {Type: "int", Name: "flag"}},
	ProcessMadviseEventID:         {{Type: "int", Name: "pidfd"}, {Type: "void*", Name: "addr"}, {Type: "size_t", Name: "length"}, {Type: "int", Name: "advice"}, {Type: "unsigned long", Name: "flags"}},
	EpollPwait2EventID:            {{Type: "int", Name: "fd"}, {Type: "struct epoll_event*", Name: "events"}, {Type: "int", Name: "maxevents"}, {Type: "const struct timespec*", Name: "timeout"}, {Type: "const sigset_t*", Name: "sigset"}},
	SysEnterEventID:               {{Type: "int", Name: "syscall"}},
	SysExitEventID:                {{Type: "int", Name: "syscall"}},
	SchedProcessForkEventID:       {{Type: "int", Name: "parent_pid"}, {Type: "int", Name: "parent_ns_pid"}, {Type: "int", Name: "child_pid"}, {Type: "int", Name: "child_ns_pid"}},
	SchedProcessExecEventID:       {{Type: "const char *", Name: "cmdpath"}, {Type: "const char *", Name: "pathname"}, {Type: "const char*const*", Name: "argv"}, {Type: "const char*const*", Name: "env"}, {Type: "dev_t", Name: "dev"}, {Type: "unsigned long", Name: "inode"}, {Type: "int", Name: "invoked_from_kernel"}},
	SchedProcessExitEventID:       {},
	DoExitEventID:                 {},
	CapCapableEventID:             {{Type: "int", Name: "cap"}, {Type: "int", Name: "syscall"}},
	VfsWriteEventID:               {{Type: "const char*", Name: "pathname"}, {Type: "dev_t", Name: "dev"}, {Type: "unsigned long", Name: "inode"}, {Type: "size_t", Name: "count"}, {Type: "off_t", Name: "pos"}},
	VfsWritevEventID:              {{Type: "const char*", Name: "pathname"}, {Type: "dev_t", Name: "dev"}, {Type: "unsigned long", Name: "inode"}, {Type: "unsigned long", Name: "vlen"}, {Type: "off_t", Name: "pos"}},
	MemProtAlertEventID:           {{Type: "alert_t", Name: "alert"}},
	CommitCredsEventID:            {{Type: "slim_cred_t", Name: "old_cred"}, {Type: "slim_cred_t", Name: "new_cred"}, {Type: "int", Name: "syscall"}},
	SwitchTaskNSEventID:           {{Type: "pid_t", Name: "pid"}, {Type: "u32", Name: "new_mnt"}, {Type: "u32", Name: "new_pid"}, {Type: "u32", Name: "new_uts"}, {Type: "u32", Name: "new_ipc"}, {Type: "u32", Name: "new_net"}, {Type: "u32", Name: "new_cgroup"}},
	MagicWriteEventID:             {{Type: "const char*", Name: "pathname"}, {Type: "bytes", Name: "bytes"}, {Type: "dev_t", Name: "dev"}, {Type: "unsigned long", Name: "inode"}},
	CgroupAttachTaskEventID:       {{Type: "const char*", Name: "cgroup_path"}},
	SecurityBprmCheckEventID:      {{Type: "const char*", Name: "pathname"}, {Type: "dev_t", Name: "dev"}, {Type: "unsigned long", Name: "inode"}},
	SecurityFileOpenEventID:       {{Type: "const char*", Name: "pathname"}, {Type: "int", Name: "flags"}, {Type: "dev_t", Name: "dev"}, {Type: "unsigned long", Name: "inode"}, {Type: "int", Name: "syscall"}},
	SecurityInodeUnlinkEventID:    {{Type: "const char*", Name: "pathname"}},
	SecuritySocketCreateEventID:   {{Type: "int", Name: "family"}, {Type: "int", Name: "type"}, {Type: "int", Name: "protocol"}, {Type: "int", Name: "kern"}},
	SecuritySocketListenEventID:   {{Type: "int", Name: "sockfd"}, {Type: "struct sockaddr*", Name: "local_addr"}, {Type: "int", Name: "backlog"}},
	SecuritySocketConnectEventID:  {{Type: "int", Name: "sockfd"}, {Type: "struct sockaddr*", Name: "remote_addr"}},
	SecuritySocketAcceptEventID:   {{Type: "int", Name: "sockfd"}, {Type: "struct sockaddr*", Name: "local_addr"}},
	SecuritySocketBindEventID:     {{Type: "int", Name: "sockfd"}, {Type: "struct sockaddr*", Name: "local_addr"}},
	SecuritySbMountEventID:        {{Type: "const char*", Name: "dev_name"}, {Type: "const char*", Name: "path"}, {Type: "const char*", Name: "type"}, {Type: "unsigned long", Name: "flags"}},
	SecurityBPFEventID:            {{Type: "int", Name: "cmd"}},
	SecurityBPFMapEventID:         {{Type: "unsigned int", Name: "map_id"}, {Type: "const char*", Name: "map_name"}},
	SecurityKernelReadFileEventID: {{Type: "const char*", Name: "pathname"}, {Type: "dev_t", Name: "dev"}, {Type: "unsigned long", Name: "inode"}},
	SystemInfoEventID:             {{Type: "map[string]int", Name: "initNamespaces"}},
}
