package tracee

// bpfConfig is an enum that include various configurations that can be passed to bpf code
// config should match defined values in ebpf code
type bpfConfig uint32

const (
	configMode bpfConfig = iota
	configDetectOrigSyscall
	configExecEnv
	configCaptureFiles
	configExtractDynCode
)

// an enum that specifies the index of a function to be used in a bpf tail call
// tail function indexes should match defined values in ebpf code
const (
	tailVfsWrite uint32 = iota
	tailSendBin
)

// binType is an enum that specifies the type of binary data sent in the file perf map
// binary types should match defined values in ebpf code
type binType uint8

const (
	modeSystem uint32 = iota
	modePid
	modeContainer
)

const (
	sendVfsWrite binType = iota + 1
	sendMprotect
)

// argType is an enum that encodes the argument types that the BPF program may write to the shared buffer
// argument types should match defined values in ebpf code
type argType uint8

const (
	noneT argType = iota
	intT
	uintT
	longT
	ulongT
	offT
	modeT
	devT
	sizeT
	pointerT
	strT
	strArrT
	sockAddrT
	alertT
)

// argTag is an enum that encodes the argument types that the BPF program may write to the shared buffer
// argument tags should match defined values in ebpf code
type argTag uint8

const (
	TagNone argTag = iota
	TagFd
	TagFilename
	TagPathname
	TagArgv
	TagEnvp
	TagDev
	TagInode
	TagDirfd
	TagFlags
	TagCap
	TagSyscall
	TagCount
	TagPos
	TagAlert
	TagMode
	TagAddr
	TagLength
	TagProt
	TagOffset
	TagPkey
	TagName
	TagOldfd
	TagNewfd
	TagDomain
	TagType
	TagProtocol
	TagRequest
	TagPid
	TagSig
	TagSockfd
	TagBacklog
	TagOption
	TagArg2
	TagArg3
	TagArg4
	TagArg5
	TagData
	TagLocalIov
	TagLiovcnt
	TagRemoteIov
	TagRiovcnt
	TagModuleImage
	TagLen
	TagParamValues
	TagTarget
	TagNewdirfd
	TagLinkpath
	TagSource
	TagFilesystemtype
	TagMountflags
	TagUid
	TagGid
	TagFsuid
	TagFsgid
	TagRuid
	TagEuid
	TagRgid
	TagEgid
	TagSuid
	TagSgid
	TagOwner
	TagGroup
)

var argNames = map[argTag]string{
	TagNone:           "",
	TagFd:             "fd",
	TagFilename:       "filename",
	TagPathname:       "pathname",
	TagArgv:           "argv",
	TagEnvp:           "envp",
	TagDev:            "dev",
	TagInode:          "inode",
	TagDirfd:          "dirfd",
	TagFlags:          "flags",
	TagCap:            "cap",
	TagSyscall:        "syscall",
	TagCount:          "count",
	TagPos:            "pos",
	TagAlert:          "alert",
	TagMode:           "mode",
	TagAddr:           "addr",
	TagLength:         "length",
	TagProt:           "prot",
	TagOffset:         "offset",
	TagPkey:           "pkey",
	TagName:           "name",
	TagOldfd:          "oldfd",
	TagNewfd:          "newfd",
	TagDomain:         "domain",
	TagType:           "type",
	TagProtocol:       "protocol",
	TagRequest:        "request",
	TagPid:            "pid",
	TagSig:            "sig",
	TagSockfd:         "sockfd",
	TagBacklog:        "backlog",
	TagOption:         "option",
	TagArg2:           "arg2",
	TagArg3:           "arg3",
	TagArg4:           "arg4",
	TagArg5:           "arg5",
	TagData:           "data",
	TagLocalIov:       "local_iov",
	TagLiovcnt:        "liovcnt",
	TagRemoteIov:      "remote_iov",
	TagRiovcnt:        "riovcnt",
	TagModuleImage:    "module_image",
	TagLen:            "len",
	TagParamValues:    "param_values",
	TagTarget:         "target",
	TagNewdirfd:       "newdirfd",
	TagLinkpath:       "linkpath",
	TagSource:         "source",
	TagFilesystemtype: "filesystemtype",
	TagMountflags:     "mountflags",
	TagUid:            "uid",
	TagGid:            "gid",
	TagFsuid:          "fsuid",
	TagFsgid:          "fsgid",
	TagRuid:           "ruid",
	TagEuid:           "euid",
	TagRgid:           "rgid",
	TagEgid:           "egid",
	TagSuid:           "suid",
	TagSgid:           "sgid",
	TagOwner:          "owner",
	TagGroup:          "group",
}

// ProbeType is an enum that describes the mechanism used to attach the event
// Syscall tracepoints are explained here: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#8-system-call-tracepoints
// Kprobes are explained here: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#1-kprobes
// Tracepoints are explained here: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#3-tracepoints
type probeType uint8

const (
	sysCall probeType = iota
	kprobe
	kretprobe
	tracepoint
)

type probe struct {
	event  string
	attach probeType
	fn     string
}

// EventConfig is a struct describing an event configuration
type EventConfig struct {
	ID               int32
	Name             string
	Probes           []probe
	EnabledByDefault bool
	EssentialEvent   bool
}

// events should match defined values in ebpf code
const (
	ReadEventID int32 = iota
	WriteEventID
	OpenEventID
	CloseEventID
	StatEventID
	FstatEventID
	LstatEventID
	PollEventID
	LseekEventID
	MmapEventID
	MprotectEventID
	MunmapEventID
	BrkEventID
	RtSigactionEventID
	RtSigprocmaskEventID
	RtSigreturnEventID
	IoctlEventID
	Pread64EventID
	Pwrite64EventID
	ReadvEventID
	WritevEventID
	AccessEventID
	PipeEventID
	SelectEventID
	SchedYieldEventID
	MremapEventID
	MsyncEventID
	MincoreEventID
	MadviseEventID
	ShmgetEventID
	ShmatEventID
	ShmctlEventID
	DupEventID
	Dup2EventID
	PauseEventID
	NanosleepEventID
	GetitimerEventID
	AlarmEventID
	SetitimerEventID
	GetpidEventID
	SendfileEventID
	SocketEventID
	ConnectEventID
	AcceptEventID
	SendtoEventID
	RecvfromEventID
	SendmsgEventID
	RecvmsgEventID
	ShutdownEventID
	BindEventID
	ListenEventID
	GetsocknameEventID
	GetpeernameEventID
	SocketpairEventID
	SetsockoptEventID
	GetsockoptEventID
	CloneEventID
	ForkEventID
	VforkEventID
	ExecveEventID
	ExitEventID
	Wait4EventID
	KillEventID
	UnameEventID
	SemgetEventID
	SemopEventID
	SemctlEventID
	ShmdtEventID
	MsggetEventID
	MsgsndEventID
	MsgrcvEventID
	MsgctlEventID
	FcntlEventID
	FlockEventID
	FsyncEventID
	FdatasyncEventID
	TruncateEventID
	FtruncateEventID
	GetdentsEventID
	GetcwdEventID
	ChdirEventID
	FchdirEventID
	RenameEventID
	MkdirEventID
	RmdirEventID
	CreatEventID
	LinkEventID
	UnlinkEventID
	SymlinkEventID
	ReadlinkEventID
	ChmodEventID
	FchmodEventID
	ChownEventID
	FchownEventID
	LchownEventID
	UmaskEventID
	GettimeofdayEventID
	GetrlimitEventID
	GetrusageEventID
	SysinfoEventID
	TimesEventID
	PtraceEventID
	GetuidEventID
	SyslogEventID
	GetgidEventID
	SetuidEventID
	SetgidEventID
	GeteuidEventID
	GetegidEventID
	SetpgidEventID
	GetppidEventID
	GetpgrpEventID
	SetsidEventID
	SetreuidEventID
	SetregidEventID
	GetgroupsEventID
	SetgroupsEventID
	SetresuidEventID
	GetresuidEventID
	SetresgidEventID
	GetresgidEventID
	GetpgidEventID
	SetfsuidEventID
	SetfsgidEventID
	GetsidEventID
	CapgetEventID
	CapsetEventID
	RtSigpendingEventID
	RtSigtimedwaitEventID
	RtSigqueueinfoEventID
	RtSigsuspendEventID
	SigaltstackEventID
	UtimeEventID
	MknodEventID
	UselibEventID
	PersonalityEventID
	UstatEventID
	StatfsEventID
	FstatfsEventID
	SysfsEventID
	GetpriorityEventID
	SetpriorityEventID
	SchedSetparamEventID
	SchedGetparamEventID
	SchedSetschedulerEventID
	SchedGetschedulerEventID
	SchedGetPriorityMaxEventID
	SchedGetPriorityMinEventID
	SchedRrGetIntervalEventID
	MlockEventID
	MunlockEventID
	MlockallEventID
	MunlockallEventID
	VhangupEventID
	ModifyLdtEventID
	PivotRootEventID
	SysctlEventID
	PrctlEventID
	ArchPrctlEventID
	AdjtimexEventID
	SetrlimitEventID
	ChrootEventID
	SyncEventID
	AcctEventID
	SettimeofdayEventID
	MountEventID
	UmountEventID
	SwaponEventID
	SwapoffEventID
	RebootEventID
	SethostnameEventID
	SetdomainnameEventID
	IoplEventID
	IopermEventID
	CreateModuleEventID
	InitModuleEventID
	DeleteModuleEventID
	GetKernelSymsEventID
	QueryModuleEventID
	QuotactlEventID
	NfsservctlEventID
	GetpmsgEventID
	PutpmsgEventID
	AfsEventID
	TuxcallEventID
	SecurityEventID
	GettidEventID
	ReadaheadEventID
	SetxattrEventID
	LsetxattrEventID
	FsetxattrEventID
	GetxattrEventID
	LgetxattrEventID
	FgetxattrEventID
	ListxattrEventID
	LlistxattrEventID
	FlistxattrEventID
	RemovexattrEventID
	LremovexattrEventID
	FremovexattrEventID
	TkillEventID
	TimeEventID
	FutexEventID
	SchedSetaffinityEventID
	SchedGetaffinityEventID
	SetThreadAreaEventID
	IoSetupEventID
	IoDestroyEventID
	IoGeteventsEventID
	IoSubmitEventID
	IoCancelEventID
	GetThreadAreaEventID
	LookupDcookieEventID
	EpollCreateEventID
	EpollCtlOldEventID
	EpollWaitOldEventID
	RemapFilePagesEventID
	Getdents64EventID
	SetTidAddressEventID
	RestartSyscallEventID
	SemtimedopEventID
	Fadvise64EventID
	TimerCreateEventID
	TimerSettimeEventID
	TimerGettimeEventID
	TimerGetoverrunEventID
	TimerDeleteEventID
	ClockSettimeEventID
	ClockGettimeEventID
	ClockGetresEventID
	ClockNanosleepEventID
	ExitGroupEventID
	EpollWaitEventID
	EpollCtlEventID
	TgkillEventID
	UtimesEventID
	VserverEventID
	MbindEventID
	SetMempolicyEventID
	GetMempolicyEventID
	MqOpenEventID
	MqUnlinkEventID
	MqTimedsendEventID
	MqTimedreceiveEventID
	MqNotifyEventID
	MqGetsetattrEventID
	KexecLoadEventID
	WaitidEventID
	AddKeyEventID
	RequestKeyEventID
	KeyctlEventID
	IoprioSetEventID
	IoprioGetEventID
	InotifyInitEventID
	InotifyAddWatchEventID
	InotifyRmWatchEventID
	MigratePagesEventID
	OpenatEventID
	MkdiratEventID
	MknodatEventID
	FchownatEventID
	FutimesatEventID
	NewfstatatEventID
	UnlinkatEventID
	RenameatEventID
	LinkatEventID
	SymlinkatEventID
	ReadlinkatEventID
	FchmodatEventID
	FaccessatEventID
	Pselect6EventID
	PpollEventID
	UnshareEventID
	SetRobustListEventID
	GetRobustListEventID
	SpliceEventID
	TeeEventID
	SyncFileRangeEventID
	VmspliceEventID
	MovePagesEventID
	UtimensatEventID
	EpollPwaitEventID
	SignalfdEventID
	TimerfdCreateEventID
	EventfdEventID
	FallocateEventID
	TimerfdSettimeEventID
	TimerfdGettimeEventID
	Accept4EventID
	Signalfd4EventID
	Eventfd2EventID
	EpollCreate1EventID
	Dup3EventID
	Pipe2EventID
	IonotifyInit1EventID
	PreadvEventID
	PwritevEventID
	RtTgsigqueueinfoEventID
	PerfEventOpenEventID
	RecvmmsgEventID
	FanotifyInitEventID
	FanotifyMarkEventID
	Prlimit64EventID
	NameTohandleAtEventID
	OpenByHandleAtEventID
	ClockAdjtimeEventID
	SycnfsEventID
	SendmmsgEventID
	SetnsEventID
	GetcpuEventID
	ProcessVmReadvEventID
	ProcessVmWritevEventID
	KcmpEventID
	FinitModuleEventID
	SchedSetattrEventID
	SchedGetattrEventID
	Renameat2EventID
	SeccompEventID
	GetrandomEventID
	MemfdCreateEventID
	KexecFileLoadEventID
	BpfEventID
	ExecveatEventID
	UserfaultfdEventID
	MembarrierEventID
	Mlock2EventID
	CopyFileRangeEventID
	Preadv2EventID
	Pwritev2EventID
	PkeyMprotectEventID
	PkeyAllocEventID
	PkeyFreeEventID
	StatxEventID
	IoPgeteventsEventID
	RseqEventID
	Reserved335EventID
	Reserved336EventID
	Reserved337EventID
	Reserved338EventID
	Reserved339EventID
	Reserved340EventID
	Reserved341EventID
	Reserved342EventID
	Reserved343EventID
	Reserved344EventID
	Reserved345EventID
	Reserved346EventID
	Reserved347EventID
	Reserved348EventID
	Reserved349EventID
	RawSyscallsEventID
	DoExitEventID
	CapCapableEventID
	SecurityBprmCheckEventID
	SecurityFileOpenEventID
	VfsWriteEventID
	MemProtAlertEventID
)

// EventsIDToEvent is list of supported events, indexed by their ID
var EventsIDToEvent = map[int32]EventConfig{
	ReadEventID:                EventConfig{ID: ReadEventID, Name: "reserved", Probes: []probe{probe{event: "read", attach: sysCall, fn: "read"}}, EnabledByDefault: false, EssentialEvent: false},
	WriteEventID:               EventConfig{ID: WriteEventID, Name: "reserved", Probes: []probe{probe{event: "write", attach: sysCall, fn: "write"}}, EnabledByDefault: false, EssentialEvent: false},
	OpenEventID:                EventConfig{ID: OpenEventID, Name: "open", Probes: []probe{probe{event: "open", attach: sysCall, fn: "open"}}, EnabledByDefault: true, EssentialEvent: false},
	CloseEventID:               EventConfig{ID: CloseEventID, Name: "close", Probes: []probe{probe{event: "close", attach: sysCall, fn: "close"}}, EnabledByDefault: true, EssentialEvent: false},
	StatEventID:                EventConfig{ID: StatEventID, Name: "newstat", Probes: []probe{probe{event: "newstat", attach: sysCall, fn: "newstat"}}, EnabledByDefault: true, EssentialEvent: false},
	FstatEventID:               EventConfig{ID: FstatEventID, Name: "reserved", Probes: []probe{probe{event: "fstat", attach: sysCall, fn: "fstat"}}, EnabledByDefault: false, EssentialEvent: false},
	LstatEventID:               EventConfig{ID: LstatEventID, Name: "newlstat", Probes: []probe{probe{event: "newlstat", attach: sysCall, fn: "newlstat"}}, EnabledByDefault: true, EssentialEvent: false},
	PollEventID:                EventConfig{ID: PollEventID, Name: "reserved", Probes: []probe{probe{event: "poll", attach: sysCall, fn: "poll"}}, EnabledByDefault: false, EssentialEvent: false},
	LseekEventID:               EventConfig{ID: LseekEventID, Name: "reserved", Probes: []probe{probe{event: "lseek", attach: sysCall, fn: "lseek"}}, EnabledByDefault: false, EssentialEvent: false},
	MmapEventID:                EventConfig{ID: MmapEventID, Name: "mmap", Probes: []probe{probe{event: "mmap", attach: sysCall, fn: "mmap"}}, EnabledByDefault: true, EssentialEvent: false},
	MprotectEventID:            EventConfig{ID: MprotectEventID, Name: "mprotect", Probes: []probe{probe{event: "mprotect", attach: sysCall, fn: "mprotect"}}, EnabledByDefault: true, EssentialEvent: false},
	MunmapEventID:              EventConfig{ID: MunmapEventID, Name: "reserved", Probes: []probe{probe{event: "munmap", attach: sysCall, fn: "munmap"}}, EnabledByDefault: false, EssentialEvent: false},
	BrkEventID:                 EventConfig{ID: BrkEventID, Name: "reserved", Probes: []probe{probe{event: "brk", attach: sysCall, fn: "brk"}}, EnabledByDefault: false, EssentialEvent: false},
	RtSigactionEventID:         EventConfig{ID: RtSigactionEventID, Name: "reserved", Probes: []probe{probe{event: "rt_sigaction", attach: sysCall, fn: "rt_sigaction"}}, EnabledByDefault: false, EssentialEvent: false},
	RtSigprocmaskEventID:       EventConfig{ID: RtSigprocmaskEventID, Name: "reserved", Probes: []probe{probe{event: "rt_sigprocmask", attach: sysCall, fn: "rt_sigprocmask"}}, EnabledByDefault: false, EssentialEvent: false},
	RtSigreturnEventID:         EventConfig{ID: RtSigreturnEventID, Name: "reserved", Probes: []probe{probe{event: "rt_sigreturn", attach: sysCall, fn: "rt_sigreturn"}}, EnabledByDefault: false, EssentialEvent: false},
	IoctlEventID:               EventConfig{ID: IoctlEventID, Name: "ioctl", Probes: []probe{probe{event: "ioctl", attach: sysCall, fn: "ioctl"}}, EnabledByDefault: true, EssentialEvent: false},
	Pread64EventID:             EventConfig{ID: Pread64EventID, Name: "reserved", Probes: []probe{probe{event: "pread64", attach: sysCall, fn: "pread64"}}, EnabledByDefault: false, EssentialEvent: false},
	Pwrite64EventID:            EventConfig{ID: Pwrite64EventID, Name: "reserved", Probes: []probe{probe{event: "pwrite64", attach: sysCall, fn: "pwrite64"}}, EnabledByDefault: false, EssentialEvent: false},
	ReadvEventID:               EventConfig{ID: ReadvEventID, Name: "reserved", Probes: []probe{probe{event: "readv", attach: sysCall, fn: "readv"}}, EnabledByDefault: false, EssentialEvent: false},
	WritevEventID:              EventConfig{ID: WritevEventID, Name: "reserved", Probes: []probe{probe{event: "writev", attach: sysCall, fn: "writev"}}, EnabledByDefault: false, EssentialEvent: false},
	AccessEventID:              EventConfig{ID: AccessEventID, Name: "access", Probes: []probe{probe{event: "access", attach: sysCall, fn: "access"}}, EnabledByDefault: true, EssentialEvent: false},
	PipeEventID:                EventConfig{ID: PipeEventID, Name: "reserved", Probes: []probe{probe{event: "pipe", attach: sysCall, fn: "pipe"}}, EnabledByDefault: false, EssentialEvent: false},
	SelectEventID:              EventConfig{ID: SelectEventID, Name: "reserved", Probes: []probe{probe{event: "select", attach: sysCall, fn: "select"}}, EnabledByDefault: false, EssentialEvent: false},
	SchedYieldEventID:          EventConfig{ID: SchedYieldEventID, Name: "reserved", Probes: []probe{probe{event: "sched_yield", attach: sysCall, fn: "sched_yield"}}, EnabledByDefault: false, EssentialEvent: false},
	MremapEventID:              EventConfig{ID: MremapEventID, Name: "reserved", Probes: []probe{probe{event: "mremap", attach: sysCall, fn: "mremap"}}, EnabledByDefault: false, EssentialEvent: false},
	MsyncEventID:               EventConfig{ID: MsyncEventID, Name: "reserved", Probes: []probe{probe{event: "msync", attach: sysCall, fn: "msync"}}, EnabledByDefault: false, EssentialEvent: false},
	MincoreEventID:             EventConfig{ID: MincoreEventID, Name: "reserved", Probes: []probe{probe{event: "mincore", attach: sysCall, fn: "mincore"}}, EnabledByDefault: false, EssentialEvent: false},
	MadviseEventID:             EventConfig{ID: MadviseEventID, Name: "reserved", Probes: []probe{probe{event: "madvise", attach: sysCall, fn: "madvise"}}, EnabledByDefault: false, EssentialEvent: false},
	ShmgetEventID:              EventConfig{ID: ShmgetEventID, Name: "reserved", Probes: []probe{probe{event: "shmget", attach: sysCall, fn: "shmget"}}, EnabledByDefault: false, EssentialEvent: false},
	ShmatEventID:               EventConfig{ID: ShmatEventID, Name: "reserved", Probes: []probe{probe{event: "shmat", attach: sysCall, fn: "shmat"}}, EnabledByDefault: false, EssentialEvent: false},
	ShmctlEventID:              EventConfig{ID: ShmctlEventID, Name: "reserved", Probes: []probe{probe{event: "shmctl", attach: sysCall, fn: "shmctl"}}, EnabledByDefault: false, EssentialEvent: false},
	DupEventID:                 EventConfig{ID: DupEventID, Name: "dup", Probes: []probe{probe{event: "dup", attach: sysCall, fn: "dup"}}, EnabledByDefault: true, EssentialEvent: false},
	Dup2EventID:                EventConfig{ID: Dup2EventID, Name: "dup2", Probes: []probe{probe{event: "dup2", attach: sysCall, fn: "dup2"}}, EnabledByDefault: true, EssentialEvent: false},
	PauseEventID:               EventConfig{ID: PauseEventID, Name: "reserved", Probes: []probe{probe{event: "pause", attach: sysCall, fn: "pause"}}, EnabledByDefault: false, EssentialEvent: false},
	NanosleepEventID:           EventConfig{ID: NanosleepEventID, Name: "reserved", Probes: []probe{probe{event: "nanosleep", attach: sysCall, fn: "nanosleep"}}, EnabledByDefault: false, EssentialEvent: false},
	GetitimerEventID:           EventConfig{ID: GetitimerEventID, Name: "reserved", Probes: []probe{probe{event: "getitimer", attach: sysCall, fn: "getitimer"}}, EnabledByDefault: false, EssentialEvent: false},
	AlarmEventID:               EventConfig{ID: AlarmEventID, Name: "reserved", Probes: []probe{probe{event: "alarm", attach: sysCall, fn: "alarm"}}, EnabledByDefault: false, EssentialEvent: false},
	SetitimerEventID:           EventConfig{ID: SetitimerEventID, Name: "reserved", Probes: []probe{probe{event: "setitimer", attach: sysCall, fn: "setitimer"}}, EnabledByDefault: false, EssentialEvent: false},
	GetpidEventID:              EventConfig{ID: GetpidEventID, Name: "reserved", Probes: []probe{probe{event: "getpid", attach: sysCall, fn: "getpid"}}, EnabledByDefault: false, EssentialEvent: false},
	SendfileEventID:            EventConfig{ID: SendfileEventID, Name: "reserved", Probes: []probe{probe{event: "sendfile", attach: sysCall, fn: "sendfile"}}, EnabledByDefault: false, EssentialEvent: false},
	SocketEventID:              EventConfig{ID: SocketEventID, Name: "socket", Probes: []probe{probe{event: "socket", attach: sysCall, fn: "socket"}}, EnabledByDefault: true, EssentialEvent: false},
	ConnectEventID:             EventConfig{ID: ConnectEventID, Name: "connect", Probes: []probe{probe{event: "connect", attach: sysCall, fn: "connect"}}, EnabledByDefault: true, EssentialEvent: false},
	AcceptEventID:              EventConfig{ID: AcceptEventID, Name: "accept", Probes: []probe{probe{event: "accept", attach: sysCall, fn: "accept"}}, EnabledByDefault: true, EssentialEvent: false},
	SendtoEventID:              EventConfig{ID: SendtoEventID, Name: "reserved", Probes: []probe{probe{event: "sendto", attach: sysCall, fn: "sendto"}}, EnabledByDefault: false, EssentialEvent: false},
	RecvfromEventID:            EventConfig{ID: RecvfromEventID, Name: "reserved", Probes: []probe{probe{event: "recvfrom", attach: sysCall, fn: "recvfrom"}}, EnabledByDefault: false, EssentialEvent: false},
	SendmsgEventID:             EventConfig{ID: SendmsgEventID, Name: "reserved", Probes: []probe{probe{event: "sendmsg", attach: sysCall, fn: "sendmsg"}}, EnabledByDefault: false, EssentialEvent: false},
	RecvmsgEventID:             EventConfig{ID: RecvmsgEventID, Name: "reserved", Probes: []probe{probe{event: "recvmsg", attach: sysCall, fn: "recvmsg"}}, EnabledByDefault: false, EssentialEvent: false},
	ShutdownEventID:            EventConfig{ID: ShutdownEventID, Name: "reserved", Probes: []probe{probe{event: "shutdown", attach: sysCall, fn: "shutdown"}}, EnabledByDefault: false, EssentialEvent: false},
	BindEventID:                EventConfig{ID: BindEventID, Name: "bind", Probes: []probe{probe{event: "bind", attach: sysCall, fn: "bind"}}, EnabledByDefault: true, EssentialEvent: false},
	ListenEventID:              EventConfig{ID: ListenEventID, Name: "listen", Probes: []probe{probe{event: "listen", attach: sysCall, fn: "listen"}}, EnabledByDefault: true, EssentialEvent: false},
	GetsocknameEventID:         EventConfig{ID: GetsocknameEventID, Name: "getsockname", Probes: []probe{probe{event: "getsockname", attach: sysCall, fn: "getsockname"}}, EnabledByDefault: true, EssentialEvent: false},
	GetpeernameEventID:         EventConfig{ID: GetpeernameEventID, Name: "reserved", Probes: []probe{probe{event: "getpeername", attach: sysCall, fn: "getpeername"}}, EnabledByDefault: false, EssentialEvent: false},
	SocketpairEventID:          EventConfig{ID: SocketpairEventID, Name: "reserved", Probes: []probe{probe{event: "socketpair", attach: sysCall, fn: "socketpair"}}, EnabledByDefault: false, EssentialEvent: false},
	SetsockoptEventID:          EventConfig{ID: SetsockoptEventID, Name: "reserved", Probes: []probe{probe{event: "setsockopt", attach: sysCall, fn: "setsockopt"}}, EnabledByDefault: false, EssentialEvent: false},
	GetsockoptEventID:          EventConfig{ID: GetsockoptEventID, Name: "reserved", Probes: []probe{probe{event: "getsockopt", attach: sysCall, fn: "getsockopt"}}, EnabledByDefault: false, EssentialEvent: false},
	CloneEventID:               EventConfig{ID: CloneEventID, Name: "clone", Probes: []probe{probe{event: "clone", attach: sysCall, fn: "clone"}}, EnabledByDefault: true, EssentialEvent: true},
	ForkEventID:                EventConfig{ID: ForkEventID, Name: "fork", Probes: []probe{probe{event: "fork", attach: sysCall, fn: "fork"}}, EnabledByDefault: true, EssentialEvent: true},
	VforkEventID:               EventConfig{ID: VforkEventID, Name: "vfork", Probes: []probe{probe{event: "vfork", attach: sysCall, fn: "vfork"}}, EnabledByDefault: true, EssentialEvent: true},
	ExecveEventID:              EventConfig{ID: ExecveEventID, Name: "execve", Probes: []probe{probe{event: "execve", attach: sysCall, fn: "execve"}}, EnabledByDefault: true, EssentialEvent: true},
	ExitEventID:                EventConfig{ID: ExitEventID, Name: "reserved", Probes: []probe{probe{event: "exit", attach: sysCall, fn: "exit"}}, EnabledByDefault: false, EssentialEvent: false},
	Wait4EventID:               EventConfig{ID: Wait4EventID, Name: "reserved", Probes: []probe{probe{event: "wait4", attach: sysCall, fn: "wait4"}}, EnabledByDefault: false, EssentialEvent: false},
	KillEventID:                EventConfig{ID: KillEventID, Name: "kill", Probes: []probe{probe{event: "kill", attach: sysCall, fn: "kill"}}, EnabledByDefault: true, EssentialEvent: false},
	UnameEventID:               EventConfig{ID: UnameEventID, Name: "reserved", Probes: []probe{probe{event: "uname", attach: sysCall, fn: "uname"}}, EnabledByDefault: false, EssentialEvent: false},
	SemgetEventID:              EventConfig{ID: SemgetEventID, Name: "reserved", Probes: []probe{probe{event: "semget", attach: sysCall, fn: "semget"}}, EnabledByDefault: false, EssentialEvent: false},
	SemopEventID:               EventConfig{ID: SemopEventID, Name: "reserved", Probes: []probe{probe{event: "semop", attach: sysCall, fn: "semop"}}, EnabledByDefault: false, EssentialEvent: false},
	SemctlEventID:              EventConfig{ID: SemctlEventID, Name: "reserved", Probes: []probe{probe{event: "semctl", attach: sysCall, fn: "semctl"}}, EnabledByDefault: false, EssentialEvent: false},
	ShmdtEventID:               EventConfig{ID: ShmdtEventID, Name: "reserved", Probes: []probe{probe{event: "shmdt", attach: sysCall, fn: "shmdt"}}, EnabledByDefault: false, EssentialEvent: false},
	MsggetEventID:              EventConfig{ID: MsggetEventID, Name: "reserved", Probes: []probe{probe{event: "msgget", attach: sysCall, fn: "msgget"}}, EnabledByDefault: false, EssentialEvent: false},
	MsgsndEventID:              EventConfig{ID: MsgsndEventID, Name: "reserved", Probes: []probe{probe{event: "msgsnd", attach: sysCall, fn: "msgsnd"}}, EnabledByDefault: false, EssentialEvent: false},
	MsgrcvEventID:              EventConfig{ID: MsgrcvEventID, Name: "reserved", Probes: []probe{probe{event: "msgrcv", attach: sysCall, fn: "msgrcv"}}, EnabledByDefault: false, EssentialEvent: false},
	MsgctlEventID:              EventConfig{ID: MsgctlEventID, Name: "reserved", Probes: []probe{probe{event: "msgctl", attach: sysCall, fn: "msgctl"}}, EnabledByDefault: false, EssentialEvent: false},
	FcntlEventID:               EventConfig{ID: FcntlEventID, Name: "reserved", Probes: []probe{probe{event: "fcntl", attach: sysCall, fn: "fcntl"}}, EnabledByDefault: false, EssentialEvent: false},
	FlockEventID:               EventConfig{ID: FlockEventID, Name: "reserved", Probes: []probe{probe{event: "flock", attach: sysCall, fn: "flock"}}, EnabledByDefault: false, EssentialEvent: false},
	FsyncEventID:               EventConfig{ID: FsyncEventID, Name: "reserved", Probes: []probe{probe{event: "fsync", attach: sysCall, fn: "fsync"}}, EnabledByDefault: false, EssentialEvent: false},
	FdatasyncEventID:           EventConfig{ID: FdatasyncEventID, Name: "reserved", Probes: []probe{probe{event: "fdatasync", attach: sysCall, fn: "fdatasync"}}, EnabledByDefault: false, EssentialEvent: false},
	TruncateEventID:            EventConfig{ID: TruncateEventID, Name: "reserved", Probes: []probe{probe{event: "truncate", attach: sysCall, fn: "truncate"}}, EnabledByDefault: false, EssentialEvent: false},
	FtruncateEventID:           EventConfig{ID: FtruncateEventID, Name: "reserved", Probes: []probe{probe{event: "ftruncate", attach: sysCall, fn: "ftruncate"}}, EnabledByDefault: false, EssentialEvent: false},
	GetdentsEventID:            EventConfig{ID: GetdentsEventID, Name: "getdents", Probes: []probe{probe{event: "getdents", attach: sysCall, fn: "getdents"}}, EnabledByDefault: true, EssentialEvent: false},
	GetcwdEventID:              EventConfig{ID: GetcwdEventID, Name: "reserved", Probes: []probe{probe{event: "getcwd", attach: sysCall, fn: "getcwd"}}, EnabledByDefault: false, EssentialEvent: false},
	ChdirEventID:               EventConfig{ID: ChdirEventID, Name: "reserved", Probes: []probe{probe{event: "chdir", attach: sysCall, fn: "chdir"}}, EnabledByDefault: false, EssentialEvent: false},
	FchdirEventID:              EventConfig{ID: FchdirEventID, Name: "reserved", Probes: []probe{probe{event: "fchdir", attach: sysCall, fn: "fchdir"}}, EnabledByDefault: false, EssentialEvent: false},
	RenameEventID:              EventConfig{ID: RenameEventID, Name: "reserved", Probes: []probe{probe{event: "rename", attach: sysCall, fn: "rename"}}, EnabledByDefault: false, EssentialEvent: false},
	MkdirEventID:               EventConfig{ID: MkdirEventID, Name: "reserved", Probes: []probe{probe{event: "mkdir", attach: sysCall, fn: "mkdir"}}, EnabledByDefault: false, EssentialEvent: false},
	RmdirEventID:               EventConfig{ID: RmdirEventID, Name: "reserved", Probes: []probe{probe{event: "rmdir", attach: sysCall, fn: "rmdir"}}, EnabledByDefault: false, EssentialEvent: false},
	CreatEventID:               EventConfig{ID: CreatEventID, Name: "creat", Probes: []probe{probe{event: "creat", attach: sysCall, fn: "creat"}}, EnabledByDefault: true, EssentialEvent: false},
	LinkEventID:                EventConfig{ID: LinkEventID, Name: "reserved", Probes: []probe{probe{event: "link", attach: sysCall, fn: "link"}}, EnabledByDefault: false, EssentialEvent: false},
	UnlinkEventID:              EventConfig{ID: UnlinkEventID, Name: "unlink", Probes: []probe{probe{event: "unlink", attach: sysCall, fn: "unlink"}}, EnabledByDefault: true, EssentialEvent: false},
	SymlinkEventID:             EventConfig{ID: SymlinkEventID, Name: "symlink", Probes: []probe{probe{event: "symlink", attach: sysCall, fn: "symlink"}}, EnabledByDefault: true, EssentialEvent: false},
	ReadlinkEventID:            EventConfig{ID: ReadlinkEventID, Name: "reserved", Probes: []probe{probe{event: "readlink", attach: sysCall, fn: "readlink"}}, EnabledByDefault: false, EssentialEvent: false},
	ChmodEventID:               EventConfig{ID: ChmodEventID, Name: "chmod", Probes: []probe{probe{event: "chmod", attach: sysCall, fn: "chmod"}}, EnabledByDefault: true, EssentialEvent: false},
	FchmodEventID:              EventConfig{ID: FchmodEventID, Name: "fchmod", Probes: []probe{probe{event: "fchmod", attach: sysCall, fn: "fchmod"}}, EnabledByDefault: true, EssentialEvent: false},
	ChownEventID:               EventConfig{ID: ChownEventID, Name: "chown", Probes: []probe{probe{event: "chown", attach: sysCall, fn: "chown"}}, EnabledByDefault: true, EssentialEvent: false},
	FchownEventID:              EventConfig{ID: FchownEventID, Name: "fchown", Probes: []probe{probe{event: "fchown", attach: sysCall, fn: "fchown"}}, EnabledByDefault: true, EssentialEvent: false},
	LchownEventID:              EventConfig{ID: LchownEventID, Name: "lchown", Probes: []probe{probe{event: "lchown", attach: sysCall, fn: "lchown"}}, EnabledByDefault: true, EssentialEvent: false},
	UmaskEventID:               EventConfig{ID: UmaskEventID, Name: "reserved", Probes: []probe{probe{event: "umask", attach: sysCall, fn: "umask"}}, EnabledByDefault: false, EssentialEvent: false},
	GettimeofdayEventID:        EventConfig{ID: GettimeofdayEventID, Name: "reserved", Probes: []probe{probe{event: "gettimeofday", attach: sysCall, fn: "gettimeofday"}}, EnabledByDefault: false, EssentialEvent: false},
	GetrlimitEventID:           EventConfig{ID: GetrlimitEventID, Name: "reserved", Probes: []probe{probe{event: "getrlimit", attach: sysCall, fn: "getrlimit"}}, EnabledByDefault: false, EssentialEvent: false},
	GetrusageEventID:           EventConfig{ID: GetrusageEventID, Name: "reserved", Probes: []probe{probe{event: "getrusage", attach: sysCall, fn: "getrusage"}}, EnabledByDefault: false, EssentialEvent: false},
	SysinfoEventID:             EventConfig{ID: SysinfoEventID, Name: "reserved", Probes: []probe{probe{event: "sysinfo", attach: sysCall, fn: "sysinfo"}}, EnabledByDefault: false, EssentialEvent: false},
	TimesEventID:               EventConfig{ID: TimesEventID, Name: "reserved", Probes: []probe{probe{event: "times", attach: sysCall, fn: "times"}}, EnabledByDefault: false, EssentialEvent: false},
	PtraceEventID:              EventConfig{ID: PtraceEventID, Name: "ptrace", Probes: []probe{probe{event: "ptrace", attach: sysCall, fn: "ptrace"}}, EnabledByDefault: true, EssentialEvent: false},
	GetuidEventID:              EventConfig{ID: GetuidEventID, Name: "reserved", Probes: []probe{probe{event: "getuid", attach: sysCall, fn: "getuid"}}, EnabledByDefault: false, EssentialEvent: false},
	SyslogEventID:              EventConfig{ID: SyslogEventID, Name: "reserved", Probes: []probe{probe{event: "syslog", attach: sysCall, fn: "syslog"}}, EnabledByDefault: false, EssentialEvent: false},
	GetgidEventID:              EventConfig{ID: GetgidEventID, Name: "reserved", Probes: []probe{probe{event: "getgid", attach: sysCall, fn: "getgid"}}, EnabledByDefault: false, EssentialEvent: false},
	SetuidEventID:              EventConfig{ID: SetuidEventID, Name: "setuid", Probes: []probe{probe{event: "setuid", attach: sysCall, fn: "setuid"}}, EnabledByDefault: true, EssentialEvent: false},
	SetgidEventID:              EventConfig{ID: SetgidEventID, Name: "setgid", Probes: []probe{probe{event: "setgid", attach: sysCall, fn: "setgid"}}, EnabledByDefault: true, EssentialEvent: false},
	GeteuidEventID:             EventConfig{ID: GeteuidEventID, Name: "reserved", Probes: []probe{probe{event: "geteuid", attach: sysCall, fn: "geteuid"}}, EnabledByDefault: false, EssentialEvent: false},
	GetegidEventID:             EventConfig{ID: GetegidEventID, Name: "reserved", Probes: []probe{probe{event: "getegid", attach: sysCall, fn: "getegid"}}, EnabledByDefault: false, EssentialEvent: false},
	SetpgidEventID:             EventConfig{ID: SetpgidEventID, Name: "reserved", Probes: []probe{probe{event: "setpgid", attach: sysCall, fn: "setpgid"}}, EnabledByDefault: false, EssentialEvent: false},
	GetppidEventID:             EventConfig{ID: GetppidEventID, Name: "reserved", Probes: []probe{probe{event: "getppid", attach: sysCall, fn: "getppid"}}, EnabledByDefault: false, EssentialEvent: false},
	GetpgrpEventID:             EventConfig{ID: GetpgrpEventID, Name: "reserved", Probes: []probe{probe{event: "getpgrp", attach: sysCall, fn: "getpgrp"}}, EnabledByDefault: false, EssentialEvent: false},
	SetsidEventID:              EventConfig{ID: SetsidEventID, Name: "reserved", Probes: []probe{probe{event: "setsid", attach: sysCall, fn: "setsid"}}, EnabledByDefault: false, EssentialEvent: false},
	SetreuidEventID:            EventConfig{ID: SetreuidEventID, Name: "setreuid", Probes: []probe{probe{event: "setreuid", attach: sysCall, fn: "setreuid"}}, EnabledByDefault: true, EssentialEvent: false},
	SetregidEventID:            EventConfig{ID: SetregidEventID, Name: "setregid", Probes: []probe{probe{event: "setregid", attach: sysCall, fn: "setregid"}}, EnabledByDefault: true, EssentialEvent: false},
	GetgroupsEventID:           EventConfig{ID: GetgroupsEventID, Name: "reserved", Probes: []probe{probe{event: "getgroups", attach: sysCall, fn: "getgroups"}}, EnabledByDefault: false, EssentialEvent: false},
	SetgroupsEventID:           EventConfig{ID: SetgroupsEventID, Name: "reserved", Probes: []probe{probe{event: "setgroups", attach: sysCall, fn: "setgroups"}}, EnabledByDefault: false, EssentialEvent: false},
	SetresuidEventID:           EventConfig{ID: SetresuidEventID, Name: "reserved", Probes: []probe{probe{event: "setresuid", attach: sysCall, fn: "setresuid"}}, EnabledByDefault: false, EssentialEvent: false},
	GetresuidEventID:           EventConfig{ID: GetresuidEventID, Name: "reserved", Probes: []probe{probe{event: "getresuid", attach: sysCall, fn: "getresuid"}}, EnabledByDefault: false, EssentialEvent: false},
	SetresgidEventID:           EventConfig{ID: SetresgidEventID, Name: "reserved", Probes: []probe{probe{event: "setresgid", attach: sysCall, fn: "setresgid"}}, EnabledByDefault: false, EssentialEvent: false},
	GetresgidEventID:           EventConfig{ID: GetresgidEventID, Name: "reserved", Probes: []probe{probe{event: "getresgid", attach: sysCall, fn: "getresgid"}}, EnabledByDefault: false, EssentialEvent: false},
	GetpgidEventID:             EventConfig{ID: GetpgidEventID, Name: "reserved", Probes: []probe{probe{event: "getpgid", attach: sysCall, fn: "getpgid"}}, EnabledByDefault: false, EssentialEvent: false},
	SetfsuidEventID:            EventConfig{ID: SetfsuidEventID, Name: "setfsuid", Probes: []probe{probe{event: "setfsuid", attach: sysCall, fn: "setfsuid"}}, EnabledByDefault: true, EssentialEvent: false},
	SetfsgidEventID:            EventConfig{ID: SetfsgidEventID, Name: "setfsgid", Probes: []probe{probe{event: "setfsgid", attach: sysCall, fn: "setfsgid"}}, EnabledByDefault: true, EssentialEvent: false},
	GetsidEventID:              EventConfig{ID: GetsidEventID, Name: "reserved", Probes: []probe{probe{event: "getsid", attach: sysCall, fn: "getsid"}}, EnabledByDefault: false, EssentialEvent: false},
	CapgetEventID:              EventConfig{ID: CapgetEventID, Name: "reserved", Probes: []probe{probe{event: "capget", attach: sysCall, fn: "capget"}}, EnabledByDefault: false, EssentialEvent: false},
	CapsetEventID:              EventConfig{ID: CapsetEventID, Name: "reserved", Probes: []probe{probe{event: "capset", attach: sysCall, fn: "capset"}}, EnabledByDefault: false, EssentialEvent: false},
	RtSigpendingEventID:        EventConfig{ID: RtSigpendingEventID, Name: "reserved", Probes: []probe{probe{event: "rt_sigpending", attach: sysCall, fn: "rt_sigpending"}}, EnabledByDefault: false, EssentialEvent: false},
	RtSigtimedwaitEventID:      EventConfig{ID: RtSigtimedwaitEventID, Name: "reserved", Probes: []probe{probe{event: "rt_sigtimedwait", attach: sysCall, fn: "rt_sigtimedwait"}}, EnabledByDefault: false, EssentialEvent: false},
	RtSigqueueinfoEventID:      EventConfig{ID: RtSigqueueinfoEventID, Name: "reserved", Probes: []probe{probe{event: "rt_sigqueueinfo", attach: sysCall, fn: "rt_sigqueueinfo"}}, EnabledByDefault: false, EssentialEvent: false},
	RtSigsuspendEventID:        EventConfig{ID: RtSigsuspendEventID, Name: "reserved", Probes: []probe{probe{event: "rt_sigsuspend", attach: sysCall, fn: "rt_sigsuspend"}}, EnabledByDefault: false, EssentialEvent: false},
	SigaltstackEventID:         EventConfig{ID: SigaltstackEventID, Name: "reserved", Probes: []probe{probe{event: "sigaltstack", attach: sysCall, fn: "sigaltstack"}}, EnabledByDefault: false, EssentialEvent: false},
	UtimeEventID:               EventConfig{ID: UtimeEventID, Name: "reserved", Probes: []probe{probe{event: "utime", attach: sysCall, fn: "utime"}}, EnabledByDefault: false, EssentialEvent: false},
	MknodEventID:               EventConfig{ID: MknodEventID, Name: "mknod", Probes: []probe{probe{event: "mknod", attach: sysCall, fn: "mknod"}}, EnabledByDefault: true, EssentialEvent: false},
	UselibEventID:              EventConfig{ID: UselibEventID, Name: "reserved", Probes: []probe{probe{event: "uselib", attach: sysCall, fn: "uselib"}}, EnabledByDefault: false, EssentialEvent: false},
	PersonalityEventID:         EventConfig{ID: PersonalityEventID, Name: "reserved", Probes: []probe{probe{event: "personality", attach: sysCall, fn: "personality"}}, EnabledByDefault: false, EssentialEvent: false},
	UstatEventID:               EventConfig{ID: UstatEventID, Name: "reserved", Probes: []probe{probe{event: "ustat", attach: sysCall, fn: "ustat"}}, EnabledByDefault: false, EssentialEvent: false},
	StatfsEventID:              EventConfig{ID: StatfsEventID, Name: "reserved", Probes: []probe{probe{event: "statfs", attach: sysCall, fn: "statfs"}}, EnabledByDefault: false, EssentialEvent: false},
	FstatfsEventID:             EventConfig{ID: FstatfsEventID, Name: "reserved", Probes: []probe{probe{event: "fstatfs", attach: sysCall, fn: "fstatfs"}}, EnabledByDefault: false, EssentialEvent: false},
	SysfsEventID:               EventConfig{ID: SysfsEventID, Name: "reserved", Probes: []probe{probe{event: "sysfs", attach: sysCall, fn: "sysfs"}}, EnabledByDefault: false, EssentialEvent: false},
	GetpriorityEventID:         EventConfig{ID: GetpriorityEventID, Name: "reserved", Probes: []probe{probe{event: "getpriority", attach: sysCall, fn: "getpriority"}}, EnabledByDefault: false, EssentialEvent: false},
	SetpriorityEventID:         EventConfig{ID: SetpriorityEventID, Name: "reserved", Probes: []probe{probe{event: "setpriority", attach: sysCall, fn: "setpriority"}}, EnabledByDefault: false, EssentialEvent: false},
	SchedSetparamEventID:       EventConfig{ID: SchedSetparamEventID, Name: "reserved", Probes: []probe{probe{event: "sched_setparam", attach: sysCall, fn: "sched_setparam"}}, EnabledByDefault: false, EssentialEvent: false},
	SchedGetparamEventID:       EventConfig{ID: SchedGetparamEventID, Name: "reserved", Probes: []probe{probe{event: "sched_getparam", attach: sysCall, fn: "sched_getparam"}}, EnabledByDefault: false, EssentialEvent: false},
	SchedSetschedulerEventID:   EventConfig{ID: SchedSetschedulerEventID, Name: "reserved", Probes: []probe{probe{event: "sched_setscheduler", attach: sysCall, fn: "sched_setscheduler"}}, EnabledByDefault: false, EssentialEvent: false},
	SchedGetschedulerEventID:   EventConfig{ID: SchedGetschedulerEventID, Name: "reserved", Probes: []probe{probe{event: "sched_getscheduler", attach: sysCall, fn: "sched_getscheduler"}}, EnabledByDefault: false, EssentialEvent: false},
	SchedGetPriorityMaxEventID: EventConfig{ID: SchedGetPriorityMaxEventID, Name: "reserved", Probes: []probe{probe{event: "sched_get_priority_max", attach: sysCall, fn: "sched_get_priority_max"}}, EnabledByDefault: false, EssentialEvent: false},
	SchedGetPriorityMinEventID: EventConfig{ID: SchedGetPriorityMinEventID, Name: "reserved", Probes: []probe{probe{event: "sched_get_priority_min", attach: sysCall, fn: "sched_get_priority_min"}}, EnabledByDefault: false, EssentialEvent: false},
	SchedRrGetIntervalEventID:  EventConfig{ID: SchedRrGetIntervalEventID, Name: "reserved", Probes: []probe{probe{event: "sched_rr_get_interval", attach: sysCall, fn: "sched_rr_get_interval"}}, EnabledByDefault: false, EssentialEvent: false},
	MlockEventID:               EventConfig{ID: MlockEventID, Name: "reserved", Probes: []probe{probe{event: "mlock", attach: sysCall, fn: "mlock"}}, EnabledByDefault: false, EssentialEvent: false},
	MunlockEventID:             EventConfig{ID: MunlockEventID, Name: "reserved", Probes: []probe{probe{event: "munlock", attach: sysCall, fn: "munlock"}}, EnabledByDefault: false, EssentialEvent: false},
	MlockallEventID:            EventConfig{ID: MlockallEventID, Name: "reserved", Probes: []probe{probe{event: "mlockall", attach: sysCall, fn: "mlockall"}}, EnabledByDefault: false, EssentialEvent: false},
	MunlockallEventID:          EventConfig{ID: MunlockallEventID, Name: "reserved", Probes: []probe{probe{event: "munlockall", attach: sysCall, fn: "munlockall"}}, EnabledByDefault: false, EssentialEvent: false},
	VhangupEventID:             EventConfig{ID: VhangupEventID, Name: "reserved", Probes: []probe{probe{event: "vhangup", attach: sysCall, fn: "vhangup"}}, EnabledByDefault: false, EssentialEvent: false},
	ModifyLdtEventID:           EventConfig{ID: ModifyLdtEventID, Name: "reserved", Probes: []probe{probe{event: "modify_ldt", attach: sysCall, fn: "modify_ldt"}}, EnabledByDefault: false, EssentialEvent: false},
	PivotRootEventID:           EventConfig{ID: PivotRootEventID, Name: "reserved", Probes: []probe{probe{event: "pivot_root", attach: sysCall, fn: "pivot_root"}}, EnabledByDefault: false, EssentialEvent: false},
	SysctlEventID:              EventConfig{ID: SysctlEventID, Name: "reserved", Probes: []probe{probe{event: "sysctl", attach: sysCall, fn: "sysctl"}}, EnabledByDefault: false, EssentialEvent: false},
	PrctlEventID:               EventConfig{ID: PrctlEventID, Name: "prctl", Probes: []probe{probe{event: "prctl", attach: sysCall, fn: "prctl"}}, EnabledByDefault: true, EssentialEvent: false},
	ArchPrctlEventID:           EventConfig{ID: ArchPrctlEventID, Name: "reserved", Probes: []probe{probe{event: "arch_prctl", attach: sysCall, fn: "arch_prctl"}}, EnabledByDefault: false, EssentialEvent: false},
	AdjtimexEventID:            EventConfig{ID: AdjtimexEventID, Name: "reserved", Probes: []probe{probe{event: "adjtimex", attach: sysCall, fn: "adjtimex"}}, EnabledByDefault: false, EssentialEvent: false},
	SetrlimitEventID:           EventConfig{ID: SetrlimitEventID, Name: "reserved", Probes: []probe{probe{event: "setrlimit", attach: sysCall, fn: "setrlimit"}}, EnabledByDefault: false, EssentialEvent: false},
	ChrootEventID:              EventConfig{ID: ChrootEventID, Name: "reserved", Probes: []probe{probe{event: "chroot", attach: sysCall, fn: "chroot"}}, EnabledByDefault: false, EssentialEvent: false},
	SyncEventID:                EventConfig{ID: SyncEventID, Name: "reserved", Probes: []probe{probe{event: "sync", attach: sysCall, fn: "sync"}}, EnabledByDefault: false, EssentialEvent: false},
	AcctEventID:                EventConfig{ID: AcctEventID, Name: "reserved", Probes: []probe{probe{event: "acct", attach: sysCall, fn: "acct"}}, EnabledByDefault: false, EssentialEvent: false},
	SettimeofdayEventID:        EventConfig{ID: SettimeofdayEventID, Name: "reserved", Probes: []probe{probe{event: "settimeofday", attach: sysCall, fn: "settimeofday"}}, EnabledByDefault: false, EssentialEvent: false},
	MountEventID:               EventConfig{ID: MountEventID, Name: "mount", Probes: []probe{probe{event: "mount", attach: sysCall, fn: "mount"}}, EnabledByDefault: true, EssentialEvent: false},
	UmountEventID:              EventConfig{ID: UmountEventID, Name: "umount", Probes: []probe{probe{event: "umount", attach: sysCall, fn: "umount"}}, EnabledByDefault: true, EssentialEvent: false},
	SwaponEventID:              EventConfig{ID: SwaponEventID, Name: "reserved", Probes: []probe{probe{event: "swapon", attach: sysCall, fn: "swapon"}}, EnabledByDefault: false, EssentialEvent: false},
	SwapoffEventID:             EventConfig{ID: SwapoffEventID, Name: "reserved", Probes: []probe{probe{event: "swapoff", attach: sysCall, fn: "swapoff"}}, EnabledByDefault: false, EssentialEvent: false},
	RebootEventID:              EventConfig{ID: RebootEventID, Name: "reserved", Probes: []probe{probe{event: "reboot", attach: sysCall, fn: "reboot"}}, EnabledByDefault: false, EssentialEvent: false},
	SethostnameEventID:         EventConfig{ID: SethostnameEventID, Name: "reserved", Probes: []probe{probe{event: "sethostname", attach: sysCall, fn: "sethostname"}}, EnabledByDefault: false, EssentialEvent: false},
	SetdomainnameEventID:       EventConfig{ID: SetdomainnameEventID, Name: "reserved", Probes: []probe{probe{event: "setdomainname", attach: sysCall, fn: "setdomainname"}}, EnabledByDefault: false, EssentialEvent: false},
	IoplEventID:                EventConfig{ID: IoplEventID, Name: "reserved", Probes: []probe{probe{event: "iopl", attach: sysCall, fn: "iopl"}}, EnabledByDefault: false, EssentialEvent: false},
	IopermEventID:              EventConfig{ID: IopermEventID, Name: "reserved", Probes: []probe{probe{event: "ioperm", attach: sysCall, fn: "ioperm"}}, EnabledByDefault: false, EssentialEvent: false},
	CreateModuleEventID:        EventConfig{ID: CreateModuleEventID, Name: "reserved", Probes: []probe{probe{event: "create_module", attach: sysCall, fn: "create_module"}}, EnabledByDefault: false, EssentialEvent: false},
	InitModuleEventID:          EventConfig{ID: InitModuleEventID, Name: "init_module", Probes: []probe{probe{event: "init_module", attach: sysCall, fn: "init_module"}}, EnabledByDefault: true, EssentialEvent: false},
	DeleteModuleEventID:        EventConfig{ID: DeleteModuleEventID, Name: "delete_module", Probes: []probe{probe{event: "delete_module", attach: sysCall, fn: "delete_module"}}, EnabledByDefault: true, EssentialEvent: false},
	GetKernelSymsEventID:       EventConfig{ID: GetKernelSymsEventID, Name: "reserved", Probes: []probe{probe{event: "get_kernel_syms", attach: sysCall, fn: "get_kernel_syms"}}, EnabledByDefault: false, EssentialEvent: false},
	QueryModuleEventID:         EventConfig{ID: QueryModuleEventID, Name: "reserved", Probes: []probe{probe{event: "query_module", attach: sysCall, fn: "query_module"}}, EnabledByDefault: false, EssentialEvent: false},
	QuotactlEventID:            EventConfig{ID: QuotactlEventID, Name: "reserved", Probes: []probe{probe{event: "quotactl", attach: sysCall, fn: "quotactl"}}, EnabledByDefault: false, EssentialEvent: false},
	NfsservctlEventID:          EventConfig{ID: NfsservctlEventID, Name: "reserved", Probes: []probe{probe{event: "nfsservctl", attach: sysCall, fn: "nfsservctl"}}, EnabledByDefault: false, EssentialEvent: false},
	GetpmsgEventID:             EventConfig{ID: GetpmsgEventID, Name: "reserved", Probes: []probe{probe{event: "getpmsg", attach: sysCall, fn: "getpmsg"}}, EnabledByDefault: false, EssentialEvent: false},
	PutpmsgEventID:             EventConfig{ID: PutpmsgEventID, Name: "reserved", Probes: []probe{probe{event: "putpmsg", attach: sysCall, fn: "putpmsg"}}, EnabledByDefault: false, EssentialEvent: false},
	AfsEventID:                 EventConfig{ID: AfsEventID, Name: "reserved", Probes: []probe{probe{event: "afs", attach: sysCall, fn: "afs"}}, EnabledByDefault: false, EssentialEvent: false},
	TuxcallEventID:             EventConfig{ID: TuxcallEventID, Name: "reserved", Probes: []probe{probe{event: "tuxcall", attach: sysCall, fn: "tuxcall"}}, EnabledByDefault: false, EssentialEvent: false},
	SecurityEventID:            EventConfig{ID: SecurityEventID, Name: "reserved", Probes: []probe{probe{event: "security", attach: sysCall, fn: "security"}}, EnabledByDefault: false, EssentialEvent: false},
	GettidEventID:              EventConfig{ID: GettidEventID, Name: "reserved", Probes: []probe{probe{event: "gettid", attach: sysCall, fn: "gettid"}}, EnabledByDefault: false, EssentialEvent: false},
	ReadaheadEventID:           EventConfig{ID: ReadaheadEventID, Name: "reserved", Probes: []probe{probe{event: "readahead", attach: sysCall, fn: "readahead"}}, EnabledByDefault: false, EssentialEvent: false},
	SetxattrEventID:            EventConfig{ID: SetxattrEventID, Name: "reserved", Probes: []probe{probe{event: "setxattr", attach: sysCall, fn: "setxattr"}}, EnabledByDefault: false, EssentialEvent: false},
	LsetxattrEventID:           EventConfig{ID: LsetxattrEventID, Name: "reserved", Probes: []probe{probe{event: "lsetxattr", attach: sysCall, fn: "lsetxattr"}}, EnabledByDefault: false, EssentialEvent: false},
	FsetxattrEventID:           EventConfig{ID: FsetxattrEventID, Name: "reserved", Probes: []probe{probe{event: "fsetxattr", attach: sysCall, fn: "fsetxattr"}}, EnabledByDefault: false, EssentialEvent: false},
	GetxattrEventID:            EventConfig{ID: GetxattrEventID, Name: "reserved", Probes: []probe{probe{event: "getxattr", attach: sysCall, fn: "getxattr"}}, EnabledByDefault: false, EssentialEvent: false},
	LgetxattrEventID:           EventConfig{ID: LgetxattrEventID, Name: "reserved", Probes: []probe{probe{event: "lgetxattr", attach: sysCall, fn: "lgetxattr"}}, EnabledByDefault: false, EssentialEvent: false},
	FgetxattrEventID:           EventConfig{ID: FgetxattrEventID, Name: "reserved", Probes: []probe{probe{event: "fgetxattr", attach: sysCall, fn: "fgetxattr"}}, EnabledByDefault: false, EssentialEvent: false},
	ListxattrEventID:           EventConfig{ID: ListxattrEventID, Name: "reserved", Probes: []probe{probe{event: "listxattr", attach: sysCall, fn: "listxattr"}}, EnabledByDefault: false, EssentialEvent: false},
	LlistxattrEventID:          EventConfig{ID: LlistxattrEventID, Name: "reserved", Probes: []probe{probe{event: "llistxattr", attach: sysCall, fn: "llistxattr"}}, EnabledByDefault: false, EssentialEvent: false},
	FlistxattrEventID:          EventConfig{ID: FlistxattrEventID, Name: "reserved", Probes: []probe{probe{event: "flistxattr", attach: sysCall, fn: "flistxattr"}}, EnabledByDefault: false, EssentialEvent: false},
	RemovexattrEventID:         EventConfig{ID: RemovexattrEventID, Name: "reserved", Probes: []probe{probe{event: "removexattr", attach: sysCall, fn: "removexattr"}}, EnabledByDefault: false, EssentialEvent: false},
	LremovexattrEventID:        EventConfig{ID: LremovexattrEventID, Name: "reserved", Probes: []probe{probe{event: "lremovexattr", attach: sysCall, fn: "lremovexattr"}}, EnabledByDefault: false, EssentialEvent: false},
	FremovexattrEventID:        EventConfig{ID: FremovexattrEventID, Name: "reserved", Probes: []probe{probe{event: "fremovexattr", attach: sysCall, fn: "fremovexattr"}}, EnabledByDefault: false, EssentialEvent: false},
	TkillEventID:               EventConfig{ID: TkillEventID, Name: "reserved", Probes: []probe{probe{event: "tkill", attach: sysCall, fn: "tkill"}}, EnabledByDefault: false, EssentialEvent: false},
	TimeEventID:                EventConfig{ID: TimeEventID, Name: "reserved", Probes: []probe{probe{event: "time", attach: sysCall, fn: "time"}}, EnabledByDefault: false, EssentialEvent: false},
	FutexEventID:               EventConfig{ID: FutexEventID, Name: "reserved", Probes: []probe{probe{event: "futex", attach: sysCall, fn: "futex"}}, EnabledByDefault: false, EssentialEvent: false},
	SchedSetaffinityEventID:    EventConfig{ID: SchedSetaffinityEventID, Name: "reserved", Probes: []probe{probe{event: "sched_setaffinity", attach: sysCall, fn: "sched_setaffinity"}}, EnabledByDefault: false, EssentialEvent: false},
	SchedGetaffinityEventID:    EventConfig{ID: SchedGetaffinityEventID, Name: "reserved", Probes: []probe{probe{event: "sched_getaffinity", attach: sysCall, fn: "sched_getaffinity"}}, EnabledByDefault: false, EssentialEvent: false},
	SetThreadAreaEventID:       EventConfig{ID: SetThreadAreaEventID, Name: "reserved", Probes: []probe{probe{event: "set_thread_area", attach: sysCall, fn: "set_thread_area"}}, EnabledByDefault: false, EssentialEvent: false},
	IoSetupEventID:             EventConfig{ID: IoSetupEventID, Name: "reserved", Probes: []probe{probe{event: "io_setup", attach: sysCall, fn: "io_setup"}}, EnabledByDefault: false, EssentialEvent: false},
	IoDestroyEventID:           EventConfig{ID: IoDestroyEventID, Name: "reserved", Probes: []probe{probe{event: "io_destroy", attach: sysCall, fn: "io_destroy"}}, EnabledByDefault: false, EssentialEvent: false},
	IoGeteventsEventID:         EventConfig{ID: IoGeteventsEventID, Name: "reserved", Probes: []probe{probe{event: "io_getevents", attach: sysCall, fn: "io_getevents"}}, EnabledByDefault: false, EssentialEvent: false},
	IoSubmitEventID:            EventConfig{ID: IoSubmitEventID, Name: "reserved", Probes: []probe{probe{event: "io_submit", attach: sysCall, fn: "io_submit"}}, EnabledByDefault: false, EssentialEvent: false},
	IoCancelEventID:            EventConfig{ID: IoCancelEventID, Name: "reserved", Probes: []probe{probe{event: "io_cancel", attach: sysCall, fn: "io_cancel"}}, EnabledByDefault: false, EssentialEvent: false},
	GetThreadAreaEventID:       EventConfig{ID: GetThreadAreaEventID, Name: "reserved", Probes: []probe{probe{event: "get_thread_area", attach: sysCall, fn: "get_thread_area"}}, EnabledByDefault: false, EssentialEvent: false},
	LookupDcookieEventID:       EventConfig{ID: LookupDcookieEventID, Name: "reserved", Probes: []probe{probe{event: "lookup_dcookie", attach: sysCall, fn: "lookup_dcookie"}}, EnabledByDefault: false, EssentialEvent: false},
	EpollCreateEventID:         EventConfig{ID: EpollCreateEventID, Name: "reserved", Probes: []probe{probe{event: "epoll_create", attach: sysCall, fn: "epoll_create"}}, EnabledByDefault: false, EssentialEvent: false},
	EpollCtlOldEventID:         EventConfig{ID: EpollCtlOldEventID, Name: "reserved", Probes: []probe{probe{event: "epoll_ctl_old", attach: sysCall, fn: "epoll_ctl_old"}}, EnabledByDefault: false, EssentialEvent: false},
	EpollWaitOldEventID:        EventConfig{ID: EpollWaitOldEventID, Name: "reserved", Probes: []probe{probe{event: "epoll_wait_old", attach: sysCall, fn: "epoll_wait_old"}}, EnabledByDefault: false, EssentialEvent: false},
	RemapFilePagesEventID:      EventConfig{ID: RemapFilePagesEventID, Name: "reserved", Probes: []probe{probe{event: "remap_file_pages", attach: sysCall, fn: "remap_file_pages"}}, EnabledByDefault: false, EssentialEvent: false},
	Getdents64EventID:          EventConfig{ID: Getdents64EventID, Name: "getdents64", Probes: []probe{probe{event: "getdents64", attach: sysCall, fn: "getdents64"}}, EnabledByDefault: true, EssentialEvent: false},
	SetTidAddressEventID:       EventConfig{ID: SetTidAddressEventID, Name: "reserved", Probes: []probe{probe{event: "set_tid_address", attach: sysCall, fn: "set_tid_address"}}, EnabledByDefault: false, EssentialEvent: false},
	RestartSyscallEventID:      EventConfig{ID: RestartSyscallEventID, Name: "reserved", Probes: []probe{probe{event: "restart_syscall", attach: sysCall, fn: "restart_syscall"}}, EnabledByDefault: false, EssentialEvent: false},
	SemtimedopEventID:          EventConfig{ID: SemtimedopEventID, Name: "reserved", Probes: []probe{probe{event: "semtimedop", attach: sysCall, fn: "semtimedop"}}, EnabledByDefault: false, EssentialEvent: false},
	Fadvise64EventID:           EventConfig{ID: Fadvise64EventID, Name: "reserved", Probes: []probe{probe{event: "fadvise64", attach: sysCall, fn: "fadvise64"}}, EnabledByDefault: false, EssentialEvent: false},
	TimerCreateEventID:         EventConfig{ID: TimerCreateEventID, Name: "reserved", Probes: []probe{probe{event: "timer_create", attach: sysCall, fn: "timer_create"}}, EnabledByDefault: false, EssentialEvent: false},
	TimerSettimeEventID:        EventConfig{ID: TimerSettimeEventID, Name: "reserved", Probes: []probe{probe{event: "timer_settime", attach: sysCall, fn: "timer_settime"}}, EnabledByDefault: false, EssentialEvent: false},
	TimerGettimeEventID:        EventConfig{ID: TimerGettimeEventID, Name: "reserved", Probes: []probe{probe{event: "timer_gettime", attach: sysCall, fn: "timer_gettime"}}, EnabledByDefault: false, EssentialEvent: false},
	TimerGetoverrunEventID:     EventConfig{ID: TimerGetoverrunEventID, Name: "reserved", Probes: []probe{probe{event: "timer_getoverrun", attach: sysCall, fn: "timer_getoverrun"}}, EnabledByDefault: false, EssentialEvent: false},
	TimerDeleteEventID:         EventConfig{ID: TimerDeleteEventID, Name: "reserved", Probes: []probe{probe{event: "timer_delete", attach: sysCall, fn: "timer_delete"}}, EnabledByDefault: false, EssentialEvent: false},
	ClockSettimeEventID:        EventConfig{ID: ClockSettimeEventID, Name: "reserved", Probes: []probe{probe{event: "clock_settime", attach: sysCall, fn: "clock_settime"}}, EnabledByDefault: false, EssentialEvent: false},
	ClockGettimeEventID:        EventConfig{ID: ClockGettimeEventID, Name: "reserved", Probes: []probe{probe{event: "clock_gettime", attach: sysCall, fn: "clock_gettime"}}, EnabledByDefault: false, EssentialEvent: false},
	ClockGetresEventID:         EventConfig{ID: ClockGetresEventID, Name: "reserved", Probes: []probe{probe{event: "clock_getres", attach: sysCall, fn: "clock_getres"}}, EnabledByDefault: false, EssentialEvent: false},
	ClockNanosleepEventID:      EventConfig{ID: ClockNanosleepEventID, Name: "reserved", Probes: []probe{probe{event: "clock_nanosleep", attach: sysCall, fn: "clock_nanosleep"}}, EnabledByDefault: false, EssentialEvent: false},
	ExitGroupEventID:           EventConfig{ID: ExitGroupEventID, Name: "reserved", Probes: []probe{probe{event: "exit_group", attach: sysCall, fn: "exit_group"}}, EnabledByDefault: false, EssentialEvent: false},
	EpollWaitEventID:           EventConfig{ID: EpollWaitEventID, Name: "reserved", Probes: []probe{probe{event: "epoll_wait", attach: sysCall, fn: "epoll_wait"}}, EnabledByDefault: false, EssentialEvent: false},
	EpollCtlEventID:            EventConfig{ID: EpollCtlEventID, Name: "reserved", Probes: []probe{probe{event: "epoll_ctl", attach: sysCall, fn: "epoll_ctl"}}, EnabledByDefault: false, EssentialEvent: false},
	TgkillEventID:              EventConfig{ID: TgkillEventID, Name: "reserved", Probes: []probe{probe{event: "tgkill", attach: sysCall, fn: "tgkill"}}, EnabledByDefault: false, EssentialEvent: false},
	UtimesEventID:              EventConfig{ID: UtimesEventID, Name: "reserved", Probes: []probe{probe{event: "utimes", attach: sysCall, fn: "utimes"}}, EnabledByDefault: false, EssentialEvent: false},
	VserverEventID:             EventConfig{ID: VserverEventID, Name: "reserved", Probes: []probe{probe{event: "vserver", attach: sysCall, fn: "vserver"}}, EnabledByDefault: false, EssentialEvent: false},
	MbindEventID:               EventConfig{ID: MbindEventID, Name: "reserved", Probes: []probe{probe{event: "mbind", attach: sysCall, fn: "mbind"}}, EnabledByDefault: false, EssentialEvent: false},
	SetMempolicyEventID:        EventConfig{ID: SetMempolicyEventID, Name: "reserved", Probes: []probe{probe{event: "set_mempolicy", attach: sysCall, fn: "set_mempolicy"}}, EnabledByDefault: false, EssentialEvent: false},
	GetMempolicyEventID:        EventConfig{ID: GetMempolicyEventID, Name: "reserved", Probes: []probe{probe{event: "get_mempolicy", attach: sysCall, fn: "get_mempolicy"}}, EnabledByDefault: false, EssentialEvent: false},
	MqOpenEventID:              EventConfig{ID: MqOpenEventID, Name: "reserved", Probes: []probe{probe{event: "mq_open", attach: sysCall, fn: "mq_open"}}, EnabledByDefault: false, EssentialEvent: false},
	MqUnlinkEventID:            EventConfig{ID: MqUnlinkEventID, Name: "reserved", Probes: []probe{probe{event: "mq_unlink", attach: sysCall, fn: "mq_unlink"}}, EnabledByDefault: false, EssentialEvent: false},
	MqTimedsendEventID:         EventConfig{ID: MqTimedsendEventID, Name: "reserved", Probes: []probe{probe{event: "mq_timedsend", attach: sysCall, fn: "mq_timedsend"}}, EnabledByDefault: false, EssentialEvent: false},
	MqTimedreceiveEventID:      EventConfig{ID: MqTimedreceiveEventID, Name: "reserved", Probes: []probe{probe{event: "mq_timedreceive", attach: sysCall, fn: "mq_timedreceive"}}, EnabledByDefault: false, EssentialEvent: false},
	MqNotifyEventID:            EventConfig{ID: MqNotifyEventID, Name: "reserved", Probes: []probe{probe{event: "mq_notify", attach: sysCall, fn: "mq_notify"}}, EnabledByDefault: false, EssentialEvent: false},
	MqGetsetattrEventID:        EventConfig{ID: MqGetsetattrEventID, Name: "reserved", Probes: []probe{probe{event: "mq_getsetattr", attach: sysCall, fn: "mq_getsetattr"}}, EnabledByDefault: false, EssentialEvent: false},
	KexecLoadEventID:           EventConfig{ID: KexecLoadEventID, Name: "reserved", Probes: []probe{probe{event: "kexec_load", attach: sysCall, fn: "kexec_load"}}, EnabledByDefault: false, EssentialEvent: false},
	WaitidEventID:              EventConfig{ID: WaitidEventID, Name: "reserved", Probes: []probe{probe{event: "waitid", attach: sysCall, fn: "waitid"}}, EnabledByDefault: false, EssentialEvent: false},
	AddKeyEventID:              EventConfig{ID: AddKeyEventID, Name: "reserved", Probes: []probe{probe{event: "add_key", attach: sysCall, fn: "add_key"}}, EnabledByDefault: false, EssentialEvent: false},
	RequestKeyEventID:          EventConfig{ID: RequestKeyEventID, Name: "reserved", Probes: []probe{probe{event: "request_key", attach: sysCall, fn: "request_key"}}, EnabledByDefault: false, EssentialEvent: false},
	KeyctlEventID:              EventConfig{ID: KeyctlEventID, Name: "reserved", Probes: []probe{probe{event: "keyctl", attach: sysCall, fn: "keyctl"}}, EnabledByDefault: false, EssentialEvent: false},
	IoprioSetEventID:           EventConfig{ID: IoprioSetEventID, Name: "reserved", Probes: []probe{probe{event: "ioprio_set", attach: sysCall, fn: "ioprio_set"}}, EnabledByDefault: false, EssentialEvent: false},
	IoprioGetEventID:           EventConfig{ID: IoprioGetEventID, Name: "reserved", Probes: []probe{probe{event: "ioprio_get", attach: sysCall, fn: "ioprio_get"}}, EnabledByDefault: false, EssentialEvent: false},
	InotifyInitEventID:         EventConfig{ID: InotifyInitEventID, Name: "reserved", Probes: []probe{probe{event: "inotify_init", attach: sysCall, fn: "inotify_init"}}, EnabledByDefault: false, EssentialEvent: false},
	InotifyAddWatchEventID:     EventConfig{ID: InotifyAddWatchEventID, Name: "reserved", Probes: []probe{probe{event: "inotify_add_watch", attach: sysCall, fn: "inotify_add_watch"}}, EnabledByDefault: false, EssentialEvent: false},
	InotifyRmWatchEventID:      EventConfig{ID: InotifyRmWatchEventID, Name: "reserved", Probes: []probe{probe{event: "inotify_rm_watch", attach: sysCall, fn: "inotify_rm_watch"}}, EnabledByDefault: false, EssentialEvent: false},
	MigratePagesEventID:        EventConfig{ID: MigratePagesEventID, Name: "reserved", Probes: []probe{probe{event: "migrate_pages", attach: sysCall, fn: "migrate_pages"}}, EnabledByDefault: false, EssentialEvent: false},
	OpenatEventID:              EventConfig{ID: OpenatEventID, Name: "openat", Probes: []probe{probe{event: "openat", attach: sysCall, fn: "openat"}}, EnabledByDefault: true, EssentialEvent: false},
	MkdiratEventID:             EventConfig{ID: MkdiratEventID, Name: "reserved", Probes: []probe{probe{event: "mkdirat", attach: sysCall, fn: "mkdirat"}}, EnabledByDefault: false, EssentialEvent: false},
	MknodatEventID:             EventConfig{ID: MknodatEventID, Name: "mknodat", Probes: []probe{probe{event: "mknodat", attach: sysCall, fn: "mknodat"}}, EnabledByDefault: true, EssentialEvent: false},
	FchownatEventID:            EventConfig{ID: FchownatEventID, Name: "fchownat", Probes: []probe{probe{event: "fchownat", attach: sysCall, fn: "fchownat"}}, EnabledByDefault: true, EssentialEvent: false},
	FutimesatEventID:           EventConfig{ID: FutimesatEventID, Name: "reserved", Probes: []probe{probe{event: "futimesat", attach: sysCall, fn: "futimesat"}}, EnabledByDefault: false, EssentialEvent: false},
	NewfstatatEventID:          EventConfig{ID: NewfstatatEventID, Name: "reserved", Probes: []probe{probe{event: "newfstatat", attach: sysCall, fn: "newfstatat"}}, EnabledByDefault: false, EssentialEvent: false},
	UnlinkatEventID:            EventConfig{ID: UnlinkatEventID, Name: "unlinkat", Probes: []probe{probe{event: "unlinkat", attach: sysCall, fn: "unlinkat"}}, EnabledByDefault: true, EssentialEvent: false},
	RenameatEventID:            EventConfig{ID: RenameatEventID, Name: "reserved", Probes: []probe{probe{event: "renameat", attach: sysCall, fn: "renameat"}}, EnabledByDefault: false, EssentialEvent: false},
	LinkatEventID:              EventConfig{ID: LinkatEventID, Name: "reserved", Probes: []probe{probe{event: "linkat", attach: sysCall, fn: "linkat"}}, EnabledByDefault: false, EssentialEvent: false},
	SymlinkatEventID:           EventConfig{ID: SymlinkatEventID, Name: "symlinkat", Probes: []probe{probe{event: "symlinkat", attach: sysCall, fn: "symlinkat"}}, EnabledByDefault: true, EssentialEvent: false},
	ReadlinkatEventID:          EventConfig{ID: ReadlinkatEventID, Name: "reserved", Probes: []probe{probe{event: "readlinkat", attach: sysCall, fn: "readlinkat"}}, EnabledByDefault: false, EssentialEvent: false},
	FchmodatEventID:            EventConfig{ID: FchmodatEventID, Name: "fchmodat", Probes: []probe{probe{event: "fchmodat", attach: sysCall, fn: "fchmodat"}}, EnabledByDefault: true, EssentialEvent: false},
	FaccessatEventID:           EventConfig{ID: FaccessatEventID, Name: "faccessat", Probes: []probe{probe{event: "faccessat", attach: sysCall, fn: "faccessat"}}, EnabledByDefault: true, EssentialEvent: false},
	Pselect6EventID:            EventConfig{ID: Pselect6EventID, Name: "reserved", Probes: []probe{probe{event: "pselect6", attach: sysCall, fn: "pselect6"}}, EnabledByDefault: false, EssentialEvent: false},
	PpollEventID:               EventConfig{ID: PpollEventID, Name: "reserved", Probes: []probe{probe{event: "ppoll", attach: sysCall, fn: "ppoll"}}, EnabledByDefault: false, EssentialEvent: false},
	UnshareEventID:             EventConfig{ID: UnshareEventID, Name: "reserved", Probes: []probe{probe{event: "unshare", attach: sysCall, fn: "unshare"}}, EnabledByDefault: false, EssentialEvent: false},
	SetRobustListEventID:       EventConfig{ID: SetRobustListEventID, Name: "reserved", Probes: []probe{probe{event: "set_robust_list", attach: sysCall, fn: "set_robust_list"}}, EnabledByDefault: false, EssentialEvent: false},
	GetRobustListEventID:       EventConfig{ID: GetRobustListEventID, Name: "reserved", Probes: []probe{probe{event: "get_robust_list", attach: sysCall, fn: "get_robust_list"}}, EnabledByDefault: false, EssentialEvent: false},
	SpliceEventID:              EventConfig{ID: SpliceEventID, Name: "reserved", Probes: []probe{probe{event: "splice", attach: sysCall, fn: "splice"}}, EnabledByDefault: false, EssentialEvent: false},
	TeeEventID:                 EventConfig{ID: TeeEventID, Name: "reserved", Probes: []probe{probe{event: "tee", attach: sysCall, fn: "tee"}}, EnabledByDefault: false, EssentialEvent: false},
	SyncFileRangeEventID:       EventConfig{ID: SyncFileRangeEventID, Name: "reserved", Probes: []probe{probe{event: "sync_file_range", attach: sysCall, fn: "sync_file_range"}}, EnabledByDefault: false, EssentialEvent: false},
	VmspliceEventID:            EventConfig{ID: VmspliceEventID, Name: "reserved", Probes: []probe{probe{event: "vmsplice", attach: sysCall, fn: "vmsplice"}}, EnabledByDefault: false, EssentialEvent: false},
	MovePagesEventID:           EventConfig{ID: MovePagesEventID, Name: "reserved", Probes: []probe{probe{event: "move_pages", attach: sysCall, fn: "move_pages"}}, EnabledByDefault: false, EssentialEvent: false},
	UtimensatEventID:           EventConfig{ID: UtimensatEventID, Name: "reserved", Probes: []probe{probe{event: "utimensat", attach: sysCall, fn: "utimensat"}}, EnabledByDefault: false, EssentialEvent: false},
	EpollPwaitEventID:          EventConfig{ID: EpollPwaitEventID, Name: "reserved", Probes: []probe{probe{event: "epoll_pwait", attach: sysCall, fn: "epoll_pwait"}}, EnabledByDefault: false, EssentialEvent: false},
	SignalfdEventID:            EventConfig{ID: SignalfdEventID, Name: "reserved", Probes: []probe{probe{event: "signalfd", attach: sysCall, fn: "signalfd"}}, EnabledByDefault: false, EssentialEvent: false},
	TimerfdCreateEventID:       EventConfig{ID: TimerfdCreateEventID, Name: "reserved", Probes: []probe{probe{event: "timerfd_create", attach: sysCall, fn: "timerfd_create"}}, EnabledByDefault: false, EssentialEvent: false},
	EventfdEventID:             EventConfig{ID: EventfdEventID, Name: "reserved", Probes: []probe{probe{event: "eventfd", attach: sysCall, fn: "eventfd"}}, EnabledByDefault: false, EssentialEvent: false},
	FallocateEventID:           EventConfig{ID: FallocateEventID, Name: "reserved", Probes: []probe{probe{event: "fallocate", attach: sysCall, fn: "fallocate"}}, EnabledByDefault: false, EssentialEvent: false},
	TimerfdSettimeEventID:      EventConfig{ID: TimerfdSettimeEventID, Name: "reserved", Probes: []probe{probe{event: "timerfd_settime", attach: sysCall, fn: "timerfd_settime"}}, EnabledByDefault: false, EssentialEvent: false},
	TimerfdGettimeEventID:      EventConfig{ID: TimerfdGettimeEventID, Name: "reserved", Probes: []probe{probe{event: "timerfd_gettime", attach: sysCall, fn: "timerfd_gettime"}}, EnabledByDefault: false, EssentialEvent: false},
	Accept4EventID:             EventConfig{ID: Accept4EventID, Name: "accept4", Probes: []probe{probe{event: "accept4", attach: sysCall, fn: "accept4"}}, EnabledByDefault: true, EssentialEvent: false},
	Signalfd4EventID:           EventConfig{ID: Signalfd4EventID, Name: "reserved", Probes: []probe{probe{event: "signalfd4", attach: sysCall, fn: "signalfd4"}}, EnabledByDefault: false, EssentialEvent: false},
	Eventfd2EventID:            EventConfig{ID: Eventfd2EventID, Name: "reserved", Probes: []probe{probe{event: "eventfd2", attach: sysCall, fn: "eventfd2"}}, EnabledByDefault: false, EssentialEvent: false},
	EpollCreate1EventID:        EventConfig{ID: EpollCreate1EventID, Name: "reserved", Probes: []probe{probe{event: "epoll_create1", attach: sysCall, fn: "epoll_create1"}}, EnabledByDefault: false, EssentialEvent: false},
	Dup3EventID:                EventConfig{ID: Dup3EventID, Name: "dup3", Probes: []probe{probe{event: "dup3", attach: sysCall, fn: "dup3"}}, EnabledByDefault: true, EssentialEvent: false},
	Pipe2EventID:               EventConfig{ID: Pipe2EventID, Name: "reserved", Probes: []probe{probe{event: "pipe2", attach: sysCall, fn: "pipe2"}}, EnabledByDefault: false, EssentialEvent: false},
	IonotifyInit1EventID:       EventConfig{ID: IonotifyInit1EventID, Name: "reserved", Probes: []probe{probe{event: "ionotify_init1", attach: sysCall, fn: "ionotify_init1"}}, EnabledByDefault: false, EssentialEvent: false},
	PreadvEventID:              EventConfig{ID: PreadvEventID, Name: "reserved", Probes: []probe{probe{event: "preadv", attach: sysCall, fn: "preadv"}}, EnabledByDefault: false, EssentialEvent: false},
	PwritevEventID:             EventConfig{ID: PwritevEventID, Name: "reserved", Probes: []probe{probe{event: "pwritev", attach: sysCall, fn: "pwritev"}}, EnabledByDefault: false, EssentialEvent: false},
	RtTgsigqueueinfoEventID:    EventConfig{ID: RtTgsigqueueinfoEventID, Name: "reserved", Probes: []probe{probe{event: "rt_tgsigqueueinfo", attach: sysCall, fn: "rt_tgsigqueueinfo"}}, EnabledByDefault: false, EssentialEvent: false},
	PerfEventOpenEventID:       EventConfig{ID: PerfEventOpenEventID, Name: "reserved", Probes: []probe{probe{event: "perf_event_open", attach: sysCall, fn: "perf_event_open"}}, EnabledByDefault: false, EssentialEvent: false},
	RecvmmsgEventID:            EventConfig{ID: RecvmmsgEventID, Name: "reserved", Probes: []probe{probe{event: "recvmmsg", attach: sysCall, fn: "recvmmsg"}}, EnabledByDefault: false, EssentialEvent: false},
	FanotifyInitEventID:        EventConfig{ID: FanotifyInitEventID, Name: "reserved", Probes: []probe{probe{event: "fanotify_init", attach: sysCall, fn: "fanotify_init"}}, EnabledByDefault: false, EssentialEvent: false},
	FanotifyMarkEventID:        EventConfig{ID: FanotifyMarkEventID, Name: "reserved", Probes: []probe{probe{event: "fanotify_mark", attach: sysCall, fn: "fanotify_mark"}}, EnabledByDefault: false, EssentialEvent: false},
	Prlimit64EventID:           EventConfig{ID: Prlimit64EventID, Name: "reserved", Probes: []probe{probe{event: "prlimit64", attach: sysCall, fn: "prlimit64"}}, EnabledByDefault: false, EssentialEvent: false},
	NameTohandleAtEventID:      EventConfig{ID: NameTohandleAtEventID, Name: "reserved", Probes: []probe{probe{event: "name_tohandle_at", attach: sysCall, fn: "name_tohandle_at"}}, EnabledByDefault: false, EssentialEvent: false},
	OpenByHandleAtEventID:      EventConfig{ID: OpenByHandleAtEventID, Name: "reserved", Probes: []probe{probe{event: "open_by_handle_at", attach: sysCall, fn: "open_by_handle_at"}}, EnabledByDefault: false, EssentialEvent: false},
	ClockAdjtimeEventID:        EventConfig{ID: ClockAdjtimeEventID, Name: "reserved", Probes: []probe{probe{event: "clock_adjtime", attach: sysCall, fn: "clock_adjtime"}}, EnabledByDefault: false, EssentialEvent: false},
	SycnfsEventID:              EventConfig{ID: SycnfsEventID, Name: "reserved", Probes: []probe{probe{event: "sycnfs", attach: sysCall, fn: "sycnfs"}}, EnabledByDefault: false, EssentialEvent: false},
	SendmmsgEventID:            EventConfig{ID: SendmmsgEventID, Name: "reserved", Probes: []probe{probe{event: "sendmmsg", attach: sysCall, fn: "sendmmsg"}}, EnabledByDefault: false, EssentialEvent: false},
	SetnsEventID:               EventConfig{ID: SetnsEventID, Name: "reserved", Probes: []probe{probe{event: "setns", attach: sysCall, fn: "setns"}}, EnabledByDefault: false, EssentialEvent: false},
	GetcpuEventID:              EventConfig{ID: GetcpuEventID, Name: "reserved", Probes: []probe{probe{event: "getcpu", attach: sysCall, fn: "getcpu"}}, EnabledByDefault: false, EssentialEvent: false},
	ProcessVmReadvEventID:      EventConfig{ID: ProcessVmReadvEventID, Name: "process_vm_readv", Probes: []probe{probe{event: "process_vm_readv", attach: sysCall, fn: "process_vm_readv"}}, EnabledByDefault: true, EssentialEvent: false},
	ProcessVmWritevEventID:     EventConfig{ID: ProcessVmWritevEventID, Name: "process_vm_writev", Probes: []probe{probe{event: "process_vm_writev", attach: sysCall, fn: "process_vm_writev"}}, EnabledByDefault: true, EssentialEvent: false},
	KcmpEventID:                EventConfig{ID: KcmpEventID, Name: "reserved", Probes: []probe{probe{event: "kcmp", attach: sysCall, fn: "kcmp"}}, EnabledByDefault: false, EssentialEvent: false},
	FinitModuleEventID:         EventConfig{ID: FinitModuleEventID, Name: "finit_module", Probes: []probe{probe{event: "finit_module", attach: sysCall, fn: "finit_module"}}, EnabledByDefault: true, EssentialEvent: false},
	SchedSetattrEventID:        EventConfig{ID: SchedSetattrEventID, Name: "reserved", Probes: []probe{probe{event: "sched_setattr", attach: sysCall, fn: "sched_setattr"}}, EnabledByDefault: false, EssentialEvent: false},
	SchedGetattrEventID:        EventConfig{ID: SchedGetattrEventID, Name: "reserved", Probes: []probe{probe{event: "sched_getattr", attach: sysCall, fn: "sched_getattr"}}, EnabledByDefault: false, EssentialEvent: false},
	Renameat2EventID:           EventConfig{ID: Renameat2EventID, Name: "reserved", Probes: []probe{probe{event: "renameat2", attach: sysCall, fn: "renameat2"}}, EnabledByDefault: false, EssentialEvent: false},
	SeccompEventID:             EventConfig{ID: SeccompEventID, Name: "reserved", Probes: []probe{probe{event: "seccomp", attach: sysCall, fn: "seccomp"}}, EnabledByDefault: false, EssentialEvent: false},
	GetrandomEventID:           EventConfig{ID: GetrandomEventID, Name: "reserved", Probes: []probe{probe{event: "getrandom", attach: sysCall, fn: "getrandom"}}, EnabledByDefault: false, EssentialEvent: false},
	MemfdCreateEventID:         EventConfig{ID: MemfdCreateEventID, Name: "memfd_create", Probes: []probe{probe{event: "memfd_create", attach: sysCall, fn: "memfd_create"}}, EnabledByDefault: true, EssentialEvent: false},
	KexecFileLoadEventID:       EventConfig{ID: KexecFileLoadEventID, Name: "reserved", Probes: []probe{probe{event: "kexec_file_load", attach: sysCall, fn: "kexec_file_load"}}, EnabledByDefault: false, EssentialEvent: false},
	BpfEventID:                 EventConfig{ID: BpfEventID, Name: "reserved", Probes: []probe{probe{event: "bpf", attach: sysCall, fn: "bpf"}}, EnabledByDefault: false, EssentialEvent: false},
	ExecveatEventID:            EventConfig{ID: ExecveatEventID, Name: "execveat", Probes: []probe{probe{event: "execveat", attach: sysCall, fn: "execveat"}}, EnabledByDefault: true, EssentialEvent: true},
	UserfaultfdEventID:         EventConfig{ID: UserfaultfdEventID, Name: "reserved", Probes: []probe{probe{event: "userfaultfd", attach: sysCall, fn: "userfaultfd"}}, EnabledByDefault: false, EssentialEvent: false},
	MembarrierEventID:          EventConfig{ID: MembarrierEventID, Name: "reserved", Probes: []probe{probe{event: "membarrier", attach: sysCall, fn: "membarrier"}}, EnabledByDefault: false, EssentialEvent: false},
	Mlock2EventID:              EventConfig{ID: Mlock2EventID, Name: "reserved", Probes: []probe{probe{event: "mlock2", attach: sysCall, fn: "mlock2"}}, EnabledByDefault: false, EssentialEvent: false},
	CopyFileRangeEventID:       EventConfig{ID: CopyFileRangeEventID, Name: "reserved", Probes: []probe{probe{event: "copy_file_range", attach: sysCall, fn: "copy_file_range"}}, EnabledByDefault: false, EssentialEvent: false},
	Preadv2EventID:             EventConfig{ID: Preadv2EventID, Name: "reserved", Probes: []probe{probe{event: "preadv2", attach: sysCall, fn: "preadv2"}}, EnabledByDefault: false, EssentialEvent: false},
	Pwritev2EventID:            EventConfig{ID: Pwritev2EventID, Name: "reserved", Probes: []probe{probe{event: "pwritev2", attach: sysCall, fn: "pwritev2"}}, EnabledByDefault: false, EssentialEvent: false},
	PkeyMprotectEventID:        EventConfig{ID: PkeyMprotectEventID, Name: "pkey_mprotect", Probes: []probe{probe{event: "pkey_mprotect", attach: sysCall, fn: "pkey_mprotect"}}, EnabledByDefault: true, EssentialEvent: false},
	PkeyAllocEventID:           EventConfig{ID: PkeyAllocEventID, Name: "reserved", Probes: []probe{probe{event: "pkey_alloc", attach: sysCall, fn: "pkey_alloc"}}, EnabledByDefault: false, EssentialEvent: false},
	PkeyFreeEventID:            EventConfig{ID: PkeyFreeEventID, Name: "reserved", Probes: []probe{probe{event: "pkey_free", attach: sysCall, fn: "pkey_free"}}, EnabledByDefault: false, EssentialEvent: false},
	StatxEventID:               EventConfig{ID: StatxEventID, Name: "reserved", Probes: []probe{probe{event: "statx", attach: sysCall, fn: "statx"}}, EnabledByDefault: false, EssentialEvent: false},
	IoPgeteventsEventID:        EventConfig{ID: IoPgeteventsEventID, Name: "reserved", Probes: []probe{probe{event: "io_pgetevents", attach: sysCall, fn: "io_pgetevents"}}, EnabledByDefault: false, EssentialEvent: false},
	RseqEventID:                EventConfig{ID: RseqEventID, Name: "reserved", Probes: []probe{probe{event: "rseq", attach: sysCall, fn: "rseq"}}, EnabledByDefault: false, EssentialEvent: false},
	Reserved335EventID:         EventConfig{ID: Reserved335EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	Reserved336EventID:         EventConfig{ID: Reserved336EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	Reserved337EventID:         EventConfig{ID: Reserved337EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	Reserved338EventID:         EventConfig{ID: Reserved338EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	Reserved339EventID:         EventConfig{ID: Reserved339EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	Reserved340EventID:         EventConfig{ID: Reserved340EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	Reserved341EventID:         EventConfig{ID: Reserved341EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	Reserved342EventID:         EventConfig{ID: Reserved342EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	Reserved343EventID:         EventConfig{ID: Reserved343EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	Reserved344EventID:         EventConfig{ID: Reserved344EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	Reserved345EventID:         EventConfig{ID: Reserved345EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	Reserved346EventID:         EventConfig{ID: Reserved346EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	Reserved347EventID:         EventConfig{ID: Reserved347EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	Reserved348EventID:         EventConfig{ID: Reserved348EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	Reserved349EventID:         EventConfig{ID: Reserved349EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	RawSyscallsEventID:         EventConfig{ID: RawSyscallsEventID, Name: "raw_syscalls", Probes: []probe{probe{event: "raw_syscalls:sys_enter", attach: tracepoint, fn: "tracepoint__raw_syscalls__sys_enter"}}, EnabledByDefault: false, EssentialEvent: false},
	DoExitEventID:              EventConfig{ID: DoExitEventID, Name: "do_exit", Probes: []probe{probe{event: "do_exit", attach: kprobe, fn: "trace_do_exit"}}, EnabledByDefault: true, EssentialEvent: true},
	CapCapableEventID:          EventConfig{ID: CapCapableEventID, Name: "cap_capable", Probes: []probe{probe{event: "cap_capable", attach: kprobe, fn: "trace_cap_capable"}}, EnabledByDefault: true, EssentialEvent: false},
	SecurityBprmCheckEventID:   EventConfig{ID: SecurityBprmCheckEventID, Name: "security_bprm_check", Probes: []probe{probe{event: "security_bprm_check", attach: kprobe, fn: "trace_security_bprm_check"}}, EnabledByDefault: true, EssentialEvent: false},
	SecurityFileOpenEventID:    EventConfig{ID: SecurityFileOpenEventID, Name: "security_file_open", Probes: []probe{probe{event: "security_file_open", attach: kprobe, fn: "trace_security_file_open"}}, EnabledByDefault: true, EssentialEvent: false},
	VfsWriteEventID:            EventConfig{ID: VfsWriteEventID, Name: "vfs_write", Probes: []probe{probe{event: "vfs_write", attach: kprobe, fn: "trace_vfs_write"}, probe{event: "vfs_write", attach: kretprobe, fn: "trace_ret_vfs_write"}}, EnabledByDefault: true, EssentialEvent: false},
	MemProtAlertEventID:        EventConfig{ID: MemProtAlertEventID, Name: "mem_prot_alert", Probes: []probe{probe{event: "security_mmap_addr", attach: kprobe, fn: "trace_mmap_alert"}, probe{event: "security_file_mprotect", attach: kprobe, fn: "trace_mprotect_alert"}}, EnabledByDefault: false, EssentialEvent: false},
}
