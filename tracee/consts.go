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
	ID             int32
	Name           string
	Probes         []probe
	EssentialEvent bool
	Sets           []string
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
	ReadEventID:                EventConfig{ID: ReadEventID, Name: "reserved", Probes: []probe{probe{event: "read", attach: sysCall, fn: "read"}}, EssentialEvent: false},
	WriteEventID:               EventConfig{ID: WriteEventID, Name: "reserved", Probes: []probe{probe{event: "write", attach: sysCall, fn: "write"}}, EssentialEvent: false},
	OpenEventID:                EventConfig{ID: OpenEventID, Name: "open", Probes: []probe{probe{event: "open", attach: sysCall, fn: "open"}}, EssentialEvent: false, Sets: []string{"default"}},
	CloseEventID:               EventConfig{ID: CloseEventID, Name: "close", Probes: []probe{probe{event: "close", attach: sysCall, fn: "close"}}, EssentialEvent: false, Sets: []string{"default"}},
	StatEventID:                EventConfig{ID: StatEventID, Name: "newstat", Probes: []probe{probe{event: "newstat", attach: sysCall, fn: "newstat"}}, EssentialEvent: false, Sets: []string{"default"}},
	FstatEventID:               EventConfig{ID: FstatEventID, Name: "reserved", Probes: []probe{probe{event: "fstat", attach: sysCall, fn: "fstat"}}, EssentialEvent: false},
	LstatEventID:               EventConfig{ID: LstatEventID, Name: "newlstat", Probes: []probe{probe{event: "newlstat", attach: sysCall, fn: "newlstat"}}, EssentialEvent: false, Sets: []string{"default"}},
	PollEventID:                EventConfig{ID: PollEventID, Name: "reserved", Probes: []probe{probe{event: "poll", attach: sysCall, fn: "poll"}}, EssentialEvent: false},
	LseekEventID:               EventConfig{ID: LseekEventID, Name: "reserved", Probes: []probe{probe{event: "lseek", attach: sysCall, fn: "lseek"}}, EssentialEvent: false},
	MmapEventID:                EventConfig{ID: MmapEventID, Name: "mmap", Probes: []probe{probe{event: "mmap", attach: sysCall, fn: "mmap"}}, EssentialEvent: false, Sets: []string{"default"}},
	MprotectEventID:            EventConfig{ID: MprotectEventID, Name: "mprotect", Probes: []probe{probe{event: "mprotect", attach: sysCall, fn: "mprotect"}}, EssentialEvent: false, Sets: []string{"default"}},
	MunmapEventID:              EventConfig{ID: MunmapEventID, Name: "reserved", Probes: []probe{probe{event: "munmap", attach: sysCall, fn: "munmap"}}, EssentialEvent: false},
	BrkEventID:                 EventConfig{ID: BrkEventID, Name: "reserved", Probes: []probe{probe{event: "brk", attach: sysCall, fn: "brk"}}, EssentialEvent: false},
	RtSigactionEventID:         EventConfig{ID: RtSigactionEventID, Name: "reserved", Probes: []probe{probe{event: "rt_sigaction", attach: sysCall, fn: "rt_sigaction"}}, EssentialEvent: false},
	RtSigprocmaskEventID:       EventConfig{ID: RtSigprocmaskEventID, Name: "reserved", Probes: []probe{probe{event: "rt_sigprocmask", attach: sysCall, fn: "rt_sigprocmask"}}, EssentialEvent: false},
	RtSigreturnEventID:         EventConfig{ID: RtSigreturnEventID, Name: "reserved", Probes: []probe{probe{event: "rt_sigreturn", attach: sysCall, fn: "rt_sigreturn"}}, EssentialEvent: false},
	IoctlEventID:               EventConfig{ID: IoctlEventID, Name: "ioctl", Probes: []probe{probe{event: "ioctl", attach: sysCall, fn: "ioctl"}}, EssentialEvent: false, Sets: []string{"default"}},
	Pread64EventID:             EventConfig{ID: Pread64EventID, Name: "reserved", Probes: []probe{probe{event: "pread64", attach: sysCall, fn: "pread64"}}, EssentialEvent: false},
	Pwrite64EventID:            EventConfig{ID: Pwrite64EventID, Name: "reserved", Probes: []probe{probe{event: "pwrite64", attach: sysCall, fn: "pwrite64"}}, EssentialEvent: false},
	ReadvEventID:               EventConfig{ID: ReadvEventID, Name: "reserved", Probes: []probe{probe{event: "readv", attach: sysCall, fn: "readv"}}, EssentialEvent: false},
	WritevEventID:              EventConfig{ID: WritevEventID, Name: "reserved", Probes: []probe{probe{event: "writev", attach: sysCall, fn: "writev"}}, EssentialEvent: false},
	AccessEventID:              EventConfig{ID: AccessEventID, Name: "access", Probes: []probe{probe{event: "access", attach: sysCall, fn: "access"}}, EssentialEvent: false, Sets: []string{"default"}},
	PipeEventID:                EventConfig{ID: PipeEventID, Name: "reserved", Probes: []probe{probe{event: "pipe", attach: sysCall, fn: "pipe"}}, EssentialEvent: false},
	SelectEventID:              EventConfig{ID: SelectEventID, Name: "reserved", Probes: []probe{probe{event: "select", attach: sysCall, fn: "select"}}, EssentialEvent: false},
	SchedYieldEventID:          EventConfig{ID: SchedYieldEventID, Name: "reserved", Probes: []probe{probe{event: "sched_yield", attach: sysCall, fn: "sched_yield"}}, EssentialEvent: false},
	MremapEventID:              EventConfig{ID: MremapEventID, Name: "reserved", Probes: []probe{probe{event: "mremap", attach: sysCall, fn: "mremap"}}, EssentialEvent: false},
	MsyncEventID:               EventConfig{ID: MsyncEventID, Name: "reserved", Probes: []probe{probe{event: "msync", attach: sysCall, fn: "msync"}}, EssentialEvent: false},
	MincoreEventID:             EventConfig{ID: MincoreEventID, Name: "reserved", Probes: []probe{probe{event: "mincore", attach: sysCall, fn: "mincore"}}, EssentialEvent: false},
	MadviseEventID:             EventConfig{ID: MadviseEventID, Name: "reserved", Probes: []probe{probe{event: "madvise", attach: sysCall, fn: "madvise"}}, EssentialEvent: false},
	ShmgetEventID:              EventConfig{ID: ShmgetEventID, Name: "reserved", Probes: []probe{probe{event: "shmget", attach: sysCall, fn: "shmget"}}, EssentialEvent: false},
	ShmatEventID:               EventConfig{ID: ShmatEventID, Name: "reserved", Probes: []probe{probe{event: "shmat", attach: sysCall, fn: "shmat"}}, EssentialEvent: false},
	ShmctlEventID:              EventConfig{ID: ShmctlEventID, Name: "reserved", Probes: []probe{probe{event: "shmctl", attach: sysCall, fn: "shmctl"}}, EssentialEvent: false},
	DupEventID:                 EventConfig{ID: DupEventID, Name: "dup", Probes: []probe{probe{event: "dup", attach: sysCall, fn: "dup"}}, EssentialEvent: false, Sets: []string{"default"}},
	Dup2EventID:                EventConfig{ID: Dup2EventID, Name: "dup2", Probes: []probe{probe{event: "dup2", attach: sysCall, fn: "dup2"}}, EssentialEvent: false, Sets: []string{"default"}},
	PauseEventID:               EventConfig{ID: PauseEventID, Name: "reserved", Probes: []probe{probe{event: "pause", attach: sysCall, fn: "pause"}}, EssentialEvent: false},
	NanosleepEventID:           EventConfig{ID: NanosleepEventID, Name: "reserved", Probes: []probe{probe{event: "nanosleep", attach: sysCall, fn: "nanosleep"}}, EssentialEvent: false},
	GetitimerEventID:           EventConfig{ID: GetitimerEventID, Name: "reserved", Probes: []probe{probe{event: "getitimer", attach: sysCall, fn: "getitimer"}}, EssentialEvent: false},
	AlarmEventID:               EventConfig{ID: AlarmEventID, Name: "reserved", Probes: []probe{probe{event: "alarm", attach: sysCall, fn: "alarm"}}, EssentialEvent: false},
	SetitimerEventID:           EventConfig{ID: SetitimerEventID, Name: "reserved", Probes: []probe{probe{event: "setitimer", attach: sysCall, fn: "setitimer"}}, EssentialEvent: false},
	GetpidEventID:              EventConfig{ID: GetpidEventID, Name: "reserved", Probes: []probe{probe{event: "getpid", attach: sysCall, fn: "getpid"}}, EssentialEvent: false},
	SendfileEventID:            EventConfig{ID: SendfileEventID, Name: "reserved", Probes: []probe{probe{event: "sendfile", attach: sysCall, fn: "sendfile"}}, EssentialEvent: false},
	SocketEventID:              EventConfig{ID: SocketEventID, Name: "socket", Probes: []probe{probe{event: "socket", attach: sysCall, fn: "socket"}}, EssentialEvent: false, Sets: []string{"default"}},
	ConnectEventID:             EventConfig{ID: ConnectEventID, Name: "connect", Probes: []probe{probe{event: "connect", attach: sysCall, fn: "connect"}}, EssentialEvent: false, Sets: []string{"default"}},
	AcceptEventID:              EventConfig{ID: AcceptEventID, Name: "accept", Probes: []probe{probe{event: "accept", attach: sysCall, fn: "accept"}}, EssentialEvent: false, Sets: []string{"default"}},
	SendtoEventID:              EventConfig{ID: SendtoEventID, Name: "reserved", Probes: []probe{probe{event: "sendto", attach: sysCall, fn: "sendto"}}, EssentialEvent: false},
	RecvfromEventID:            EventConfig{ID: RecvfromEventID, Name: "reserved", Probes: []probe{probe{event: "recvfrom", attach: sysCall, fn: "recvfrom"}}, EssentialEvent: false},
	SendmsgEventID:             EventConfig{ID: SendmsgEventID, Name: "reserved", Probes: []probe{probe{event: "sendmsg", attach: sysCall, fn: "sendmsg"}}, EssentialEvent: false},
	RecvmsgEventID:             EventConfig{ID: RecvmsgEventID, Name: "reserved", Probes: []probe{probe{event: "recvmsg", attach: sysCall, fn: "recvmsg"}}, EssentialEvent: false},
	ShutdownEventID:            EventConfig{ID: ShutdownEventID, Name: "reserved", Probes: []probe{probe{event: "shutdown", attach: sysCall, fn: "shutdown"}}, EssentialEvent: false},
	BindEventID:                EventConfig{ID: BindEventID, Name: "bind", Probes: []probe{probe{event: "bind", attach: sysCall, fn: "bind"}}, EssentialEvent: false, Sets: []string{"default"}},
	ListenEventID:              EventConfig{ID: ListenEventID, Name: "listen", Probes: []probe{probe{event: "listen", attach: sysCall, fn: "listen"}}, EssentialEvent: false, Sets: []string{"default"}},
	GetsocknameEventID:         EventConfig{ID: GetsocknameEventID, Name: "getsockname", Probes: []probe{probe{event: "getsockname", attach: sysCall, fn: "getsockname"}}, EssentialEvent: false, Sets: []string{"default"}},
	GetpeernameEventID:         EventConfig{ID: GetpeernameEventID, Name: "reserved", Probes: []probe{probe{event: "getpeername", attach: sysCall, fn: "getpeername"}}, EssentialEvent: false},
	SocketpairEventID:          EventConfig{ID: SocketpairEventID, Name: "reserved", Probes: []probe{probe{event: "socketpair", attach: sysCall, fn: "socketpair"}}, EssentialEvent: false},
	SetsockoptEventID:          EventConfig{ID: SetsockoptEventID, Name: "reserved", Probes: []probe{probe{event: "setsockopt", attach: sysCall, fn: "setsockopt"}}, EssentialEvent: false},
	GetsockoptEventID:          EventConfig{ID: GetsockoptEventID, Name: "reserved", Probes: []probe{probe{event: "getsockopt", attach: sysCall, fn: "getsockopt"}}, EssentialEvent: false},
	CloneEventID:               EventConfig{ID: CloneEventID, Name: "clone", Probes: []probe{probe{event: "clone", attach: sysCall, fn: "clone"}}, EssentialEvent: true, Sets: []string{"default"}},
	ForkEventID:                EventConfig{ID: ForkEventID, Name: "fork", Probes: []probe{probe{event: "fork", attach: sysCall, fn: "fork"}}, EssentialEvent: true, Sets: []string{"default"}},
	VforkEventID:               EventConfig{ID: VforkEventID, Name: "vfork", Probes: []probe{probe{event: "vfork", attach: sysCall, fn: "vfork"}}, EssentialEvent: true, Sets: []string{"default"}},
	ExecveEventID:              EventConfig{ID: ExecveEventID, Name: "execve", Probes: []probe{probe{event: "execve", attach: sysCall, fn: "execve"}}, EssentialEvent: true, Sets: []string{"default"}},
	ExitEventID:                EventConfig{ID: ExitEventID, Name: "reserved", Probes: []probe{probe{event: "exit", attach: sysCall, fn: "exit"}}, EssentialEvent: false},
	Wait4EventID:               EventConfig{ID: Wait4EventID, Name: "reserved", Probes: []probe{probe{event: "wait4", attach: sysCall, fn: "wait4"}}, EssentialEvent: false},
	KillEventID:                EventConfig{ID: KillEventID, Name: "kill", Probes: []probe{probe{event: "kill", attach: sysCall, fn: "kill"}}, EssentialEvent: false, Sets: []string{"default"}},
	UnameEventID:               EventConfig{ID: UnameEventID, Name: "reserved", Probes: []probe{probe{event: "uname", attach: sysCall, fn: "uname"}}, EssentialEvent: false},
	SemgetEventID:              EventConfig{ID: SemgetEventID, Name: "reserved", Probes: []probe{probe{event: "semget", attach: sysCall, fn: "semget"}}, EssentialEvent: false},
	SemopEventID:               EventConfig{ID: SemopEventID, Name: "reserved", Probes: []probe{probe{event: "semop", attach: sysCall, fn: "semop"}}, EssentialEvent: false},
	SemctlEventID:              EventConfig{ID: SemctlEventID, Name: "reserved", Probes: []probe{probe{event: "semctl", attach: sysCall, fn: "semctl"}}, EssentialEvent: false},
	ShmdtEventID:               EventConfig{ID: ShmdtEventID, Name: "reserved", Probes: []probe{probe{event: "shmdt", attach: sysCall, fn: "shmdt"}}, EssentialEvent: false},
	MsggetEventID:              EventConfig{ID: MsggetEventID, Name: "reserved", Probes: []probe{probe{event: "msgget", attach: sysCall, fn: "msgget"}}, EssentialEvent: false},
	MsgsndEventID:              EventConfig{ID: MsgsndEventID, Name: "reserved", Probes: []probe{probe{event: "msgsnd", attach: sysCall, fn: "msgsnd"}}, EssentialEvent: false},
	MsgrcvEventID:              EventConfig{ID: MsgrcvEventID, Name: "reserved", Probes: []probe{probe{event: "msgrcv", attach: sysCall, fn: "msgrcv"}}, EssentialEvent: false},
	MsgctlEventID:              EventConfig{ID: MsgctlEventID, Name: "reserved", Probes: []probe{probe{event: "msgctl", attach: sysCall, fn: "msgctl"}}, EssentialEvent: false},
	FcntlEventID:               EventConfig{ID: FcntlEventID, Name: "reserved", Probes: []probe{probe{event: "fcntl", attach: sysCall, fn: "fcntl"}}, EssentialEvent: false},
	FlockEventID:               EventConfig{ID: FlockEventID, Name: "reserved", Probes: []probe{probe{event: "flock", attach: sysCall, fn: "flock"}}, EssentialEvent: false},
	FsyncEventID:               EventConfig{ID: FsyncEventID, Name: "reserved", Probes: []probe{probe{event: "fsync", attach: sysCall, fn: "fsync"}}, EssentialEvent: false},
	FdatasyncEventID:           EventConfig{ID: FdatasyncEventID, Name: "reserved", Probes: []probe{probe{event: "fdatasync", attach: sysCall, fn: "fdatasync"}}, EssentialEvent: false},
	TruncateEventID:            EventConfig{ID: TruncateEventID, Name: "reserved", Probes: []probe{probe{event: "truncate", attach: sysCall, fn: "truncate"}}, EssentialEvent: false},
	FtruncateEventID:           EventConfig{ID: FtruncateEventID, Name: "reserved", Probes: []probe{probe{event: "ftruncate", attach: sysCall, fn: "ftruncate"}}, EssentialEvent: false},
	GetdentsEventID:            EventConfig{ID: GetdentsEventID, Name: "getdents", Probes: []probe{probe{event: "getdents", attach: sysCall, fn: "getdents"}}, EssentialEvent: false, Sets: []string{"default"}},
	GetcwdEventID:              EventConfig{ID: GetcwdEventID, Name: "reserved", Probes: []probe{probe{event: "getcwd", attach: sysCall, fn: "getcwd"}}, EssentialEvent: false},
	ChdirEventID:               EventConfig{ID: ChdirEventID, Name: "reserved", Probes: []probe{probe{event: "chdir", attach: sysCall, fn: "chdir"}}, EssentialEvent: false},
	FchdirEventID:              EventConfig{ID: FchdirEventID, Name: "reserved", Probes: []probe{probe{event: "fchdir", attach: sysCall, fn: "fchdir"}}, EssentialEvent: false},
	RenameEventID:              EventConfig{ID: RenameEventID, Name: "reserved", Probes: []probe{probe{event: "rename", attach: sysCall, fn: "rename"}}, EssentialEvent: false},
	MkdirEventID:               EventConfig{ID: MkdirEventID, Name: "reserved", Probes: []probe{probe{event: "mkdir", attach: sysCall, fn: "mkdir"}}, EssentialEvent: false},
	RmdirEventID:               EventConfig{ID: RmdirEventID, Name: "reserved", Probes: []probe{probe{event: "rmdir", attach: sysCall, fn: "rmdir"}}, EssentialEvent: false},
	CreatEventID:               EventConfig{ID: CreatEventID, Name: "creat", Probes: []probe{probe{event: "creat", attach: sysCall, fn: "creat"}}, EssentialEvent: false, Sets: []string{"default"}},
	LinkEventID:                EventConfig{ID: LinkEventID, Name: "reserved", Probes: []probe{probe{event: "link", attach: sysCall, fn: "link"}}, EssentialEvent: false},
	UnlinkEventID:              EventConfig{ID: UnlinkEventID, Name: "unlink", Probes: []probe{probe{event: "unlink", attach: sysCall, fn: "unlink"}}, EssentialEvent: false, Sets: []string{"default"}},
	SymlinkEventID:             EventConfig{ID: SymlinkEventID, Name: "symlink", Probes: []probe{probe{event: "symlink", attach: sysCall, fn: "symlink"}}, EssentialEvent: false, Sets: []string{"default"}},
	ReadlinkEventID:            EventConfig{ID: ReadlinkEventID, Name: "reserved", Probes: []probe{probe{event: "readlink", attach: sysCall, fn: "readlink"}}, EssentialEvent: false},
	ChmodEventID:               EventConfig{ID: ChmodEventID, Name: "chmod", Probes: []probe{probe{event: "chmod", attach: sysCall, fn: "chmod"}}, EssentialEvent: false, Sets: []string{"default"}},
	FchmodEventID:              EventConfig{ID: FchmodEventID, Name: "fchmod", Probes: []probe{probe{event: "fchmod", attach: sysCall, fn: "fchmod"}}, EssentialEvent: false, Sets: []string{"default"}},
	ChownEventID:               EventConfig{ID: ChownEventID, Name: "chown", Probes: []probe{probe{event: "chown", attach: sysCall, fn: "chown"}}, EssentialEvent: false, Sets: []string{"default"}},
	FchownEventID:              EventConfig{ID: FchownEventID, Name: "fchown", Probes: []probe{probe{event: "fchown", attach: sysCall, fn: "fchown"}}, EssentialEvent: false, Sets: []string{"default"}},
	LchownEventID:              EventConfig{ID: LchownEventID, Name: "lchown", Probes: []probe{probe{event: "lchown", attach: sysCall, fn: "lchown"}}, EssentialEvent: false, Sets: []string{"default"}},
	UmaskEventID:               EventConfig{ID: UmaskEventID, Name: "reserved", Probes: []probe{probe{event: "umask", attach: sysCall, fn: "umask"}}, EssentialEvent: false},
	GettimeofdayEventID:        EventConfig{ID: GettimeofdayEventID, Name: "reserved", Probes: []probe{probe{event: "gettimeofday", attach: sysCall, fn: "gettimeofday"}}, EssentialEvent: false},
	GetrlimitEventID:           EventConfig{ID: GetrlimitEventID, Name: "reserved", Probes: []probe{probe{event: "getrlimit", attach: sysCall, fn: "getrlimit"}}, EssentialEvent: false},
	GetrusageEventID:           EventConfig{ID: GetrusageEventID, Name: "reserved", Probes: []probe{probe{event: "getrusage", attach: sysCall, fn: "getrusage"}}, EssentialEvent: false},
	SysinfoEventID:             EventConfig{ID: SysinfoEventID, Name: "reserved", Probes: []probe{probe{event: "sysinfo", attach: sysCall, fn: "sysinfo"}}, EssentialEvent: false},
	TimesEventID:               EventConfig{ID: TimesEventID, Name: "reserved", Probes: []probe{probe{event: "times", attach: sysCall, fn: "times"}}, EssentialEvent: false},
	PtraceEventID:              EventConfig{ID: PtraceEventID, Name: "ptrace", Probes: []probe{probe{event: "ptrace", attach: sysCall, fn: "ptrace"}}, EssentialEvent: false, Sets: []string{"default"}},
	GetuidEventID:              EventConfig{ID: GetuidEventID, Name: "reserved", Probes: []probe{probe{event: "getuid", attach: sysCall, fn: "getuid"}}, EssentialEvent: false},
	SyslogEventID:              EventConfig{ID: SyslogEventID, Name: "reserved", Probes: []probe{probe{event: "syslog", attach: sysCall, fn: "syslog"}}, EssentialEvent: false},
	GetgidEventID:              EventConfig{ID: GetgidEventID, Name: "reserved", Probes: []probe{probe{event: "getgid", attach: sysCall, fn: "getgid"}}, EssentialEvent: false},
	SetuidEventID:              EventConfig{ID: SetuidEventID, Name: "setuid", Probes: []probe{probe{event: "setuid", attach: sysCall, fn: "setuid"}}, EssentialEvent: false, Sets: []string{"default"}},
	SetgidEventID:              EventConfig{ID: SetgidEventID, Name: "setgid", Probes: []probe{probe{event: "setgid", attach: sysCall, fn: "setgid"}}, EssentialEvent: false, Sets: []string{"default"}},
	GeteuidEventID:             EventConfig{ID: GeteuidEventID, Name: "reserved", Probes: []probe{probe{event: "geteuid", attach: sysCall, fn: "geteuid"}}, EssentialEvent: false},
	GetegidEventID:             EventConfig{ID: GetegidEventID, Name: "reserved", Probes: []probe{probe{event: "getegid", attach: sysCall, fn: "getegid"}}, EssentialEvent: false},
	SetpgidEventID:             EventConfig{ID: SetpgidEventID, Name: "reserved", Probes: []probe{probe{event: "setpgid", attach: sysCall, fn: "setpgid"}}, EssentialEvent: false},
	GetppidEventID:             EventConfig{ID: GetppidEventID, Name: "reserved", Probes: []probe{probe{event: "getppid", attach: sysCall, fn: "getppid"}}, EssentialEvent: false},
	GetpgrpEventID:             EventConfig{ID: GetpgrpEventID, Name: "reserved", Probes: []probe{probe{event: "getpgrp", attach: sysCall, fn: "getpgrp"}}, EssentialEvent: false},
	SetsidEventID:              EventConfig{ID: SetsidEventID, Name: "reserved", Probes: []probe{probe{event: "setsid", attach: sysCall, fn: "setsid"}}, EssentialEvent: false},
	SetreuidEventID:            EventConfig{ID: SetreuidEventID, Name: "setreuid", Probes: []probe{probe{event: "setreuid", attach: sysCall, fn: "setreuid"}}, EssentialEvent: false, Sets: []string{"default"}},
	SetregidEventID:            EventConfig{ID: SetregidEventID, Name: "setregid", Probes: []probe{probe{event: "setregid", attach: sysCall, fn: "setregid"}}, EssentialEvent: false, Sets: []string{"default"}},
	GetgroupsEventID:           EventConfig{ID: GetgroupsEventID, Name: "reserved", Probes: []probe{probe{event: "getgroups", attach: sysCall, fn: "getgroups"}}, EssentialEvent: false},
	SetgroupsEventID:           EventConfig{ID: SetgroupsEventID, Name: "reserved", Probes: []probe{probe{event: "setgroups", attach: sysCall, fn: "setgroups"}}, EssentialEvent: false},
	SetresuidEventID:           EventConfig{ID: SetresuidEventID, Name: "reserved", Probes: []probe{probe{event: "setresuid", attach: sysCall, fn: "setresuid"}}, EssentialEvent: false},
	GetresuidEventID:           EventConfig{ID: GetresuidEventID, Name: "reserved", Probes: []probe{probe{event: "getresuid", attach: sysCall, fn: "getresuid"}}, EssentialEvent: false},
	SetresgidEventID:           EventConfig{ID: SetresgidEventID, Name: "reserved", Probes: []probe{probe{event: "setresgid", attach: sysCall, fn: "setresgid"}}, EssentialEvent: false},
	GetresgidEventID:           EventConfig{ID: GetresgidEventID, Name: "reserved", Probes: []probe{probe{event: "getresgid", attach: sysCall, fn: "getresgid"}}, EssentialEvent: false},
	GetpgidEventID:             EventConfig{ID: GetpgidEventID, Name: "reserved", Probes: []probe{probe{event: "getpgid", attach: sysCall, fn: "getpgid"}}, EssentialEvent: false},
	SetfsuidEventID:            EventConfig{ID: SetfsuidEventID, Name: "setfsuid", Probes: []probe{probe{event: "setfsuid", attach: sysCall, fn: "setfsuid"}}, EssentialEvent: false, Sets: []string{"default"}},
	SetfsgidEventID:            EventConfig{ID: SetfsgidEventID, Name: "setfsgid", Probes: []probe{probe{event: "setfsgid", attach: sysCall, fn: "setfsgid"}}, EssentialEvent: false, Sets: []string{"default"}},
	GetsidEventID:              EventConfig{ID: GetsidEventID, Name: "reserved", Probes: []probe{probe{event: "getsid", attach: sysCall, fn: "getsid"}}, EssentialEvent: false},
	CapgetEventID:              EventConfig{ID: CapgetEventID, Name: "reserved", Probes: []probe{probe{event: "capget", attach: sysCall, fn: "capget"}}, EssentialEvent: false},
	CapsetEventID:              EventConfig{ID: CapsetEventID, Name: "reserved", Probes: []probe{probe{event: "capset", attach: sysCall, fn: "capset"}}, EssentialEvent: false},
	RtSigpendingEventID:        EventConfig{ID: RtSigpendingEventID, Name: "reserved", Probes: []probe{probe{event: "rt_sigpending", attach: sysCall, fn: "rt_sigpending"}}, EssentialEvent: false},
	RtSigtimedwaitEventID:      EventConfig{ID: RtSigtimedwaitEventID, Name: "reserved", Probes: []probe{probe{event: "rt_sigtimedwait", attach: sysCall, fn: "rt_sigtimedwait"}}, EssentialEvent: false},
	RtSigqueueinfoEventID:      EventConfig{ID: RtSigqueueinfoEventID, Name: "reserved", Probes: []probe{probe{event: "rt_sigqueueinfo", attach: sysCall, fn: "rt_sigqueueinfo"}}, EssentialEvent: false},
	RtSigsuspendEventID:        EventConfig{ID: RtSigsuspendEventID, Name: "reserved", Probes: []probe{probe{event: "rt_sigsuspend", attach: sysCall, fn: "rt_sigsuspend"}}, EssentialEvent: false},
	SigaltstackEventID:         EventConfig{ID: SigaltstackEventID, Name: "reserved", Probes: []probe{probe{event: "sigaltstack", attach: sysCall, fn: "sigaltstack"}}, EssentialEvent: false},
	UtimeEventID:               EventConfig{ID: UtimeEventID, Name: "reserved", Probes: []probe{probe{event: "utime", attach: sysCall, fn: "utime"}}, EssentialEvent: false},
	MknodEventID:               EventConfig{ID: MknodEventID, Name: "mknod", Probes: []probe{probe{event: "mknod", attach: sysCall, fn: "mknod"}}, EssentialEvent: false, Sets: []string{"default"}},
	UselibEventID:              EventConfig{ID: UselibEventID, Name: "reserved", Probes: []probe{probe{event: "uselib", attach: sysCall, fn: "uselib"}}, EssentialEvent: false},
	PersonalityEventID:         EventConfig{ID: PersonalityEventID, Name: "reserved", Probes: []probe{probe{event: "personality", attach: sysCall, fn: "personality"}}, EssentialEvent: false},
	UstatEventID:               EventConfig{ID: UstatEventID, Name: "reserved", Probes: []probe{probe{event: "ustat", attach: sysCall, fn: "ustat"}}, EssentialEvent: false},
	StatfsEventID:              EventConfig{ID: StatfsEventID, Name: "reserved", Probes: []probe{probe{event: "statfs", attach: sysCall, fn: "statfs"}}, EssentialEvent: false},
	FstatfsEventID:             EventConfig{ID: FstatfsEventID, Name: "reserved", Probes: []probe{probe{event: "fstatfs", attach: sysCall, fn: "fstatfs"}}, EssentialEvent: false},
	SysfsEventID:               EventConfig{ID: SysfsEventID, Name: "reserved", Probes: []probe{probe{event: "sysfs", attach: sysCall, fn: "sysfs"}}, EssentialEvent: false},
	GetpriorityEventID:         EventConfig{ID: GetpriorityEventID, Name: "reserved", Probes: []probe{probe{event: "getpriority", attach: sysCall, fn: "getpriority"}}, EssentialEvent: false},
	SetpriorityEventID:         EventConfig{ID: SetpriorityEventID, Name: "reserved", Probes: []probe{probe{event: "setpriority", attach: sysCall, fn: "setpriority"}}, EssentialEvent: false},
	SchedSetparamEventID:       EventConfig{ID: SchedSetparamEventID, Name: "reserved", Probes: []probe{probe{event: "sched_setparam", attach: sysCall, fn: "sched_setparam"}}, EssentialEvent: false},
	SchedGetparamEventID:       EventConfig{ID: SchedGetparamEventID, Name: "reserved", Probes: []probe{probe{event: "sched_getparam", attach: sysCall, fn: "sched_getparam"}}, EssentialEvent: false},
	SchedSetschedulerEventID:   EventConfig{ID: SchedSetschedulerEventID, Name: "reserved", Probes: []probe{probe{event: "sched_setscheduler", attach: sysCall, fn: "sched_setscheduler"}}, EssentialEvent: false},
	SchedGetschedulerEventID:   EventConfig{ID: SchedGetschedulerEventID, Name: "reserved", Probes: []probe{probe{event: "sched_getscheduler", attach: sysCall, fn: "sched_getscheduler"}}, EssentialEvent: false},
	SchedGetPriorityMaxEventID: EventConfig{ID: SchedGetPriorityMaxEventID, Name: "reserved", Probes: []probe{probe{event: "sched_get_priority_max", attach: sysCall, fn: "sched_get_priority_max"}}, EssentialEvent: false},
	SchedGetPriorityMinEventID: EventConfig{ID: SchedGetPriorityMinEventID, Name: "reserved", Probes: []probe{probe{event: "sched_get_priority_min", attach: sysCall, fn: "sched_get_priority_min"}}, EssentialEvent: false},
	SchedRrGetIntervalEventID:  EventConfig{ID: SchedRrGetIntervalEventID, Name: "reserved", Probes: []probe{probe{event: "sched_rr_get_interval", attach: sysCall, fn: "sched_rr_get_interval"}}, EssentialEvent: false},
	MlockEventID:               EventConfig{ID: MlockEventID, Name: "reserved", Probes: []probe{probe{event: "mlock", attach: sysCall, fn: "mlock"}}, EssentialEvent: false},
	MunlockEventID:             EventConfig{ID: MunlockEventID, Name: "reserved", Probes: []probe{probe{event: "munlock", attach: sysCall, fn: "munlock"}}, EssentialEvent: false},
	MlockallEventID:            EventConfig{ID: MlockallEventID, Name: "reserved", Probes: []probe{probe{event: "mlockall", attach: sysCall, fn: "mlockall"}}, EssentialEvent: false},
	MunlockallEventID:          EventConfig{ID: MunlockallEventID, Name: "reserved", Probes: []probe{probe{event: "munlockall", attach: sysCall, fn: "munlockall"}}, EssentialEvent: false},
	VhangupEventID:             EventConfig{ID: VhangupEventID, Name: "reserved", Probes: []probe{probe{event: "vhangup", attach: sysCall, fn: "vhangup"}}, EssentialEvent: false},
	ModifyLdtEventID:           EventConfig{ID: ModifyLdtEventID, Name: "reserved", Probes: []probe{probe{event: "modify_ldt", attach: sysCall, fn: "modify_ldt"}}, EssentialEvent: false},
	PivotRootEventID:           EventConfig{ID: PivotRootEventID, Name: "reserved", Probes: []probe{probe{event: "pivot_root", attach: sysCall, fn: "pivot_root"}}, EssentialEvent: false},
	SysctlEventID:              EventConfig{ID: SysctlEventID, Name: "reserved", Probes: []probe{probe{event: "sysctl", attach: sysCall, fn: "sysctl"}}, EssentialEvent: false},
	PrctlEventID:               EventConfig{ID: PrctlEventID, Name: "prctl", Probes: []probe{probe{event: "prctl", attach: sysCall, fn: "prctl"}}, EssentialEvent: false, Sets: []string{"default"}},
	ArchPrctlEventID:           EventConfig{ID: ArchPrctlEventID, Name: "reserved", Probes: []probe{probe{event: "arch_prctl", attach: sysCall, fn: "arch_prctl"}}, EssentialEvent: false},
	AdjtimexEventID:            EventConfig{ID: AdjtimexEventID, Name: "reserved", Probes: []probe{probe{event: "adjtimex", attach: sysCall, fn: "adjtimex"}}, EssentialEvent: false},
	SetrlimitEventID:           EventConfig{ID: SetrlimitEventID, Name: "reserved", Probes: []probe{probe{event: "setrlimit", attach: sysCall, fn: "setrlimit"}}, EssentialEvent: false},
	ChrootEventID:              EventConfig{ID: ChrootEventID, Name: "reserved", Probes: []probe{probe{event: "chroot", attach: sysCall, fn: "chroot"}}, EssentialEvent: false},
	SyncEventID:                EventConfig{ID: SyncEventID, Name: "reserved", Probes: []probe{probe{event: "sync", attach: sysCall, fn: "sync"}}, EssentialEvent: false},
	AcctEventID:                EventConfig{ID: AcctEventID, Name: "reserved", Probes: []probe{probe{event: "acct", attach: sysCall, fn: "acct"}}, EssentialEvent: false},
	SettimeofdayEventID:        EventConfig{ID: SettimeofdayEventID, Name: "reserved", Probes: []probe{probe{event: "settimeofday", attach: sysCall, fn: "settimeofday"}}, EssentialEvent: false},
	MountEventID:               EventConfig{ID: MountEventID, Name: "mount", Probes: []probe{probe{event: "mount", attach: sysCall, fn: "mount"}}, EssentialEvent: false, Sets: []string{"default"}},
	UmountEventID:              EventConfig{ID: UmountEventID, Name: "umount", Probes: []probe{probe{event: "umount", attach: sysCall, fn: "umount"}}, EssentialEvent: false, Sets: []string{"default"}},
	SwaponEventID:              EventConfig{ID: SwaponEventID, Name: "reserved", Probes: []probe{probe{event: "swapon", attach: sysCall, fn: "swapon"}}, EssentialEvent: false},
	SwapoffEventID:             EventConfig{ID: SwapoffEventID, Name: "reserved", Probes: []probe{probe{event: "swapoff", attach: sysCall, fn: "swapoff"}}, EssentialEvent: false},
	RebootEventID:              EventConfig{ID: RebootEventID, Name: "reserved", Probes: []probe{probe{event: "reboot", attach: sysCall, fn: "reboot"}}, EssentialEvent: false},
	SethostnameEventID:         EventConfig{ID: SethostnameEventID, Name: "reserved", Probes: []probe{probe{event: "sethostname", attach: sysCall, fn: "sethostname"}}, EssentialEvent: false},
	SetdomainnameEventID:       EventConfig{ID: SetdomainnameEventID, Name: "reserved", Probes: []probe{probe{event: "setdomainname", attach: sysCall, fn: "setdomainname"}}, EssentialEvent: false},
	IoplEventID:                EventConfig{ID: IoplEventID, Name: "reserved", Probes: []probe{probe{event: "iopl", attach: sysCall, fn: "iopl"}}, EssentialEvent: false},
	IopermEventID:              EventConfig{ID: IopermEventID, Name: "reserved", Probes: []probe{probe{event: "ioperm", attach: sysCall, fn: "ioperm"}}, EssentialEvent: false},
	CreateModuleEventID:        EventConfig{ID: CreateModuleEventID, Name: "reserved", Probes: []probe{probe{event: "create_module", attach: sysCall, fn: "create_module"}}, EssentialEvent: false},
	InitModuleEventID:          EventConfig{ID: InitModuleEventID, Name: "init_module", Probes: []probe{probe{event: "init_module", attach: sysCall, fn: "init_module"}}, EssentialEvent: false, Sets: []string{"default"}},
	DeleteModuleEventID:        EventConfig{ID: DeleteModuleEventID, Name: "delete_module", Probes: []probe{probe{event: "delete_module", attach: sysCall, fn: "delete_module"}}, EssentialEvent: false, Sets: []string{"default"}},
	GetKernelSymsEventID:       EventConfig{ID: GetKernelSymsEventID, Name: "reserved", Probes: []probe{probe{event: "get_kernel_syms", attach: sysCall, fn: "get_kernel_syms"}}, EssentialEvent: false},
	QueryModuleEventID:         EventConfig{ID: QueryModuleEventID, Name: "reserved", Probes: []probe{probe{event: "query_module", attach: sysCall, fn: "query_module"}}, EssentialEvent: false},
	QuotactlEventID:            EventConfig{ID: QuotactlEventID, Name: "reserved", Probes: []probe{probe{event: "quotactl", attach: sysCall, fn: "quotactl"}}, EssentialEvent: false},
	NfsservctlEventID:          EventConfig{ID: NfsservctlEventID, Name: "reserved", Probes: []probe{probe{event: "nfsservctl", attach: sysCall, fn: "nfsservctl"}}, EssentialEvent: false},
	GetpmsgEventID:             EventConfig{ID: GetpmsgEventID, Name: "reserved", Probes: []probe{probe{event: "getpmsg", attach: sysCall, fn: "getpmsg"}}, EssentialEvent: false},
	PutpmsgEventID:             EventConfig{ID: PutpmsgEventID, Name: "reserved", Probes: []probe{probe{event: "putpmsg", attach: sysCall, fn: "putpmsg"}}, EssentialEvent: false},
	AfsEventID:                 EventConfig{ID: AfsEventID, Name: "reserved", Probes: []probe{probe{event: "afs", attach: sysCall, fn: "afs"}}, EssentialEvent: false},
	TuxcallEventID:             EventConfig{ID: TuxcallEventID, Name: "reserved", Probes: []probe{probe{event: "tuxcall", attach: sysCall, fn: "tuxcall"}}, EssentialEvent: false},
	SecurityEventID:            EventConfig{ID: SecurityEventID, Name: "reserved", Probes: []probe{probe{event: "security", attach: sysCall, fn: "security"}}, EssentialEvent: false},
	GettidEventID:              EventConfig{ID: GettidEventID, Name: "reserved", Probes: []probe{probe{event: "gettid", attach: sysCall, fn: "gettid"}}, EssentialEvent: false},
	ReadaheadEventID:           EventConfig{ID: ReadaheadEventID, Name: "reserved", Probes: []probe{probe{event: "readahead", attach: sysCall, fn: "readahead"}}, EssentialEvent: false},
	SetxattrEventID:            EventConfig{ID: SetxattrEventID, Name: "reserved", Probes: []probe{probe{event: "setxattr", attach: sysCall, fn: "setxattr"}}, EssentialEvent: false},
	LsetxattrEventID:           EventConfig{ID: LsetxattrEventID, Name: "reserved", Probes: []probe{probe{event: "lsetxattr", attach: sysCall, fn: "lsetxattr"}}, EssentialEvent: false},
	FsetxattrEventID:           EventConfig{ID: FsetxattrEventID, Name: "reserved", Probes: []probe{probe{event: "fsetxattr", attach: sysCall, fn: "fsetxattr"}}, EssentialEvent: false},
	GetxattrEventID:            EventConfig{ID: GetxattrEventID, Name: "reserved", Probes: []probe{probe{event: "getxattr", attach: sysCall, fn: "getxattr"}}, EssentialEvent: false},
	LgetxattrEventID:           EventConfig{ID: LgetxattrEventID, Name: "reserved", Probes: []probe{probe{event: "lgetxattr", attach: sysCall, fn: "lgetxattr"}}, EssentialEvent: false},
	FgetxattrEventID:           EventConfig{ID: FgetxattrEventID, Name: "reserved", Probes: []probe{probe{event: "fgetxattr", attach: sysCall, fn: "fgetxattr"}}, EssentialEvent: false},
	ListxattrEventID:           EventConfig{ID: ListxattrEventID, Name: "reserved", Probes: []probe{probe{event: "listxattr", attach: sysCall, fn: "listxattr"}}, EssentialEvent: false},
	LlistxattrEventID:          EventConfig{ID: LlistxattrEventID, Name: "reserved", Probes: []probe{probe{event: "llistxattr", attach: sysCall, fn: "llistxattr"}}, EssentialEvent: false},
	FlistxattrEventID:          EventConfig{ID: FlistxattrEventID, Name: "reserved", Probes: []probe{probe{event: "flistxattr", attach: sysCall, fn: "flistxattr"}}, EssentialEvent: false},
	RemovexattrEventID:         EventConfig{ID: RemovexattrEventID, Name: "reserved", Probes: []probe{probe{event: "removexattr", attach: sysCall, fn: "removexattr"}}, EssentialEvent: false},
	LremovexattrEventID:        EventConfig{ID: LremovexattrEventID, Name: "reserved", Probes: []probe{probe{event: "lremovexattr", attach: sysCall, fn: "lremovexattr"}}, EssentialEvent: false},
	FremovexattrEventID:        EventConfig{ID: FremovexattrEventID, Name: "reserved", Probes: []probe{probe{event: "fremovexattr", attach: sysCall, fn: "fremovexattr"}}, EssentialEvent: false},
	TkillEventID:               EventConfig{ID: TkillEventID, Name: "reserved", Probes: []probe{probe{event: "tkill", attach: sysCall, fn: "tkill"}}, EssentialEvent: false},
	TimeEventID:                EventConfig{ID: TimeEventID, Name: "reserved", Probes: []probe{probe{event: "time", attach: sysCall, fn: "time"}}, EssentialEvent: false},
	FutexEventID:               EventConfig{ID: FutexEventID, Name: "reserved", Probes: []probe{probe{event: "futex", attach: sysCall, fn: "futex"}}, EssentialEvent: false},
	SchedSetaffinityEventID:    EventConfig{ID: SchedSetaffinityEventID, Name: "reserved", Probes: []probe{probe{event: "sched_setaffinity", attach: sysCall, fn: "sched_setaffinity"}}, EssentialEvent: false},
	SchedGetaffinityEventID:    EventConfig{ID: SchedGetaffinityEventID, Name: "reserved", Probes: []probe{probe{event: "sched_getaffinity", attach: sysCall, fn: "sched_getaffinity"}}, EssentialEvent: false},
	SetThreadAreaEventID:       EventConfig{ID: SetThreadAreaEventID, Name: "reserved", Probes: []probe{probe{event: "set_thread_area", attach: sysCall, fn: "set_thread_area"}}, EssentialEvent: false},
	IoSetupEventID:             EventConfig{ID: IoSetupEventID, Name: "reserved", Probes: []probe{probe{event: "io_setup", attach: sysCall, fn: "io_setup"}}, EssentialEvent: false},
	IoDestroyEventID:           EventConfig{ID: IoDestroyEventID, Name: "reserved", Probes: []probe{probe{event: "io_destroy", attach: sysCall, fn: "io_destroy"}}, EssentialEvent: false},
	IoGeteventsEventID:         EventConfig{ID: IoGeteventsEventID, Name: "reserved", Probes: []probe{probe{event: "io_getevents", attach: sysCall, fn: "io_getevents"}}, EssentialEvent: false},
	IoSubmitEventID:            EventConfig{ID: IoSubmitEventID, Name: "reserved", Probes: []probe{probe{event: "io_submit", attach: sysCall, fn: "io_submit"}}, EssentialEvent: false},
	IoCancelEventID:            EventConfig{ID: IoCancelEventID, Name: "reserved", Probes: []probe{probe{event: "io_cancel", attach: sysCall, fn: "io_cancel"}}, EssentialEvent: false},
	GetThreadAreaEventID:       EventConfig{ID: GetThreadAreaEventID, Name: "reserved", Probes: []probe{probe{event: "get_thread_area", attach: sysCall, fn: "get_thread_area"}}, EssentialEvent: false},
	LookupDcookieEventID:       EventConfig{ID: LookupDcookieEventID, Name: "reserved", Probes: []probe{probe{event: "lookup_dcookie", attach: sysCall, fn: "lookup_dcookie"}}, EssentialEvent: false},
	EpollCreateEventID:         EventConfig{ID: EpollCreateEventID, Name: "reserved", Probes: []probe{probe{event: "epoll_create", attach: sysCall, fn: "epoll_create"}}, EssentialEvent: false},
	EpollCtlOldEventID:         EventConfig{ID: EpollCtlOldEventID, Name: "reserved", Probes: []probe{probe{event: "epoll_ctl_old", attach: sysCall, fn: "epoll_ctl_old"}}, EssentialEvent: false},
	EpollWaitOldEventID:        EventConfig{ID: EpollWaitOldEventID, Name: "reserved", Probes: []probe{probe{event: "epoll_wait_old", attach: sysCall, fn: "epoll_wait_old"}}, EssentialEvent: false},
	RemapFilePagesEventID:      EventConfig{ID: RemapFilePagesEventID, Name: "reserved", Probes: []probe{probe{event: "remap_file_pages", attach: sysCall, fn: "remap_file_pages"}}, EssentialEvent: false},
	Getdents64EventID:          EventConfig{ID: Getdents64EventID, Name: "getdents64", Probes: []probe{probe{event: "getdents64", attach: sysCall, fn: "getdents64"}}, EssentialEvent: false, Sets: []string{"default"}},
	SetTidAddressEventID:       EventConfig{ID: SetTidAddressEventID, Name: "reserved", Probes: []probe{probe{event: "set_tid_address", attach: sysCall, fn: "set_tid_address"}}, EssentialEvent: false},
	RestartSyscallEventID:      EventConfig{ID: RestartSyscallEventID, Name: "reserved", Probes: []probe{probe{event: "restart_syscall", attach: sysCall, fn: "restart_syscall"}}, EssentialEvent: false},
	SemtimedopEventID:          EventConfig{ID: SemtimedopEventID, Name: "reserved", Probes: []probe{probe{event: "semtimedop", attach: sysCall, fn: "semtimedop"}}, EssentialEvent: false},
	Fadvise64EventID:           EventConfig{ID: Fadvise64EventID, Name: "reserved", Probes: []probe{probe{event: "fadvise64", attach: sysCall, fn: "fadvise64"}}, EssentialEvent: false},
	TimerCreateEventID:         EventConfig{ID: TimerCreateEventID, Name: "reserved", Probes: []probe{probe{event: "timer_create", attach: sysCall, fn: "timer_create"}}, EssentialEvent: false},
	TimerSettimeEventID:        EventConfig{ID: TimerSettimeEventID, Name: "reserved", Probes: []probe{probe{event: "timer_settime", attach: sysCall, fn: "timer_settime"}}, EssentialEvent: false},
	TimerGettimeEventID:        EventConfig{ID: TimerGettimeEventID, Name: "reserved", Probes: []probe{probe{event: "timer_gettime", attach: sysCall, fn: "timer_gettime"}}, EssentialEvent: false},
	TimerGetoverrunEventID:     EventConfig{ID: TimerGetoverrunEventID, Name: "reserved", Probes: []probe{probe{event: "timer_getoverrun", attach: sysCall, fn: "timer_getoverrun"}}, EssentialEvent: false},
	TimerDeleteEventID:         EventConfig{ID: TimerDeleteEventID, Name: "reserved", Probes: []probe{probe{event: "timer_delete", attach: sysCall, fn: "timer_delete"}}, EssentialEvent: false},
	ClockSettimeEventID:        EventConfig{ID: ClockSettimeEventID, Name: "reserved", Probes: []probe{probe{event: "clock_settime", attach: sysCall, fn: "clock_settime"}}, EssentialEvent: false},
	ClockGettimeEventID:        EventConfig{ID: ClockGettimeEventID, Name: "reserved", Probes: []probe{probe{event: "clock_gettime", attach: sysCall, fn: "clock_gettime"}}, EssentialEvent: false},
	ClockGetresEventID:         EventConfig{ID: ClockGetresEventID, Name: "reserved", Probes: []probe{probe{event: "clock_getres", attach: sysCall, fn: "clock_getres"}}, EssentialEvent: false},
	ClockNanosleepEventID:      EventConfig{ID: ClockNanosleepEventID, Name: "reserved", Probes: []probe{probe{event: "clock_nanosleep", attach: sysCall, fn: "clock_nanosleep"}}, EssentialEvent: false},
	ExitGroupEventID:           EventConfig{ID: ExitGroupEventID, Name: "reserved", Probes: []probe{probe{event: "exit_group", attach: sysCall, fn: "exit_group"}}, EssentialEvent: false},
	EpollWaitEventID:           EventConfig{ID: EpollWaitEventID, Name: "reserved", Probes: []probe{probe{event: "epoll_wait", attach: sysCall, fn: "epoll_wait"}}, EssentialEvent: false},
	EpollCtlEventID:            EventConfig{ID: EpollCtlEventID, Name: "reserved", Probes: []probe{probe{event: "epoll_ctl", attach: sysCall, fn: "epoll_ctl"}}, EssentialEvent: false},
	TgkillEventID:              EventConfig{ID: TgkillEventID, Name: "reserved", Probes: []probe{probe{event: "tgkill", attach: sysCall, fn: "tgkill"}}, EssentialEvent: false},
	UtimesEventID:              EventConfig{ID: UtimesEventID, Name: "reserved", Probes: []probe{probe{event: "utimes", attach: sysCall, fn: "utimes"}}, EssentialEvent: false},
	VserverEventID:             EventConfig{ID: VserverEventID, Name: "reserved", Probes: []probe{probe{event: "vserver", attach: sysCall, fn: "vserver"}}, EssentialEvent: false},
	MbindEventID:               EventConfig{ID: MbindEventID, Name: "reserved", Probes: []probe{probe{event: "mbind", attach: sysCall, fn: "mbind"}}, EssentialEvent: false},
	SetMempolicyEventID:        EventConfig{ID: SetMempolicyEventID, Name: "reserved", Probes: []probe{probe{event: "set_mempolicy", attach: sysCall, fn: "set_mempolicy"}}, EssentialEvent: false},
	GetMempolicyEventID:        EventConfig{ID: GetMempolicyEventID, Name: "reserved", Probes: []probe{probe{event: "get_mempolicy", attach: sysCall, fn: "get_mempolicy"}}, EssentialEvent: false},
	MqOpenEventID:              EventConfig{ID: MqOpenEventID, Name: "reserved", Probes: []probe{probe{event: "mq_open", attach: sysCall, fn: "mq_open"}}, EssentialEvent: false},
	MqUnlinkEventID:            EventConfig{ID: MqUnlinkEventID, Name: "reserved", Probes: []probe{probe{event: "mq_unlink", attach: sysCall, fn: "mq_unlink"}}, EssentialEvent: false},
	MqTimedsendEventID:         EventConfig{ID: MqTimedsendEventID, Name: "reserved", Probes: []probe{probe{event: "mq_timedsend", attach: sysCall, fn: "mq_timedsend"}}, EssentialEvent: false},
	MqTimedreceiveEventID:      EventConfig{ID: MqTimedreceiveEventID, Name: "reserved", Probes: []probe{probe{event: "mq_timedreceive", attach: sysCall, fn: "mq_timedreceive"}}, EssentialEvent: false},
	MqNotifyEventID:            EventConfig{ID: MqNotifyEventID, Name: "reserved", Probes: []probe{probe{event: "mq_notify", attach: sysCall, fn: "mq_notify"}}, EssentialEvent: false},
	MqGetsetattrEventID:        EventConfig{ID: MqGetsetattrEventID, Name: "reserved", Probes: []probe{probe{event: "mq_getsetattr", attach: sysCall, fn: "mq_getsetattr"}}, EssentialEvent: false},
	KexecLoadEventID:           EventConfig{ID: KexecLoadEventID, Name: "reserved", Probes: []probe{probe{event: "kexec_load", attach: sysCall, fn: "kexec_load"}}, EssentialEvent: false},
	WaitidEventID:              EventConfig{ID: WaitidEventID, Name: "reserved", Probes: []probe{probe{event: "waitid", attach: sysCall, fn: "waitid"}}, EssentialEvent: false},
	AddKeyEventID:              EventConfig{ID: AddKeyEventID, Name: "reserved", Probes: []probe{probe{event: "add_key", attach: sysCall, fn: "add_key"}}, EssentialEvent: false},
	RequestKeyEventID:          EventConfig{ID: RequestKeyEventID, Name: "reserved", Probes: []probe{probe{event: "request_key", attach: sysCall, fn: "request_key"}}, EssentialEvent: false},
	KeyctlEventID:              EventConfig{ID: KeyctlEventID, Name: "reserved", Probes: []probe{probe{event: "keyctl", attach: sysCall, fn: "keyctl"}}, EssentialEvent: false},
	IoprioSetEventID:           EventConfig{ID: IoprioSetEventID, Name: "reserved", Probes: []probe{probe{event: "ioprio_set", attach: sysCall, fn: "ioprio_set"}}, EssentialEvent: false},
	IoprioGetEventID:           EventConfig{ID: IoprioGetEventID, Name: "reserved", Probes: []probe{probe{event: "ioprio_get", attach: sysCall, fn: "ioprio_get"}}, EssentialEvent: false},
	InotifyInitEventID:         EventConfig{ID: InotifyInitEventID, Name: "reserved", Probes: []probe{probe{event: "inotify_init", attach: sysCall, fn: "inotify_init"}}, EssentialEvent: false},
	InotifyAddWatchEventID:     EventConfig{ID: InotifyAddWatchEventID, Name: "reserved", Probes: []probe{probe{event: "inotify_add_watch", attach: sysCall, fn: "inotify_add_watch"}}, EssentialEvent: false},
	InotifyRmWatchEventID:      EventConfig{ID: InotifyRmWatchEventID, Name: "reserved", Probes: []probe{probe{event: "inotify_rm_watch", attach: sysCall, fn: "inotify_rm_watch"}}, EssentialEvent: false},
	MigratePagesEventID:        EventConfig{ID: MigratePagesEventID, Name: "reserved", Probes: []probe{probe{event: "migrate_pages", attach: sysCall, fn: "migrate_pages"}}, EssentialEvent: false},
	OpenatEventID:              EventConfig{ID: OpenatEventID, Name: "openat", Probes: []probe{probe{event: "openat", attach: sysCall, fn: "openat"}}, EssentialEvent: false, Sets: []string{"default"}},
	MkdiratEventID:             EventConfig{ID: MkdiratEventID, Name: "reserved", Probes: []probe{probe{event: "mkdirat", attach: sysCall, fn: "mkdirat"}}, EssentialEvent: false},
	MknodatEventID:             EventConfig{ID: MknodatEventID, Name: "mknodat", Probes: []probe{probe{event: "mknodat", attach: sysCall, fn: "mknodat"}}, EssentialEvent: false, Sets: []string{"default"}},
	FchownatEventID:            EventConfig{ID: FchownatEventID, Name: "fchownat", Probes: []probe{probe{event: "fchownat", attach: sysCall, fn: "fchownat"}}, EssentialEvent: false, Sets: []string{"default"}},
	FutimesatEventID:           EventConfig{ID: FutimesatEventID, Name: "reserved", Probes: []probe{probe{event: "futimesat", attach: sysCall, fn: "futimesat"}}, EssentialEvent: false},
	NewfstatatEventID:          EventConfig{ID: NewfstatatEventID, Name: "reserved", Probes: []probe{probe{event: "newfstatat", attach: sysCall, fn: "newfstatat"}}, EssentialEvent: false},
	UnlinkatEventID:            EventConfig{ID: UnlinkatEventID, Name: "unlinkat", Probes: []probe{probe{event: "unlinkat", attach: sysCall, fn: "unlinkat"}}, EssentialEvent: false, Sets: []string{"default"}},
	RenameatEventID:            EventConfig{ID: RenameatEventID, Name: "reserved", Probes: []probe{probe{event: "renameat", attach: sysCall, fn: "renameat"}}, EssentialEvent: false},
	LinkatEventID:              EventConfig{ID: LinkatEventID, Name: "reserved", Probes: []probe{probe{event: "linkat", attach: sysCall, fn: "linkat"}}, EssentialEvent: false},
	SymlinkatEventID:           EventConfig{ID: SymlinkatEventID, Name: "symlinkat", Probes: []probe{probe{event: "symlinkat", attach: sysCall, fn: "symlinkat"}}, EssentialEvent: false, Sets: []string{"default"}},
	ReadlinkatEventID:          EventConfig{ID: ReadlinkatEventID, Name: "reserved", Probes: []probe{probe{event: "readlinkat", attach: sysCall, fn: "readlinkat"}}, EssentialEvent: false},
	FchmodatEventID:            EventConfig{ID: FchmodatEventID, Name: "fchmodat", Probes: []probe{probe{event: "fchmodat", attach: sysCall, fn: "fchmodat"}}, EssentialEvent: false, Sets: []string{"default"}},
	FaccessatEventID:           EventConfig{ID: FaccessatEventID, Name: "faccessat", Probes: []probe{probe{event: "faccessat", attach: sysCall, fn: "faccessat"}}, EssentialEvent: false, Sets: []string{"default"}},
	Pselect6EventID:            EventConfig{ID: Pselect6EventID, Name: "reserved", Probes: []probe{probe{event: "pselect6", attach: sysCall, fn: "pselect6"}}, EssentialEvent: false},
	PpollEventID:               EventConfig{ID: PpollEventID, Name: "reserved", Probes: []probe{probe{event: "ppoll", attach: sysCall, fn: "ppoll"}}, EssentialEvent: false},
	UnshareEventID:             EventConfig{ID: UnshareEventID, Name: "reserved", Probes: []probe{probe{event: "unshare", attach: sysCall, fn: "unshare"}}, EssentialEvent: false},
	SetRobustListEventID:       EventConfig{ID: SetRobustListEventID, Name: "reserved", Probes: []probe{probe{event: "set_robust_list", attach: sysCall, fn: "set_robust_list"}}, EssentialEvent: false},
	GetRobustListEventID:       EventConfig{ID: GetRobustListEventID, Name: "reserved", Probes: []probe{probe{event: "get_robust_list", attach: sysCall, fn: "get_robust_list"}}, EssentialEvent: false},
	SpliceEventID:              EventConfig{ID: SpliceEventID, Name: "reserved", Probes: []probe{probe{event: "splice", attach: sysCall, fn: "splice"}}, EssentialEvent: false},
	TeeEventID:                 EventConfig{ID: TeeEventID, Name: "reserved", Probes: []probe{probe{event: "tee", attach: sysCall, fn: "tee"}}, EssentialEvent: false},
	SyncFileRangeEventID:       EventConfig{ID: SyncFileRangeEventID, Name: "reserved", Probes: []probe{probe{event: "sync_file_range", attach: sysCall, fn: "sync_file_range"}}, EssentialEvent: false},
	VmspliceEventID:            EventConfig{ID: VmspliceEventID, Name: "reserved", Probes: []probe{probe{event: "vmsplice", attach: sysCall, fn: "vmsplice"}}, EssentialEvent: false},
	MovePagesEventID:           EventConfig{ID: MovePagesEventID, Name: "reserved", Probes: []probe{probe{event: "move_pages", attach: sysCall, fn: "move_pages"}}, EssentialEvent: false},
	UtimensatEventID:           EventConfig{ID: UtimensatEventID, Name: "reserved", Probes: []probe{probe{event: "utimensat", attach: sysCall, fn: "utimensat"}}, EssentialEvent: false},
	EpollPwaitEventID:          EventConfig{ID: EpollPwaitEventID, Name: "reserved", Probes: []probe{probe{event: "epoll_pwait", attach: sysCall, fn: "epoll_pwait"}}, EssentialEvent: false},
	SignalfdEventID:            EventConfig{ID: SignalfdEventID, Name: "reserved", Probes: []probe{probe{event: "signalfd", attach: sysCall, fn: "signalfd"}}, EssentialEvent: false},
	TimerfdCreateEventID:       EventConfig{ID: TimerfdCreateEventID, Name: "reserved", Probes: []probe{probe{event: "timerfd_create", attach: sysCall, fn: "timerfd_create"}}, EssentialEvent: false},
	EventfdEventID:             EventConfig{ID: EventfdEventID, Name: "reserved", Probes: []probe{probe{event: "eventfd", attach: sysCall, fn: "eventfd"}}, EssentialEvent: false},
	FallocateEventID:           EventConfig{ID: FallocateEventID, Name: "reserved", Probes: []probe{probe{event: "fallocate", attach: sysCall, fn: "fallocate"}}, EssentialEvent: false},
	TimerfdSettimeEventID:      EventConfig{ID: TimerfdSettimeEventID, Name: "reserved", Probes: []probe{probe{event: "timerfd_settime", attach: sysCall, fn: "timerfd_settime"}}, EssentialEvent: false},
	TimerfdGettimeEventID:      EventConfig{ID: TimerfdGettimeEventID, Name: "reserved", Probes: []probe{probe{event: "timerfd_gettime", attach: sysCall, fn: "timerfd_gettime"}}, EssentialEvent: false},
	Accept4EventID:             EventConfig{ID: Accept4EventID, Name: "accept4", Probes: []probe{probe{event: "accept4", attach: sysCall, fn: "accept4"}}, EssentialEvent: false, Sets: []string{"default"}},
	Signalfd4EventID:           EventConfig{ID: Signalfd4EventID, Name: "reserved", Probes: []probe{probe{event: "signalfd4", attach: sysCall, fn: "signalfd4"}}, EssentialEvent: false},
	Eventfd2EventID:            EventConfig{ID: Eventfd2EventID, Name: "reserved", Probes: []probe{probe{event: "eventfd2", attach: sysCall, fn: "eventfd2"}}, EssentialEvent: false},
	EpollCreate1EventID:        EventConfig{ID: EpollCreate1EventID, Name: "reserved", Probes: []probe{probe{event: "epoll_create1", attach: sysCall, fn: "epoll_create1"}}, EssentialEvent: false},
	Dup3EventID:                EventConfig{ID: Dup3EventID, Name: "dup3", Probes: []probe{probe{event: "dup3", attach: sysCall, fn: "dup3"}}, EssentialEvent: false, Sets: []string{"default"}},
	Pipe2EventID:               EventConfig{ID: Pipe2EventID, Name: "reserved", Probes: []probe{probe{event: "pipe2", attach: sysCall, fn: "pipe2"}}, EssentialEvent: false},
	IonotifyInit1EventID:       EventConfig{ID: IonotifyInit1EventID, Name: "reserved", Probes: []probe{probe{event: "ionotify_init1", attach: sysCall, fn: "ionotify_init1"}}, EssentialEvent: false},
	PreadvEventID:              EventConfig{ID: PreadvEventID, Name: "reserved", Probes: []probe{probe{event: "preadv", attach: sysCall, fn: "preadv"}}, EssentialEvent: false},
	PwritevEventID:             EventConfig{ID: PwritevEventID, Name: "reserved", Probes: []probe{probe{event: "pwritev", attach: sysCall, fn: "pwritev"}}, EssentialEvent: false},
	RtTgsigqueueinfoEventID:    EventConfig{ID: RtTgsigqueueinfoEventID, Name: "reserved", Probes: []probe{probe{event: "rt_tgsigqueueinfo", attach: sysCall, fn: "rt_tgsigqueueinfo"}}, EssentialEvent: false},
	PerfEventOpenEventID:       EventConfig{ID: PerfEventOpenEventID, Name: "reserved", Probes: []probe{probe{event: "perf_event_open", attach: sysCall, fn: "perf_event_open"}}, EssentialEvent: false},
	RecvmmsgEventID:            EventConfig{ID: RecvmmsgEventID, Name: "reserved", Probes: []probe{probe{event: "recvmmsg", attach: sysCall, fn: "recvmmsg"}}, EssentialEvent: false},
	FanotifyInitEventID:        EventConfig{ID: FanotifyInitEventID, Name: "reserved", Probes: []probe{probe{event: "fanotify_init", attach: sysCall, fn: "fanotify_init"}}, EssentialEvent: false},
	FanotifyMarkEventID:        EventConfig{ID: FanotifyMarkEventID, Name: "reserved", Probes: []probe{probe{event: "fanotify_mark", attach: sysCall, fn: "fanotify_mark"}}, EssentialEvent: false},
	Prlimit64EventID:           EventConfig{ID: Prlimit64EventID, Name: "reserved", Probes: []probe{probe{event: "prlimit64", attach: sysCall, fn: "prlimit64"}}, EssentialEvent: false},
	NameTohandleAtEventID:      EventConfig{ID: NameTohandleAtEventID, Name: "reserved", Probes: []probe{probe{event: "name_tohandle_at", attach: sysCall, fn: "name_tohandle_at"}}, EssentialEvent: false},
	OpenByHandleAtEventID:      EventConfig{ID: OpenByHandleAtEventID, Name: "reserved", Probes: []probe{probe{event: "open_by_handle_at", attach: sysCall, fn: "open_by_handle_at"}}, EssentialEvent: false},
	ClockAdjtimeEventID:        EventConfig{ID: ClockAdjtimeEventID, Name: "reserved", Probes: []probe{probe{event: "clock_adjtime", attach: sysCall, fn: "clock_adjtime"}}, EssentialEvent: false},
	SycnfsEventID:              EventConfig{ID: SycnfsEventID, Name: "reserved", Probes: []probe{probe{event: "sycnfs", attach: sysCall, fn: "sycnfs"}}, EssentialEvent: false},
	SendmmsgEventID:            EventConfig{ID: SendmmsgEventID, Name: "reserved", Probes: []probe{probe{event: "sendmmsg", attach: sysCall, fn: "sendmmsg"}}, EssentialEvent: false},
	SetnsEventID:               EventConfig{ID: SetnsEventID, Name: "reserved", Probes: []probe{probe{event: "setns", attach: sysCall, fn: "setns"}}, EssentialEvent: false},
	GetcpuEventID:              EventConfig{ID: GetcpuEventID, Name: "reserved", Probes: []probe{probe{event: "getcpu", attach: sysCall, fn: "getcpu"}}, EssentialEvent: false},
	ProcessVmReadvEventID:      EventConfig{ID: ProcessVmReadvEventID, Name: "process_vm_readv", Probes: []probe{probe{event: "process_vm_readv", attach: sysCall, fn: "process_vm_readv"}}, EssentialEvent: false, Sets: []string{"default"}},
	ProcessVmWritevEventID:     EventConfig{ID: ProcessVmWritevEventID, Name: "process_vm_writev", Probes: []probe{probe{event: "process_vm_writev", attach: sysCall, fn: "process_vm_writev"}}, EssentialEvent: false, Sets: []string{"default"}},
	KcmpEventID:                EventConfig{ID: KcmpEventID, Name: "reserved", Probes: []probe{probe{event: "kcmp", attach: sysCall, fn: "kcmp"}}, EssentialEvent: false},
	FinitModuleEventID:         EventConfig{ID: FinitModuleEventID, Name: "finit_module", Probes: []probe{probe{event: "finit_module", attach: sysCall, fn: "finit_module"}}, EssentialEvent: false, Sets: []string{"default"}},
	SchedSetattrEventID:        EventConfig{ID: SchedSetattrEventID, Name: "reserved", Probes: []probe{probe{event: "sched_setattr", attach: sysCall, fn: "sched_setattr"}}, EssentialEvent: false},
	SchedGetattrEventID:        EventConfig{ID: SchedGetattrEventID, Name: "reserved", Probes: []probe{probe{event: "sched_getattr", attach: sysCall, fn: "sched_getattr"}}, EssentialEvent: false},
	Renameat2EventID:           EventConfig{ID: Renameat2EventID, Name: "reserved", Probes: []probe{probe{event: "renameat2", attach: sysCall, fn: "renameat2"}}, EssentialEvent: false},
	SeccompEventID:             EventConfig{ID: SeccompEventID, Name: "reserved", Probes: []probe{probe{event: "seccomp", attach: sysCall, fn: "seccomp"}}, EssentialEvent: false},
	GetrandomEventID:           EventConfig{ID: GetrandomEventID, Name: "reserved", Probes: []probe{probe{event: "getrandom", attach: sysCall, fn: "getrandom"}}, EssentialEvent: false},
	MemfdCreateEventID:         EventConfig{ID: MemfdCreateEventID, Name: "memfd_create", Probes: []probe{probe{event: "memfd_create", attach: sysCall, fn: "memfd_create"}}, EssentialEvent: false, Sets: []string{"default"}},
	KexecFileLoadEventID:       EventConfig{ID: KexecFileLoadEventID, Name: "reserved", Probes: []probe{probe{event: "kexec_file_load", attach: sysCall, fn: "kexec_file_load"}}, EssentialEvent: false},
	BpfEventID:                 EventConfig{ID: BpfEventID, Name: "reserved", Probes: []probe{probe{event: "bpf", attach: sysCall, fn: "bpf"}}, EssentialEvent: false},
	ExecveatEventID:            EventConfig{ID: ExecveatEventID, Name: "execveat", Probes: []probe{probe{event: "execveat", attach: sysCall, fn: "execveat"}}, EssentialEvent: true, Sets: []string{"default"}},
	UserfaultfdEventID:         EventConfig{ID: UserfaultfdEventID, Name: "reserved", Probes: []probe{probe{event: "userfaultfd", attach: sysCall, fn: "userfaultfd"}}, EssentialEvent: false},
	MembarrierEventID:          EventConfig{ID: MembarrierEventID, Name: "reserved", Probes: []probe{probe{event: "membarrier", attach: sysCall, fn: "membarrier"}}, EssentialEvent: false},
	Mlock2EventID:              EventConfig{ID: Mlock2EventID, Name: "reserved", Probes: []probe{probe{event: "mlock2", attach: sysCall, fn: "mlock2"}}, EssentialEvent: false},
	CopyFileRangeEventID:       EventConfig{ID: CopyFileRangeEventID, Name: "reserved", Probes: []probe{probe{event: "copy_file_range", attach: sysCall, fn: "copy_file_range"}}, EssentialEvent: false},
	Preadv2EventID:             EventConfig{ID: Preadv2EventID, Name: "reserved", Probes: []probe{probe{event: "preadv2", attach: sysCall, fn: "preadv2"}}, EssentialEvent: false},
	Pwritev2EventID:            EventConfig{ID: Pwritev2EventID, Name: "reserved", Probes: []probe{probe{event: "pwritev2", attach: sysCall, fn: "pwritev2"}}, EssentialEvent: false},
	PkeyMprotectEventID:        EventConfig{ID: PkeyMprotectEventID, Name: "pkey_mprotect", Probes: []probe{probe{event: "pkey_mprotect", attach: sysCall, fn: "pkey_mprotect"}}, EssentialEvent: false, Sets: []string{"default"}},
	PkeyAllocEventID:           EventConfig{ID: PkeyAllocEventID, Name: "reserved", Probes: []probe{probe{event: "pkey_alloc", attach: sysCall, fn: "pkey_alloc"}}, EssentialEvent: false},
	PkeyFreeEventID:            EventConfig{ID: PkeyFreeEventID, Name: "reserved", Probes: []probe{probe{event: "pkey_free", attach: sysCall, fn: "pkey_free"}}, EssentialEvent: false},
	StatxEventID:               EventConfig{ID: StatxEventID, Name: "reserved", Probes: []probe{probe{event: "statx", attach: sysCall, fn: "statx"}}, EssentialEvent: false},
	IoPgeteventsEventID:        EventConfig{ID: IoPgeteventsEventID, Name: "reserved", Probes: []probe{probe{event: "io_pgetevents", attach: sysCall, fn: "io_pgetevents"}}, EssentialEvent: false},
	RseqEventID:                EventConfig{ID: RseqEventID, Name: "reserved", Probes: []probe{probe{event: "rseq", attach: sysCall, fn: "rseq"}}, EssentialEvent: false},
	Reserved335EventID:         EventConfig{ID: Reserved335EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false},
	Reserved336EventID:         EventConfig{ID: Reserved336EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false},
	Reserved337EventID:         EventConfig{ID: Reserved337EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false},
	Reserved338EventID:         EventConfig{ID: Reserved338EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false},
	Reserved339EventID:         EventConfig{ID: Reserved339EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false},
	Reserved340EventID:         EventConfig{ID: Reserved340EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false},
	Reserved341EventID:         EventConfig{ID: Reserved341EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false},
	Reserved342EventID:         EventConfig{ID: Reserved342EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false},
	Reserved343EventID:         EventConfig{ID: Reserved343EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false},
	Reserved344EventID:         EventConfig{ID: Reserved344EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false},
	Reserved345EventID:         EventConfig{ID: Reserved345EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false},
	Reserved346EventID:         EventConfig{ID: Reserved346EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false},
	Reserved347EventID:         EventConfig{ID: Reserved347EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false},
	Reserved348EventID:         EventConfig{ID: Reserved348EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false},
	Reserved349EventID:         EventConfig{ID: Reserved349EventID, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false},
	RawSyscallsEventID:         EventConfig{ID: RawSyscallsEventID, Name: "raw_syscalls", Probes: []probe{probe{event: "raw_syscalls:sys_enter", attach: tracepoint, fn: "tracepoint__raw_syscalls__sys_enter"}}, EssentialEvent: false},
	DoExitEventID:              EventConfig{ID: DoExitEventID, Name: "do_exit", Probes: []probe{probe{event: "do_exit", attach: kprobe, fn: "trace_do_exit"}}, EssentialEvent: true, Sets: []string{"default"}},
	CapCapableEventID:          EventConfig{ID: CapCapableEventID, Name: "cap_capable", Probes: []probe{probe{event: "cap_capable", attach: kprobe, fn: "trace_cap_capable"}}, EssentialEvent: false, Sets: []string{"default"}},
	SecurityBprmCheckEventID:   EventConfig{ID: SecurityBprmCheckEventID, Name: "security_bprm_check", Probes: []probe{probe{event: "security_bprm_check", attach: kprobe, fn: "trace_security_bprm_check"}}, EssentialEvent: false, Sets: []string{"default"}},
	SecurityFileOpenEventID:    EventConfig{ID: SecurityFileOpenEventID, Name: "security_file_open", Probes: []probe{probe{event: "security_file_open", attach: kprobe, fn: "trace_security_file_open"}}, EssentialEvent: false, Sets: []string{"default"}},
	VfsWriteEventID:            EventConfig{ID: VfsWriteEventID, Name: "vfs_write", Probes: []probe{probe{event: "vfs_write", attach: kprobe, fn: "trace_vfs_write"}, probe{event: "vfs_write", attach: kretprobe, fn: "trace_ret_vfs_write"}}, EssentialEvent: false, Sets: []string{"default"}},
	MemProtAlertEventID:        EventConfig{ID: MemProtAlertEventID, Name: "mem_prot_alert", Probes: []probe{probe{event: "security_mmap_addr", attach: kprobe, fn: "trace_mmap_alert"}, probe{event: "security_file_mprotect", attach: kprobe, fn: "trace_mprotect_alert"}}, EssentialEvent: false},
}
