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
	TagBuf
	TagWhence
	TagAdvice
	TagDestAddr
	TagSrcAddr
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
	TagBuf:            "buf",
	TagWhence:         "whence",
	TagAdvice:         "advice",
	TagDestAddr:       "dest_addr",
	TagSrcAddr:        "src_addr",
}

// ProbeType is an enum that describes the mechanism used to attach the event
// Kprobes are explained here: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#1-kprobes
// Tracepoints are explained here: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#3-tracepoints
// Raw tracepoints are explained here: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#7-raw-tracepoints
type probeType uint8

const (
	sysCall probeType = iota
	kprobe
	kretprobe
	tracepoint
	rawTracepoint
)

type probe struct {
	event  string
	attach probeType
	fn     string
}

// EventConfig is a struct describing an event configuration
type EventConfig struct {
	ID             int32
	ID32Bit        int32
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
	InotifyInit1EventID
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
	SyncfsEventID
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
	SysEnterEventID
	SysExitEventID
	DoExitEventID
	CapCapableEventID
	SecurityBprmCheckEventID
	SecurityFileOpenEventID
	VfsWriteEventID
	MemProtAlertEventID
)

// 32bit syscall numbers
const (
	sys32restart_syscall              int32 = 0
	sys32exit                         int32 = 1
	sys32fork                         int32 = 2
	sys32read                         int32 = 3
	sys32write                        int32 = 4
	sys32open                         int32 = 5
	sys32close                        int32 = 6
	sys32waitpid                      int32 = 7
	sys32creat                        int32 = 8
	sys32link                         int32 = 9
	sys32unlink                       int32 = 10
	sys32execve                       int32 = 11
	sys32chdir                        int32 = 12
	sys32time                         int32 = 13
	sys32mknod                        int32 = 14
	sys32chmod                        int32 = 15
	sys32lchown                       int32 = 16
	sys32break                        int32 = 17
	sys32oldstat                      int32 = 18
	sys32lseek                        int32 = 19
	sys32getpid                       int32 = 20
	sys32mount                        int32 = 21
	sys32umount                       int32 = 22
	sys32setuid                       int32 = 23
	sys32getuid                       int32 = 24
	sys32stime                        int32 = 25
	sys32ptrace                       int32 = 26
	sys32alarm                        int32 = 27
	sys32oldfstat                     int32 = 28
	sys32pause                        int32 = 29
	sys32utime                        int32 = 30
	sys32stty                         int32 = 31
	sys32gtty                         int32 = 32
	sys32access                       int32 = 33
	sys32nice                         int32 = 34
	sys32ftime                        int32 = 35
	sys32sync                         int32 = 36
	sys32kill                         int32 = 37
	sys32rename                       int32 = 38
	sys32mkdir                        int32 = 39
	sys32rmdir                        int32 = 40
	sys32dup                          int32 = 41
	sys32pipe                         int32 = 42
	sys32times                        int32 = 43
	sys32prof                         int32 = 44
	sys32brk                          int32 = 45
	sys32setgid                       int32 = 46
	sys32getgid                       int32 = 47
	sys32signal                       int32 = 48
	sys32geteuid                      int32 = 49
	sys32getegid                      int32 = 50
	sys32acct                         int32 = 51
	sys32umount2                      int32 = 52
	sys32lock                         int32 = 53
	sys32ioctl                        int32 = 54
	sys32fcntl                        int32 = 55
	sys32mpx                          int32 = 56
	sys32setpgid                      int32 = 57
	sys32ulimit                       int32 = 58
	sys32oldolduname                  int32 = 59
	sys32umask                        int32 = 60
	sys32chroot                       int32 = 61
	sys32ustat                        int32 = 62
	sys32dup2                         int32 = 63
	sys32getppid                      int32 = 64
	sys32getpgrp                      int32 = 65
	sys32setsid                       int32 = 66
	sys32sigaction                    int32 = 67
	sys32sgetmask                     int32 = 68
	sys32ssetmask                     int32 = 69
	sys32setreuid                     int32 = 70
	sys32setregid                     int32 = 71
	sys32sigsuspend                   int32 = 72
	sys32sigpending                   int32 = 73
	sys32sethostname                  int32 = 74
	sys32setrlimit                    int32 = 75
	sys32getrlimit                    int32 = 76
	sys32getrusage                    int32 = 77
	sys32gettimeofday                 int32 = 78
	sys32settimeofday                 int32 = 79
	sys32getgroups                    int32 = 80
	sys32setgroups                    int32 = 81
	sys32select                       int32 = 82
	sys32symlink                      int32 = 83
	sys32oldlstat                     int32 = 84
	sys32readlink                     int32 = 85
	sys32uselib                       int32 = 86
	sys32swapon                       int32 = 87
	sys32reboot                       int32 = 88
	sys32readdir                      int32 = 89
	sys32mmap                         int32 = 90
	sys32munmap                       int32 = 91
	sys32truncate                     int32 = 92
	sys32ftruncate                    int32 = 93
	sys32fchmod                       int32 = 94
	sys32fchown                       int32 = 95
	sys32getpriority                  int32 = 96
	sys32setpriority                  int32 = 97
	sys32profil                       int32 = 98
	sys32statfs                       int32 = 99
	sys32fstatfs                      int32 = 100
	sys32ioperm                       int32 = 101
	sys32socketcall                   int32 = 102
	sys32syslog                       int32 = 103
	sys32setitimer                    int32 = 104
	sys32getitimer                    int32 = 105
	sys32stat                         int32 = 106
	sys32lstat                        int32 = 107
	sys32fstat                        int32 = 108
	sys32olduname                     int32 = 109
	sys32iopl                         int32 = 110
	sys32vhangup                      int32 = 111
	sys32idle                         int32 = 112
	sys32vm86old                      int32 = 113
	sys32wait4                        int32 = 114
	sys32swapoff                      int32 = 115
	sys32sysinfo                      int32 = 116
	sys32ipc                          int32 = 117
	sys32fsync                        int32 = 118
	sys32sigreturn                    int32 = 119
	sys32clone                        int32 = 120
	sys32setdomainname                int32 = 121
	sys32uname                        int32 = 122
	sys32modify_ldt                   int32 = 123
	sys32adjtimex                     int32 = 124
	sys32mprotect                     int32 = 125
	sys32sigprocmask                  int32 = 126
	sys32create_module                int32 = 127
	sys32init_module                  int32 = 128
	sys32delete_module                int32 = 129
	sys32get_kernel_syms              int32 = 130
	sys32quotactl                     int32 = 131
	sys32getpgid                      int32 = 132
	sys32fchdir                       int32 = 133
	sys32bdflush                      int32 = 134
	sys32sysfs                        int32 = 135
	sys32personality                  int32 = 136
	sys32afs_syscall                  int32 = 137
	sys32setfsuid                     int32 = 138
	sys32setfsgid                     int32 = 139
	sys32_llseek                      int32 = 140
	sys32getdents                     int32 = 141
	sys32_newselect                   int32 = 142
	sys32flock                        int32 = 143
	sys32msync                        int32 = 144
	sys32readv                        int32 = 145
	sys32writev                       int32 = 146
	sys32getsid                       int32 = 147
	sys32fdatasync                    int32 = 148
	sys32_sysctl                      int32 = 149
	sys32mlock                        int32 = 150
	sys32munlock                      int32 = 151
	sys32mlockall                     int32 = 152
	sys32munlockall                   int32 = 153
	sys32sched_setparam               int32 = 154
	sys32sched_getparam               int32 = 155
	sys32sched_setscheduler           int32 = 156
	sys32sched_getscheduler           int32 = 157
	sys32sched_yield                  int32 = 158
	sys32sched_get_priority_max       int32 = 159
	sys32sched_get_priority_min       int32 = 160
	sys32sched_rr_get_interval        int32 = 161
	sys32nanosleep                    int32 = 162
	sys32mremap                       int32 = 163
	sys32setresuid                    int32 = 164
	sys32getresuid                    int32 = 165
	sys32vm86                         int32 = 166
	sys32query_module                 int32 = 167
	sys32poll                         int32 = 168
	sys32nfsservctl                   int32 = 169
	sys32setresgid                    int32 = 170
	sys32getresgid                    int32 = 171
	sys32prctl                        int32 = 172
	sys32rt_sigreturn                 int32 = 173
	sys32rt_sigaction                 int32 = 174
	sys32rt_sigprocmask               int32 = 175
	sys32rt_sigpending                int32 = 176
	sys32rt_sigtimedwait              int32 = 177
	sys32rt_sigqueueinfo              int32 = 178
	sys32rt_sigsuspend                int32 = 179
	sys32pread64                      int32 = 180
	sys32pwrite64                     int32 = 181
	sys32chown                        int32 = 182
	sys32getcwd                       int32 = 183
	sys32capget                       int32 = 184
	sys32capset                       int32 = 185
	sys32sigaltstack                  int32 = 186
	sys32sendfile                     int32 = 187
	sys32getpmsg                      int32 = 188
	sys32putpmsg                      int32 = 189
	sys32vfork                        int32 = 190
	sys32ugetrlimit                   int32 = 191
	sys32mmap2                        int32 = 192
	sys32truncate64                   int32 = 193
	sys32ftruncate64                  int32 = 194
	sys32stat64                       int32 = 195
	sys32lstat64                      int32 = 196
	sys32fstat64                      int32 = 197
	sys32lchown32                     int32 = 198
	sys32getuid32                     int32 = 199
	sys32getgid32                     int32 = 200
	sys32geteuid32                    int32 = 201
	sys32getegid32                    int32 = 202
	sys32setreuid32                   int32 = 203
	sys32setregid32                   int32 = 204
	sys32getgroups32                  int32 = 205
	sys32setgroups32                  int32 = 206
	sys32fchown32                     int32 = 207
	sys32setresuid32                  int32 = 208
	sys32getresuid32                  int32 = 209
	sys32setresgid32                  int32 = 210
	sys32getresgid32                  int32 = 211
	sys32chown32                      int32 = 212
	sys32setuid32                     int32 = 213
	sys32setgid32                     int32 = 214
	sys32setfsuid32                   int32 = 215
	sys32setfsgid32                   int32 = 216
	sys32pivot_root                   int32 = 217
	sys32mincore                      int32 = 218
	sys32madvise                      int32 = 219
	sys32getdents64                   int32 = 220
	sys32fcntl64                      int32 = 221
	sys32gettid                       int32 = 224
	sys32readahead                    int32 = 225
	sys32setxattr                     int32 = 226
	sys32lsetxattr                    int32 = 227
	sys32fsetxattr                    int32 = 228
	sys32getxattr                     int32 = 229
	sys32lgetxattr                    int32 = 230
	sys32fgetxattr                    int32 = 231
	sys32listxattr                    int32 = 232
	sys32llistxattr                   int32 = 233
	sys32flistxattr                   int32 = 234
	sys32removexattr                  int32 = 235
	sys32lremovexattr                 int32 = 236
	sys32fremovexattr                 int32 = 237
	sys32tkill                        int32 = 238
	sys32sendfile64                   int32 = 239
	sys32futex                        int32 = 240
	sys32sched_setaffinity            int32 = 241
	sys32sched_getaffinity            int32 = 242
	sys32set_thread_area              int32 = 243
	sys32get_thread_area              int32 = 244
	sys32io_setup                     int32 = 245
	sys32io_destroy                   int32 = 246
	sys32io_getevents                 int32 = 247
	sys32io_submit                    int32 = 248
	sys32io_cancel                    int32 = 249
	sys32fadvise64                    int32 = 250
	sys32exit_group                   int32 = 252
	sys32lookup_dcookie               int32 = 253
	sys32epoll_create                 int32 = 254
	sys32epoll_ctl                    int32 = 255
	sys32epoll_wait                   int32 = 256
	sys32remap_file_pages             int32 = 257
	sys32set_tid_address              int32 = 258
	sys32timer_create                 int32 = 259
	sys32timer_settime                int32 = 260
	sys32timer_gettime                int32 = 261
	sys32timer_getoverrun             int32 = 262
	sys32timer_delete                 int32 = 263
	sys32clock_settime                int32 = 264
	sys32clock_gettime                int32 = 265
	sys32clock_getres                 int32 = 266
	sys32clock_nanosleep              int32 = 267
	sys32statfs64                     int32 = 268
	sys32fstatfs64                    int32 = 269
	sys32tgkill                       int32 = 270
	sys32utimes                       int32 = 271
	sys32fadvise64_64                 int32 = 272
	sys32vserver                      int32 = 273
	sys32mbind                        int32 = 274
	sys32get_mempolicy                int32 = 275
	sys32set_mempolicy                int32 = 276
	sys32mq_open                      int32 = 277
	sys32mq_unlink                    int32 = 278
	sys32mq_timedsend                 int32 = 279
	sys32mq_timedreceive              int32 = 280
	sys32mq_notify                    int32 = 281
	sys32mq_getsetattr                int32 = 282
	sys32kexec_load                   int32 = 283
	sys32waitid                       int32 = 284
	sys32add_key                      int32 = 286
	sys32request_key                  int32 = 287
	sys32keyctl                       int32 = 288
	sys32ioprio_set                   int32 = 289
	sys32ioprio_get                   int32 = 290
	sys32inotify_init                 int32 = 291
	sys32inotify_add_watch            int32 = 292
	sys32inotify_rm_watch             int32 = 293
	sys32migrate_pages                int32 = 294
	sys32openat                       int32 = 295
	sys32mkdirat                      int32 = 296
	sys32mknodat                      int32 = 297
	sys32fchownat                     int32 = 298
	sys32futimesat                    int32 = 299
	sys32fstatat64                    int32 = 300
	sys32unlinkat                     int32 = 301
	sys32renameat                     int32 = 302
	sys32linkat                       int32 = 303
	sys32symlinkat                    int32 = 304
	sys32readlinkat                   int32 = 305
	sys32fchmodat                     int32 = 306
	sys32faccessat                    int32 = 307
	sys32pselect6                     int32 = 308
	sys32ppoll                        int32 = 309
	sys32unshare                      int32 = 310
	sys32set_robust_list              int32 = 311
	sys32get_robust_list              int32 = 312
	sys32splice                       int32 = 313
	sys32sync_file_range              int32 = 314
	sys32tee                          int32 = 315
	sys32vmsplice                     int32 = 316
	sys32move_pages                   int32 = 317
	sys32getcpu                       int32 = 318
	sys32epoll_pwait                  int32 = 319
	sys32utimensat                    int32 = 320
	sys32signalfd                     int32 = 321
	sys32timerfd_create               int32 = 322
	sys32eventfd                      int32 = 323
	sys32fallocate                    int32 = 324
	sys32timerfd_settime              int32 = 325
	sys32timerfd_gettime              int32 = 326
	sys32signalfd4                    int32 = 327
	sys32eventfd2                     int32 = 328
	sys32epoll_create1                int32 = 329
	sys32dup3                         int32 = 330
	sys32pipe2                        int32 = 331
	sys32inotify_init1                int32 = 332
	sys32preadv                       int32 = 333
	sys32pwritev                      int32 = 334
	sys32rt_tgsigqueueinfo            int32 = 335
	sys32perf_event_open              int32 = 336
	sys32recvmmsg                     int32 = 337
	sys32fanotify_init                int32 = 338
	sys32fanotify_mark                int32 = 339
	sys32prlimit64                    int32 = 340
	sys32name_to_handle_at            int32 = 341
	sys32open_by_handle_at            int32 = 342
	sys32clock_adjtime                int32 = 343
	sys32syncfs                       int32 = 344
	sys32sendmmsg                     int32 = 345
	sys32setns                        int32 = 346
	sys32process_vm_readv             int32 = 347
	sys32process_vm_writev            int32 = 348
	sys32kcmp                         int32 = 349
	sys32finit_module                 int32 = 350
	sys32sched_setattr                int32 = 351
	sys32sched_getattr                int32 = 352
	sys32renameat2                    int32 = 353
	sys32seccomp                      int32 = 354
	sys32getrandom                    int32 = 355
	sys32memfd_create                 int32 = 356
	sys32bpf                          int32 = 357
	sys32execveat                     int32 = 358
	sys32socket                       int32 = 359
	sys32socketpair                   int32 = 360
	sys32bind                         int32 = 361
	sys32connect                      int32 = 362
	sys32listen                       int32 = 363
	sys32accept4                      int32 = 364
	sys32getsockopt                   int32 = 365
	sys32setsockopt                   int32 = 366
	sys32getsockname                  int32 = 367
	sys32getpeername                  int32 = 368
	sys32sendto                       int32 = 369
	sys32sendmsg                      int32 = 370
	sys32recvfrom                     int32 = 371
	sys32recvmsg                      int32 = 372
	sys32shutdown                     int32 = 373
	sys32userfaultfd                  int32 = 374
	sys32membarrier                   int32 = 375
	sys32mlock2                       int32 = 376
	sys32copy_file_range              int32 = 377
	sys32preadv2                      int32 = 378
	sys32pwritev2                     int32 = 379
	sys32pkey_mprotect                int32 = 380
	sys32pkey_alloc                   int32 = 381
	sys32pkey_free                    int32 = 382
	sys32statx                        int32 = 383
	sys32arch_prctl                   int32 = 384
	sys32io_pgetevents                int32 = 385
	sys32rseq                         int32 = 386
	sys32semget                       int32 = 393
	sys32semctl                       int32 = 394
	sys32shmget                       int32 = 395
	sys32shmctl                       int32 = 396
	sys32shmat                        int32 = 397
	sys32shmdt                        int32 = 398
	sys32msgget                       int32 = 399
	sys32msgsnd                       int32 = 400
	sys32msgrcv                       int32 = 401
	sys32msgctl                       int32 = 402
	sys32clock_gettime64              int32 = 403
	sys32clock_settime64              int32 = 404
	sys32clock_adjtime64              int32 = 405
	sys32clock_getres_time64          int32 = 406
	sys32clock_nanosleep_time64       int32 = 407
	sys32timer_gettime64              int32 = 408
	sys32timer_settime64              int32 = 409
	sys32timerfd_gettime64            int32 = 410
	sys32timerfd_settime64            int32 = 411
	sys32utimensat_time64             int32 = 412
	sys32pselect6_time64              int32 = 413
	sys32ppoll_time64                 int32 = 414
	sys32io_pgetevents_time64         int32 = 416
	sys32recvmmsg_time64              int32 = 417
	sys32mq_timedsend_time64          int32 = 418
	sys32mq_timedreceive_time64       int32 = 419
	sys32semtimedop_time64            int32 = 420
	sys32rt_sigtimedwait_time64       int32 = 421
	sys32futex_time64                 int32 = 422
	sys32sched_rr_get_interval_time64 int32 = 423
	sys32pidfd_send_signal            int32 = 424
	sys32io_uring_setup               int32 = 425
	sys32io_uring_enter               int32 = 426
	sys32io_uring_register            int32 = 427
	sys32open_tree                    int32 = 428
	sys32move_mount                   int32 = 429
	sys32fsopen                       int32 = 430
	sys32fsconfig                     int32 = 431
	sys32fsmount                      int32 = 432
	sys32fspick                       int32 = 433
	sys32pidfd_open                   int32 = 434
	sys32clone3                       int32 = 435
	sys32openat2                      int32 = 437
	sys32pidfd_getfd                  int32 = 438
	sys32undefined                    int32 = 1000
)

// EventsIDToEvent is list of supported events, indexed by their ID
var EventsIDToEvent = map[int32]EventConfig{
	ReadEventID:                EventConfig{ID: ReadEventID, ID32Bit: sys32read, Name: "read", Probes: []probe{probe{event: "read", attach: sysCall, fn: "read"}}, EssentialEvent: false, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	WriteEventID:               EventConfig{ID: WriteEventID, ID32Bit: sys32write, Name: "write", Probes: []probe{probe{event: "write", attach: sysCall, fn: "write"}}, EssentialEvent: false, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	OpenEventID:                EventConfig{ID: OpenEventID, ID32Bit: sys32open, Name: "open", Probes: []probe{probe{event: "open", attach: sysCall, fn: "open"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	CloseEventID:               EventConfig{ID: CloseEventID, ID32Bit: sys32close, Name: "close", Probes: []probe{probe{event: "close", attach: sysCall, fn: "close"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	StatEventID:                EventConfig{ID: StatEventID, ID32Bit: sys32stat, Name: "stat", Probes: []probe{probe{event: "newstat", attach: sysCall, fn: "newstat"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	FstatEventID:               EventConfig{ID: FstatEventID, ID32Bit: sys32fstat, Name: "fstat", Probes: []probe{probe{event: "newfstat", attach: sysCall, fn: "newfstat"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	LstatEventID:               EventConfig{ID: LstatEventID, ID32Bit: sys32lstat, Name: "lstat", Probes: []probe{probe{event: "newlstat", attach: sysCall, fn: "newlstat"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	PollEventID:                EventConfig{ID: PollEventID, ID32Bit: sys32poll, Name: "reserved", Probes: []probe{probe{event: "poll", attach: sysCall, fn: "poll"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_mux_io"*/ }},
	LseekEventID:               EventConfig{ID: LseekEventID, ID32Bit: sys32lseek, Name: "lseek", Probes: []probe{probe{event: "lseek", attach: sysCall, fn: "lseek"}}, EssentialEvent: false, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	MmapEventID:                EventConfig{ID: MmapEventID, ID32Bit: sys32mmap, Name: "mmap", Probes: []probe{probe{event: "mmap", attach: sysCall, fn: "mmap"}}, EssentialEvent: false, Sets: []string{"syscalls", "proc", "proc_mem"}},
	MprotectEventID:            EventConfig{ID: MprotectEventID, ID32Bit: sys32mprotect, Name: "mprotect", Probes: []probe{probe{event: "mprotect", attach: sysCall, fn: "mprotect"}}, EssentialEvent: false, Sets: []string{"syscalls", "proc", "proc_mem"}},
	MunmapEventID:              EventConfig{ID: MunmapEventID, ID32Bit: sys32munmap, Name: "munmap", Probes: []probe{probe{event: "munmap", attach: sysCall, fn: "munmap"}}, EssentialEvent: false, Sets: []string{"syscalls", "proc", "proc_mem"}},
	BrkEventID:                 EventConfig{ID: BrkEventID, ID32Bit: sys32brk, Name: "brk", Probes: []probe{probe{event: "brk", attach: sysCall, fn: "brk"}}, EssentialEvent: false, Sets: []string{"syscalls", "proc", "proc_mem"}},
	RtSigactionEventID:         EventConfig{ID: RtSigactionEventID, ID32Bit: sys32rt_sigaction, Name: "reserved", Probes: []probe{probe{event: "rt_sigaction", attach: sysCall, fn: "rt_sigaction"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "signals"*/ }},
	RtSigprocmaskEventID:       EventConfig{ID: RtSigprocmaskEventID, ID32Bit: sys32rt_sigprocmask, Name: "reserved", Probes: []probe{probe{event: "rt_sigprocmask", attach: sysCall, fn: "rt_sigprocmask"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "signals"*/ }},
	RtSigreturnEventID:         EventConfig{ID: RtSigreturnEventID, ID32Bit: sys32rt_sigreturn, Name: "reserved", Probes: []probe{probe{event: "rt_sigreturn", attach: sysCall, fn: "rt_sigreturn"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "signals"*/ }},
	IoctlEventID:               EventConfig{ID: IoctlEventID, ID32Bit: sys32ioctl, Name: "ioctl", Probes: []probe{probe{event: "ioctl", attach: sysCall, fn: "ioctl"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_fd_ops"}},
	Pread64EventID:             EventConfig{ID: Pread64EventID, ID32Bit: sys32pread64, Name: "pread64", Probes: []probe{probe{event: "pread64", attach: sysCall, fn: "pread64"}}, EssentialEvent: false, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	Pwrite64EventID:            EventConfig{ID: Pwrite64EventID, ID32Bit: sys32pwrite64, Name: "pwrite64", Probes: []probe{probe{event: "pwrite64", attach: sysCall, fn: "pwrite64"}}, EssentialEvent: false, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	ReadvEventID:               EventConfig{ID: ReadvEventID, ID32Bit: sys32readv, Name: "reserved", Probes: []probe{probe{event: "readv", attach: sysCall, fn: "readv"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_read_write"*/ }},
	WritevEventID:              EventConfig{ID: WritevEventID, ID32Bit: sys32writev, Name: "reserved", Probes: []probe{probe{event: "writev", attach: sysCall, fn: "writev"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_read_write"*/ }},
	AccessEventID:              EventConfig{ID: AccessEventID, ID32Bit: sys32access, Name: "access", Probes: []probe{probe{event: "access", attach: sysCall, fn: "access"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	PipeEventID:                EventConfig{ID: PipeEventID, ID32Bit: sys32pipe, Name: "reserved", Probes: []probe{probe{event: "pipe", attach: sysCall, fn: "pipe"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "ipc", "ipc_pipe"*/ }},
	SelectEventID:              EventConfig{ID: SelectEventID, ID32Bit: sys32select, Name: "reserved", Probes: []probe{probe{event: "select", attach: sysCall, fn: "select"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_mux_io"*/ }},
	SchedYieldEventID:          EventConfig{ID: SchedYieldEventID, ID32Bit: sys32sched_yield, Name: "sched_yield", Probes: []probe{probe{event: "sched_yield", attach: sysCall, fn: "sched_yield"}}, EssentialEvent: false, Sets: []string{"syscalls", "proc", "proc_sched"}},
	MremapEventID:              EventConfig{ID: MremapEventID, ID32Bit: sys32mremap, Name: "reserved", Probes: []probe{probe{event: "mremap", attach: sysCall, fn: "mremap"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_mem"*/ }},
	MsyncEventID:               EventConfig{ID: MsyncEventID, ID32Bit: sys32msync, Name: "msync", Probes: []probe{probe{event: "msync", attach: sysCall, fn: "msync"}}, EssentialEvent: false, Sets: []string{"syscalls", "fs", "fs_sync"}},
	MincoreEventID:             EventConfig{ID: MincoreEventID, ID32Bit: sys32mincore, Name: "reserved", Probes: []probe{probe{event: "mincore", attach: sysCall, fn: "mincore"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_mem"*/ }},
	MadviseEventID:             EventConfig{ID: MadviseEventID, ID32Bit: sys32madvise, Name: "madvise", Probes: []probe{probe{event: "madvise", attach: sysCall, fn: "madvise"}}, EssentialEvent: false, Sets: []string{"syscalls", "proc", "proc_mem"}},
	ShmgetEventID:              EventConfig{ID: ShmgetEventID, ID32Bit: sys32shmget, Name: "reserved", Probes: []probe{probe{event: "shmget", attach: sysCall, fn: "shmget"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "ipc", "ipc_shm"*/ }},
	ShmatEventID:               EventConfig{ID: ShmatEventID, ID32Bit: sys32shmat, Name: "reserved", Probes: []probe{probe{event: "shmat", attach: sysCall, fn: "shmat"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "ipc", "ipc_shm"*/ }},
	ShmctlEventID:              EventConfig{ID: ShmctlEventID, ID32Bit: sys32shmctl, Name: "reserved", Probes: []probe{probe{event: "shmctl", attach: sysCall, fn: "shmctl"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "ipc", "ipc_shm"*/ }},
	DupEventID:                 EventConfig{ID: DupEventID, ID32Bit: sys32dup, Name: "dup", Probes: []probe{probe{event: "dup", attach: sysCall, fn: "dup"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_fd_ops"}},
	Dup2EventID:                EventConfig{ID: Dup2EventID, ID32Bit: sys32dup2, Name: "dup2", Probes: []probe{probe{event: "dup2", attach: sysCall, fn: "dup2"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_fd_ops"}},
	PauseEventID:               EventConfig{ID: PauseEventID, ID32Bit: sys32pause, Name: "reserved", Probes: []probe{probe{event: "pause", attach: sysCall, fn: "pause"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "signals"*/ }},
	NanosleepEventID:           EventConfig{ID: NanosleepEventID, ID32Bit: sys32nanosleep, Name: "reserved", Probes: []probe{probe{event: "nanosleep", attach: sysCall, fn: "nanosleep"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "time", "time_timer"*/ }},
	GetitimerEventID:           EventConfig{ID: GetitimerEventID, ID32Bit: sys32getitimer, Name: "reserved", Probes: []probe{probe{event: "getitimer", attach: sysCall, fn: "getitimer"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "time", "time_timer"*/ }},
	AlarmEventID:               EventConfig{ID: AlarmEventID, ID32Bit: sys32alarm, Name: "reserved", Probes: []probe{probe{event: "alarm", attach: sysCall, fn: "alarm"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "time", "time_timer"*/ }},
	SetitimerEventID:           EventConfig{ID: SetitimerEventID, ID32Bit: sys32setitimer, Name: "reserved", Probes: []probe{probe{event: "setitimer", attach: sysCall, fn: "setitimer"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "time", "time_timer"*/ }},
	GetpidEventID:              EventConfig{ID: GetpidEventID, ID32Bit: sys32getpid, Name: "getpid", Probes: []probe{probe{event: "getpid", attach: sysCall, fn: "getpid"}}, EssentialEvent: false, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SendfileEventID:            EventConfig{ID: SendfileEventID, ID32Bit: sys32sendfile, Name: "reserved", Probes: []probe{probe{event: "sendfile", attach: sysCall, fn: "sendfile"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_read_write"*/ }},
	SocketEventID:              EventConfig{ID: SocketEventID, ID32Bit: sys32socket, Name: "socket", Probes: []probe{probe{event: "socket", attach: sysCall, fn: "socket"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	ConnectEventID:             EventConfig{ID: ConnectEventID, ID32Bit: sys32connect, Name: "connect", Probes: []probe{probe{event: "connect", attach: sysCall, fn: "connect"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	AcceptEventID:              EventConfig{ID: AcceptEventID, ID32Bit: sys32undefined, Name: "accept", Probes: []probe{probe{event: "accept", attach: sysCall, fn: "accept"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	SendtoEventID:              EventConfig{ID: SendtoEventID, ID32Bit: sys32sendto, Name: "sendto", Probes: []probe{probe{event: "sendto", attach: sysCall, fn: "sendto"}}, EssentialEvent: false, Sets: []string{"syscalls", "net", "net_snd_rcv"}},
	RecvfromEventID:            EventConfig{ID: RecvfromEventID, ID32Bit: sys32recvfrom, Name: "recvfrom", Probes: []probe{probe{event: "recvfrom", attach: sysCall, fn: "recvfrom"}}, EssentialEvent: false, Sets: []string{"syscalls", "net", "net_snd_rcv"}},
	SendmsgEventID:             EventConfig{ID: SendmsgEventID, ID32Bit: sys32sendmsg, Name: "reserved", Probes: []probe{probe{event: "sendmsg", attach: sysCall, fn: "sendmsg"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "net", "net_snd_rcv"*/ }},
	RecvmsgEventID:             EventConfig{ID: RecvmsgEventID, ID32Bit: sys32recvmsg, Name: "reserved", Probes: []probe{probe{event: "recvmsg", attach: sysCall, fn: "recvmsg"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "net", "net_snd_rcv"*/ }},
	ShutdownEventID:            EventConfig{ID: ShutdownEventID, ID32Bit: sys32shutdown, Name: "reserved", Probes: []probe{probe{event: "shutdown", attach: sysCall, fn: "shutdown"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "net", "net_sock"*/ }},
	BindEventID:                EventConfig{ID: BindEventID, ID32Bit: sys32bind, Name: "bind", Probes: []probe{probe{event: "bind", attach: sysCall, fn: "bind"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	ListenEventID:              EventConfig{ID: ListenEventID, ID32Bit: sys32listen, Name: "listen", Probes: []probe{probe{event: "listen", attach: sysCall, fn: "listen"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	GetsocknameEventID:         EventConfig{ID: GetsocknameEventID, ID32Bit: sys32getsockname, Name: "getsockname", Probes: []probe{probe{event: "getsockname", attach: sysCall, fn: "getsockname"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	GetpeernameEventID:         EventConfig{ID: GetpeernameEventID, ID32Bit: sys32getpeername, Name: "reserved", Probes: []probe{probe{event: "getpeername", attach: sysCall, fn: "getpeername"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "net", "net_sock"*/ }},
	SocketpairEventID:          EventConfig{ID: SocketpairEventID, ID32Bit: sys32socketpair, Name: "reserved", Probes: []probe{probe{event: "socketpair", attach: sysCall, fn: "socketpair"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "net", "net_sock"*/ }},
	SetsockoptEventID:          EventConfig{ID: SetsockoptEventID, ID32Bit: sys32setsockopt, Name: "reserved", Probes: []probe{probe{event: "setsockopt", attach: sysCall, fn: "setsockopt"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "net", "net_sock"*/ }},
	GetsockoptEventID:          EventConfig{ID: GetsockoptEventID, ID32Bit: sys32getsockopt, Name: "reserved", Probes: []probe{probe{event: "getsockopt", attach: sysCall, fn: "getsockopt"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "net", "net_sock"*/ }},
	CloneEventID:               EventConfig{ID: CloneEventID, ID32Bit: sys32clone, Name: "clone", Probes: []probe{probe{event: "clone", attach: sysCall, fn: "clone"}}, EssentialEvent: true, Sets: []string{"default", "syscalls", "proc", "proc_life"}},
	ForkEventID:                EventConfig{ID: ForkEventID, ID32Bit: sys32fork, Name: "fork", Probes: []probe{probe{event: "fork", attach: sysCall, fn: "fork"}}, EssentialEvent: true, Sets: []string{"default", "syscalls", "proc", "proc_life"}},
	VforkEventID:               EventConfig{ID: VforkEventID, ID32Bit: sys32vfork, Name: "vfork", Probes: []probe{probe{event: "vfork", attach: sysCall, fn: "vfork"}}, EssentialEvent: true, Sets: []string{"default", "syscalls", "proc", "proc_life"}},
	ExecveEventID:              EventConfig{ID: ExecveEventID, ID32Bit: sys32execve, Name: "execve", Probes: []probe{probe{event: "execve", attach: sysCall, fn: "execve"}}, EssentialEvent: true, Sets: []string{"default", "syscalls", "proc", "proc_life"}},
	ExitEventID:                EventConfig{ID: ExitEventID, ID32Bit: sys32exit, Name: "reserved", Probes: []probe{probe{event: "exit", attach: sysCall, fn: "exit"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_life"*/ }},
	Wait4EventID:               EventConfig{ID: Wait4EventID, ID32Bit: sys32wait4, Name: "reserved", Probes: []probe{probe{event: "wait4", attach: sysCall, fn: "wait4"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_life"*/ }},
	KillEventID:                EventConfig{ID: KillEventID, ID32Bit: sys32kill, Name: "kill", Probes: []probe{probe{event: "kill", attach: sysCall, fn: "kill"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "signals"}},
	UnameEventID:               EventConfig{ID: UnameEventID, ID32Bit: sys32uname, Name: "reserved", Probes: []probe{probe{event: "uname", attach: sysCall, fn: "uname"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system"*/ }},
	SemgetEventID:              EventConfig{ID: SemgetEventID, ID32Bit: sys32semget, Name: "reserved", Probes: []probe{probe{event: "semget", attach: sysCall, fn: "semget"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "ipc", "ipc_sem"*/ }},
	SemopEventID:               EventConfig{ID: SemopEventID, ID32Bit: sys32undefined, Name: "reserved", Probes: []probe{probe{event: "semop", attach: sysCall, fn: "semop"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "ipc", "ipc_sem"*/ }},
	SemctlEventID:              EventConfig{ID: SemctlEventID, ID32Bit: sys32semctl, Name: "reserved", Probes: []probe{probe{event: "semctl", attach: sysCall, fn: "semctl"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "ipc", "ipc_sem"*/ }},
	ShmdtEventID:               EventConfig{ID: ShmdtEventID, ID32Bit: sys32shmdt, Name: "reserved", Probes: []probe{probe{event: "shmdt", attach: sysCall, fn: "shmdt"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "ipc", "ipc_shm"*/ }},
	MsggetEventID:              EventConfig{ID: MsggetEventID, ID32Bit: sys32msgget, Name: "reserved", Probes: []probe{probe{event: "msgget", attach: sysCall, fn: "msgget"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "ipc", "ipc_msgq"*/ }},
	MsgsndEventID:              EventConfig{ID: MsgsndEventID, ID32Bit: sys32msgsnd, Name: "reserved", Probes: []probe{probe{event: "msgsnd", attach: sysCall, fn: "msgsnd"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "ipc", "ipc_msgq"*/ }},
	MsgrcvEventID:              EventConfig{ID: MsgrcvEventID, ID32Bit: sys32msgrcv, Name: "reserved", Probes: []probe{probe{event: "msgrcv", attach: sysCall, fn: "msgrcv"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "ipc", "ipc_msgq"*/ }},
	MsgctlEventID:              EventConfig{ID: MsgctlEventID, ID32Bit: sys32msgctl, Name: "reserved", Probes: []probe{probe{event: "msgctl", attach: sysCall, fn: "msgctl"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "ipc", "ipc_msgq"*/ }},
	FcntlEventID:               EventConfig{ID: FcntlEventID, ID32Bit: sys32fcntl, Name: "reserved", Probes: []probe{probe{event: "fcntl", attach: sysCall, fn: "fcntl"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_fd_ops"*/ }},
	FlockEventID:               EventConfig{ID: FlockEventID, ID32Bit: sys32flock, Name: "reserved", Probes: []probe{probe{event: "flock", attach: sysCall, fn: "flock"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_fd_ops"*/ }},
	FsyncEventID:               EventConfig{ID: FsyncEventID, ID32Bit: sys32fsync, Name: "reserved", Probes: []probe{probe{event: "fsync", attach: sysCall, fn: "fsync"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_sync"*/ }},
	FdatasyncEventID:           EventConfig{ID: FdatasyncEventID, ID32Bit: sys32fdatasync, Name: "reserved", Probes: []probe{probe{event: "fdatasync", attach: sysCall, fn: "fdatasync"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_sync"*/ }},
	TruncateEventID:            EventConfig{ID: TruncateEventID, ID32Bit: sys32truncate, Name: "reserved", Probes: []probe{probe{event: "truncate", attach: sysCall, fn: "truncate"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_ops"*/ }},
	FtruncateEventID:           EventConfig{ID: FtruncateEventID, ID32Bit: sys32ftruncate, Name: "reserved", Probes: []probe{probe{event: "ftruncate", attach: sysCall, fn: "ftruncate"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_ops"*/ }},
	GetdentsEventID:            EventConfig{ID: GetdentsEventID, ID32Bit: sys32getdents, Name: "getdents", Probes: []probe{probe{event: "getdents", attach: sysCall, fn: "getdents"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_dir_ops"}},
	GetcwdEventID:              EventConfig{ID: GetcwdEventID, ID32Bit: sys32getcwd, Name: "reserved", Probes: []probe{probe{event: "getcwd", attach: sysCall, fn: "getcwd"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_dir_ops"*/ }},
	ChdirEventID:               EventConfig{ID: ChdirEventID, ID32Bit: sys32chdir, Name: "reserved", Probes: []probe{probe{event: "chdir", attach: sysCall, fn: "chdir"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_dir_ops"*/ }},
	FchdirEventID:              EventConfig{ID: FchdirEventID, ID32Bit: sys32fchdir, Name: "reserved", Probes: []probe{probe{event: "fchdir", attach: sysCall, fn: "fchdir"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_dir_ops"*/ }},
	RenameEventID:              EventConfig{ID: RenameEventID, ID32Bit: sys32rename, Name: "reserved", Probes: []probe{probe{event: "rename", attach: sysCall, fn: "rename"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_ops"*/ }},
	MkdirEventID:               EventConfig{ID: MkdirEventID, ID32Bit: sys32mkdir, Name: "reserved", Probes: []probe{probe{event: "mkdir", attach: sysCall, fn: "mkdir"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_dir_ops"*/ }},
	RmdirEventID:               EventConfig{ID: RmdirEventID, ID32Bit: sys32rmdir, Name: "reserved", Probes: []probe{probe{event: "rmdir", attach: sysCall, fn: "rmdir"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_dir_ops"*/ }},
	CreatEventID:               EventConfig{ID: CreatEventID, ID32Bit: sys32creat, Name: "creat", Probes: []probe{probe{event: "creat", attach: sysCall, fn: "creat"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	LinkEventID:                EventConfig{ID: LinkEventID, ID32Bit: sys32link, Name: "reserved", Probes: []probe{probe{event: "link", attach: sysCall, fn: "link"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_link_ops"*/ }},
	UnlinkEventID:              EventConfig{ID: UnlinkEventID, ID32Bit: sys32unlink, Name: "unlink", Probes: []probe{probe{event: "unlink", attach: sysCall, fn: "unlink"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_link_ops"}},
	SymlinkEventID:             EventConfig{ID: SymlinkEventID, ID32Bit: sys32symlink, Name: "symlink", Probes: []probe{probe{event: "symlink", attach: sysCall, fn: "symlink"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_link_ops"}},
	ReadlinkEventID:            EventConfig{ID: ReadlinkEventID, ID32Bit: sys32readlink, Name: "reserved", Probes: []probe{probe{event: "readlink", attach: sysCall, fn: "readlink"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_link_ops"*/ }},
	ChmodEventID:               EventConfig{ID: ChmodEventID, ID32Bit: sys32chmod, Name: "chmod", Probes: []probe{probe{event: "chmod", attach: sysCall, fn: "chmod"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	FchmodEventID:              EventConfig{ID: FchmodEventID, ID32Bit: sys32fchmod, Name: "fchmod", Probes: []probe{probe{event: "fchmod", attach: sysCall, fn: "fchmod"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	ChownEventID:               EventConfig{ID: ChownEventID, ID32Bit: sys32chown, Name: "chown", Probes: []probe{probe{event: "chown", attach: sysCall, fn: "chown"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	FchownEventID:              EventConfig{ID: FchownEventID, ID32Bit: sys32fchown, Name: "fchown", Probes: []probe{probe{event: "fchown", attach: sysCall, fn: "fchown"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	LchownEventID:              EventConfig{ID: LchownEventID, ID32Bit: sys32lchown, Name: "lchown", Probes: []probe{probe{event: "lchown", attach: sysCall, fn: "lchown"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	UmaskEventID:               EventConfig{ID: UmaskEventID, ID32Bit: sys32umask, Name: "reserved", Probes: []probe{probe{event: "umask", attach: sysCall, fn: "umask"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_attr"*/ }},
	GettimeofdayEventID:        EventConfig{ID: GettimeofdayEventID, ID32Bit: sys32gettimeofday, Name: "reserved", Probes: []probe{probe{event: "gettimeofday", attach: sysCall, fn: "gettimeofday"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "time", "time_tod"*/ }},
	GetrlimitEventID:           EventConfig{ID: GetrlimitEventID, ID32Bit: sys32getrlimit, Name: "reserved", Probes: []probe{probe{event: "getrlimit", attach: sysCall, fn: "getrlimit"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc"*/ }},
	GetrusageEventID:           EventConfig{ID: GetrusageEventID, ID32Bit: sys32getrusage, Name: "reserved", Probes: []probe{probe{event: "getrusage", attach: sysCall, fn: "getrusage"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc"*/ }},
	SysinfoEventID:             EventConfig{ID: SysinfoEventID, ID32Bit: sys32sysinfo, Name: "reserved", Probes: []probe{probe{event: "sysinfo", attach: sysCall, fn: "sysinfo"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system"*/ }},
	TimesEventID:               EventConfig{ID: TimesEventID, ID32Bit: sys32times, Name: "reserved", Probes: []probe{probe{event: "times", attach: sysCall, fn: "times"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc"*/ }},
	PtraceEventID:              EventConfig{ID: PtraceEventID, ID32Bit: sys32ptrace, Name: "ptrace", Probes: []probe{probe{event: "ptrace", attach: sysCall, fn: "ptrace"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "proc"}},
	GetuidEventID:              EventConfig{ID: GetuidEventID, ID32Bit: sys32getuid, Name: "reserved", Probes: []probe{probe{event: "getuid", attach: sysCall, fn: "getuid"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_ids"*/ }},
	SyslogEventID:              EventConfig{ID: SyslogEventID, ID32Bit: sys32syslog, Name: "reserved", Probes: []probe{probe{event: "syslog", attach: sysCall, fn: "syslog"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system"*/ }},
	GetgidEventID:              EventConfig{ID: GetgidEventID, ID32Bit: sys32getgid, Name: "reserved", Probes: []probe{probe{event: "getgid", attach: sysCall, fn: "getgid"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_ids"*/ }},
	SetuidEventID:              EventConfig{ID: SetuidEventID, ID32Bit: sys32setuid, Name: "setuid", Probes: []probe{probe{event: "setuid", attach: sysCall, fn: "setuid"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "proc", "proc_ids"}},
	SetgidEventID:              EventConfig{ID: SetgidEventID, ID32Bit: sys32setgid, Name: "setgid", Probes: []probe{probe{event: "setgid", attach: sysCall, fn: "setgid"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "proc", "proc_ids"}},
	GeteuidEventID:             EventConfig{ID: GeteuidEventID, ID32Bit: sys32geteuid, Name: "reserved", Probes: []probe{probe{event: "geteuid", attach: sysCall, fn: "geteuid"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_ids"*/ }},
	GetegidEventID:             EventConfig{ID: GetegidEventID, ID32Bit: sys32getegid, Name: "reserved", Probes: []probe{probe{event: "getegid", attach: sysCall, fn: "getegid"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_ids"*/ }},
	SetpgidEventID:             EventConfig{ID: SetpgidEventID, ID32Bit: sys32setpgid, Name: "reserved", Probes: []probe{probe{event: "setpgid", attach: sysCall, fn: "setpgid"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_ids"*/ }},
	GetppidEventID:             EventConfig{ID: GetppidEventID, ID32Bit: sys32getppid, Name: "getppid", Probes: []probe{probe{event: "getppid", attach: sysCall, fn: "getppid"}}, EssentialEvent: false, Sets: []string{"syscalls", "proc", "proc_ids"}},
	GetpgrpEventID:             EventConfig{ID: GetpgrpEventID, ID32Bit: sys32getpgrp, Name: "reserved", Probes: []probe{probe{event: "getpgrp", attach: sysCall, fn: "getpgrp"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_ids"*/ }},
	SetsidEventID:              EventConfig{ID: SetsidEventID, ID32Bit: sys32setsid, Name: "reserved", Probes: []probe{probe{event: "setsid", attach: sysCall, fn: "setsid"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_ids"*/ }},
	SetreuidEventID:            EventConfig{ID: SetreuidEventID, ID32Bit: sys32setreuid, Name: "setreuid", Probes: []probe{probe{event: "setreuid", attach: sysCall, fn: "setreuid"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "proc", "proc_ids"}},
	SetregidEventID:            EventConfig{ID: SetregidEventID, ID32Bit: sys32setregid, Name: "setregid", Probes: []probe{probe{event: "setregid", attach: sysCall, fn: "setregid"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "proc", "proc_ids"}},
	GetgroupsEventID:           EventConfig{ID: GetgroupsEventID, ID32Bit: sys32getgroups, Name: "reserved", Probes: []probe{probe{event: "getgroups", attach: sysCall, fn: "getgroups"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_ids"*/ }},
	SetgroupsEventID:           EventConfig{ID: SetgroupsEventID, ID32Bit: sys32setgroups, Name: "reserved", Probes: []probe{probe{event: "setgroups", attach: sysCall, fn: "setgroups"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_ids"*/ }},
	SetresuidEventID:           EventConfig{ID: SetresuidEventID, ID32Bit: sys32setresuid, Name: "reserved", Probes: []probe{probe{event: "setresuid", attach: sysCall, fn: "setresuid"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_ids"*/ }},
	GetresuidEventID:           EventConfig{ID: GetresuidEventID, ID32Bit: sys32getresuid, Name: "reserved", Probes: []probe{probe{event: "getresuid", attach: sysCall, fn: "getresuid"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_ids"*/ }},
	SetresgidEventID:           EventConfig{ID: SetresgidEventID, ID32Bit: sys32setresgid, Name: "reserved", Probes: []probe{probe{event: "setresgid", attach: sysCall, fn: "setresgid"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_ids"*/ }},
	GetresgidEventID:           EventConfig{ID: GetresgidEventID, ID32Bit: sys32getresgid, Name: "reserved", Probes: []probe{probe{event: "getresgid", attach: sysCall, fn: "getresgid"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_ids"*/ }},
	GetpgidEventID:             EventConfig{ID: GetpgidEventID, ID32Bit: sys32getpgid, Name: "reserved", Probes: []probe{probe{event: "getpgid", attach: sysCall, fn: "getpgid"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_ids"*/ }},
	SetfsuidEventID:            EventConfig{ID: SetfsuidEventID, ID32Bit: sys32setfsuid, Name: "setfsuid", Probes: []probe{probe{event: "setfsuid", attach: sysCall, fn: "setfsuid"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "proc", "proc_ids"}},
	SetfsgidEventID:            EventConfig{ID: SetfsgidEventID, ID32Bit: sys32setfsgid, Name: "setfsgid", Probes: []probe{probe{event: "setfsgid", attach: sysCall, fn: "setfsgid"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "proc", "proc_ids"}},
	GetsidEventID:              EventConfig{ID: GetsidEventID, ID32Bit: sys32getsid, Name: "reserved", Probes: []probe{probe{event: "getsid", attach: sysCall, fn: "getsid"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_ids"*/ }},
	CapgetEventID:              EventConfig{ID: CapgetEventID, ID32Bit: sys32capget, Name: "reserved", Probes: []probe{probe{event: "capget", attach: sysCall, fn: "capget"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc"*/ }},
	CapsetEventID:              EventConfig{ID: CapsetEventID, ID32Bit: sys32capset, Name: "reserved", Probes: []probe{probe{event: "capset", attach: sysCall, fn: "capset"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc"*/ }},
	RtSigpendingEventID:        EventConfig{ID: RtSigpendingEventID, ID32Bit: sys32rt_sigpending, Name: "reserved", Probes: []probe{probe{event: "rt_sigpending", attach: sysCall, fn: "rt_sigpending"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "signals"*/ }},
	RtSigtimedwaitEventID:      EventConfig{ID: RtSigtimedwaitEventID, ID32Bit: sys32rt_sigtimedwait, Name: "reserved", Probes: []probe{probe{event: "rt_sigtimedwait", attach: sysCall, fn: "rt_sigtimedwait"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "signals"*/ }},
	RtSigqueueinfoEventID:      EventConfig{ID: RtSigqueueinfoEventID, ID32Bit: sys32rt_sigqueueinfo, Name: "reserved", Probes: []probe{probe{event: "rt_sigqueueinfo", attach: sysCall, fn: "rt_sigqueueinfo"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "signals"*/ }},
	RtSigsuspendEventID:        EventConfig{ID: RtSigsuspendEventID, ID32Bit: sys32rt_sigsuspend, Name: "reserved", Probes: []probe{probe{event: "rt_sigsuspend", attach: sysCall, fn: "rt_sigsuspend"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "signals"*/ }},
	SigaltstackEventID:         EventConfig{ID: SigaltstackEventID, ID32Bit: sys32sigaltstack, Name: "reserved", Probes: []probe{probe{event: "sigaltstack", attach: sysCall, fn: "sigaltstack"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "signals"*/ }},
	UtimeEventID:               EventConfig{ID: UtimeEventID, ID32Bit: sys32utime, Name: "reserved", Probes: []probe{probe{event: "utime", attach: sysCall, fn: "utime"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_attr"*/ }},
	MknodEventID:               EventConfig{ID: MknodEventID, ID32Bit: sys32mknod, Name: "mknod", Probes: []probe{probe{event: "mknod", attach: sysCall, fn: "mknod"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	UselibEventID:              EventConfig{ID: UselibEventID, ID32Bit: sys32uselib, Name: "reserved", Probes: []probe{probe{event: "uselib", attach: sysCall, fn: "uselib"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc"*/ }},
	PersonalityEventID:         EventConfig{ID: PersonalityEventID, ID32Bit: sys32personality, Name: "reserved", Probes: []probe{probe{event: "personality", attach: sysCall, fn: "personality"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system"*/ }},
	UstatEventID:               EventConfig{ID: UstatEventID, ID32Bit: sys32ustat, Name: "reserved", Probes: []probe{probe{event: "ustat", attach: sysCall, fn: "ustat"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_info"*/ }},
	StatfsEventID:              EventConfig{ID: StatfsEventID, ID32Bit: sys32statfs, Name: "reserved", Probes: []probe{probe{event: "statfs", attach: sysCall, fn: "statfs"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_info"*/ }},
	FstatfsEventID:             EventConfig{ID: FstatfsEventID, ID32Bit: sys32fstatfs, Name: "reserved", Probes: []probe{probe{event: "fstatfs", attach: sysCall, fn: "fstatfs"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_info"*/ }},
	SysfsEventID:               EventConfig{ID: SysfsEventID, ID32Bit: sys32sysfs, Name: "reserved", Probes: []probe{probe{event: "sysfs", attach: sysCall, fn: "sysfs"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_info"*/ }},
	GetpriorityEventID:         EventConfig{ID: GetpriorityEventID, ID32Bit: sys32getpriority, Name: "reserved", Probes: []probe{probe{event: "getpriority", attach: sysCall, fn: "getpriority"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_sched"*/ }},
	SetpriorityEventID:         EventConfig{ID: SetpriorityEventID, ID32Bit: sys32setpriority, Name: "reserved", Probes: []probe{probe{event: "setpriority", attach: sysCall, fn: "setpriority"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_sched"*/ }},
	SchedSetparamEventID:       EventConfig{ID: SchedSetparamEventID, ID32Bit: sys32sched_setparam, Name: "reserved", Probes: []probe{probe{event: "sched_setparam", attach: sysCall, fn: "sched_setparam"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_sched"*/ }},
	SchedGetparamEventID:       EventConfig{ID: SchedGetparamEventID, ID32Bit: sys32sched_getparam, Name: "reserved", Probes: []probe{probe{event: "sched_getparam", attach: sysCall, fn: "sched_getparam"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_sched"*/ }},
	SchedSetschedulerEventID:   EventConfig{ID: SchedSetschedulerEventID, ID32Bit: sys32sched_setscheduler, Name: "reserved", Probes: []probe{probe{event: "sched_setscheduler", attach: sysCall, fn: "sched_setscheduler"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_sched"*/ }},
	SchedGetschedulerEventID:   EventConfig{ID: SchedGetschedulerEventID, ID32Bit: sys32sched_getscheduler, Name: "reserved", Probes: []probe{probe{event: "sched_getscheduler", attach: sysCall, fn: "sched_getscheduler"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_sched"*/ }},
	SchedGetPriorityMaxEventID: EventConfig{ID: SchedGetPriorityMaxEventID, ID32Bit: sys32sched_get_priority_max, Name: "reserved", Probes: []probe{probe{event: "sched_get_priority_max", attach: sysCall, fn: "sched_get_priority_max"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_sched"*/ }},
	SchedGetPriorityMinEventID: EventConfig{ID: SchedGetPriorityMinEventID, ID32Bit: sys32sched_get_priority_min, Name: "reserved", Probes: []probe{probe{event: "sched_get_priority_min", attach: sysCall, fn: "sched_get_priority_min"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_sched"*/ }},
	SchedRrGetIntervalEventID:  EventConfig{ID: SchedRrGetIntervalEventID, ID32Bit: sys32sched_rr_get_interval, Name: "reserved", Probes: []probe{probe{event: "sched_rr_get_interval", attach: sysCall, fn: "sched_rr_get_interval"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_sched"*/ }},
	MlockEventID:               EventConfig{ID: MlockEventID, ID32Bit: sys32mlock, Name: "reserved", Probes: []probe{probe{event: "mlock", attach: sysCall, fn: "mlock"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_mem"*/ }},
	MunlockEventID:             EventConfig{ID: MunlockEventID, ID32Bit: sys32munlock, Name: "reserved", Probes: []probe{probe{event: "munlock", attach: sysCall, fn: "munlock"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_mem"*/ }},
	MlockallEventID:            EventConfig{ID: MlockallEventID, ID32Bit: sys32mlockall, Name: "reserved", Probes: []probe{probe{event: "mlockall", attach: sysCall, fn: "mlockall"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_mem"*/ }},
	MunlockallEventID:          EventConfig{ID: MunlockallEventID, ID32Bit: sys32munlockall, Name: "reserved", Probes: []probe{probe{event: "munlockall", attach: sysCall, fn: "munlockall"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_mem"*/ }},
	VhangupEventID:             EventConfig{ID: VhangupEventID, ID32Bit: sys32vhangup, Name: "reserved", Probes: []probe{probe{event: "vhangup", attach: sysCall, fn: "vhangup"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system"*/ }},
	ModifyLdtEventID:           EventConfig{ID: ModifyLdtEventID, ID32Bit: sys32modify_ldt, Name: "reserved", Probes: []probe{probe{event: "modify_ldt", attach: sysCall, fn: "modify_ldt"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_mem"*/ }},
	PivotRootEventID:           EventConfig{ID: PivotRootEventID, ID32Bit: sys32pivot_root, Name: "reserved", Probes: []probe{probe{event: "pivot_root", attach: sysCall, fn: "pivot_root"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs"*/ }},
	SysctlEventID:              EventConfig{ID: SysctlEventID, ID32Bit: sys32undefined, Name: "reserved", Probes: []probe{probe{event: "sysctl", attach: sysCall, fn: "sysctl"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system"*/ }},
	PrctlEventID:               EventConfig{ID: PrctlEventID, ID32Bit: sys32prctl, Name: "prctl", Probes: []probe{probe{event: "prctl", attach: sysCall, fn: "prctl"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "proc"}},
	ArchPrctlEventID:           EventConfig{ID: ArchPrctlEventID, ID32Bit: sys32arch_prctl, Name: "reserved", Probes: []probe{probe{event: "arch_prctl", attach: sysCall, fn: "arch_prctl"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc"*/ }},
	AdjtimexEventID:            EventConfig{ID: AdjtimexEventID, ID32Bit: sys32adjtimex, Name: "reserved", Probes: []probe{probe{event: "adjtimex", attach: sysCall, fn: "adjtimex"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "time", "time_clock"*/ }},
	SetrlimitEventID:           EventConfig{ID: SetrlimitEventID, ID32Bit: sys32setrlimit, Name: "reserved", Probes: []probe{probe{event: "setrlimit", attach: sysCall, fn: "setrlimit"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc"*/ }},
	ChrootEventID:              EventConfig{ID: ChrootEventID, ID32Bit: sys32chroot, Name: "reserved", Probes: []probe{probe{event: "chroot", attach: sysCall, fn: "chroot"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_dir_ops"*/ }},
	SyncEventID:                EventConfig{ID: SyncEventID, ID32Bit: sys32sync, Name: "reserved", Probes: []probe{probe{event: "sync", attach: sysCall, fn: "sync"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_sync"*/ }},
	AcctEventID:                EventConfig{ID: AcctEventID, ID32Bit: sys32acct, Name: "reserved", Probes: []probe{probe{event: "acct", attach: sysCall, fn: "acct"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system"*/ }},
	SettimeofdayEventID:        EventConfig{ID: SettimeofdayEventID, ID32Bit: sys32settimeofday, Name: "reserved", Probes: []probe{probe{event: "settimeofday", attach: sysCall, fn: "settimeofday"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "time", "time_tod"*/ }},
	MountEventID:               EventConfig{ID: MountEventID, ID32Bit: sys32mount, Name: "mount", Probes: []probe{probe{event: "mount", attach: sysCall, fn: "mount"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs"}},
	UmountEventID:              EventConfig{ID: UmountEventID, ID32Bit: sys32umount, Name: "umount", Probes: []probe{probe{event: "umount", attach: sysCall, fn: "umount"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs"}},
	SwaponEventID:              EventConfig{ID: SwaponEventID, ID32Bit: sys32swapon, Name: "reserved", Probes: []probe{probe{event: "swapon", attach: sysCall, fn: "swapon"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs"*/ }},
	SwapoffEventID:             EventConfig{ID: SwapoffEventID, ID32Bit: sys32swapoff, Name: "reserved", Probes: []probe{probe{event: "swapoff", attach: sysCall, fn: "swapoff"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs"*/ }},
	RebootEventID:              EventConfig{ID: RebootEventID, ID32Bit: sys32reboot, Name: "reserved", Probes: []probe{probe{event: "reboot", attach: sysCall, fn: "reboot"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system"*/ }},
	SethostnameEventID:         EventConfig{ID: SethostnameEventID, ID32Bit: sys32sethostname, Name: "reserved", Probes: []probe{probe{event: "sethostname", attach: sysCall, fn: "sethostname"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "net"*/ }},
	SetdomainnameEventID:       EventConfig{ID: SetdomainnameEventID, ID32Bit: sys32setdomainname, Name: "reserved", Probes: []probe{probe{event: "setdomainname", attach: sysCall, fn: "setdomainname"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "net"*/ }},
	IoplEventID:                EventConfig{ID: IoplEventID, ID32Bit: sys32iopl, Name: "reserved", Probes: []probe{probe{event: "iopl", attach: sysCall, fn: "iopl"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system"*/ }},
	IopermEventID:              EventConfig{ID: IopermEventID, ID32Bit: sys32ioperm, Name: "reserved", Probes: []probe{probe{event: "ioperm", attach: sysCall, fn: "ioperm"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system"*/ }},
	CreateModuleEventID:        EventConfig{ID: CreateModuleEventID, ID32Bit: sys32create_module, Name: "reserved", Probes: []probe{probe{event: "create_module", attach: sysCall, fn: "create_module"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system", "system_module"*/ }},
	InitModuleEventID:          EventConfig{ID: InitModuleEventID, ID32Bit: sys32init_module, Name: "init_module", Probes: []probe{probe{event: "init_module", attach: sysCall, fn: "init_module"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "system", "system_module"}},
	DeleteModuleEventID:        EventConfig{ID: DeleteModuleEventID, ID32Bit: sys32delete_module, Name: "delete_module", Probes: []probe{probe{event: "delete_module", attach: sysCall, fn: "delete_module"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "system", "system_module"}},
	GetKernelSymsEventID:       EventConfig{ID: GetKernelSymsEventID, ID32Bit: sys32get_kernel_syms, Name: "reserved", Probes: []probe{probe{event: "get_kernel_syms", attach: sysCall, fn: "get_kernel_syms"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system", "system_module"*/ }},
	QueryModuleEventID:         EventConfig{ID: QueryModuleEventID, ID32Bit: sys32query_module, Name: "reserved", Probes: []probe{probe{event: "query_module", attach: sysCall, fn: "query_module"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system", "system_module"*/ }},
	QuotactlEventID:            EventConfig{ID: QuotactlEventID, ID32Bit: sys32quotactl, Name: "reserved", Probes: []probe{probe{event: "quotactl", attach: sysCall, fn: "quotactl"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system"*/ }},
	NfsservctlEventID:          EventConfig{ID: NfsservctlEventID, ID32Bit: sys32nfsservctl, Name: "reserved", Probes: []probe{probe{event: "nfsservctl", attach: sysCall, fn: "nfsservctl"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs"*/ }},
	GetpmsgEventID:             EventConfig{ID: GetpmsgEventID, ID32Bit: sys32getpmsg, Name: "reserved", Probes: []probe{probe{event: "getpmsg", attach: sysCall, fn: "getpmsg"}}, EssentialEvent: false, Sets: []string{ /*"syscalls"*/ }},
	PutpmsgEventID:             EventConfig{ID: PutpmsgEventID, ID32Bit: sys32putpmsg, Name: "reserved", Probes: []probe{probe{event: "putpmsg", attach: sysCall, fn: "putpmsg"}}, EssentialEvent: false, Sets: []string{ /*"syscalls"*/ }},
	AfsEventID:                 EventConfig{ID: AfsEventID, ID32Bit: sys32undefined, Name: "reserved", Probes: []probe{probe{event: "afs", attach: sysCall, fn: "afs"}}, EssentialEvent: false, Sets: []string{ /*"syscalls"*/ }},
	TuxcallEventID:             EventConfig{ID: TuxcallEventID, ID32Bit: sys32undefined, Name: "reserved", Probes: []probe{probe{event: "tuxcall", attach: sysCall, fn: "tuxcall"}}, EssentialEvent: false, Sets: []string{ /*"syscalls"*/ }},
	SecurityEventID:            EventConfig{ID: SecurityEventID, ID32Bit: sys32undefined, Name: "reserved", Probes: []probe{probe{event: "security", attach: sysCall, fn: "security"}}, EssentialEvent: false, Sets: []string{ /*"syscalls"*/ }},
	GettidEventID:              EventConfig{ID: GettidEventID, ID32Bit: sys32gettid, Name: "gettid", Probes: []probe{probe{event: "gettid", attach: sysCall, fn: "gettid"}}, EssentialEvent: false, Sets: []string{"syscalls", "proc", "proc_ids"}},
	ReadaheadEventID:           EventConfig{ID: ReadaheadEventID, ID32Bit: sys32readahead, Name: "reserved", Probes: []probe{probe{event: "readahead", attach: sysCall, fn: "readahead"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs"*/ }},
	SetxattrEventID:            EventConfig{ID: SetxattrEventID, ID32Bit: sys32setxattr, Name: "reserved", Probes: []probe{probe{event: "setxattr", attach: sysCall, fn: "setxattr"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_attr"*/ }},
	LsetxattrEventID:           EventConfig{ID: LsetxattrEventID, ID32Bit: sys32lsetxattr, Name: "reserved", Probes: []probe{probe{event: "lsetxattr", attach: sysCall, fn: "lsetxattr"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_attr"*/ }},
	FsetxattrEventID:           EventConfig{ID: FsetxattrEventID, ID32Bit: sys32fsetxattr, Name: "reserved", Probes: []probe{probe{event: "fsetxattr", attach: sysCall, fn: "fsetxattr"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_attr"*/ }},
	GetxattrEventID:            EventConfig{ID: GetxattrEventID, ID32Bit: sys32getxattr, Name: "reserved", Probes: []probe{probe{event: "getxattr", attach: sysCall, fn: "getxattr"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_attr"*/ }},
	LgetxattrEventID:           EventConfig{ID: LgetxattrEventID, ID32Bit: sys32lgetxattr, Name: "reserved", Probes: []probe{probe{event: "lgetxattr", attach: sysCall, fn: "lgetxattr"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_attr"*/ }},
	FgetxattrEventID:           EventConfig{ID: FgetxattrEventID, ID32Bit: sys32fgetxattr, Name: "reserved", Probes: []probe{probe{event: "fgetxattr", attach: sysCall, fn: "fgetxattr"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_attr"*/ }},
	ListxattrEventID:           EventConfig{ID: ListxattrEventID, ID32Bit: sys32listxattr, Name: "reserved", Probes: []probe{probe{event: "listxattr", attach: sysCall, fn: "listxattr"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_attr"*/ }},
	LlistxattrEventID:          EventConfig{ID: LlistxattrEventID, ID32Bit: sys32llistxattr, Name: "reserved", Probes: []probe{probe{event: "llistxattr", attach: sysCall, fn: "llistxattr"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_attr"*/ }},
	FlistxattrEventID:          EventConfig{ID: FlistxattrEventID, ID32Bit: sys32flistxattr, Name: "reserved", Probes: []probe{probe{event: "flistxattr", attach: sysCall, fn: "flistxattr"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_attr"*/ }},
	RemovexattrEventID:         EventConfig{ID: RemovexattrEventID, ID32Bit: sys32removexattr, Name: "reserved", Probes: []probe{probe{event: "removexattr", attach: sysCall, fn: "removexattr"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_attr"*/ }},
	LremovexattrEventID:        EventConfig{ID: LremovexattrEventID, ID32Bit: sys32lremovexattr, Name: "reserved", Probes: []probe{probe{event: "lremovexattr", attach: sysCall, fn: "lremovexattr"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_attr"*/ }},
	FremovexattrEventID:        EventConfig{ID: FremovexattrEventID, ID32Bit: sys32fremovexattr, Name: "reserved", Probes: []probe{probe{event: "fremovexattr", attach: sysCall, fn: "fremovexattr"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_attr"*/ }},
	TkillEventID:               EventConfig{ID: TkillEventID, ID32Bit: sys32tkill, Name: "reserved", Probes: []probe{probe{event: "tkill", attach: sysCall, fn: "tkill"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "signals"*/ }},
	TimeEventID:                EventConfig{ID: TimeEventID, ID32Bit: sys32time, Name: "reserved", Probes: []probe{probe{event: "time", attach: sysCall, fn: "time"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "time", "time_tod"*/ }},
	FutexEventID:               EventConfig{ID: FutexEventID, ID32Bit: sys32futex, Name: "reserved", Probes: []probe{probe{event: "futex", attach: sysCall, fn: "futex"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "ipc", "ipc_futex"*/ }},
	SchedSetaffinityEventID:    EventConfig{ID: SchedSetaffinityEventID, ID32Bit: sys32sched_setaffinity, Name: "reserved", Probes: []probe{probe{event: "sched_setaffinity", attach: sysCall, fn: "sched_setaffinity"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_sched"*/ }},
	SchedGetaffinityEventID:    EventConfig{ID: SchedGetaffinityEventID, ID32Bit: sys32sched_getaffinity, Name: "reserved", Probes: []probe{probe{event: "sched_getaffinity", attach: sysCall, fn: "sched_getaffinity"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_sched"*/ }},
	SetThreadAreaEventID:       EventConfig{ID: SetThreadAreaEventID, ID32Bit: sys32set_thread_area, Name: "reserved", Probes: []probe{probe{event: "set_thread_area", attach: sysCall, fn: "set_thread_area"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc"*/ }},
	IoSetupEventID:             EventConfig{ID: IoSetupEventID, ID32Bit: sys32io_setup, Name: "reserved", Probes: []probe{probe{event: "io_setup", attach: sysCall, fn: "io_setup"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_async_io"*/ }},
	IoDestroyEventID:           EventConfig{ID: IoDestroyEventID, ID32Bit: sys32io_destroy, Name: "reserved", Probes: []probe{probe{event: "io_destroy", attach: sysCall, fn: "io_destroy"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_async_io"*/ }},
	IoGeteventsEventID:         EventConfig{ID: IoGeteventsEventID, ID32Bit: sys32io_getevents, Name: "reserved", Probes: []probe{probe{event: "io_getevents", attach: sysCall, fn: "io_getevents"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_async_io"*/ }},
	IoSubmitEventID:            EventConfig{ID: IoSubmitEventID, ID32Bit: sys32io_submit, Name: "reserved", Probes: []probe{probe{event: "io_submit", attach: sysCall, fn: "io_submit"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_async_io"*/ }},
	IoCancelEventID:            EventConfig{ID: IoCancelEventID, ID32Bit: sys32io_cancel, Name: "reserved", Probes: []probe{probe{event: "io_cancel", attach: sysCall, fn: "io_cancel"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_async_io"*/ }},
	GetThreadAreaEventID:       EventConfig{ID: GetThreadAreaEventID, ID32Bit: sys32get_thread_area, Name: "reserved", Probes: []probe{probe{event: "get_thread_area", attach: sysCall, fn: "get_thread_area"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc"*/ }},
	LookupDcookieEventID:       EventConfig{ID: LookupDcookieEventID, ID32Bit: sys32lookup_dcookie, Name: "reserved", Probes: []probe{probe{event: "lookup_dcookie", attach: sysCall, fn: "lookup_dcookie"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_dir_ops"*/ }},
	EpollCreateEventID:         EventConfig{ID: EpollCreateEventID, ID32Bit: sys32epoll_create, Name: "reserved", Probes: []probe{probe{event: "epoll_create", attach: sysCall, fn: "epoll_create"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_mux_io"*/ }},
	EpollCtlOldEventID:         EventConfig{ID: EpollCtlOldEventID, ID32Bit: sys32undefined, Name: "reserved", Probes: []probe{probe{event: "epoll_ctl_old", attach: sysCall, fn: "epoll_ctl_old"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_mux_io"*/ }},
	EpollWaitOldEventID:        EventConfig{ID: EpollWaitOldEventID, ID32Bit: sys32undefined, Name: "reserved", Probes: []probe{probe{event: "epoll_wait_old", attach: sysCall, fn: "epoll_wait_old"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_mux_io"*/ }},
	RemapFilePagesEventID:      EventConfig{ID: RemapFilePagesEventID, ID32Bit: sys32remap_file_pages, Name: "reserved", Probes: []probe{probe{event: "remap_file_pages", attach: sysCall, fn: "remap_file_pages"}}, EssentialEvent: false, Sets: []string{ /*"syscalls"*/ }},
	Getdents64EventID:          EventConfig{ID: Getdents64EventID, ID32Bit: sys32getdents64, Name: "getdents64", Probes: []probe{probe{event: "getdents64", attach: sysCall, fn: "getdents64"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_dir_ops"}},
	SetTidAddressEventID:       EventConfig{ID: SetTidAddressEventID, ID32Bit: sys32set_tid_address, Name: "reserved", Probes: []probe{probe{event: "set_tid_address", attach: sysCall, fn: "set_tid_address"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc"*/ }},
	RestartSyscallEventID:      EventConfig{ID: RestartSyscallEventID, ID32Bit: sys32restart_syscall, Name: "reserved", Probes: []probe{probe{event: "restart_syscall", attach: sysCall, fn: "restart_syscall"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "signals"*/ }},
	SemtimedopEventID:          EventConfig{ID: SemtimedopEventID, ID32Bit: sys32semtimedop_time64, Name: "reserved", Probes: []probe{probe{event: "semtimedop", attach: sysCall, fn: "semtimedop"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "ipc", "ipc_sem"*/ }},
	Fadvise64EventID:           EventConfig{ID: Fadvise64EventID, ID32Bit: sys32fadvise64, Name: "reserved", Probes: []probe{probe{event: "fadvise64", attach: sysCall, fn: "fadvise64"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs"*/ }},
	TimerCreateEventID:         EventConfig{ID: TimerCreateEventID, ID32Bit: sys32timer_create, Name: "reserved", Probes: []probe{probe{event: "timer_create", attach: sysCall, fn: "timer_create"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "time", "time_timer"*/ }},
	TimerSettimeEventID:        EventConfig{ID: TimerSettimeEventID, ID32Bit: sys32timer_settime, Name: "reserved", Probes: []probe{probe{event: "timer_settime", attach: sysCall, fn: "timer_settime"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "time", "time_timer"*/ }},
	TimerGettimeEventID:        EventConfig{ID: TimerGettimeEventID, ID32Bit: sys32timer_gettime, Name: "reserved", Probes: []probe{probe{event: "timer_gettime", attach: sysCall, fn: "timer_gettime"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "time", "time_timer"*/ }},
	TimerGetoverrunEventID:     EventConfig{ID: TimerGetoverrunEventID, ID32Bit: sys32timer_getoverrun, Name: "reserved", Probes: []probe{probe{event: "timer_getoverrun", attach: sysCall, fn: "timer_getoverrun"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "time", "time_timer"*/ }},
	TimerDeleteEventID:         EventConfig{ID: TimerDeleteEventID, ID32Bit: sys32timer_delete, Name: "reserved", Probes: []probe{probe{event: "timer_delete", attach: sysCall, fn: "timer_delete"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "time", "time_timer"*/ }},
	ClockSettimeEventID:        EventConfig{ID: ClockSettimeEventID, ID32Bit: sys32clock_settime, Name: "reserved", Probes: []probe{probe{event: "clock_settime", attach: sysCall, fn: "clock_settime"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "time", "time_clock"*/ }},
	ClockGettimeEventID:        EventConfig{ID: ClockGettimeEventID, ID32Bit: sys32clock_gettime, Name: "reserved", Probes: []probe{probe{event: "clock_gettime", attach: sysCall, fn: "clock_gettime"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "time", "time_clock"*/ }},
	ClockGetresEventID:         EventConfig{ID: ClockGetresEventID, ID32Bit: sys32clock_getres, Name: "reserved", Probes: []probe{probe{event: "clock_getres", attach: sysCall, fn: "clock_getres"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "time", "time_clock"*/ }},
	ClockNanosleepEventID:      EventConfig{ID: ClockNanosleepEventID, ID32Bit: sys32clock_nanosleep, Name: "reserved", Probes: []probe{probe{event: "clock_nanosleep", attach: sysCall, fn: "clock_nanosleep"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "time", "time_clock"*/ }},
	ExitGroupEventID:           EventConfig{ID: ExitGroupEventID, ID32Bit: sys32exit_group, Name: "reserved", Probes: []probe{probe{event: "exit_group", attach: sysCall, fn: "exit_group"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_life"*/ }},
	EpollWaitEventID:           EventConfig{ID: EpollWaitEventID, ID32Bit: sys32epoll_wait, Name: "reserved", Probes: []probe{probe{event: "epoll_wait", attach: sysCall, fn: "epoll_wait"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_mux_io"*/ }},
	EpollCtlEventID:            EventConfig{ID: EpollCtlEventID, ID32Bit: sys32epoll_ctl, Name: "reserved", Probes: []probe{probe{event: "epoll_ctl", attach: sysCall, fn: "epoll_ctl"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_mux_io"*/ }},
	TgkillEventID:              EventConfig{ID: TgkillEventID, ID32Bit: sys32tgkill, Name: "reserved", Probes: []probe{probe{event: "tgkill", attach: sysCall, fn: "tgkill"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "signals"*/ }},
	UtimesEventID:              EventConfig{ID: UtimesEventID, ID32Bit: sys32utimes, Name: "reserved", Probes: []probe{probe{event: "utimes", attach: sysCall, fn: "utimes"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_attr"*/ }},
	VserverEventID:             EventConfig{ID: VserverEventID, ID32Bit: sys32vserver, Name: "reserved", Probes: []probe{probe{event: "vserver", attach: sysCall, fn: "vserver"}}, EssentialEvent: false, Sets: []string{ /*"syscalls"*/ }},
	MbindEventID:               EventConfig{ID: MbindEventID, ID32Bit: sys32mbind, Name: "reserved", Probes: []probe{probe{event: "mbind", attach: sysCall, fn: "mbind"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system", "system_numa"*/ }},
	SetMempolicyEventID:        EventConfig{ID: SetMempolicyEventID, ID32Bit: sys32set_mempolicy, Name: "reserved", Probes: []probe{probe{event: "set_mempolicy", attach: sysCall, fn: "set_mempolicy"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system", "system_numa"*/ }},
	GetMempolicyEventID:        EventConfig{ID: GetMempolicyEventID, ID32Bit: sys32get_mempolicy, Name: "reserved", Probes: []probe{probe{event: "get_mempolicy", attach: sysCall, fn: "get_mempolicy"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system", "system_numa"*/ }},
	MqOpenEventID:              EventConfig{ID: MqOpenEventID, ID32Bit: sys32mq_open, Name: "reserved", Probes: []probe{probe{event: "mq_open", attach: sysCall, fn: "mq_open"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "ipc", "ipc_msgq"*/ }},
	MqUnlinkEventID:            EventConfig{ID: MqUnlinkEventID, ID32Bit: sys32mq_unlink, Name: "reserved", Probes: []probe{probe{event: "mq_unlink", attach: sysCall, fn: "mq_unlink"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "ipc", "ipc_msgq"*/ }},
	MqTimedsendEventID:         EventConfig{ID: MqTimedsendEventID, ID32Bit: sys32mq_timedsend, Name: "reserved", Probes: []probe{probe{event: "mq_timedsend", attach: sysCall, fn: "mq_timedsend"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "ipc", "ipc_msgq"*/ }},
	MqTimedreceiveEventID:      EventConfig{ID: MqTimedreceiveEventID, ID32Bit: sys32mq_timedreceive, Name: "reserved", Probes: []probe{probe{event: "mq_timedreceive", attach: sysCall, fn: "mq_timedreceive"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "ipc", "ipc_msgq"*/ }},
	MqNotifyEventID:            EventConfig{ID: MqNotifyEventID, ID32Bit: sys32mq_notify, Name: "reserved", Probes: []probe{probe{event: "mq_notify", attach: sysCall, fn: "mq_notify"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "ipc", "ipc_msgq"*/ }},
	MqGetsetattrEventID:        EventConfig{ID: MqGetsetattrEventID, ID32Bit: sys32mq_getsetattr, Name: "reserved", Probes: []probe{probe{event: "mq_getsetattr", attach: sysCall, fn: "mq_getsetattr"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "ipc", "ipc_msgq"*/ }},
	KexecLoadEventID:           EventConfig{ID: KexecLoadEventID, ID32Bit: sys32kexec_load, Name: "reserved", Probes: []probe{probe{event: "kexec_load", attach: sysCall, fn: "kexec_load"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system"*/ }},
	WaitidEventID:              EventConfig{ID: WaitidEventID, ID32Bit: sys32waitid, Name: "reserved", Probes: []probe{probe{event: "waitid", attach: sysCall, fn: "waitid"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_life"*/ }},
	AddKeyEventID:              EventConfig{ID: AddKeyEventID, ID32Bit: sys32add_key, Name: "reserved", Probes: []probe{probe{event: "add_key", attach: sysCall, fn: "add_key"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system", "system_keys"*/ }},
	RequestKeyEventID:          EventConfig{ID: RequestKeyEventID, ID32Bit: sys32request_key, Name: "reserved", Probes: []probe{probe{event: "request_key", attach: sysCall, fn: "request_key"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system", "system_keys"*/ }},
	KeyctlEventID:              EventConfig{ID: KeyctlEventID, ID32Bit: sys32keyctl, Name: "reserved", Probes: []probe{probe{event: "keyctl", attach: sysCall, fn: "keyctl"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system", "system_keys"*/ }},
	IoprioSetEventID:           EventConfig{ID: IoprioSetEventID, ID32Bit: sys32ioprio_set, Name: "reserved", Probes: []probe{probe{event: "ioprio_set", attach: sysCall, fn: "ioprio_set"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_sched"*/ }},
	IoprioGetEventID:           EventConfig{ID: IoprioGetEventID, ID32Bit: sys32ioprio_get, Name: "reserved", Probes: []probe{probe{event: "ioprio_get", attach: sysCall, fn: "ioprio_get"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_sched"*/ }},
	InotifyInitEventID:         EventConfig{ID: InotifyInitEventID, ID32Bit: sys32inotify_init, Name: "reserved", Probes: []probe{probe{event: "inotify_init", attach: sysCall, fn: "inotify_init"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_monitor"*/ }},
	InotifyAddWatchEventID:     EventConfig{ID: InotifyAddWatchEventID, ID32Bit: sys32inotify_add_watch, Name: "reserved", Probes: []probe{probe{event: "inotify_add_watch", attach: sysCall, fn: "inotify_add_watch"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_monitor"*/ }},
	InotifyRmWatchEventID:      EventConfig{ID: InotifyRmWatchEventID, ID32Bit: sys32inotify_rm_watch, Name: "reserved", Probes: []probe{probe{event: "inotify_rm_watch", attach: sysCall, fn: "inotify_rm_watch"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_monitor"*/ }},
	MigratePagesEventID:        EventConfig{ID: MigratePagesEventID, ID32Bit: sys32migrate_pages, Name: "reserved", Probes: []probe{probe{event: "migrate_pages", attach: sysCall, fn: "migrate_pages"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system", "system_numa"*/ }},
	OpenatEventID:              EventConfig{ID: OpenatEventID, ID32Bit: sys32openat, Name: "openat", Probes: []probe{probe{event: "openat", attach: sysCall, fn: "openat"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	MkdiratEventID:             EventConfig{ID: MkdiratEventID, ID32Bit: sys32mkdirat, Name: "reserved", Probes: []probe{probe{event: "mkdirat", attach: sysCall, fn: "mkdirat"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_dir_ops"*/ }},
	MknodatEventID:             EventConfig{ID: MknodatEventID, ID32Bit: sys32mknodat, Name: "mknodat", Probes: []probe{probe{event: "mknodat", attach: sysCall, fn: "mknodat"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	FchownatEventID:            EventConfig{ID: FchownatEventID, ID32Bit: sys32fchownat, Name: "fchownat", Probes: []probe{probe{event: "fchownat", attach: sysCall, fn: "fchownat"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	FutimesatEventID:           EventConfig{ID: FutimesatEventID, ID32Bit: sys32futimesat, Name: "reserved", Probes: []probe{probe{event: "futimesat", attach: sysCall, fn: "futimesat"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_attr"*/ }},
	NewfstatatEventID:          EventConfig{ID: NewfstatatEventID, ID32Bit: sys32fstatat64, Name: "reserved", Probes: []probe{probe{event: "newfstatat", attach: sysCall, fn: "newfstatat"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_attr"*/ }},
	UnlinkatEventID:            EventConfig{ID: UnlinkatEventID, ID32Bit: sys32unlinkat, Name: "unlinkat", Probes: []probe{probe{event: "unlinkat", attach: sysCall, fn: "unlinkat"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_link_ops"}},
	RenameatEventID:            EventConfig{ID: RenameatEventID, ID32Bit: sys32renameat, Name: "reserved", Probes: []probe{probe{event: "renameat", attach: sysCall, fn: "renameat"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_ops"*/ }},
	LinkatEventID:              EventConfig{ID: LinkatEventID, ID32Bit: sys32linkat, Name: "reserved", Probes: []probe{probe{event: "linkat", attach: sysCall, fn: "linkat"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_link_ops"*/ }},
	SymlinkatEventID:           EventConfig{ID: SymlinkatEventID, ID32Bit: sys32symlinkat, Name: "symlinkat", Probes: []probe{probe{event: "symlinkat", attach: sysCall, fn: "symlinkat"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_link_ops"}},
	ReadlinkatEventID:          EventConfig{ID: ReadlinkatEventID, ID32Bit: sys32readlinkat, Name: "reserved", Probes: []probe{probe{event: "readlinkat", attach: sysCall, fn: "readlinkat"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_link_ops"*/ }},
	FchmodatEventID:            EventConfig{ID: FchmodatEventID, ID32Bit: sys32fchmodat, Name: "fchmodat", Probes: []probe{probe{event: "fchmodat", attach: sysCall, fn: "fchmodat"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	FaccessatEventID:           EventConfig{ID: FaccessatEventID, ID32Bit: sys32faccessat, Name: "faccessat", Probes: []probe{probe{event: "faccessat", attach: sysCall, fn: "faccessat"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	Pselect6EventID:            EventConfig{ID: Pselect6EventID, ID32Bit: sys32pselect6, Name: "reserved", Probes: []probe{probe{event: "pselect6", attach: sysCall, fn: "pselect6"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_mux_io"*/ }},
	PpollEventID:               EventConfig{ID: PpollEventID, ID32Bit: sys32ppoll, Name: "reserved", Probes: []probe{probe{event: "ppoll", attach: sysCall, fn: "ppoll"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_mux_io"*/ }},
	UnshareEventID:             EventConfig{ID: UnshareEventID, ID32Bit: sys32unshare, Name: "reserved", Probes: []probe{probe{event: "unshare", attach: sysCall, fn: "unshare"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc"*/ }},
	SetRobustListEventID:       EventConfig{ID: SetRobustListEventID, ID32Bit: sys32set_robust_list, Name: "reserved", Probes: []probe{probe{event: "set_robust_list", attach: sysCall, fn: "set_robust_list"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "ipc", "ipc_futex"*/ }},
	GetRobustListEventID:       EventConfig{ID: GetRobustListEventID, ID32Bit: sys32get_robust_list, Name: "reserved", Probes: []probe{probe{event: "get_robust_list", attach: sysCall, fn: "get_robust_list"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "ipc", "ipc_futex"*/ }},
	SpliceEventID:              EventConfig{ID: SpliceEventID, ID32Bit: sys32splice, Name: "reserved", Probes: []probe{probe{event: "splice", attach: sysCall, fn: "splice"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "ipc", "ipc_pipe"*/ }},
	TeeEventID:                 EventConfig{ID: TeeEventID, ID32Bit: sys32tee, Name: "reserved", Probes: []probe{probe{event: "tee", attach: sysCall, fn: "tee"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "ipc", "ipc_pipe"*/ }},
	SyncFileRangeEventID:       EventConfig{ID: SyncFileRangeEventID, ID32Bit: sys32sync_file_range, Name: "reserved", Probes: []probe{probe{event: "sync_file_range", attach: sysCall, fn: "sync_file_range"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_sync"*/ }},
	VmspliceEventID:            EventConfig{ID: VmspliceEventID, ID32Bit: sys32vmsplice, Name: "reserved", Probes: []probe{probe{event: "vmsplice", attach: sysCall, fn: "vmsplice"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "ipc", "ipc_pipe"*/ }},
	MovePagesEventID:           EventConfig{ID: MovePagesEventID, ID32Bit: sys32move_pages, Name: "reserved", Probes: []probe{probe{event: "move_pages", attach: sysCall, fn: "move_pages"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system", "system_numa"*/ }},
	UtimensatEventID:           EventConfig{ID: UtimensatEventID, ID32Bit: sys32utimensat, Name: "reserved", Probes: []probe{probe{event: "utimensat", attach: sysCall, fn: "utimensat"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_attr"*/ }},
	EpollPwaitEventID:          EventConfig{ID: EpollPwaitEventID, ID32Bit: sys32epoll_pwait, Name: "reserved", Probes: []probe{probe{event: "epoll_pwait", attach: sysCall, fn: "epoll_pwait"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_mux_io"*/ }},
	SignalfdEventID:            EventConfig{ID: SignalfdEventID, ID32Bit: sys32signalfd, Name: "reserved", Probes: []probe{probe{event: "signalfd", attach: sysCall, fn: "signalfd"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "signals"*/ }},
	TimerfdCreateEventID:       EventConfig{ID: TimerfdCreateEventID, ID32Bit: sys32timerfd_create, Name: "reserved", Probes: []probe{probe{event: "timerfd_create", attach: sysCall, fn: "timerfd_create"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "time", "time_timer"*/ }},
	EventfdEventID:             EventConfig{ID: EventfdEventID, ID32Bit: sys32eventfd, Name: "reserved", Probes: []probe{probe{event: "eventfd", attach: sysCall, fn: "eventfd"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "signals"*/ }},
	FallocateEventID:           EventConfig{ID: FallocateEventID, ID32Bit: sys32fallocate, Name: "reserved", Probes: []probe{probe{event: "fallocate", attach: sysCall, fn: "fallocate"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_ops"*/ }},
	TimerfdSettimeEventID:      EventConfig{ID: TimerfdSettimeEventID, ID32Bit: sys32timerfd_settime, Name: "reserved", Probes: []probe{probe{event: "timerfd_settime", attach: sysCall, fn: "timerfd_settime"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "time", "time_timer"*/ }},
	TimerfdGettimeEventID:      EventConfig{ID: TimerfdGettimeEventID, ID32Bit: sys32timerfd_gettime, Name: "reserved", Probes: []probe{probe{event: "timerfd_gettime", attach: sysCall, fn: "timerfd_gettime"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "time", "time_timer"*/ }},
	Accept4EventID:             EventConfig{ID: Accept4EventID, ID32Bit: sys32accept4, Name: "accept4", Probes: []probe{probe{event: "accept4", attach: sysCall, fn: "accept4"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	Signalfd4EventID:           EventConfig{ID: Signalfd4EventID, ID32Bit: sys32signalfd4, Name: "reserved", Probes: []probe{probe{event: "signalfd4", attach: sysCall, fn: "signalfd4"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "signals"*/ }},
	Eventfd2EventID:            EventConfig{ID: Eventfd2EventID, ID32Bit: sys32eventfd2, Name: "reserved", Probes: []probe{probe{event: "eventfd2", attach: sysCall, fn: "eventfd2"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "signals"*/ }},
	EpollCreate1EventID:        EventConfig{ID: EpollCreate1EventID, ID32Bit: sys32epoll_create1, Name: "reserved", Probes: []probe{probe{event: "epoll_create1", attach: sysCall, fn: "epoll_create1"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_mux_io"*/ }},
	Dup3EventID:                EventConfig{ID: Dup3EventID, ID32Bit: sys32dup3, Name: "dup3", Probes: []probe{probe{event: "dup3", attach: sysCall, fn: "dup3"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_fd_ops"}},
	Pipe2EventID:               EventConfig{ID: Pipe2EventID, ID32Bit: sys32pipe2, Name: "reserved", Probes: []probe{probe{event: "pipe2", attach: sysCall, fn: "pipe2"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "ipc", "ipc_pipe"*/ }},
	InotifyInit1EventID:        EventConfig{ID: InotifyInit1EventID, ID32Bit: sys32inotify_init1, Name: "reserved", Probes: []probe{probe{event: "inotify_init1", attach: sysCall, fn: "inotify_init1"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_monitor"*/ }},
	PreadvEventID:              EventConfig{ID: PreadvEventID, ID32Bit: sys32preadv, Name: "reserved", Probes: []probe{probe{event: "preadv", attach: sysCall, fn: "preadv"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_read_write"*/ }},
	PwritevEventID:             EventConfig{ID: PwritevEventID, ID32Bit: sys32pwritev, Name: "reserved", Probes: []probe{probe{event: "pwritev", attach: sysCall, fn: "pwritev"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_read_write"*/ }},
	RtTgsigqueueinfoEventID:    EventConfig{ID: RtTgsigqueueinfoEventID, ID32Bit: sys32rt_tgsigqueueinfo, Name: "reserved", Probes: []probe{probe{event: "rt_tgsigqueueinfo", attach: sysCall, fn: "rt_tgsigqueueinfo"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "signals"*/ }},
	PerfEventOpenEventID:       EventConfig{ID: PerfEventOpenEventID, ID32Bit: sys32perf_event_open, Name: "reserved", Probes: []probe{probe{event: "perf_event_open", attach: sysCall, fn: "perf_event_open"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system"*/ }},
	RecvmmsgEventID:            EventConfig{ID: RecvmmsgEventID, ID32Bit: sys32recvmmsg, Name: "reserved", Probes: []probe{probe{event: "recvmmsg", attach: sysCall, fn: "recvmmsg"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "net", "net_snd_rcv"*/ }},
	FanotifyInitEventID:        EventConfig{ID: FanotifyInitEventID, ID32Bit: sys32fanotify_init, Name: "reserved", Probes: []probe{probe{event: "fanotify_init", attach: sysCall, fn: "fanotify_init"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_monitor"*/ }},
	FanotifyMarkEventID:        EventConfig{ID: FanotifyMarkEventID, ID32Bit: sys32fanotify_mark, Name: "reserved", Probes: []probe{probe{event: "fanotify_mark", attach: sysCall, fn: "fanotify_mark"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_monitor"*/ }},
	Prlimit64EventID:           EventConfig{ID: Prlimit64EventID, ID32Bit: sys32prlimit64, Name: "reserved", Probes: []probe{probe{event: "prlimit64", attach: sysCall, fn: "prlimit64"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc"*/ }},
	NameTohandleAtEventID:      EventConfig{ID: NameTohandleAtEventID, ID32Bit: sys32name_to_handle_at, Name: "reserved", Probes: []probe{probe{event: "name_to_handle_at", attach: sysCall, fn: "name_to_handle_at"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_ops"*/ }},
	OpenByHandleAtEventID:      EventConfig{ID: OpenByHandleAtEventID, ID32Bit: sys32open_by_handle_at, Name: "reserved", Probes: []probe{probe{event: "open_by_handle_at", attach: sysCall, fn: "open_by_handle_at"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_ops"*/ }},
	ClockAdjtimeEventID:        EventConfig{ID: ClockAdjtimeEventID, ID32Bit: sys32clock_adjtime, Name: "reserved", Probes: []probe{probe{event: "clock_adjtime", attach: sysCall, fn: "clock_adjtime"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "time", "time_clock"*/ }},
	SyncfsEventID:              EventConfig{ID: SyncfsEventID, ID32Bit: sys32syncfs, Name: "reserved", Probes: []probe{probe{event: "syncfs", attach: sysCall, fn: "syncfs"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_sync"*/ }},
	SendmmsgEventID:            EventConfig{ID: SendmmsgEventID, ID32Bit: sys32sendmmsg, Name: "reserved", Probes: []probe{probe{event: "sendmmsg", attach: sysCall, fn: "sendmmsg"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "net", "net_snd_rcv"*/ }},
	SetnsEventID:               EventConfig{ID: SetnsEventID, ID32Bit: sys32setns, Name: "reserved", Probes: []probe{probe{event: "setns", attach: sysCall, fn: "setns"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc"*/ }},
	GetcpuEventID:              EventConfig{ID: GetcpuEventID, ID32Bit: sys32getcpu, Name: "reserved", Probes: []probe{probe{event: "getcpu", attach: sysCall, fn: "getcpu"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system", "system_numa"*/ }},
	ProcessVmReadvEventID:      EventConfig{ID: ProcessVmReadvEventID, ID32Bit: sys32process_vm_readv, Name: "process_vm_readv", Probes: []probe{probe{event: "process_vm_readv", attach: sysCall, fn: "process_vm_readv"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "proc"}},
	ProcessVmWritevEventID:     EventConfig{ID: ProcessVmWritevEventID, ID32Bit: sys32process_vm_writev, Name: "process_vm_writev", Probes: []probe{probe{event: "process_vm_writev", attach: sysCall, fn: "process_vm_writev"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "proc"}},
	KcmpEventID:                EventConfig{ID: KcmpEventID, ID32Bit: sys32kcmp, Name: "reserved", Probes: []probe{probe{event: "kcmp", attach: sysCall, fn: "kcmp"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc"*/ }},
	FinitModuleEventID:         EventConfig{ID: FinitModuleEventID, ID32Bit: sys32finit_module, Name: "finit_module", Probes: []probe{probe{event: "finit_module", attach: sysCall, fn: "finit_module"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "system", "system_module"}},
	SchedSetattrEventID:        EventConfig{ID: SchedSetattrEventID, ID32Bit: sys32sched_setattr, Name: "reserved", Probes: []probe{probe{event: "sched_setattr", attach: sysCall, fn: "sched_setattr"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_sched"*/ }},
	SchedGetattrEventID:        EventConfig{ID: SchedGetattrEventID, ID32Bit: sys32sched_getattr, Name: "reserved", Probes: []probe{probe{event: "sched_getattr", attach: sysCall, fn: "sched_getattr"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_sched"*/ }},
	Renameat2EventID:           EventConfig{ID: Renameat2EventID, ID32Bit: sys32renameat2, Name: "reserved", Probes: []probe{probe{event: "renameat2", attach: sysCall, fn: "renameat2"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_ops"*/ }},
	SeccompEventID:             EventConfig{ID: SeccompEventID, ID32Bit: sys32seccomp, Name: "reserved", Probes: []probe{probe{event: "seccomp", attach: sysCall, fn: "seccomp"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc"*/ }},
	GetrandomEventID:           EventConfig{ID: GetrandomEventID, ID32Bit: sys32getrandom, Name: "reserved", Probes: []probe{probe{event: "getrandom", attach: sysCall, fn: "getrandom"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs"*/ }},
	MemfdCreateEventID:         EventConfig{ID: MemfdCreateEventID, ID32Bit: sys32memfd_create, Name: "memfd_create", Probes: []probe{probe{event: "memfd_create", attach: sysCall, fn: "memfd_create"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	KexecFileLoadEventID:       EventConfig{ID: KexecFileLoadEventID, ID32Bit: sys32undefined, Name: "reserved", Probes: []probe{probe{event: "kexec_file_load", attach: sysCall, fn: "kexec_file_load"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system"*/ }},
	BpfEventID:                 EventConfig{ID: BpfEventID, ID32Bit: sys32bpf, Name: "reserved", Probes: []probe{probe{event: "bpf", attach: sysCall, fn: "bpf"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system"*/ }},
	ExecveatEventID:            EventConfig{ID: ExecveatEventID, ID32Bit: sys32execveat, Name: "execveat", Probes: []probe{probe{event: "execveat", attach: sysCall, fn: "execveat"}}, EssentialEvent: true, Sets: []string{"default", "syscalls", "proc", "proc_life"}},
	UserfaultfdEventID:         EventConfig{ID: UserfaultfdEventID, ID32Bit: sys32userfaultfd, Name: "reserved", Probes: []probe{probe{event: "userfaultfd", attach: sysCall, fn: "userfaultfd"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "system"*/ }},
	MembarrierEventID:          EventConfig{ID: MembarrierEventID, ID32Bit: sys32membarrier, Name: "reserved", Probes: []probe{probe{event: "membarrier", attach: sysCall, fn: "membarrier"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_mem"*/ }},
	Mlock2EventID:              EventConfig{ID: Mlock2EventID, ID32Bit: sys32mlock2, Name: "reserved", Probes: []probe{probe{event: "mlock2", attach: sysCall, fn: "mlock2"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_mem"*/ }},
	CopyFileRangeEventID:       EventConfig{ID: CopyFileRangeEventID, ID32Bit: sys32copy_file_range, Name: "reserved", Probes: []probe{probe{event: "copy_file_range", attach: sysCall, fn: "copy_file_range"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_read_write"*/ }},
	Preadv2EventID:             EventConfig{ID: Preadv2EventID, ID32Bit: sys32preadv2, Name: "reserved", Probes: []probe{probe{event: "preadv2", attach: sysCall, fn: "preadv2"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_read_write"*/ }},
	Pwritev2EventID:            EventConfig{ID: Pwritev2EventID, ID32Bit: sys32pwritev2, Name: "reserved", Probes: []probe{probe{event: "pwritev2", attach: sysCall, fn: "pwritev2"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_read_write"*/ }},
	PkeyMprotectEventID:        EventConfig{ID: PkeyMprotectEventID, ID32Bit: sys32pkey_mprotect, Name: "pkey_mprotect", Probes: []probe{probe{event: "pkey_mprotect", attach: sysCall, fn: "pkey_mprotect"}}, EssentialEvent: false, Sets: []string{"default", "syscalls", "proc", "proc_mem"}},
	PkeyAllocEventID:           EventConfig{ID: PkeyAllocEventID, ID32Bit: sys32pkey_alloc, Name: "reserved", Probes: []probe{probe{event: "pkey_alloc", attach: sysCall, fn: "pkey_alloc"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_mem"*/ }},
	PkeyFreeEventID:            EventConfig{ID: PkeyFreeEventID, ID32Bit: sys32pkey_free, Name: "reserved", Probes: []probe{probe{event: "pkey_free", attach: sysCall, fn: "pkey_free"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "proc", "proc_mem"*/ }},
	StatxEventID:               EventConfig{ID: StatxEventID, ID32Bit: sys32statx, Name: "reserved", Probes: []probe{probe{event: "statx", attach: sysCall, fn: "statx"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_file_attr"*/ }},
	IoPgeteventsEventID:        EventConfig{ID: IoPgeteventsEventID, ID32Bit: sys32io_pgetevents, Name: "reserved", Probes: []probe{probe{event: "io_pgetevents", attach: sysCall, fn: "io_pgetevents"}}, EssentialEvent: false, Sets: []string{ /*"syscalls", "fs", "fs_async_io"*/ }},
	RseqEventID:                EventConfig{ID: RseqEventID, ID32Bit: sys32rseq, Name: "reserved", Probes: []probe{probe{event: "rseq", attach: sysCall, fn: "rseq"}}, EssentialEvent: false, Sets: []string{ /*"syscalls"*/ }},
	Reserved335EventID:         EventConfig{ID: Reserved335EventID, ID32Bit: sys32undefined, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false, Sets: []string{}},
	Reserved336EventID:         EventConfig{ID: Reserved336EventID, ID32Bit: sys32undefined, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false, Sets: []string{}},
	Reserved337EventID:         EventConfig{ID: Reserved337EventID, ID32Bit: sys32undefined, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false, Sets: []string{}},
	Reserved338EventID:         EventConfig{ID: Reserved338EventID, ID32Bit: sys32undefined, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false, Sets: []string{}},
	Reserved339EventID:         EventConfig{ID: Reserved339EventID, ID32Bit: sys32undefined, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false, Sets: []string{}},
	Reserved340EventID:         EventConfig{ID: Reserved340EventID, ID32Bit: sys32undefined, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false, Sets: []string{}},
	Reserved341EventID:         EventConfig{ID: Reserved341EventID, ID32Bit: sys32undefined, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false, Sets: []string{}},
	Reserved342EventID:         EventConfig{ID: Reserved342EventID, ID32Bit: sys32undefined, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false, Sets: []string{}},
	Reserved343EventID:         EventConfig{ID: Reserved343EventID, ID32Bit: sys32undefined, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false, Sets: []string{}},
	Reserved344EventID:         EventConfig{ID: Reserved344EventID, ID32Bit: sys32undefined, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false, Sets: []string{}},
	Reserved345EventID:         EventConfig{ID: Reserved345EventID, ID32Bit: sys32undefined, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false, Sets: []string{}},
	Reserved346EventID:         EventConfig{ID: Reserved346EventID, ID32Bit: sys32undefined, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false, Sets: []string{}},
	Reserved347EventID:         EventConfig{ID: Reserved347EventID, ID32Bit: sys32undefined, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false, Sets: []string{}},
	Reserved348EventID:         EventConfig{ID: Reserved348EventID, ID32Bit: sys32undefined, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false, Sets: []string{}},
	Reserved349EventID:         EventConfig{ID: Reserved349EventID, ID32Bit: sys32undefined, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EssentialEvent: false, Sets: []string{}},
	SysEnterEventID:            EventConfig{ID: SysEnterEventID, ID32Bit: sys32undefined, Name: "sys_enter", Probes: []probe{probe{event: "raw_syscalls:sys_enter", attach: rawTracepoint, fn: "raw_tracepoint__sys_enter"}}, EssentialEvent: true, Sets: []string{}},
	SysExitEventID:             EventConfig{ID: SysExitEventID, ID32Bit: sys32undefined, Name: "sys_exit", Probes: []probe{probe{event: "raw_syscalls:sys_exit", attach: rawTracepoint, fn: "raw_tracepoint__sys_exit"}}, EssentialEvent: true, Sets: []string{}},
	DoExitEventID:              EventConfig{ID: DoExitEventID, ID32Bit: sys32undefined, Name: "do_exit", Probes: []probe{probe{event: "do_exit", attach: kprobe, fn: "trace_do_exit"}}, EssentialEvent: true, Sets: []string{"default"}},
	CapCapableEventID:          EventConfig{ID: CapCapableEventID, ID32Bit: sys32undefined, Name: "cap_capable", Probes: []probe{probe{event: "cap_capable", attach: kprobe, fn: "trace_cap_capable"}}, EssentialEvent: false, Sets: []string{"default"}},
	SecurityBprmCheckEventID:   EventConfig{ID: SecurityBprmCheckEventID, ID32Bit: sys32undefined, Name: "security_bprm_check", Probes: []probe{probe{event: "security_bprm_check", attach: kprobe, fn: "trace_security_bprm_check"}}, EssentialEvent: false, Sets: []string{"default"}},
	SecurityFileOpenEventID:    EventConfig{ID: SecurityFileOpenEventID, ID32Bit: sys32undefined, Name: "security_file_open", Probes: []probe{probe{event: "security_file_open", attach: kprobe, fn: "trace_security_file_open"}}, EssentialEvent: false, Sets: []string{"default"}},
	VfsWriteEventID:            EventConfig{ID: VfsWriteEventID, ID32Bit: sys32undefined, Name: "vfs_write", Probes: []probe{probe{event: "vfs_write", attach: kprobe, fn: "trace_vfs_write"}, probe{event: "vfs_write", attach: kretprobe, fn: "trace_ret_vfs_write"}}, EssentialEvent: false, Sets: []string{"default"}},
	MemProtAlertEventID:        EventConfig{ID: MemProtAlertEventID, ID32Bit: sys32undefined, Name: "mem_prot_alert", Probes: []probe{probe{event: "security_mmap_addr", attach: kprobe, fn: "trace_mmap_alert"}, probe{event: "security_file_mprotect", attach: kprobe, fn: "trace_mprotect_alert"}}, EssentialEvent: false, Sets: []string{}},
}
