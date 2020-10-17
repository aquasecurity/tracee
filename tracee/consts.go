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
	configTraceePid
)

// an enum that specifies the index of a function to be used in a bpf tail call
// tail function indexes should match defined values in ebpf code
const (
	tailVfsWrite uint32 = iota
	tailVfsWritev
	tailSendBin
)

// binType is an enum that specifies the type of binary data sent in the file perf map
// binary types should match defined values in ebpf code
type binType uint8

const (
	ModeProcessAll uint32 = iota
	ModeProcessNew
	ModeProcessList
	ModeContainerAll
	ModeContainerNew
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
	NameToHandleAtEventID
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
	SysEnterEventID
	SysExitEventID
	DoExitEventID
	CapCapableEventID
	SecurityBprmCheckEventID
	SecurityFileOpenEventID
	VfsWriteEventID
	VfsWritevEventID
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
	ReadEventID:                EventConfig{ID: ReadEventID, ID32Bit: sys32read, Name: "read", Probes: []probe{probe{event: "read", attach: sysCall, fn: "read"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	WriteEventID:               EventConfig{ID: WriteEventID, ID32Bit: sys32write, Name: "write", Probes: []probe{probe{event: "write", attach: sysCall, fn: "write"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	OpenEventID:                EventConfig{ID: OpenEventID, ID32Bit: sys32open, Name: "open", Probes: []probe{probe{event: "open", attach: sysCall, fn: "open"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	CloseEventID:               EventConfig{ID: CloseEventID, ID32Bit: sys32close, Name: "close", Probes: []probe{probe{event: "close", attach: sysCall, fn: "close"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	StatEventID:                EventConfig{ID: StatEventID, ID32Bit: sys32stat, Name: "stat", Probes: []probe{probe{event: "newstat", attach: sysCall, fn: "newstat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	FstatEventID:               EventConfig{ID: FstatEventID, ID32Bit: sys32fstat, Name: "fstat", Probes: []probe{probe{event: "newfstat", attach: sysCall, fn: "newfstat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	LstatEventID:               EventConfig{ID: LstatEventID, ID32Bit: sys32lstat, Name: "lstat", Probes: []probe{probe{event: "newlstat", attach: sysCall, fn: "newlstat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	PollEventID:                EventConfig{ID: PollEventID, ID32Bit: sys32poll, Name: "poll", Probes: []probe{probe{event: "poll", attach: sysCall, fn: "poll"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	LseekEventID:               EventConfig{ID: LseekEventID, ID32Bit: sys32lseek, Name: "lseek", Probes: []probe{probe{event: "lseek", attach: sysCall, fn: "lseek"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	MmapEventID:                EventConfig{ID: MmapEventID, ID32Bit: sys32mmap, Name: "mmap", Probes: []probe{probe{event: "mmap", attach: sysCall, fn: "mmap"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	MprotectEventID:            EventConfig{ID: MprotectEventID, ID32Bit: sys32mprotect, Name: "mprotect", Probes: []probe{probe{event: "mprotect", attach: sysCall, fn: "mprotect"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	MunmapEventID:              EventConfig{ID: MunmapEventID, ID32Bit: sys32munmap, Name: "munmap", Probes: []probe{probe{event: "munmap", attach: sysCall, fn: "munmap"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	BrkEventID:                 EventConfig{ID: BrkEventID, ID32Bit: sys32brk, Name: "brk", Probes: []probe{probe{event: "brk", attach: sysCall, fn: "brk"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	RtSigactionEventID:         EventConfig{ID: RtSigactionEventID, ID32Bit: sys32rt_sigaction, Name: "rt_sigaction", Probes: []probe{probe{event: "rt_sigaction", attach: sysCall, fn: "rt_sigaction"}}, Sets: []string{"syscalls", "signals"}},
	RtSigprocmaskEventID:       EventConfig{ID: RtSigprocmaskEventID, ID32Bit: sys32rt_sigprocmask, Name: "rt_sigprocmask", Probes: []probe{probe{event: "rt_sigprocmask", attach: sysCall, fn: "rt_sigprocmask"}}, Sets: []string{"syscalls", "signals"}},
	RtSigreturnEventID:         EventConfig{ID: RtSigreturnEventID, ID32Bit: sys32rt_sigreturn, Name: "rt_sigreturn", Probes: []probe{probe{event: "rt_sigreturn", attach: sysCall, fn: "rt_sigreturn"}}, Sets: []string{"syscalls", "signals"}},
	IoctlEventID:               EventConfig{ID: IoctlEventID, ID32Bit: sys32ioctl, Name: "ioctl", Probes: []probe{probe{event: "ioctl", attach: sysCall, fn: "ioctl"}}, Sets: []string{"default", "syscalls", "fs", "fs_fd_ops"}},
	Pread64EventID:             EventConfig{ID: Pread64EventID, ID32Bit: sys32pread64, Name: "pread64", Probes: []probe{probe{event: "pread64", attach: sysCall, fn: "pread64"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	Pwrite64EventID:            EventConfig{ID: Pwrite64EventID, ID32Bit: sys32pwrite64, Name: "pwrite64", Probes: []probe{probe{event: "pwrite64", attach: sysCall, fn: "pwrite64"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	ReadvEventID:               EventConfig{ID: ReadvEventID, ID32Bit: sys32readv, Name: "readv", Probes: []probe{probe{event: "readv", attach: sysCall, fn: "readv"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	WritevEventID:              EventConfig{ID: WritevEventID, ID32Bit: sys32writev, Name: "writev", Probes: []probe{probe{event: "writev", attach: sysCall, fn: "writev"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	AccessEventID:              EventConfig{ID: AccessEventID, ID32Bit: sys32access, Name: "access", Probes: []probe{probe{event: "access", attach: sysCall, fn: "access"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	PipeEventID:                EventConfig{ID: PipeEventID, ID32Bit: sys32pipe, Name: "pipe", Probes: []probe{probe{event: "pipe", attach: sysCall, fn: "pipe"}}, Sets: []string{"syscalls", "ipc", "ipc_pipe"}},
	SelectEventID:              EventConfig{ID: SelectEventID, ID32Bit: sys32select, Name: "select", Probes: []probe{probe{event: "select", attach: sysCall, fn: "select"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	SchedYieldEventID:          EventConfig{ID: SchedYieldEventID, ID32Bit: sys32sched_yield, Name: "sched_yield", Probes: []probe{probe{event: "sched_yield", attach: sysCall, fn: "sched_yield"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	MremapEventID:              EventConfig{ID: MremapEventID, ID32Bit: sys32mremap, Name: "mremap", Probes: []probe{probe{event: "mremap", attach: sysCall, fn: "mremap"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	MsyncEventID:               EventConfig{ID: MsyncEventID, ID32Bit: sys32msync, Name: "msync", Probes: []probe{probe{event: "msync", attach: sysCall, fn: "msync"}}, Sets: []string{"syscalls", "fs", "fs_sync"}},
	MincoreEventID:             EventConfig{ID: MincoreEventID, ID32Bit: sys32mincore, Name: "mincore", Probes: []probe{probe{event: "mincore", attach: sysCall, fn: "mincore"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	MadviseEventID:             EventConfig{ID: MadviseEventID, ID32Bit: sys32madvise, Name: "madvise", Probes: []probe{probe{event: "madvise", attach: sysCall, fn: "madvise"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	ShmgetEventID:              EventConfig{ID: ShmgetEventID, ID32Bit: sys32shmget, Name: "shmget", Probes: []probe{probe{event: "shmget", attach: sysCall, fn: "shmget"}}, Sets: []string{"syscalls", "ipc", "ipc_shm"}},
	ShmatEventID:               EventConfig{ID: ShmatEventID, ID32Bit: sys32shmat, Name: "shmat", Probes: []probe{probe{event: "shmat", attach: sysCall, fn: "shmat"}}, Sets: []string{"syscalls", "ipc", "ipc_shm"}},
	ShmctlEventID:              EventConfig{ID: ShmctlEventID, ID32Bit: sys32shmctl, Name: "shmctl", Probes: []probe{probe{event: "shmctl", attach: sysCall, fn: "shmctl"}}, Sets: []string{"syscalls", "ipc", "ipc_shm"}},
	DupEventID:                 EventConfig{ID: DupEventID, ID32Bit: sys32dup, Name: "dup", Probes: []probe{probe{event: "dup", attach: sysCall, fn: "dup"}}, Sets: []string{"default", "syscalls", "fs", "fs_fd_ops"}},
	Dup2EventID:                EventConfig{ID: Dup2EventID, ID32Bit: sys32dup2, Name: "dup2", Probes: []probe{probe{event: "dup2", attach: sysCall, fn: "dup2"}}, Sets: []string{"default", "syscalls", "fs", "fs_fd_ops"}},
	PauseEventID:               EventConfig{ID: PauseEventID, ID32Bit: sys32pause, Name: "pause", Probes: []probe{probe{event: "pause", attach: sysCall, fn: "pause"}}, Sets: []string{"syscalls", "signals"}},
	NanosleepEventID:           EventConfig{ID: NanosleepEventID, ID32Bit: sys32nanosleep, Name: "nanosleep", Probes: []probe{probe{event: "nanosleep", attach: sysCall, fn: "nanosleep"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	GetitimerEventID:           EventConfig{ID: GetitimerEventID, ID32Bit: sys32getitimer, Name: "getitimer", Probes: []probe{probe{event: "getitimer", attach: sysCall, fn: "getitimer"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	AlarmEventID:               EventConfig{ID: AlarmEventID, ID32Bit: sys32alarm, Name: "alarm", Probes: []probe{probe{event: "alarm", attach: sysCall, fn: "alarm"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	SetitimerEventID:           EventConfig{ID: SetitimerEventID, ID32Bit: sys32setitimer, Name: "setitimer", Probes: []probe{probe{event: "setitimer", attach: sysCall, fn: "setitimer"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	GetpidEventID:              EventConfig{ID: GetpidEventID, ID32Bit: sys32getpid, Name: "getpid", Probes: []probe{probe{event: "getpid", attach: sysCall, fn: "getpid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SendfileEventID:            EventConfig{ID: SendfileEventID, ID32Bit: sys32sendfile, Name: "sendfile", Probes: []probe{probe{event: "sendfile", attach: sysCall, fn: "sendfile"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	SocketEventID:              EventConfig{ID: SocketEventID, ID32Bit: sys32socket, Name: "socket", Probes: []probe{probe{event: "socket", attach: sysCall, fn: "socket"}}, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	ConnectEventID:             EventConfig{ID: ConnectEventID, ID32Bit: sys32connect, Name: "connect", Probes: []probe{probe{event: "connect", attach: sysCall, fn: "connect"}}, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	AcceptEventID:              EventConfig{ID: AcceptEventID, ID32Bit: sys32undefined, Name: "accept", Probes: []probe{probe{event: "accept", attach: sysCall, fn: "accept"}}, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	SendtoEventID:              EventConfig{ID: SendtoEventID, ID32Bit: sys32sendto, Name: "sendto", Probes: []probe{probe{event: "sendto", attach: sysCall, fn: "sendto"}}, Sets: []string{"syscalls", "net", "net_snd_rcv"}},
	RecvfromEventID:            EventConfig{ID: RecvfromEventID, ID32Bit: sys32recvfrom, Name: "recvfrom", Probes: []probe{probe{event: "recvfrom", attach: sysCall, fn: "recvfrom"}}, Sets: []string{"syscalls", "net", "net_snd_rcv"}},
	SendmsgEventID:             EventConfig{ID: SendmsgEventID, ID32Bit: sys32sendmsg, Name: "sendmsg", Probes: []probe{probe{event: "sendmsg", attach: sysCall, fn: "sendmsg"}}, Sets: []string{"syscalls", "net", "net_snd_rcv"}},
	RecvmsgEventID:             EventConfig{ID: RecvmsgEventID, ID32Bit: sys32recvmsg, Name: "recvmsg", Probes: []probe{probe{event: "recvmsg", attach: sysCall, fn: "recvmsg"}}, Sets: []string{"syscalls", "net", "net_snd_rcv"}},
	ShutdownEventID:            EventConfig{ID: ShutdownEventID, ID32Bit: sys32shutdown, Name: "shutdown", Probes: []probe{probe{event: "shutdown", attach: sysCall, fn: "shutdown"}}, Sets: []string{"syscalls", "net", "net_sock"}},
	BindEventID:                EventConfig{ID: BindEventID, ID32Bit: sys32bind, Name: "bind", Probes: []probe{probe{event: "bind", attach: sysCall, fn: "bind"}}, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	ListenEventID:              EventConfig{ID: ListenEventID, ID32Bit: sys32listen, Name: "listen", Probes: []probe{probe{event: "listen", attach: sysCall, fn: "listen"}}, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	GetsocknameEventID:         EventConfig{ID: GetsocknameEventID, ID32Bit: sys32getsockname, Name: "getsockname", Probes: []probe{probe{event: "getsockname", attach: sysCall, fn: "getsockname"}}, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	GetpeernameEventID:         EventConfig{ID: GetpeernameEventID, ID32Bit: sys32getpeername, Name: "getpeername", Probes: []probe{probe{event: "getpeername", attach: sysCall, fn: "getpeername"}}, Sets: []string{"syscalls", "net", "net_sock"}},
	SocketpairEventID:          EventConfig{ID: SocketpairEventID, ID32Bit: sys32socketpair, Name: "socketpair", Probes: []probe{probe{event: "socketpair", attach: sysCall, fn: "socketpair"}}, Sets: []string{"syscalls", "net", "net_sock"}},
	SetsockoptEventID:          EventConfig{ID: SetsockoptEventID, ID32Bit: sys32setsockopt, Name: "setsockopt", Probes: []probe{probe{event: "setsockopt", attach: sysCall, fn: "setsockopt"}}, Sets: []string{"syscalls", "net", "net_sock"}},
	GetsockoptEventID:          EventConfig{ID: GetsockoptEventID, ID32Bit: sys32getsockopt, Name: "getsockopt", Probes: []probe{probe{event: "getsockopt", attach: sysCall, fn: "getsockopt"}}, Sets: []string{"syscalls", "net", "net_sock"}},
	CloneEventID:               EventConfig{ID: CloneEventID, ID32Bit: sys32clone, Name: "clone", Probes: []probe{probe{event: "clone", attach: sysCall, fn: "clone"}}, Sets: []string{"default", "syscalls", "proc", "proc_life"}},
	ForkEventID:                EventConfig{ID: ForkEventID, ID32Bit: sys32fork, Name: "fork", Probes: []probe{probe{event: "fork", attach: sysCall, fn: "fork"}}, Sets: []string{"default", "syscalls", "proc", "proc_life"}},
	VforkEventID:               EventConfig{ID: VforkEventID, ID32Bit: sys32vfork, Name: "vfork", Probes: []probe{probe{event: "vfork", attach: sysCall, fn: "vfork"}}, Sets: []string{"default", "syscalls", "proc", "proc_life"}},
	ExecveEventID:              EventConfig{ID: ExecveEventID, ID32Bit: sys32execve, Name: "execve", Probes: []probe{probe{event: "execve", attach: sysCall, fn: "execve"}}, Sets: []string{"default", "syscalls", "proc", "proc_life"}},
	ExitEventID:                EventConfig{ID: ExitEventID, ID32Bit: sys32exit, Name: "exit", Probes: []probe{probe{event: "exit", attach: sysCall, fn: "exit"}}, Sets: []string{"syscalls", "proc", "proc_life"}},
	Wait4EventID:               EventConfig{ID: Wait4EventID, ID32Bit: sys32wait4, Name: "wait4", Probes: []probe{probe{event: "wait4", attach: sysCall, fn: "wait4"}}, Sets: []string{"syscalls", "proc", "proc_life"}},
	KillEventID:                EventConfig{ID: KillEventID, ID32Bit: sys32kill, Name: "kill", Probes: []probe{probe{event: "kill", attach: sysCall, fn: "kill"}}, Sets: []string{"default", "syscalls", "signals"}},
	UnameEventID:               EventConfig{ID: UnameEventID, ID32Bit: sys32uname, Name: "uname", Probes: []probe{probe{event: "uname", attach: sysCall, fn: "uname"}}, Sets: []string{"syscalls", "system"}},
	SemgetEventID:              EventConfig{ID: SemgetEventID, ID32Bit: sys32semget, Name: "semget", Probes: []probe{probe{event: "semget", attach: sysCall, fn: "semget"}}, Sets: []string{"syscalls", "ipc", "ipc_sem"}},
	SemopEventID:               EventConfig{ID: SemopEventID, ID32Bit: sys32undefined, Name: "semop", Probes: []probe{probe{event: "semop", attach: sysCall, fn: "semop"}}, Sets: []string{"syscalls", "ipc", "ipc_sem"}},
	SemctlEventID:              EventConfig{ID: SemctlEventID, ID32Bit: sys32semctl, Name: "semctl", Probes: []probe{probe{event: "semctl", attach: sysCall, fn: "semctl"}}, Sets: []string{"syscalls", "ipc", "ipc_sem"}},
	ShmdtEventID:               EventConfig{ID: ShmdtEventID, ID32Bit: sys32shmdt, Name: "shmdt", Probes: []probe{probe{event: "shmdt", attach: sysCall, fn: "shmdt"}}, Sets: []string{"syscalls", "ipc", "ipc_shm"}},
	MsggetEventID:              EventConfig{ID: MsggetEventID, ID32Bit: sys32msgget, Name: "msgget", Probes: []probe{probe{event: "msgget", attach: sysCall, fn: "msgget"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	MsgsndEventID:              EventConfig{ID: MsgsndEventID, ID32Bit: sys32msgsnd, Name: "msgsnd", Probes: []probe{probe{event: "msgsnd", attach: sysCall, fn: "msgsnd"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	MsgrcvEventID:              EventConfig{ID: MsgrcvEventID, ID32Bit: sys32msgrcv, Name: "msgrcv", Probes: []probe{probe{event: "msgrcv", attach: sysCall, fn: "msgrcv"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	MsgctlEventID:              EventConfig{ID: MsgctlEventID, ID32Bit: sys32msgctl, Name: "msgctl", Probes: []probe{probe{event: "msgctl", attach: sysCall, fn: "msgctl"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	FcntlEventID:               EventConfig{ID: FcntlEventID, ID32Bit: sys32fcntl, Name: "fcntl", Probes: []probe{probe{event: "fcntl", attach: sysCall, fn: "fcntl"}}, Sets: []string{"syscalls", "fs", "fs_fd_ops"}},
	FlockEventID:               EventConfig{ID: FlockEventID, ID32Bit: sys32flock, Name: "flock", Probes: []probe{probe{event: "flock", attach: sysCall, fn: "flock"}}, Sets: []string{"syscalls", "fs", "fs_fd_ops"}},
	FsyncEventID:               EventConfig{ID: FsyncEventID, ID32Bit: sys32fsync, Name: "fsync", Probes: []probe{probe{event: "fsync", attach: sysCall, fn: "fsync"}}, Sets: []string{"syscalls", "fs", "fs_sync"}},
	FdatasyncEventID:           EventConfig{ID: FdatasyncEventID, ID32Bit: sys32fdatasync, Name: "fdatasync", Probes: []probe{probe{event: "fdatasync", attach: sysCall, fn: "fdatasync"}}, Sets: []string{"syscalls", "fs", "fs_sync"}},
	TruncateEventID:            EventConfig{ID: TruncateEventID, ID32Bit: sys32truncate, Name: "truncate", Probes: []probe{probe{event: "truncate", attach: sysCall, fn: "truncate"}}, Sets: []string{"syscalls", "fs", "fs_file_ops"}},
	FtruncateEventID:           EventConfig{ID: FtruncateEventID, ID32Bit: sys32ftruncate, Name: "ftruncate", Probes: []probe{probe{event: "ftruncate", attach: sysCall, fn: "ftruncate"}}, Sets: []string{"syscalls", "fs", "fs_file_ops"}},
	GetdentsEventID:            EventConfig{ID: GetdentsEventID, ID32Bit: sys32getdents, Name: "getdents", Probes: []probe{probe{event: "getdents", attach: sysCall, fn: "getdents"}}, Sets: []string{"default", "syscalls", "fs", "fs_dir_ops"}},
	GetcwdEventID:              EventConfig{ID: GetcwdEventID, ID32Bit: sys32getcwd, Name: "getcwd", Probes: []probe{probe{event: "getcwd", attach: sysCall, fn: "getcwd"}}, Sets: []string{"syscalls", "fs", "fs_dir_ops"}},
	ChdirEventID:               EventConfig{ID: ChdirEventID, ID32Bit: sys32chdir, Name: "chdir", Probes: []probe{probe{event: "chdir", attach: sysCall, fn: "chdir"}}, Sets: []string{"syscalls", "fs", "fs_dir_ops"}},
	FchdirEventID:              EventConfig{ID: FchdirEventID, ID32Bit: sys32fchdir, Name: "fchdir", Probes: []probe{probe{event: "fchdir", attach: sysCall, fn: "fchdir"}}, Sets: []string{"syscalls", "fs", "fs_dir_ops"}},
	RenameEventID:              EventConfig{ID: RenameEventID, ID32Bit: sys32rename, Name: "rename", Probes: []probe{probe{event: "rename", attach: sysCall, fn: "rename"}}, Sets: []string{"syscalls", "fs", "fs_file_ops"}},
	MkdirEventID:               EventConfig{ID: MkdirEventID, ID32Bit: sys32mkdir, Name: "mkdir", Probes: []probe{probe{event: "mkdir", attach: sysCall, fn: "mkdir"}}, Sets: []string{"syscalls", "fs", "fs_dir_ops"}},
	RmdirEventID:               EventConfig{ID: RmdirEventID, ID32Bit: sys32rmdir, Name: "rmdir", Probes: []probe{probe{event: "rmdir", attach: sysCall, fn: "rmdir"}}, Sets: []string{"syscalls", "fs", "fs_dir_ops"}},
	CreatEventID:               EventConfig{ID: CreatEventID, ID32Bit: sys32creat, Name: "creat", Probes: []probe{probe{event: "creat", attach: sysCall, fn: "creat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	LinkEventID:                EventConfig{ID: LinkEventID, ID32Bit: sys32link, Name: "link", Probes: []probe{probe{event: "link", attach: sysCall, fn: "link"}}, Sets: []string{"syscalls", "fs", "fs_link_ops"}},
	UnlinkEventID:              EventConfig{ID: UnlinkEventID, ID32Bit: sys32unlink, Name: "unlink", Probes: []probe{probe{event: "unlink", attach: sysCall, fn: "unlink"}}, Sets: []string{"default", "syscalls", "fs", "fs_link_ops"}},
	SymlinkEventID:             EventConfig{ID: SymlinkEventID, ID32Bit: sys32symlink, Name: "symlink", Probes: []probe{probe{event: "symlink", attach: sysCall, fn: "symlink"}}, Sets: []string{"default", "syscalls", "fs", "fs_link_ops"}},
	ReadlinkEventID:            EventConfig{ID: ReadlinkEventID, ID32Bit: sys32readlink, Name: "readlink", Probes: []probe{probe{event: "readlink", attach: sysCall, fn: "readlink"}}, Sets: []string{"syscalls", "fs", "fs_link_ops"}},
	ChmodEventID:               EventConfig{ID: ChmodEventID, ID32Bit: sys32chmod, Name: "chmod", Probes: []probe{probe{event: "chmod", attach: sysCall, fn: "chmod"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	FchmodEventID:              EventConfig{ID: FchmodEventID, ID32Bit: sys32fchmod, Name: "fchmod", Probes: []probe{probe{event: "fchmod", attach: sysCall, fn: "fchmod"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	ChownEventID:               EventConfig{ID: ChownEventID, ID32Bit: sys32chown, Name: "chown", Probes: []probe{probe{event: "chown", attach: sysCall, fn: "chown"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	FchownEventID:              EventConfig{ID: FchownEventID, ID32Bit: sys32fchown, Name: "fchown", Probes: []probe{probe{event: "fchown", attach: sysCall, fn: "fchown"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	LchownEventID:              EventConfig{ID: LchownEventID, ID32Bit: sys32lchown, Name: "lchown", Probes: []probe{probe{event: "lchown", attach: sysCall, fn: "lchown"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	UmaskEventID:               EventConfig{ID: UmaskEventID, ID32Bit: sys32umask, Name: "umask", Probes: []probe{probe{event: "umask", attach: sysCall, fn: "umask"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	GettimeofdayEventID:        EventConfig{ID: GettimeofdayEventID, ID32Bit: sys32gettimeofday, Name: "gettimeofday", Probes: []probe{probe{event: "gettimeofday", attach: sysCall, fn: "gettimeofday"}}, Sets: []string{"syscalls", "time", "time_tod"}},
	GetrlimitEventID:           EventConfig{ID: GetrlimitEventID, ID32Bit: sys32getrlimit, Name: "getrlimit", Probes: []probe{probe{event: "getrlimit", attach: sysCall, fn: "getrlimit"}}, Sets: []string{"syscalls", "proc"}},
	GetrusageEventID:           EventConfig{ID: GetrusageEventID, ID32Bit: sys32getrusage, Name: "getrusage", Probes: []probe{probe{event: "getrusage", attach: sysCall, fn: "getrusage"}}, Sets: []string{"syscalls", "proc"}},
	SysinfoEventID:             EventConfig{ID: SysinfoEventID, ID32Bit: sys32sysinfo, Name: "sysinfo", Probes: []probe{probe{event: "sysinfo", attach: sysCall, fn: "sysinfo"}}, Sets: []string{"syscalls", "system"}},
	TimesEventID:               EventConfig{ID: TimesEventID, ID32Bit: sys32times, Name: "times", Probes: []probe{probe{event: "times", attach: sysCall, fn: "times"}}, Sets: []string{"syscalls", "proc"}},
	PtraceEventID:              EventConfig{ID: PtraceEventID, ID32Bit: sys32ptrace, Name: "ptrace", Probes: []probe{probe{event: "ptrace", attach: sysCall, fn: "ptrace"}}, Sets: []string{"default", "syscalls", "proc"}},
	GetuidEventID:              EventConfig{ID: GetuidEventID, ID32Bit: sys32getuid, Name: "getuid", Probes: []probe{probe{event: "getuid", attach: sysCall, fn: "getuid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SyslogEventID:              EventConfig{ID: SyslogEventID, ID32Bit: sys32syslog, Name: "syslog", Probes: []probe{probe{event: "syslog", attach: sysCall, fn: "syslog"}}, Sets: []string{"syscalls", "system"}},
	GetgidEventID:              EventConfig{ID: GetgidEventID, ID32Bit: sys32getgid, Name: "getgid", Probes: []probe{probe{event: "getgid", attach: sysCall, fn: "getgid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SetuidEventID:              EventConfig{ID: SetuidEventID, ID32Bit: sys32setuid, Name: "setuid", Probes: []probe{probe{event: "setuid", attach: sysCall, fn: "setuid"}}, Sets: []string{"default", "syscalls", "proc", "proc_ids"}},
	SetgidEventID:              EventConfig{ID: SetgidEventID, ID32Bit: sys32setgid, Name: "setgid", Probes: []probe{probe{event: "setgid", attach: sysCall, fn: "setgid"}}, Sets: []string{"default", "syscalls", "proc", "proc_ids"}},
	GeteuidEventID:             EventConfig{ID: GeteuidEventID, ID32Bit: sys32geteuid, Name: "geteuid", Probes: []probe{probe{event: "geteuid", attach: sysCall, fn: "geteuid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	GetegidEventID:             EventConfig{ID: GetegidEventID, ID32Bit: sys32getegid, Name: "getegid", Probes: []probe{probe{event: "getegid", attach: sysCall, fn: "getegid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SetpgidEventID:             EventConfig{ID: SetpgidEventID, ID32Bit: sys32setpgid, Name: "setpgid", Probes: []probe{probe{event: "setpgid", attach: sysCall, fn: "setpgid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	GetppidEventID:             EventConfig{ID: GetppidEventID, ID32Bit: sys32getppid, Name: "getppid", Probes: []probe{probe{event: "getppid", attach: sysCall, fn: "getppid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	GetpgrpEventID:             EventConfig{ID: GetpgrpEventID, ID32Bit: sys32getpgrp, Name: "getpgrp", Probes: []probe{probe{event: "getpgrp", attach: sysCall, fn: "getpgrp"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SetsidEventID:              EventConfig{ID: SetsidEventID, ID32Bit: sys32setsid, Name: "setsid", Probes: []probe{probe{event: "setsid", attach: sysCall, fn: "setsid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SetreuidEventID:            EventConfig{ID: SetreuidEventID, ID32Bit: sys32setreuid, Name: "setreuid", Probes: []probe{probe{event: "setreuid", attach: sysCall, fn: "setreuid"}}, Sets: []string{"default", "syscalls", "proc", "proc_ids"}},
	SetregidEventID:            EventConfig{ID: SetregidEventID, ID32Bit: sys32setregid, Name: "setregid", Probes: []probe{probe{event: "setregid", attach: sysCall, fn: "setregid"}}, Sets: []string{"default", "syscalls", "proc", "proc_ids"}},
	GetgroupsEventID:           EventConfig{ID: GetgroupsEventID, ID32Bit: sys32getgroups, Name: "getgroups", Probes: []probe{probe{event: "getgroups", attach: sysCall, fn: "getgroups"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SetgroupsEventID:           EventConfig{ID: SetgroupsEventID, ID32Bit: sys32setgroups, Name: "setgroups", Probes: []probe{probe{event: "setgroups", attach: sysCall, fn: "setgroups"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SetresuidEventID:           EventConfig{ID: SetresuidEventID, ID32Bit: sys32setresuid, Name: "setresuid", Probes: []probe{probe{event: "setresuid", attach: sysCall, fn: "setresuid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	GetresuidEventID:           EventConfig{ID: GetresuidEventID, ID32Bit: sys32getresuid, Name: "getresuid", Probes: []probe{probe{event: "getresuid", attach: sysCall, fn: "getresuid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SetresgidEventID:           EventConfig{ID: SetresgidEventID, ID32Bit: sys32setresgid, Name: "setresgid", Probes: []probe{probe{event: "setresgid", attach: sysCall, fn: "setresgid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	GetresgidEventID:           EventConfig{ID: GetresgidEventID, ID32Bit: sys32getresgid, Name: "getresgid", Probes: []probe{probe{event: "getresgid", attach: sysCall, fn: "getresgid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	GetpgidEventID:             EventConfig{ID: GetpgidEventID, ID32Bit: sys32getpgid, Name: "getpgid", Probes: []probe{probe{event: "getpgid", attach: sysCall, fn: "getpgid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SetfsuidEventID:            EventConfig{ID: SetfsuidEventID, ID32Bit: sys32setfsuid, Name: "setfsuid", Probes: []probe{probe{event: "setfsuid", attach: sysCall, fn: "setfsuid"}}, Sets: []string{"default", "syscalls", "proc", "proc_ids"}},
	SetfsgidEventID:            EventConfig{ID: SetfsgidEventID, ID32Bit: sys32setfsgid, Name: "setfsgid", Probes: []probe{probe{event: "setfsgid", attach: sysCall, fn: "setfsgid"}}, Sets: []string{"default", "syscalls", "proc", "proc_ids"}},
	GetsidEventID:              EventConfig{ID: GetsidEventID, ID32Bit: sys32getsid, Name: "getsid", Probes: []probe{probe{event: "getsid", attach: sysCall, fn: "getsid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	CapgetEventID:              EventConfig{ID: CapgetEventID, ID32Bit: sys32capget, Name: "capget", Probes: []probe{probe{event: "capget", attach: sysCall, fn: "capget"}}, Sets: []string{"syscalls", "proc"}},
	CapsetEventID:              EventConfig{ID: CapsetEventID, ID32Bit: sys32capset, Name: "capset", Probes: []probe{probe{event: "capset", attach: sysCall, fn: "capset"}}, Sets: []string{"syscalls", "proc"}},
	RtSigpendingEventID:        EventConfig{ID: RtSigpendingEventID, ID32Bit: sys32rt_sigpending, Name: "rt_sigpending", Probes: []probe{probe{event: "rt_sigpending", attach: sysCall, fn: "rt_sigpending"}}, Sets: []string{"syscalls", "signals"}},
	RtSigtimedwaitEventID:      EventConfig{ID: RtSigtimedwaitEventID, ID32Bit: sys32rt_sigtimedwait, Name: "rt_sigtimedwait", Probes: []probe{probe{event: "rt_sigtimedwait", attach: sysCall, fn: "rt_sigtimedwait"}}, Sets: []string{"syscalls", "signals"}},
	RtSigqueueinfoEventID:      EventConfig{ID: RtSigqueueinfoEventID, ID32Bit: sys32rt_sigqueueinfo, Name: "rt_sigqueueinfo", Probes: []probe{probe{event: "rt_sigqueueinfo", attach: sysCall, fn: "rt_sigqueueinfo"}}, Sets: []string{"syscalls", "signals"}},
	RtSigsuspendEventID:        EventConfig{ID: RtSigsuspendEventID, ID32Bit: sys32rt_sigsuspend, Name: "rt_sigsuspend", Probes: []probe{probe{event: "rt_sigsuspend", attach: sysCall, fn: "rt_sigsuspend"}}, Sets: []string{"syscalls", "signals"}},
	SigaltstackEventID:         EventConfig{ID: SigaltstackEventID, ID32Bit: sys32sigaltstack, Name: "sigaltstack", Probes: []probe{probe{event: "sigaltstack", attach: sysCall, fn: "sigaltstack"}}, Sets: []string{"syscalls", "signals"}},
	UtimeEventID:               EventConfig{ID: UtimeEventID, ID32Bit: sys32utime, Name: "utime", Probes: []probe{probe{event: "utime", attach: sysCall, fn: "utime"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	MknodEventID:               EventConfig{ID: MknodEventID, ID32Bit: sys32mknod, Name: "mknod", Probes: []probe{probe{event: "mknod", attach: sysCall, fn: "mknod"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	UselibEventID:              EventConfig{ID: UselibEventID, ID32Bit: sys32uselib, Name: "uselib", Probes: []probe{probe{event: "uselib", attach: sysCall, fn: "uselib"}}, Sets: []string{"syscalls", "proc"}},
	PersonalityEventID:         EventConfig{ID: PersonalityEventID, ID32Bit: sys32personality, Name: "personality", Probes: []probe{probe{event: "personality", attach: sysCall, fn: "personality"}}, Sets: []string{"syscalls", "system"}},
	UstatEventID:               EventConfig{ID: UstatEventID, ID32Bit: sys32ustat, Name: "ustat", Probes: []probe{probe{event: "ustat", attach: sysCall, fn: "ustat"}}, Sets: []string{"syscalls", "fs", "fs_info"}},
	StatfsEventID:              EventConfig{ID: StatfsEventID, ID32Bit: sys32statfs, Name: "statfs", Probes: []probe{probe{event: "statfs", attach: sysCall, fn: "statfs"}}, Sets: []string{"syscalls", "fs", "fs_info"}},
	FstatfsEventID:             EventConfig{ID: FstatfsEventID, ID32Bit: sys32fstatfs, Name: "fstatfs", Probes: []probe{probe{event: "fstatfs", attach: sysCall, fn: "fstatfs"}}, Sets: []string{"syscalls", "fs", "fs_info"}},
	SysfsEventID:               EventConfig{ID: SysfsEventID, ID32Bit: sys32sysfs, Name: "sysfs", Probes: []probe{probe{event: "sysfs", attach: sysCall, fn: "sysfs"}}, Sets: []string{"syscalls", "fs", "fs_info"}},
	GetpriorityEventID:         EventConfig{ID: GetpriorityEventID, ID32Bit: sys32getpriority, Name: "getpriority", Probes: []probe{probe{event: "getpriority", attach: sysCall, fn: "getpriority"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SetpriorityEventID:         EventConfig{ID: SetpriorityEventID, ID32Bit: sys32setpriority, Name: "setpriority", Probes: []probe{probe{event: "setpriority", attach: sysCall, fn: "setpriority"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedSetparamEventID:       EventConfig{ID: SchedSetparamEventID, ID32Bit: sys32sched_setparam, Name: "sched_setparam", Probes: []probe{probe{event: "sched_setparam", attach: sysCall, fn: "sched_setparam"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedGetparamEventID:       EventConfig{ID: SchedGetparamEventID, ID32Bit: sys32sched_getparam, Name: "sched_getparam", Probes: []probe{probe{event: "sched_getparam", attach: sysCall, fn: "sched_getparam"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedSetschedulerEventID:   EventConfig{ID: SchedSetschedulerEventID, ID32Bit: sys32sched_setscheduler, Name: "sched_setscheduler", Probes: []probe{probe{event: "sched_setscheduler", attach: sysCall, fn: "sched_setscheduler"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedGetschedulerEventID:   EventConfig{ID: SchedGetschedulerEventID, ID32Bit: sys32sched_getscheduler, Name: "sched_getscheduler", Probes: []probe{probe{event: "sched_getscheduler", attach: sysCall, fn: "sched_getscheduler"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedGetPriorityMaxEventID: EventConfig{ID: SchedGetPriorityMaxEventID, ID32Bit: sys32sched_get_priority_max, Name: "sched_get_priority_max", Probes: []probe{probe{event: "sched_get_priority_max", attach: sysCall, fn: "sched_get_priority_max"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedGetPriorityMinEventID: EventConfig{ID: SchedGetPriorityMinEventID, ID32Bit: sys32sched_get_priority_min, Name: "sched_get_priority_min", Probes: []probe{probe{event: "sched_get_priority_min", attach: sysCall, fn: "sched_get_priority_min"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedRrGetIntervalEventID:  EventConfig{ID: SchedRrGetIntervalEventID, ID32Bit: sys32sched_rr_get_interval, Name: "sched_rr_get_interval", Probes: []probe{probe{event: "sched_rr_get_interval", attach: sysCall, fn: "sched_rr_get_interval"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	MlockEventID:               EventConfig{ID: MlockEventID, ID32Bit: sys32mlock, Name: "mlock", Probes: []probe{probe{event: "mlock", attach: sysCall, fn: "mlock"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	MunlockEventID:             EventConfig{ID: MunlockEventID, ID32Bit: sys32munlock, Name: "munlock", Probes: []probe{probe{event: "munlock", attach: sysCall, fn: "munlock"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	MlockallEventID:            EventConfig{ID: MlockallEventID, ID32Bit: sys32mlockall, Name: "mlockall", Probes: []probe{probe{event: "mlockall", attach: sysCall, fn: "mlockall"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	MunlockallEventID:          EventConfig{ID: MunlockallEventID, ID32Bit: sys32munlockall, Name: "munlockall", Probes: []probe{probe{event: "munlockall", attach: sysCall, fn: "munlockall"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	VhangupEventID:             EventConfig{ID: VhangupEventID, ID32Bit: sys32vhangup, Name: "vhangup", Probes: []probe{probe{event: "vhangup", attach: sysCall, fn: "vhangup"}}, Sets: []string{"syscalls", "system"}},
	ModifyLdtEventID:           EventConfig{ID: ModifyLdtEventID, ID32Bit: sys32modify_ldt, Name: "modify_ldt", Probes: []probe{probe{event: "modify_ldt", attach: sysCall, fn: "modify_ldt"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	PivotRootEventID:           EventConfig{ID: PivotRootEventID, ID32Bit: sys32pivot_root, Name: "pivot_root", Probes: []probe{probe{event: "pivot_root", attach: sysCall, fn: "pivot_root"}}, Sets: []string{"syscalls", "fs"}},
	SysctlEventID:              EventConfig{ID: SysctlEventID, ID32Bit: sys32undefined, Name: "sysctl", Probes: []probe{probe{event: "sysctl", attach: sysCall, fn: "sysctl"}}, Sets: []string{"syscalls", "system"}},
	PrctlEventID:               EventConfig{ID: PrctlEventID, ID32Bit: sys32prctl, Name: "prctl", Probes: []probe{probe{event: "prctl", attach: sysCall, fn: "prctl"}}, Sets: []string{"default", "syscalls", "proc"}},
	ArchPrctlEventID:           EventConfig{ID: ArchPrctlEventID, ID32Bit: sys32arch_prctl, Name: "arch_prctl", Probes: []probe{probe{event: "arch_prctl", attach: sysCall, fn: "arch_prctl"}}, Sets: []string{"syscalls", "proc"}},
	AdjtimexEventID:            EventConfig{ID: AdjtimexEventID, ID32Bit: sys32adjtimex, Name: "adjtimex", Probes: []probe{probe{event: "adjtimex", attach: sysCall, fn: "adjtimex"}}, Sets: []string{"syscalls", "time", "time_clock"}},
	SetrlimitEventID:           EventConfig{ID: SetrlimitEventID, ID32Bit: sys32setrlimit, Name: "setrlimit", Probes: []probe{probe{event: "setrlimit", attach: sysCall, fn: "setrlimit"}}, Sets: []string{"syscalls", "proc"}},
	ChrootEventID:              EventConfig{ID: ChrootEventID, ID32Bit: sys32chroot, Name: "chroot", Probes: []probe{probe{event: "chroot", attach: sysCall, fn: "chroot"}}, Sets: []string{"syscalls", "fs", "fs_dir_ops"}},
	SyncEventID:                EventConfig{ID: SyncEventID, ID32Bit: sys32sync, Name: "sync", Probes: []probe{probe{event: "sync", attach: sysCall, fn: "sync"}}, Sets: []string{"syscalls", "fs", "fs_sync"}},
	AcctEventID:                EventConfig{ID: AcctEventID, ID32Bit: sys32acct, Name: "acct", Probes: []probe{probe{event: "acct", attach: sysCall, fn: "acct"}}, Sets: []string{"syscalls", "system"}},
	SettimeofdayEventID:        EventConfig{ID: SettimeofdayEventID, ID32Bit: sys32settimeofday, Name: "settimeofday", Probes: []probe{probe{event: "settimeofday", attach: sysCall, fn: "settimeofday"}}, Sets: []string{"syscalls", "time", "time_tod"}},
	MountEventID:               EventConfig{ID: MountEventID, ID32Bit: sys32mount, Name: "mount", Probes: []probe{probe{event: "mount", attach: sysCall, fn: "mount"}}, Sets: []string{"default", "syscalls", "fs"}},
	UmountEventID:              EventConfig{ID: UmountEventID, ID32Bit: sys32umount, Name: "umount", Probes: []probe{probe{event: "umount", attach: sysCall, fn: "umount"}}, Sets: []string{"default", "syscalls", "fs"}},
	SwaponEventID:              EventConfig{ID: SwaponEventID, ID32Bit: sys32swapon, Name: "swapon", Probes: []probe{probe{event: "swapon", attach: sysCall, fn: "swapon"}}, Sets: []string{"syscalls", "fs"}},
	SwapoffEventID:             EventConfig{ID: SwapoffEventID, ID32Bit: sys32swapoff, Name: "swapoff", Probes: []probe{probe{event: "swapoff", attach: sysCall, fn: "swapoff"}}, Sets: []string{"syscalls", "fs"}},
	RebootEventID:              EventConfig{ID: RebootEventID, ID32Bit: sys32reboot, Name: "reboot", Probes: []probe{probe{event: "reboot", attach: sysCall, fn: "reboot"}}, Sets: []string{"syscalls", "system"}},
	SethostnameEventID:         EventConfig{ID: SethostnameEventID, ID32Bit: sys32sethostname, Name: "sethostname", Probes: []probe{probe{event: "sethostname", attach: sysCall, fn: "sethostname"}}, Sets: []string{"syscalls", "net"}},
	SetdomainnameEventID:       EventConfig{ID: SetdomainnameEventID, ID32Bit: sys32setdomainname, Name: "setdomainname", Probes: []probe{probe{event: "setdomainname", attach: sysCall, fn: "setdomainname"}}, Sets: []string{"syscalls", "net"}},
	IoplEventID:                EventConfig{ID: IoplEventID, ID32Bit: sys32iopl, Name: "iopl", Probes: []probe{probe{event: "iopl", attach: sysCall, fn: "iopl"}}, Sets: []string{"syscalls", "system"}},
	IopermEventID:              EventConfig{ID: IopermEventID, ID32Bit: sys32ioperm, Name: "ioperm", Probes: []probe{probe{event: "ioperm", attach: sysCall, fn: "ioperm"}}, Sets: []string{"syscalls", "system"}},
	CreateModuleEventID:        EventConfig{ID: CreateModuleEventID, ID32Bit: sys32create_module, Name: "create_module", Probes: []probe{probe{event: "create_module", attach: sysCall, fn: "create_module"}}, Sets: []string{"syscalls", "system", "system_module"}},
	InitModuleEventID:          EventConfig{ID: InitModuleEventID, ID32Bit: sys32init_module, Name: "init_module", Probes: []probe{probe{event: "init_module", attach: sysCall, fn: "init_module"}}, Sets: []string{"default", "syscalls", "system", "system_module"}},
	DeleteModuleEventID:        EventConfig{ID: DeleteModuleEventID, ID32Bit: sys32delete_module, Name: "delete_module", Probes: []probe{probe{event: "delete_module", attach: sysCall, fn: "delete_module"}}, Sets: []string{"default", "syscalls", "system", "system_module"}},
	GetKernelSymsEventID:       EventConfig{ID: GetKernelSymsEventID, ID32Bit: sys32get_kernel_syms, Name: "get_kernel_syms", Probes: []probe{probe{event: "get_kernel_syms", attach: sysCall, fn: "get_kernel_syms"}}, Sets: []string{"syscalls", "system", "system_module"}},
	QueryModuleEventID:         EventConfig{ID: QueryModuleEventID, ID32Bit: sys32query_module, Name: "query_module", Probes: []probe{probe{event: "query_module", attach: sysCall, fn: "query_module"}}, Sets: []string{"syscalls", "system", "system_module"}},
	QuotactlEventID:            EventConfig{ID: QuotactlEventID, ID32Bit: sys32quotactl, Name: "quotactl", Probes: []probe{probe{event: "quotactl", attach: sysCall, fn: "quotactl"}}, Sets: []string{"syscalls", "system"}},
	NfsservctlEventID:          EventConfig{ID: NfsservctlEventID, ID32Bit: sys32nfsservctl, Name: "nfsservctl", Probes: []probe{probe{event: "nfsservctl", attach: sysCall, fn: "nfsservctl"}}, Sets: []string{"syscalls", "fs"}},
	GetpmsgEventID:             EventConfig{ID: GetpmsgEventID, ID32Bit: sys32getpmsg, Name: "getpmsg", Probes: []probe{probe{event: "getpmsg", attach: sysCall, fn: "getpmsg"}}, Sets: []string{"syscalls"}},
	PutpmsgEventID:             EventConfig{ID: PutpmsgEventID, ID32Bit: sys32putpmsg, Name: "putpmsg", Probes: []probe{probe{event: "putpmsg", attach: sysCall, fn: "putpmsg"}}, Sets: []string{"syscalls"}},
	AfsEventID:                 EventConfig{ID: AfsEventID, ID32Bit: sys32undefined, Name: "afs", Probes: []probe{probe{event: "afs", attach: sysCall, fn: "afs"}}, Sets: []string{"syscalls"}},
	TuxcallEventID:             EventConfig{ID: TuxcallEventID, ID32Bit: sys32undefined, Name: "tuxcall", Probes: []probe{probe{event: "tuxcall", attach: sysCall, fn: "tuxcall"}}, Sets: []string{"syscalls"}},
	SecurityEventID:            EventConfig{ID: SecurityEventID, ID32Bit: sys32undefined, Name: "security", Probes: []probe{probe{event: "security", attach: sysCall, fn: "security"}}, Sets: []string{"syscalls"}},
	GettidEventID:              EventConfig{ID: GettidEventID, ID32Bit: sys32gettid, Name: "gettid", Probes: []probe{probe{event: "gettid", attach: sysCall, fn: "gettid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	ReadaheadEventID:           EventConfig{ID: ReadaheadEventID, ID32Bit: sys32readahead, Name: "readahead", Probes: []probe{probe{event: "readahead", attach: sysCall, fn: "readahead"}}, Sets: []string{"syscalls", "fs"}},
	SetxattrEventID:            EventConfig{ID: SetxattrEventID, ID32Bit: sys32setxattr, Name: "setxattr", Probes: []probe{probe{event: "setxattr", attach: sysCall, fn: "setxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	LsetxattrEventID:           EventConfig{ID: LsetxattrEventID, ID32Bit: sys32lsetxattr, Name: "lsetxattr", Probes: []probe{probe{event: "lsetxattr", attach: sysCall, fn: "lsetxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	FsetxattrEventID:           EventConfig{ID: FsetxattrEventID, ID32Bit: sys32fsetxattr, Name: "fsetxattr", Probes: []probe{probe{event: "fsetxattr", attach: sysCall, fn: "fsetxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	GetxattrEventID:            EventConfig{ID: GetxattrEventID, ID32Bit: sys32getxattr, Name: "getxattr", Probes: []probe{probe{event: "getxattr", attach: sysCall, fn: "getxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	LgetxattrEventID:           EventConfig{ID: LgetxattrEventID, ID32Bit: sys32lgetxattr, Name: "lgetxattr", Probes: []probe{probe{event: "lgetxattr", attach: sysCall, fn: "lgetxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	FgetxattrEventID:           EventConfig{ID: FgetxattrEventID, ID32Bit: sys32fgetxattr, Name: "fgetxattr", Probes: []probe{probe{event: "fgetxattr", attach: sysCall, fn: "fgetxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	ListxattrEventID:           EventConfig{ID: ListxattrEventID, ID32Bit: sys32listxattr, Name: "listxattr", Probes: []probe{probe{event: "listxattr", attach: sysCall, fn: "listxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	LlistxattrEventID:          EventConfig{ID: LlistxattrEventID, ID32Bit: sys32llistxattr, Name: "llistxattr", Probes: []probe{probe{event: "llistxattr", attach: sysCall, fn: "llistxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	FlistxattrEventID:          EventConfig{ID: FlistxattrEventID, ID32Bit: sys32flistxattr, Name: "flistxattr", Probes: []probe{probe{event: "flistxattr", attach: sysCall, fn: "flistxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	RemovexattrEventID:         EventConfig{ID: RemovexattrEventID, ID32Bit: sys32removexattr, Name: "removexattr", Probes: []probe{probe{event: "removexattr", attach: sysCall, fn: "removexattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	LremovexattrEventID:        EventConfig{ID: LremovexattrEventID, ID32Bit: sys32lremovexattr, Name: "lremovexattr", Probes: []probe{probe{event: "lremovexattr", attach: sysCall, fn: "lremovexattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	FremovexattrEventID:        EventConfig{ID: FremovexattrEventID, ID32Bit: sys32fremovexattr, Name: "fremovexattr", Probes: []probe{probe{event: "fremovexattr", attach: sysCall, fn: "fremovexattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	TkillEventID:               EventConfig{ID: TkillEventID, ID32Bit: sys32tkill, Name: "tkill", Probes: []probe{probe{event: "tkill", attach: sysCall, fn: "tkill"}}, Sets: []string{"syscalls", "signals"}},
	TimeEventID:                EventConfig{ID: TimeEventID, ID32Bit: sys32time, Name: "time", Probes: []probe{probe{event: "time", attach: sysCall, fn: "time"}}, Sets: []string{"syscalls", "time", "time_tod"}},
	FutexEventID:               EventConfig{ID: FutexEventID, ID32Bit: sys32futex, Name: "futex", Probes: []probe{probe{event: "futex", attach: sysCall, fn: "futex"}}, Sets: []string{"syscalls", "ipc", "ipc_futex"}},
	SchedSetaffinityEventID:    EventConfig{ID: SchedSetaffinityEventID, ID32Bit: sys32sched_setaffinity, Name: "sched_setaffinity", Probes: []probe{probe{event: "sched_setaffinity", attach: sysCall, fn: "sched_setaffinity"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedGetaffinityEventID:    EventConfig{ID: SchedGetaffinityEventID, ID32Bit: sys32sched_getaffinity, Name: "sched_getaffinity", Probes: []probe{probe{event: "sched_getaffinity", attach: sysCall, fn: "sched_getaffinity"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SetThreadAreaEventID:       EventConfig{ID: SetThreadAreaEventID, ID32Bit: sys32set_thread_area, Name: "set_thread_area", Probes: []probe{probe{event: "set_thread_area", attach: sysCall, fn: "set_thread_area"}}, Sets: []string{"syscalls", "proc"}},
	IoSetupEventID:             EventConfig{ID: IoSetupEventID, ID32Bit: sys32io_setup, Name: "io_setup", Probes: []probe{probe{event: "io_setup", attach: sysCall, fn: "io_setup"}}, Sets: []string{"syscalls", "fs", "fs_async_io"}},
	IoDestroyEventID:           EventConfig{ID: IoDestroyEventID, ID32Bit: sys32io_destroy, Name: "io_destroy", Probes: []probe{probe{event: "io_destroy", attach: sysCall, fn: "io_destroy"}}, Sets: []string{"syscalls", "fs", "fs_async_io"}},
	IoGeteventsEventID:         EventConfig{ID: IoGeteventsEventID, ID32Bit: sys32io_getevents, Name: "io_getevents", Probes: []probe{probe{event: "io_getevents", attach: sysCall, fn: "io_getevents"}}, Sets: []string{"syscalls", "fs", "fs_async_io"}},
	IoSubmitEventID:            EventConfig{ID: IoSubmitEventID, ID32Bit: sys32io_submit, Name: "io_submit", Probes: []probe{probe{event: "io_submit", attach: sysCall, fn: "io_submit"}}, Sets: []string{"syscalls", "fs", "fs_async_io"}},
	IoCancelEventID:            EventConfig{ID: IoCancelEventID, ID32Bit: sys32io_cancel, Name: "io_cancel", Probes: []probe{probe{event: "io_cancel", attach: sysCall, fn: "io_cancel"}}, Sets: []string{"syscalls", "fs", "fs_async_io"}},
	GetThreadAreaEventID:       EventConfig{ID: GetThreadAreaEventID, ID32Bit: sys32get_thread_area, Name: "get_thread_area", Probes: []probe{probe{event: "get_thread_area", attach: sysCall, fn: "get_thread_area"}}, Sets: []string{"syscalls", "proc"}},
	LookupDcookieEventID:       EventConfig{ID: LookupDcookieEventID, ID32Bit: sys32lookup_dcookie, Name: "lookup_dcookie", Probes: []probe{probe{event: "lookup_dcookie", attach: sysCall, fn: "lookup_dcookie"}}, Sets: []string{"syscalls", "fs", "fs_dir_ops"}},
	EpollCreateEventID:         EventConfig{ID: EpollCreateEventID, ID32Bit: sys32epoll_create, Name: "epoll_create", Probes: []probe{probe{event: "epoll_create", attach: sysCall, fn: "epoll_create"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	EpollCtlOldEventID:         EventConfig{ID: EpollCtlOldEventID, ID32Bit: sys32undefined, Name: "epoll_ctl_old", Probes: []probe{probe{event: "epoll_ctl_old", attach: sysCall, fn: "epoll_ctl_old"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	EpollWaitOldEventID:        EventConfig{ID: EpollWaitOldEventID, ID32Bit: sys32undefined, Name: "epoll_wait_old", Probes: []probe{probe{event: "epoll_wait_old", attach: sysCall, fn: "epoll_wait_old"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	RemapFilePagesEventID:      EventConfig{ID: RemapFilePagesEventID, ID32Bit: sys32remap_file_pages, Name: "remap_file_pages", Probes: []probe{probe{event: "remap_file_pages", attach: sysCall, fn: "remap_file_pages"}}, Sets: []string{"syscalls"}},
	Getdents64EventID:          EventConfig{ID: Getdents64EventID, ID32Bit: sys32getdents64, Name: "getdents64", Probes: []probe{probe{event: "getdents64", attach: sysCall, fn: "getdents64"}}, Sets: []string{"default", "syscalls", "fs", "fs_dir_ops"}},
	SetTidAddressEventID:       EventConfig{ID: SetTidAddressEventID, ID32Bit: sys32set_tid_address, Name: "set_tid_address", Probes: []probe{probe{event: "set_tid_address", attach: sysCall, fn: "set_tid_address"}}, Sets: []string{"syscalls", "proc"}},
	RestartSyscallEventID:      EventConfig{ID: RestartSyscallEventID, ID32Bit: sys32restart_syscall, Name: "restart_syscall", Probes: []probe{probe{event: "restart_syscall", attach: sysCall, fn: "restart_syscall"}}, Sets: []string{"syscalls", "signals"}},
	SemtimedopEventID:          EventConfig{ID: SemtimedopEventID, ID32Bit: sys32semtimedop_time64, Name: "semtimedop", Probes: []probe{probe{event: "semtimedop", attach: sysCall, fn: "semtimedop"}}, Sets: []string{"syscalls", "ipc", "ipc_sem"}},
	Fadvise64EventID:           EventConfig{ID: Fadvise64EventID, ID32Bit: sys32fadvise64, Name: "fadvise64", Probes: []probe{probe{event: "fadvise64", attach: sysCall, fn: "fadvise64"}}, Sets: []string{"syscalls", "fs"}},
	TimerCreateEventID:         EventConfig{ID: TimerCreateEventID, ID32Bit: sys32timer_create, Name: "timer_create", Probes: []probe{probe{event: "timer_create", attach: sysCall, fn: "timer_create"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	TimerSettimeEventID:        EventConfig{ID: TimerSettimeEventID, ID32Bit: sys32timer_settime, Name: "timer_settime", Probes: []probe{probe{event: "timer_settime", attach: sysCall, fn: "timer_settime"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	TimerGettimeEventID:        EventConfig{ID: TimerGettimeEventID, ID32Bit: sys32timer_gettime, Name: "timer_gettime", Probes: []probe{probe{event: "timer_gettime", attach: sysCall, fn: "timer_gettime"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	TimerGetoverrunEventID:     EventConfig{ID: TimerGetoverrunEventID, ID32Bit: sys32timer_getoverrun, Name: "timer_getoverrun", Probes: []probe{probe{event: "timer_getoverrun", attach: sysCall, fn: "timer_getoverrun"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	TimerDeleteEventID:         EventConfig{ID: TimerDeleteEventID, ID32Bit: sys32timer_delete, Name: "timer_delete", Probes: []probe{probe{event: "timer_delete", attach: sysCall, fn: "timer_delete"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	ClockSettimeEventID:        EventConfig{ID: ClockSettimeEventID, ID32Bit: sys32clock_settime, Name: "clock_settime", Probes: []probe{probe{event: "clock_settime", attach: sysCall, fn: "clock_settime"}}, Sets: []string{"syscalls", "time", "time_clock"}},
	ClockGettimeEventID:        EventConfig{ID: ClockGettimeEventID, ID32Bit: sys32clock_gettime, Name: "clock_gettime", Probes: []probe{probe{event: "clock_gettime", attach: sysCall, fn: "clock_gettime"}}, Sets: []string{"syscalls", "time", "time_clock"}},
	ClockGetresEventID:         EventConfig{ID: ClockGetresEventID, ID32Bit: sys32clock_getres, Name: "clock_getres", Probes: []probe{probe{event: "clock_getres", attach: sysCall, fn: "clock_getres"}}, Sets: []string{"syscalls", "time", "time_clock"}},
	ClockNanosleepEventID:      EventConfig{ID: ClockNanosleepEventID, ID32Bit: sys32clock_nanosleep, Name: "clock_nanosleep", Probes: []probe{probe{event: "clock_nanosleep", attach: sysCall, fn: "clock_nanosleep"}}, Sets: []string{"syscalls", "time", "time_clock"}},
	ExitGroupEventID:           EventConfig{ID: ExitGroupEventID, ID32Bit: sys32exit_group, Name: "exit_group", Probes: []probe{probe{event: "exit_group", attach: sysCall, fn: "exit_group"}}, Sets: []string{"syscalls", "proc", "proc_life"}},
	EpollWaitEventID:           EventConfig{ID: EpollWaitEventID, ID32Bit: sys32epoll_wait, Name: "epoll_wait", Probes: []probe{probe{event: "epoll_wait", attach: sysCall, fn: "epoll_wait"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	EpollCtlEventID:            EventConfig{ID: EpollCtlEventID, ID32Bit: sys32epoll_ctl, Name: "epoll_ctl", Probes: []probe{probe{event: "epoll_ctl", attach: sysCall, fn: "epoll_ctl"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	TgkillEventID:              EventConfig{ID: TgkillEventID, ID32Bit: sys32tgkill, Name: "tgkill", Probes: []probe{probe{event: "tgkill", attach: sysCall, fn: "tgkill"}}, Sets: []string{"syscalls", "signals"}},
	UtimesEventID:              EventConfig{ID: UtimesEventID, ID32Bit: sys32utimes, Name: "utimes", Probes: []probe{probe{event: "utimes", attach: sysCall, fn: "utimes"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	VserverEventID:             EventConfig{ID: VserverEventID, ID32Bit: sys32vserver, Name: "vserver", Probes: []probe{probe{event: "vserver", attach: sysCall, fn: "vserver"}}, Sets: []string{"syscalls"}},
	MbindEventID:               EventConfig{ID: MbindEventID, ID32Bit: sys32mbind, Name: "mbind", Probes: []probe{probe{event: "mbind", attach: sysCall, fn: "mbind"}}, Sets: []string{"syscalls", "system", "system_numa"}},
	SetMempolicyEventID:        EventConfig{ID: SetMempolicyEventID, ID32Bit: sys32set_mempolicy, Name: "set_mempolicy", Probes: []probe{probe{event: "set_mempolicy", attach: sysCall, fn: "set_mempolicy"}}, Sets: []string{"syscalls", "system", "system_numa"}},
	GetMempolicyEventID:        EventConfig{ID: GetMempolicyEventID, ID32Bit: sys32get_mempolicy, Name: "get_mempolicy", Probes: []probe{probe{event: "get_mempolicy", attach: sysCall, fn: "get_mempolicy"}}, Sets: []string{"syscalls", "system", "system_numa"}},
	MqOpenEventID:              EventConfig{ID: MqOpenEventID, ID32Bit: sys32mq_open, Name: "mq_open", Probes: []probe{probe{event: "mq_open", attach: sysCall, fn: "mq_open"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	MqUnlinkEventID:            EventConfig{ID: MqUnlinkEventID, ID32Bit: sys32mq_unlink, Name: "mq_unlink", Probes: []probe{probe{event: "mq_unlink", attach: sysCall, fn: "mq_unlink"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	MqTimedsendEventID:         EventConfig{ID: MqTimedsendEventID, ID32Bit: sys32mq_timedsend, Name: "mq_timedsend", Probes: []probe{probe{event: "mq_timedsend", attach: sysCall, fn: "mq_timedsend"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	MqTimedreceiveEventID:      EventConfig{ID: MqTimedreceiveEventID, ID32Bit: sys32mq_timedreceive, Name: "mq_timedreceive", Probes: []probe{probe{event: "mq_timedreceive", attach: sysCall, fn: "mq_timedreceive"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	MqNotifyEventID:            EventConfig{ID: MqNotifyEventID, ID32Bit: sys32mq_notify, Name: "mq_notify", Probes: []probe{probe{event: "mq_notify", attach: sysCall, fn: "mq_notify"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	MqGetsetattrEventID:        EventConfig{ID: MqGetsetattrEventID, ID32Bit: sys32mq_getsetattr, Name: "mq_getsetattr", Probes: []probe{probe{event: "mq_getsetattr", attach: sysCall, fn: "mq_getsetattr"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	KexecLoadEventID:           EventConfig{ID: KexecLoadEventID, ID32Bit: sys32kexec_load, Name: "kexec_load", Probes: []probe{probe{event: "kexec_load", attach: sysCall, fn: "kexec_load"}}, Sets: []string{"syscalls", "system"}},
	WaitidEventID:              EventConfig{ID: WaitidEventID, ID32Bit: sys32waitid, Name: "waitid", Probes: []probe{probe{event: "waitid", attach: sysCall, fn: "waitid"}}, Sets: []string{"syscalls", "proc", "proc_life"}},
	AddKeyEventID:              EventConfig{ID: AddKeyEventID, ID32Bit: sys32add_key, Name: "add_key", Probes: []probe{probe{event: "add_key", attach: sysCall, fn: "add_key"}}, Sets: []string{"syscalls", "system", "system_keys"}},
	RequestKeyEventID:          EventConfig{ID: RequestKeyEventID, ID32Bit: sys32request_key, Name: "request_key", Probes: []probe{probe{event: "request_key", attach: sysCall, fn: "request_key"}}, Sets: []string{"syscalls", "system", "system_keys"}},
	KeyctlEventID:              EventConfig{ID: KeyctlEventID, ID32Bit: sys32keyctl, Name: "keyctl", Probes: []probe{probe{event: "keyctl", attach: sysCall, fn: "keyctl"}}, Sets: []string{"syscalls", "system", "system_keys"}},
	IoprioSetEventID:           EventConfig{ID: IoprioSetEventID, ID32Bit: sys32ioprio_set, Name: "ioprio_set", Probes: []probe{probe{event: "ioprio_set", attach: sysCall, fn: "ioprio_set"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	IoprioGetEventID:           EventConfig{ID: IoprioGetEventID, ID32Bit: sys32ioprio_get, Name: "ioprio_get", Probes: []probe{probe{event: "ioprio_get", attach: sysCall, fn: "ioprio_get"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	InotifyInitEventID:         EventConfig{ID: InotifyInitEventID, ID32Bit: sys32inotify_init, Name: "inotify_init", Probes: []probe{probe{event: "inotify_init", attach: sysCall, fn: "inotify_init"}}, Sets: []string{"syscalls", "fs", "fs_monitor"}},
	InotifyAddWatchEventID:     EventConfig{ID: InotifyAddWatchEventID, ID32Bit: sys32inotify_add_watch, Name: "inotify_add_watch", Probes: []probe{probe{event: "inotify_add_watch", attach: sysCall, fn: "inotify_add_watch"}}, Sets: []string{"syscalls", "fs", "fs_monitor"}},
	InotifyRmWatchEventID:      EventConfig{ID: InotifyRmWatchEventID, ID32Bit: sys32inotify_rm_watch, Name: "inotify_rm_watch", Probes: []probe{probe{event: "inotify_rm_watch", attach: sysCall, fn: "inotify_rm_watch"}}, Sets: []string{"syscalls", "fs", "fs_monitor"}},
	MigratePagesEventID:        EventConfig{ID: MigratePagesEventID, ID32Bit: sys32migrate_pages, Name: "migrate_pages", Probes: []probe{probe{event: "migrate_pages", attach: sysCall, fn: "migrate_pages"}}, Sets: []string{"syscalls", "system", "system_numa"}},
	OpenatEventID:              EventConfig{ID: OpenatEventID, ID32Bit: sys32openat, Name: "openat", Probes: []probe{probe{event: "openat", attach: sysCall, fn: "openat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	MkdiratEventID:             EventConfig{ID: MkdiratEventID, ID32Bit: sys32mkdirat, Name: "mkdirat", Probes: []probe{probe{event: "mkdirat", attach: sysCall, fn: "mkdirat"}}, Sets: []string{"syscalls", "fs", "fs_dir_ops"}},
	MknodatEventID:             EventConfig{ID: MknodatEventID, ID32Bit: sys32mknodat, Name: "mknodat", Probes: []probe{probe{event: "mknodat", attach: sysCall, fn: "mknodat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	FchownatEventID:            EventConfig{ID: FchownatEventID, ID32Bit: sys32fchownat, Name: "fchownat", Probes: []probe{probe{event: "fchownat", attach: sysCall, fn: "fchownat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	FutimesatEventID:           EventConfig{ID: FutimesatEventID, ID32Bit: sys32futimesat, Name: "futimesat", Probes: []probe{probe{event: "futimesat", attach: sysCall, fn: "futimesat"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	NewfstatatEventID:          EventConfig{ID: NewfstatatEventID, ID32Bit: sys32fstatat64, Name: "newfstatat", Probes: []probe{probe{event: "newfstatat", attach: sysCall, fn: "newfstatat"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	UnlinkatEventID:            EventConfig{ID: UnlinkatEventID, ID32Bit: sys32unlinkat, Name: "unlinkat", Probes: []probe{probe{event: "unlinkat", attach: sysCall, fn: "unlinkat"}}, Sets: []string{"default", "syscalls", "fs", "fs_link_ops"}},
	RenameatEventID:            EventConfig{ID: RenameatEventID, ID32Bit: sys32renameat, Name: "renameat", Probes: []probe{probe{event: "renameat", attach: sysCall, fn: "renameat"}}, Sets: []string{"syscalls", "fs", "fs_file_ops"}},
	LinkatEventID:              EventConfig{ID: LinkatEventID, ID32Bit: sys32linkat, Name: "linkat", Probes: []probe{probe{event: "linkat", attach: sysCall, fn: "linkat"}}, Sets: []string{"syscalls", "fs", "fs_link_ops"}},
	SymlinkatEventID:           EventConfig{ID: SymlinkatEventID, ID32Bit: sys32symlinkat, Name: "symlinkat", Probes: []probe{probe{event: "symlinkat", attach: sysCall, fn: "symlinkat"}}, Sets: []string{"default", "syscalls", "fs", "fs_link_ops"}},
	ReadlinkatEventID:          EventConfig{ID: ReadlinkatEventID, ID32Bit: sys32readlinkat, Name: "readlinkat", Probes: []probe{probe{event: "readlinkat", attach: sysCall, fn: "readlinkat"}}, Sets: []string{"syscalls", "fs", "fs_link_ops"}},
	FchmodatEventID:            EventConfig{ID: FchmodatEventID, ID32Bit: sys32fchmodat, Name: "fchmodat", Probes: []probe{probe{event: "fchmodat", attach: sysCall, fn: "fchmodat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	FaccessatEventID:           EventConfig{ID: FaccessatEventID, ID32Bit: sys32faccessat, Name: "faccessat", Probes: []probe{probe{event: "faccessat", attach: sysCall, fn: "faccessat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	Pselect6EventID:            EventConfig{ID: Pselect6EventID, ID32Bit: sys32pselect6, Name: "pselect6", Probes: []probe{probe{event: "pselect6", attach: sysCall, fn: "pselect6"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	PpollEventID:               EventConfig{ID: PpollEventID, ID32Bit: sys32ppoll, Name: "ppoll", Probes: []probe{probe{event: "ppoll", attach: sysCall, fn: "ppoll"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	UnshareEventID:             EventConfig{ID: UnshareEventID, ID32Bit: sys32unshare, Name: "unshare", Probes: []probe{probe{event: "unshare", attach: sysCall, fn: "unshare"}}, Sets: []string{"syscalls", "proc"}},
	SetRobustListEventID:       EventConfig{ID: SetRobustListEventID, ID32Bit: sys32set_robust_list, Name: "set_robust_list", Probes: []probe{probe{event: "set_robust_list", attach: sysCall, fn: "set_robust_list"}}, Sets: []string{"syscalls", "ipc", "ipc_futex"}},
	GetRobustListEventID:       EventConfig{ID: GetRobustListEventID, ID32Bit: sys32get_robust_list, Name: "get_robust_list", Probes: []probe{probe{event: "get_robust_list", attach: sysCall, fn: "get_robust_list"}}, Sets: []string{"syscalls", "ipc", "ipc_futex"}},
	SpliceEventID:              EventConfig{ID: SpliceEventID, ID32Bit: sys32splice, Name: "splice", Probes: []probe{probe{event: "splice", attach: sysCall, fn: "splice"}}, Sets: []string{"syscalls", "ipc", "ipc_pipe"}},
	TeeEventID:                 EventConfig{ID: TeeEventID, ID32Bit: sys32tee, Name: "tee", Probes: []probe{probe{event: "tee", attach: sysCall, fn: "tee"}}, Sets: []string{"syscalls", "ipc", "ipc_pipe"}},
	SyncFileRangeEventID:       EventConfig{ID: SyncFileRangeEventID, ID32Bit: sys32sync_file_range, Name: "sync_file_range", Probes: []probe{probe{event: "sync_file_range", attach: sysCall, fn: "sync_file_range"}}, Sets: []string{"syscalls", "fs", "fs_sync"}},
	VmspliceEventID:            EventConfig{ID: VmspliceEventID, ID32Bit: sys32vmsplice, Name: "vmsplice", Probes: []probe{probe{event: "vmsplice", attach: sysCall, fn: "vmsplice"}}, Sets: []string{"syscalls", "ipc", "ipc_pipe"}},
	MovePagesEventID:           EventConfig{ID: MovePagesEventID, ID32Bit: sys32move_pages, Name: "move_pages", Probes: []probe{probe{event: "move_pages", attach: sysCall, fn: "move_pages"}}, Sets: []string{"syscalls", "system", "system_numa"}},
	UtimensatEventID:           EventConfig{ID: UtimensatEventID, ID32Bit: sys32utimensat, Name: "utimensat", Probes: []probe{probe{event: "utimensat", attach: sysCall, fn: "utimensat"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	EpollPwaitEventID:          EventConfig{ID: EpollPwaitEventID, ID32Bit: sys32epoll_pwait, Name: "epoll_pwait", Probes: []probe{probe{event: "epoll_pwait", attach: sysCall, fn: "epoll_pwait"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	SignalfdEventID:            EventConfig{ID: SignalfdEventID, ID32Bit: sys32signalfd, Name: "signalfd", Probes: []probe{probe{event: "signalfd", attach: sysCall, fn: "signalfd"}}, Sets: []string{"syscalls", "signals"}},
	TimerfdCreateEventID:       EventConfig{ID: TimerfdCreateEventID, ID32Bit: sys32timerfd_create, Name: "timerfd_create", Probes: []probe{probe{event: "timerfd_create", attach: sysCall, fn: "timerfd_create"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	EventfdEventID:             EventConfig{ID: EventfdEventID, ID32Bit: sys32eventfd, Name: "eventfd", Probes: []probe{probe{event: "eventfd", attach: sysCall, fn: "eventfd"}}, Sets: []string{"syscalls", "signals"}},
	FallocateEventID:           EventConfig{ID: FallocateEventID, ID32Bit: sys32fallocate, Name: "fallocate", Probes: []probe{probe{event: "fallocate", attach: sysCall, fn: "fallocate"}}, Sets: []string{"syscalls", "fs", "fs_file_ops"}},
	TimerfdSettimeEventID:      EventConfig{ID: TimerfdSettimeEventID, ID32Bit: sys32timerfd_settime, Name: "timerfd_settime", Probes: []probe{probe{event: "timerfd_settime", attach: sysCall, fn: "timerfd_settime"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	TimerfdGettimeEventID:      EventConfig{ID: TimerfdGettimeEventID, ID32Bit: sys32timerfd_gettime, Name: "timerfd_gettime", Probes: []probe{probe{event: "timerfd_gettime", attach: sysCall, fn: "timerfd_gettime"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	Accept4EventID:             EventConfig{ID: Accept4EventID, ID32Bit: sys32accept4, Name: "accept4", Probes: []probe{probe{event: "accept4", attach: sysCall, fn: "accept4"}}, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	Signalfd4EventID:           EventConfig{ID: Signalfd4EventID, ID32Bit: sys32signalfd4, Name: "signalfd4", Probes: []probe{probe{event: "signalfd4", attach: sysCall, fn: "signalfd4"}}, Sets: []string{"syscalls", "signals"}},
	Eventfd2EventID:            EventConfig{ID: Eventfd2EventID, ID32Bit: sys32eventfd2, Name: "eventfd2", Probes: []probe{probe{event: "eventfd2", attach: sysCall, fn: "eventfd2"}}, Sets: []string{"syscalls", "signals"}},
	EpollCreate1EventID:        EventConfig{ID: EpollCreate1EventID, ID32Bit: sys32epoll_create1, Name: "epoll_create1", Probes: []probe{probe{event: "epoll_create1", attach: sysCall, fn: "epoll_create1"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	Dup3EventID:                EventConfig{ID: Dup3EventID, ID32Bit: sys32dup3, Name: "dup3", Probes: []probe{probe{event: "dup3", attach: sysCall, fn: "dup3"}}, Sets: []string{"default", "syscalls", "fs", "fs_fd_ops"}},
	Pipe2EventID:               EventConfig{ID: Pipe2EventID, ID32Bit: sys32pipe2, Name: "pipe2", Probes: []probe{probe{event: "pipe2", attach: sysCall, fn: "pipe2"}}, Sets: []string{"syscalls", "ipc", "ipc_pipe"}},
	InotifyInit1EventID:        EventConfig{ID: InotifyInit1EventID, ID32Bit: sys32inotify_init1, Name: "inotify_init1", Probes: []probe{probe{event: "inotify_init1", attach: sysCall, fn: "inotify_init1"}}, Sets: []string{"syscalls", "fs", "fs_monitor"}},
	PreadvEventID:              EventConfig{ID: PreadvEventID, ID32Bit: sys32preadv, Name: "preadv", Probes: []probe{probe{event: "preadv", attach: sysCall, fn: "preadv"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	PwritevEventID:             EventConfig{ID: PwritevEventID, ID32Bit: sys32pwritev, Name: "pwritev", Probes: []probe{probe{event: "pwritev", attach: sysCall, fn: "pwritev"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	RtTgsigqueueinfoEventID:    EventConfig{ID: RtTgsigqueueinfoEventID, ID32Bit: sys32rt_tgsigqueueinfo, Name: "rt_tgsigqueueinfo", Probes: []probe{probe{event: "rt_tgsigqueueinfo", attach: sysCall, fn: "rt_tgsigqueueinfo"}}, Sets: []string{"syscalls", "signals"}},
	PerfEventOpenEventID:       EventConfig{ID: PerfEventOpenEventID, ID32Bit: sys32perf_event_open, Name: "perf_event_open", Probes: []probe{probe{event: "perf_event_open", attach: sysCall, fn: "perf_event_open"}}, Sets: []string{"syscalls", "system"}},
	RecvmmsgEventID:            EventConfig{ID: RecvmmsgEventID, ID32Bit: sys32recvmmsg, Name: "recvmmsg", Probes: []probe{probe{event: "recvmmsg", attach: sysCall, fn: "recvmmsg"}}, Sets: []string{"syscalls", "net", "net_snd_rcv"}},
	FanotifyInitEventID:        EventConfig{ID: FanotifyInitEventID, ID32Bit: sys32fanotify_init, Name: "fanotify_init", Probes: []probe{probe{event: "fanotify_init", attach: sysCall, fn: "fanotify_init"}}, Sets: []string{"syscalls", "fs", "fs_monitor"}},
	FanotifyMarkEventID:        EventConfig{ID: FanotifyMarkEventID, ID32Bit: sys32fanotify_mark, Name: "fanotify_mark", Probes: []probe{probe{event: "fanotify_mark", attach: sysCall, fn: "fanotify_mark"}}, Sets: []string{"syscalls", "fs", "fs_monitor"}},
	Prlimit64EventID:           EventConfig{ID: Prlimit64EventID, ID32Bit: sys32prlimit64, Name: "prlimit64", Probes: []probe{probe{event: "prlimit64", attach: sysCall, fn: "prlimit64"}}, Sets: []string{"syscalls", "proc"}},
	NameToHandleAtEventID:      EventConfig{ID: NameToHandleAtEventID, ID32Bit: sys32name_to_handle_at, Name: "name_to_handle_at", Probes: []probe{probe{event: "name_to_handle_at", attach: sysCall, fn: "name_to_handle_at"}}, Sets: []string{"syscalls", "fs", "fs_file_ops"}},
	OpenByHandleAtEventID:      EventConfig{ID: OpenByHandleAtEventID, ID32Bit: sys32open_by_handle_at, Name: "open_by_handle_at", Probes: []probe{probe{event: "open_by_handle_at", attach: sysCall, fn: "open_by_handle_at"}}, Sets: []string{"syscalls", "fs", "fs_file_ops"}},
	ClockAdjtimeEventID:        EventConfig{ID: ClockAdjtimeEventID, ID32Bit: sys32clock_adjtime, Name: "clock_adjtime", Probes: []probe{probe{event: "clock_adjtime", attach: sysCall, fn: "clock_adjtime"}}, Sets: []string{"syscalls", "time", "time_clock"}},
	SyncfsEventID:              EventConfig{ID: SyncfsEventID, ID32Bit: sys32syncfs, Name: "syncfs", Probes: []probe{probe{event: "syncfs", attach: sysCall, fn: "syncfs"}}, Sets: []string{"syscalls", "fs", "fs_sync"}},
	SendmmsgEventID:            EventConfig{ID: SendmmsgEventID, ID32Bit: sys32sendmmsg, Name: "sendmmsg", Probes: []probe{probe{event: "sendmmsg", attach: sysCall, fn: "sendmmsg"}}, Sets: []string{"syscalls", "net", "net_snd_rcv"}},
	SetnsEventID:               EventConfig{ID: SetnsEventID, ID32Bit: sys32setns, Name: "setns", Probes: []probe{probe{event: "setns", attach: sysCall, fn: "setns"}}, Sets: []string{"syscalls", "proc"}},
	GetcpuEventID:              EventConfig{ID: GetcpuEventID, ID32Bit: sys32getcpu, Name: "getcpu", Probes: []probe{probe{event: "getcpu", attach: sysCall, fn: "getcpu"}}, Sets: []string{"syscalls", "system", "system_numa"}},
	ProcessVmReadvEventID:      EventConfig{ID: ProcessVmReadvEventID, ID32Bit: sys32process_vm_readv, Name: "process_vm_readv", Probes: []probe{probe{event: "process_vm_readv", attach: sysCall, fn: "process_vm_readv"}}, Sets: []string{"default", "syscalls", "proc"}},
	ProcessVmWritevEventID:     EventConfig{ID: ProcessVmWritevEventID, ID32Bit: sys32process_vm_writev, Name: "process_vm_writev", Probes: []probe{probe{event: "process_vm_writev", attach: sysCall, fn: "process_vm_writev"}}, Sets: []string{"default", "syscalls", "proc"}},
	KcmpEventID:                EventConfig{ID: KcmpEventID, ID32Bit: sys32kcmp, Name: "kcmp", Probes: []probe{probe{event: "kcmp", attach: sysCall, fn: "kcmp"}}, Sets: []string{"syscalls", "proc"}},
	FinitModuleEventID:         EventConfig{ID: FinitModuleEventID, ID32Bit: sys32finit_module, Name: "finit_module", Probes: []probe{probe{event: "finit_module", attach: sysCall, fn: "finit_module"}}, Sets: []string{"default", "syscalls", "system", "system_module"}},
	SchedSetattrEventID:        EventConfig{ID: SchedSetattrEventID, ID32Bit: sys32sched_setattr, Name: "sched_setattr", Probes: []probe{probe{event: "sched_setattr", attach: sysCall, fn: "sched_setattr"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedGetattrEventID:        EventConfig{ID: SchedGetattrEventID, ID32Bit: sys32sched_getattr, Name: "sched_getattr", Probes: []probe{probe{event: "sched_getattr", attach: sysCall, fn: "sched_getattr"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	Renameat2EventID:           EventConfig{ID: Renameat2EventID, ID32Bit: sys32renameat2, Name: "renameat2", Probes: []probe{probe{event: "renameat2", attach: sysCall, fn: "renameat2"}}, Sets: []string{"syscalls", "fs", "fs_file_ops"}},
	SeccompEventID:             EventConfig{ID: SeccompEventID, ID32Bit: sys32seccomp, Name: "seccomp", Probes: []probe{probe{event: "seccomp", attach: sysCall, fn: "seccomp"}}, Sets: []string{"syscalls", "proc"}},
	GetrandomEventID:           EventConfig{ID: GetrandomEventID, ID32Bit: sys32getrandom, Name: "getrandom", Probes: []probe{probe{event: "getrandom", attach: sysCall, fn: "getrandom"}}, Sets: []string{"syscalls", "fs"}},
	MemfdCreateEventID:         EventConfig{ID: MemfdCreateEventID, ID32Bit: sys32memfd_create, Name: "memfd_create", Probes: []probe{probe{event: "memfd_create", attach: sysCall, fn: "memfd_create"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	KexecFileLoadEventID:       EventConfig{ID: KexecFileLoadEventID, ID32Bit: sys32undefined, Name: "kexec_file_load", Probes: []probe{probe{event: "kexec_file_load", attach: sysCall, fn: "kexec_file_load"}}, Sets: []string{"syscalls", "system"}},
	BpfEventID:                 EventConfig{ID: BpfEventID, ID32Bit: sys32bpf, Name: "bpf", Probes: []probe{probe{event: "bpf", attach: sysCall, fn: "bpf"}}, Sets: []string{"syscalls", "system"}},
	ExecveatEventID:            EventConfig{ID: ExecveatEventID, ID32Bit: sys32execveat, Name: "execveat", Probes: []probe{probe{event: "execveat", attach: sysCall, fn: "execveat"}}, Sets: []string{"default", "syscalls", "proc", "proc_life"}},
	UserfaultfdEventID:         EventConfig{ID: UserfaultfdEventID, ID32Bit: sys32userfaultfd, Name: "userfaultfd", Probes: []probe{probe{event: "userfaultfd", attach: sysCall, fn: "userfaultfd"}}, Sets: []string{"syscalls", "system"}},
	MembarrierEventID:          EventConfig{ID: MembarrierEventID, ID32Bit: sys32membarrier, Name: "membarrier", Probes: []probe{probe{event: "membarrier", attach: sysCall, fn: "membarrier"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	Mlock2EventID:              EventConfig{ID: Mlock2EventID, ID32Bit: sys32mlock2, Name: "mlock2", Probes: []probe{probe{event: "mlock2", attach: sysCall, fn: "mlock2"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	CopyFileRangeEventID:       EventConfig{ID: CopyFileRangeEventID, ID32Bit: sys32copy_file_range, Name: "copy_file_range", Probes: []probe{probe{event: "copy_file_range", attach: sysCall, fn: "copy_file_range"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	Preadv2EventID:             EventConfig{ID: Preadv2EventID, ID32Bit: sys32preadv2, Name: "preadv2", Probes: []probe{probe{event: "preadv2", attach: sysCall, fn: "preadv2"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	Pwritev2EventID:            EventConfig{ID: Pwritev2EventID, ID32Bit: sys32pwritev2, Name: "pwritev2", Probes: []probe{probe{event: "pwritev2", attach: sysCall, fn: "pwritev2"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	PkeyMprotectEventID:        EventConfig{ID: PkeyMprotectEventID, ID32Bit: sys32pkey_mprotect, Name: "pkey_mprotect", Probes: []probe{probe{event: "pkey_mprotect", attach: sysCall, fn: "pkey_mprotect"}}, Sets: []string{"default", "syscalls", "proc", "proc_mem"}},
	PkeyAllocEventID:           EventConfig{ID: PkeyAllocEventID, ID32Bit: sys32pkey_alloc, Name: "pkey_alloc", Probes: []probe{probe{event: "pkey_alloc", attach: sysCall, fn: "pkey_alloc"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	PkeyFreeEventID:            EventConfig{ID: PkeyFreeEventID, ID32Bit: sys32pkey_free, Name: "pkey_free", Probes: []probe{probe{event: "pkey_free", attach: sysCall, fn: "pkey_free"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	StatxEventID:               EventConfig{ID: StatxEventID, ID32Bit: sys32statx, Name: "statx", Probes: []probe{probe{event: "statx", attach: sysCall, fn: "statx"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	IoPgeteventsEventID:        EventConfig{ID: IoPgeteventsEventID, ID32Bit: sys32io_pgetevents, Name: "io_pgetevents", Probes: []probe{probe{event: "io_pgetevents", attach: sysCall, fn: "io_pgetevents"}}, Sets: []string{"syscalls", "fs", "fs_async_io"}},
	RseqEventID:                EventConfig{ID: RseqEventID, ID32Bit: sys32rseq, Name: "rseq", Probes: []probe{probe{event: "rseq", attach: sysCall, fn: "rseq"}}, Sets: []string{"syscalls"}},
	SysEnterEventID:            EventConfig{ID: SysEnterEventID, ID32Bit: sys32undefined, Name: "sys_enter", Probes: []probe{probe{event: "raw_syscalls:sys_enter", attach: rawTracepoint, fn: "tracepoint__raw_syscalls__sys_enter"}}, EssentialEvent: true, Sets: []string{}},
	SysExitEventID:             EventConfig{ID: SysExitEventID, ID32Bit: sys32undefined, Name: "sys_exit", Probes: []probe{probe{event: "raw_syscalls:sys_exit", attach: rawTracepoint, fn: "tracepoint__raw_syscalls__sys_exit"}}, EssentialEvent: true, Sets: []string{}},
	DoExitEventID:              EventConfig{ID: DoExitEventID, ID32Bit: sys32undefined, Name: "do_exit", Probes: []probe{probe{event: "do_exit", attach: kprobe, fn: "trace_do_exit"}}, EssentialEvent: true, Sets: []string{"default"}},
	CapCapableEventID:          EventConfig{ID: CapCapableEventID, ID32Bit: sys32undefined, Name: "cap_capable", Probes: []probe{probe{event: "cap_capable", attach: kprobe, fn: "trace_cap_capable"}}, Sets: []string{"default"}},
	SecurityBprmCheckEventID:   EventConfig{ID: SecurityBprmCheckEventID, ID32Bit: sys32undefined, Name: "security_bprm_check", Probes: []probe{probe{event: "security_bprm_check", attach: kprobe, fn: "trace_security_bprm_check"}}, Sets: []string{"default"}},
	SecurityFileOpenEventID:    EventConfig{ID: SecurityFileOpenEventID, ID32Bit: sys32undefined, Name: "security_file_open", Probes: []probe{probe{event: "security_file_open", attach: kprobe, fn: "trace_security_file_open"}}, Sets: []string{"default"}},
	VfsWriteEventID:            EventConfig{ID: VfsWriteEventID, ID32Bit: sys32undefined, Name: "vfs_write", Probes: []probe{probe{event: "vfs_write", attach: kprobe, fn: "trace_vfs_write"}, probe{event: "vfs_write", attach: kretprobe, fn: "trace_ret_vfs_write"}}, Sets: []string{"default"}},
	VfsWritevEventID:           EventConfig{ID: VfsWritevEventID, ID32Bit: sys32undefined, Name: "vfs_writev", Probes: []probe{probe{event: "vfs_writev", attach: kprobe, fn: "trace_vfs_writev"}, probe{event: "vfs_writev", attach: kretprobe, fn: "trace_ret_vfs_writev"}}, Sets: []string{"default"}},
	MemProtAlertEventID:        EventConfig{ID: MemProtAlertEventID, ID32Bit: sys32undefined, Name: "mem_prot_alert", Probes: []probe{probe{event: "security_mmap_addr", attach: kprobe, fn: "trace_mmap_alert"}, probe{event: "security_file_mprotect", attach: kprobe, fn: "trace_mprotect_alert"}}, Sets: []string{}},
}

type param struct {
	pType string
	pName string
}

// EventsIDToParams is list of the parameters (name and type) used by the events
var EventsIDToParams = map[int32][]param{
	ReadEventID:                []param{param{pType: "int", pName: "fd"}, param{pType: "void*", pName: "buf"}, param{pType: "size_t", pName: "count"}},
	WriteEventID:               []param{param{pType: "int", pName: "fd"}, param{pType: "void*", pName: "buf"}, param{pType: "size_t", pName: "count"}},
	OpenEventID:                []param{param{pType: "const char*", pName: "pathname"}, param{pType: "int", pName: "flags"}, param{pType: "mode_t", pName: "mode"}},
	CloseEventID:               []param{param{pType: "int", pName: "fd"}},
	StatEventID:                []param{param{pType: "const char*", pName: "pathname"}, param{pType: "struct stat*", pName: "statbuf"}},
	FstatEventID:               []param{param{pType: "int", pName: "fd"}, param{pType: "struct stat*", pName: "statbuf"}},
	LstatEventID:               []param{param{pType: "const char*", pName: "pathname"}, param{pType: "struct stat*", pName: "statbuf"}},
	PollEventID:                []param{param{pType: "struct pollfd*", pName: "fds"}, param{pType: "unsigned int", pName: "nfds"}, param{pType: "int", pName: "timeout"}},
	LseekEventID:               []param{param{pType: "int", pName: "fd"}, param{pType: "off_t", pName: "offset"}, param{pType: "unsigned int", pName: "whence"}},
	MmapEventID:                []param{param{pType: "void*", pName: "addr"}, param{pType: "size_t", pName: "length"}, param{pType: "int", pName: "prot"}, param{pType: "int", pName: "flags"}, param{pType: "int", pName: "fd"}, param{pType: "off_t", pName: "off"}},
	MprotectEventID:            []param{param{pType: "void*", pName: "addr"}, param{pType: "size_t", pName: "len"}, param{pType: "int", pName: "prot"}},
	MunmapEventID:              []param{param{pType: "void*", pName: "addr"}, param{pType: "size_t", pName: "length"}},
	BrkEventID:                 []param{param{pType: "void*", pName: "addr"}},
	RtSigactionEventID:         []param{param{pType: "int", pName: "signum"}, param{pType: "const struct sigaction*", pName: "act"}, param{pType: "struct sigaction*", pName: "oldact"}, param{pType: "size_t", pName: "sigsetsize"}},
	RtSigprocmaskEventID:       []param{param{pType: "int", pName: "how"}, param{pType: "sigset_t*", pName: "set"}, param{pType: "sigset_t*", pName: "oldset"}, param{pType: "size_t", pName: "sigsetsize"}},
	RtSigreturnEventID:         []param{},
	IoctlEventID:               []param{param{pType: "int", pName: "fd"}, param{pType: "unsigned long", pName: "request"}, param{pType: "unsigned long", pName: "arg"}},
	Pread64EventID:             []param{param{pType: "int", pName: "fd"}, param{pType: "void*", pName: "buf"}, param{pType: "size_t", pName: "count"}, param{pType: "off_t", pName: "offset"}},
	Pwrite64EventID:            []param{param{pType: "int", pName: "fd"}, param{pType: "const void*", pName: "buf"}, param{pType: "size_t", pName: "count"}, param{pType: "off_t", pName: "offset"}},
	ReadvEventID:               []param{param{pType: "int", pName: "fd"}, param{pType: "const struct iovec*", pName: "iov"}, param{pType: "int", pName: "iovcnt"}},
	WritevEventID:              []param{param{pType: "int", pName: "fd"}, param{pType: "const struct iovec*", pName: "iov"}, param{pType: "int", pName: "iovcnt"}},
	AccessEventID:              []param{param{pType: "const char*", pName: "pathname"}, param{pType: "int", pName: "mode"}},
	PipeEventID:                []param{param{pType: "int[2]", pName: "pipefd"}},
	SelectEventID:              []param{param{pType: "int", pName: "nfds"}, param{pType: "fd_set*", pName: "readfds"}, param{pType: "fd_set*", pName: "writefds"}, param{pType: "fd_set*", pName: "exceptfds"}, param{pType: "struct timeval*", pName: "timeout"}},
	SchedYieldEventID:          []param{},
	MremapEventID:              []param{param{pType: "void*", pName: "old_address"}, param{pType: "size_t", pName: "old_size"}, param{pType: "size_t", pName: "new_size"}, param{pType: "int", pName: "flags"}, param{pType: "void*", pName: "new_address"}},
	MsyncEventID:               []param{param{pType: "void*", pName: "addr"}, param{pType: "size_t", pName: "length"}, param{pType: "int", pName: "flags"}},
	MincoreEventID:             []param{param{pType: "void*", pName: "addr"}, param{pType: "size_t", pName: "length"}, param{pType: "unsigned char*", pName: "vec"}},
	MadviseEventID:             []param{param{pType: "void*", pName: "addr"}, param{pType: "size_t", pName: "length"}, param{pType: "int", pName: "advice"}},
	ShmgetEventID:              []param{param{pType: "key_t", pName: "key"}, param{pType: "size_t", pName: "size"}, param{pType: "int", pName: "shmflg"}},
	ShmatEventID:               []param{param{pType: "int", pName: "shmid"}, param{pType: "const void*", pName: "shmaddr"}, param{pType: "int", pName: "shmflg"}},
	ShmctlEventID:              []param{param{pType: "int", pName: "shmid"}, param{pType: "int", pName: "cmd"}, param{pType: "struct shmid_ds*", pName: "buf"}},
	DupEventID:                 []param{param{pType: "int", pName: "oldfd"}},
	Dup2EventID:                []param{param{pType: "int", pName: "oldfd"}, param{pType: "int", pName: "newfd"}},
	PauseEventID:               []param{},
	NanosleepEventID:           []param{param{pType: "const struct timespec*", pName: "req"}, param{pType: "struct timespec*", pName: "rem"}},
	GetitimerEventID:           []param{param{pType: "int", pName: "which"}, param{pType: "struct itimerval*", pName: "curr_value"}},
	AlarmEventID:               []param{param{pType: "unsigned int", pName: "seconds"}},
	SetitimerEventID:           []param{param{pType: "int", pName: "which"}, param{pType: "struct itimerval*", pName: "new_value"}, param{pType: "struct itimerval*", pName: "old_value"}},
	GetpidEventID:              []param{},
	SendfileEventID:            []param{param{pType: "int", pName: "out_fd"}, param{pType: "int", pName: "in_fd"}, param{pType: "off_t*", pName: "offset"}, param{pType: "size_t", pName: "count"}},
	SocketEventID:              []param{param{pType: "int", pName: "domain"}, param{pType: "int", pName: "type"}, param{pType: "int", pName: "protocol"}},
	ConnectEventID:             []param{param{pType: "int", pName: "sockfd"}, param{pType: "struct sockaddr*", pName: "addr"}, param{pType: "int", pName: "addrlen"}},
	AcceptEventID:              []param{param{pType: "int", pName: "sockfd"}, param{pType: "struct sockaddr*", pName: "addr"}, param{pType: "int*", pName: "addrlen"}},
	SendtoEventID:              []param{param{pType: "int", pName: "sockfd"}, param{pType: "void*", pName: "buf"}, param{pType: "size_t", pName: "len"}, param{pType: "int", pName: "flags"}, param{pType: "struct sockaddr*", pName: "dest_addr"}, param{pType: "int", pName: "addrlen"}},
	RecvfromEventID:            []param{param{pType: "int", pName: "sockfd"}, param{pType: "void*", pName: "buf"}, param{pType: "size_t", pName: "len"}, param{pType: "int", pName: "flags"}, param{pType: "struct sockaddr*", pName: "src_addr"}, param{pType: "int*", pName: "addrlen"}},
	SendmsgEventID:             []param{param{pType: "int", pName: "sockfd"}, param{pType: "struct msghdr*", pName: "msg"}, param{pType: "int", pName: "flags"}},
	RecvmsgEventID:             []param{param{pType: "int", pName: "sockfd"}, param{pType: "struct msghdr*", pName: "msg"}, param{pType: "int", pName: "flags"}},
	ShutdownEventID:            []param{param{pType: "int", pName: "sockfd"}, param{pType: "int", pName: "how"}},
	BindEventID:                []param{param{pType: "int", pName: "sockfd"}, param{pType: "struct sockaddr*", pName: "addr"}, param{pType: "int", pName: "addrlen"}},
	ListenEventID:              []param{param{pType: "int", pName: "sockfd"}, param{pType: "int", pName: "backlog"}},
	GetsocknameEventID:         []param{param{pType: "int", pName: "sockfd"}, param{pType: "struct sockaddr*", pName: "addr"}, param{pType: "int*", pName: "addrlen"}},
	GetpeernameEventID:         []param{param{pType: "int", pName: "sockfd"}, param{pType: "struct sockaddr*", pName: "addr"}, param{pType: "int*", pName: "addrlen"}},
	SocketpairEventID:          []param{param{pType: "int", pName: "domain"}, param{pType: "int", pName: "type"}, param{pType: "int", pName: "protocol"}, param{pType: "int[2]", pName: "sv"}},
	SetsockoptEventID:          []param{param{pType: "int", pName: "sockfd"}, param{pType: "int", pName: "level"}, param{pType: "int", pName: "optname"}, param{pType: "const void*", pName: "optval"}, param{pType: "int", pName: "optlen"}},
	GetsockoptEventID:          []param{param{pType: "int", pName: "sockfd"}, param{pType: "int", pName: "level"}, param{pType: "int", pName: "optname"}, param{pType: "char*", pName: "optval"}, param{pType: "int*", pName: "optlen"}},
	CloneEventID:               []param{param{pType: "unsigned long", pName: "flags"}, param{pType: "void*", pName: "stack"}, param{pType: "int*", pName: "parent_tid"}, param{pType: "int*", pName: "child_tid"}, param{pType: "unsigned long", pName: "tls"}},
	ForkEventID:                []param{},
	VforkEventID:               []param{},
	ExecveEventID:              []param{param{pType: "const char*", pName: "pathname"}, param{pType: "const char*const*", pName: "argv"}, param{pType: "const char*const*", pName: "envp"}},
	ExitEventID:                []param{param{pType: "int", pName: "status"}},
	Wait4EventID:               []param{param{pType: "pid_t", pName: "pid"}, param{pType: "int*", pName: "wstatus"}, param{pType: "int", pName: "options"}, param{pType: "struct rusage*", pName: "rusage"}},
	KillEventID:                []param{param{pType: "pid_t", pName: "pid"}, param{pType: "int", pName: "sig"}},
	UnameEventID:               []param{param{pType: "struct utsname*", pName: "buf"}},
	SemgetEventID:              []param{param{pType: "key_t", pName: "key"}, param{pType: "int", pName: "nsems"}, param{pType: "int", pName: "semflg"}},
	SemopEventID:               []param{param{pType: "int", pName: "semid"}, param{pType: "struct sembuf*", pName: "sops"}, param{pType: "size_t", pName: "nsops"}},
	SemctlEventID:              []param{param{pType: "int", pName: "semid"}, param{pType: "int", pName: "semnum"}, param{pType: "int", pName: "cmd"}, param{pType: "unsigned long", pName: "arg"}},
	ShmdtEventID:               []param{param{pType: "const void*", pName: "shmaddr"}},
	MsggetEventID:              []param{param{pType: "key_t", pName: "key"}, param{pType: "int", pName: "msgflg"}},
	MsgsndEventID:              []param{param{pType: "int", pName: "msqid"}, param{pType: "struct msgbuf*", pName: "msgp"}, param{pType: "size_t", pName: "msgsz"}, param{pType: "int", pName: "msgflg"}},
	MsgrcvEventID:              []param{param{pType: "int", pName: "msqid"}, param{pType: "struct msgbuf*", pName: "msgp"}, param{pType: "size_t", pName: "msgsz"}, param{pType: "long", pName: "msgtyp"}, param{pType: "int", pName: "msgflg"}},
	MsgctlEventID:              []param{param{pType: "int", pName: "msqid"}, param{pType: "int", pName: "cmd"}, param{pType: "struct msqid_ds*", pName: "buf"}},
	FcntlEventID:               []param{param{pType: "int", pName: "fd"}, param{pType: "int", pName: "cmd"}, param{pType: "unsigned long", pName: "arg"}},
	FlockEventID:               []param{param{pType: "int", pName: "fd"}, param{pType: "int", pName: "operation"}},
	FsyncEventID:               []param{param{pType: "int", pName: "fd"}},
	FdatasyncEventID:           []param{param{pType: "int", pName: "fd"}},
	TruncateEventID:            []param{param{pType: "const char*", pName: "path"}, param{pType: "off_t", pName: "length"}},
	FtruncateEventID:           []param{param{pType: "int", pName: "fd"}, param{pType: "off_t", pName: "length"}},
	GetdentsEventID:            []param{param{pType: "int", pName: "fd"}, param{pType: "struct linux_dirent*", pName: "dirp"}, param{pType: "unsigned int", pName: "count"}},
	GetcwdEventID:              []param{param{pType: "char*", pName: "buf"}, param{pType: "size_t", pName: "size"}},
	ChdirEventID:               []param{param{pType: "const char*", pName: "path"}},
	FchdirEventID:              []param{param{pType: "int", pName: "fd"}},
	RenameEventID:              []param{param{pType: "const char*", pName: "oldpath"}, param{pType: "const char*", pName: "newpath"}},
	MkdirEventID:               []param{param{pType: "const char*", pName: "pathname"}, param{pType: "mode_t", pName: "mode"}},
	RmdirEventID:               []param{param{pType: "const char*", pName: "pathname"}},
	CreatEventID:               []param{param{pType: "const char*", pName: "pathname"}, param{pType: "mode_t", pName: "mode"}},
	LinkEventID:                []param{param{pType: "const char*", pName: "oldpath"}, param{pType: "const char*", pName: "newpath"}},
	UnlinkEventID:              []param{param{pType: "const char*", pName: "pathname"}},
	SymlinkEventID:             []param{param{pType: "const char*", pName: "target"}, param{pType: "const char*", pName: "linkpath"}},
	ReadlinkEventID:            []param{param{pType: "const char*", pName: "pathname"}, param{pType: "char*", pName: "buf"}, param{pType: "size_t", pName: "bufsiz"}},
	ChmodEventID:               []param{param{pType: "const char*", pName: "pathname"}, param{pType: "mode_t", pName: "mode"}},
	FchmodEventID:              []param{param{pType: "int", pName: "fd"}, param{pType: "mode_t", pName: "mode"}},
	ChownEventID:               []param{param{pType: "const char*", pName: "pathname"}, param{pType: "uid_t", pName: "owner"}, param{pType: "gid_t", pName: "group"}},
	FchownEventID:              []param{param{pType: "int", pName: "fd"}, param{pType: "uid_t", pName: "owner"}, param{pType: "gid_t", pName: "group"}},
	LchownEventID:              []param{param{pType: "const char*", pName: "pathname"}, param{pType: "uid_t", pName: "owner"}, param{pType: "gid_t", pName: "group"}},
	UmaskEventID:               []param{param{pType: "mode_t", pName: "mask"}},
	GettimeofdayEventID:        []param{param{pType: "struct timeval*", pName: "tv"}, param{pType: "struct timezone*", pName: "tz"}},
	GetrlimitEventID:           []param{param{pType: "int", pName: "resource"}, param{pType: "struct rlimit*", pName: "rlim"}},
	GetrusageEventID:           []param{param{pType: "int", pName: "who"}, param{pType: "struct rusage*", pName: "usage"}},
	SysinfoEventID:             []param{param{pType: "struct sysinfo*", pName: "info"}},
	TimesEventID:               []param{param{pType: "struct tms*", pName: "buf"}},
	PtraceEventID:              []param{param{pType: "long", pName: "request"}, param{pType: "pid_t", pName: "pid"}, param{pType: "void*", pName: "addr"}, param{pType: "void*", pName: "data"}},
	GetuidEventID:              []param{},
	SyslogEventID:              []param{param{pType: "int", pName: "type"}, param{pType: "char*", pName: "bufp"}, param{pType: "int", pName: "len"}},
	GetgidEventID:              []param{},
	SetuidEventID:              []param{param{pType: "uid_t", pName: "uid"}},
	SetgidEventID:              []param{param{pType: "gid_t", pName: "gid"}},
	GeteuidEventID:             []param{},
	GetegidEventID:             []param{},
	SetpgidEventID:             []param{param{pType: "pid_t", pName: "pid"}, param{pType: "pid_t", pName: "pgid"}},
	GetppidEventID:             []param{},
	GetpgrpEventID:             []param{},
	SetsidEventID:              []param{},
	SetreuidEventID:            []param{param{pType: "uid_t", pName: "ruid"}, param{pType: "uid_t", pName: "euid"}},
	SetregidEventID:            []param{param{pType: "gid_t", pName: "rgid"}, param{pType: "gid_t", pName: "egid"}},
	GetgroupsEventID:           []param{param{pType: "int", pName: "size"}, param{pType: "gid_t*", pName: "list"}},
	SetgroupsEventID:           []param{param{pType: "int", pName: "size"}, param{pType: "gid_t*", pName: "list"}},
	SetresuidEventID:           []param{param{pType: "uid_t", pName: "ruid"}, param{pType: "uid_t", pName: "euid"}, param{pType: "uid_t", pName: "suid"}},
	GetresuidEventID:           []param{param{pType: "uid_t*", pName: "ruid"}, param{pType: "uid_t*", pName: "euid"}, param{pType: "uid_t*", pName: "suid"}},
	SetresgidEventID:           []param{param{pType: "gid_t", pName: "rgid"}, param{pType: "gid_t", pName: "egid"}, param{pType: "gid_t", pName: "sgid"}},
	GetresgidEventID:           []param{param{pType: "gid_t*", pName: "rgid"}, param{pType: "gid_t*", pName: "egid"}, param{pType: "gid_t*", pName: "sgid"}},
	GetpgidEventID:             []param{param{pType: "pid_t", pName: "pid"}},
	SetfsuidEventID:            []param{param{pType: "uid_t", pName: "fsuid"}},
	SetfsgidEventID:            []param{param{pType: "gid_t", pName: "fsgid"}},
	GetsidEventID:              []param{param{pType: "pid_t", pName: "pid"}},
	CapgetEventID:              []param{param{pType: "cap_user_header_t", pName: "hdrp"}, param{pType: "cap_user_data_t", pName: "datap"}},
	CapsetEventID:              []param{param{pType: "cap_user_header_t", pName: "hdrp"}, param{pType: "const cap_user_data_t", pName: "datap"}},
	RtSigpendingEventID:        []param{param{pType: "sigset_t*", pName: "set"}, param{pType: "size_t", pName: "sigsetsize"}},
	RtSigtimedwaitEventID:      []param{param{pType: "const sigset_t*", pName: "set"}, param{pType: "siginfo_t*", pName: "info"}, param{pType: "const struct timespec*", pName: "timeout"}, param{pType: "size_t", pName: "sigsetsize"}},
	RtSigqueueinfoEventID:      []param{param{pType: "pid_t", pName: "tgid"}, param{pType: "int", pName: "sig"}, param{pType: "siginfo_t*", pName: "info"}},
	RtSigsuspendEventID:        []param{param{pType: "sigset_t*", pName: "mask"}, param{pType: "size_t", pName: "sigsetsize"}},
	SigaltstackEventID:         []param{param{pType: "const stack_t*", pName: "ss"}, param{pType: "stack_t*", pName: "old_ss"}},
	UtimeEventID:               []param{param{pType: "const char*", pName: "filename"}, param{pType: "const struct utimbuf*", pName: "times"}},
	MknodEventID:               []param{param{pType: "const char*", pName: "pathname"}, param{pType: "mode_t", pName: "mode"}, param{pType: "dev_t", pName: "dev"}},
	UselibEventID:              []param{param{pType: "const char*", pName: "library"}},
	PersonalityEventID:         []param{param{pType: "unsigned long", pName: "persona"}},
	UstatEventID:               []param{param{pType: "dev_t", pName: "dev"}, param{pType: "struct ustat*", pName: "ubuf"}},
	StatfsEventID:              []param{param{pType: "const char*", pName: "path"}, param{pType: "struct statfs*", pName: "buf"}},
	FstatfsEventID:             []param{param{pType: "int", pName: "fd"}, param{pType: "struct statfs*", pName: "buf"}},
	SysfsEventID:               []param{param{pType: "int", pName: "option"}},
	GetpriorityEventID:         []param{param{pType: "int", pName: "which"}, param{pType: "int", pName: "who"}},
	SetpriorityEventID:         []param{param{pType: "int", pName: "which"}, param{pType: "int", pName: "who"}, param{pType: "int", pName: "prio"}},
	SchedSetparamEventID:       []param{param{pType: "pid_t", pName: "pid"}, param{pType: "struct sched_param*", pName: "param"}},
	SchedGetparamEventID:       []param{param{pType: "pid_t", pName: "pid"}, param{pType: "struct sched_param*", pName: "param"}},
	SchedSetschedulerEventID:   []param{param{pType: "pid_t", pName: "pid"}, param{pType: "int", pName: "policy"}, param{pType: "struct sched_param*", pName: "param"}},
	SchedGetschedulerEventID:   []param{param{pType: "pid_t", pName: "pid"}},
	SchedGetPriorityMaxEventID: []param{param{pType: "int", pName: "policy"}},
	SchedGetPriorityMinEventID: []param{param{pType: "int", pName: "policy"}},
	SchedRrGetIntervalEventID:  []param{param{pType: "pid_t", pName: "pid"}, param{pType: "struct timespec*", pName: "tp"}},
	MlockEventID:               []param{param{pType: "const void*", pName: "addr"}, param{pType: "size_t", pName: "len"}},
	MunlockEventID:             []param{param{pType: "const void*", pName: "addr"}, param{pType: "size_t", pName: "len"}},
	MlockallEventID:            []param{param{pType: "int", pName: "flags"}},
	MunlockallEventID:          []param{},
	VhangupEventID:             []param{},
	ModifyLdtEventID:           []param{param{pType: "int", pName: "func"}, param{pType: "void*", pName: "ptr"}, param{pType: "unsigned long", pName: "bytecount"}},
	PivotRootEventID:           []param{param{pType: "const char*", pName: "new_root"}, param{pType: "const char*", pName: "put_old"}},
	SysctlEventID:              []param{param{pType: "struct __sysctl_args*", pName: "args"}},
	PrctlEventID:               []param{param{pType: "int", pName: "option"}, param{pType: "unsigned long", pName: "arg2"}, param{pType: "unsigned long", pName: "arg3"}, param{pType: "unsigned long", pName: "arg4"}, param{pType: "unsigned long", pName: "arg5"}},
	ArchPrctlEventID:           []param{param{pType: "int", pName: "option"}, param{pType: "unsigned long", pName: "addr"}},
	AdjtimexEventID:            []param{param{pType: "struct timex*", pName: "buf"}},
	SetrlimitEventID:           []param{param{pType: "int", pName: "resource"}, param{pType: "const struct rlimit*", pName: "rlim"}},
	ChrootEventID:              []param{param{pType: "const char*", pName: "path"}},
	SyncEventID:                []param{},
	AcctEventID:                []param{param{pType: "const char*", pName: "filename"}},
	SettimeofdayEventID:        []param{param{pType: "const struct timeval*", pName: "tv"}, param{pType: "const struct timezone*", pName: "tz"}},
	MountEventID:               []param{param{pType: "const char*", pName: "source"}, param{pType: "const char*", pName: "target"}, param{pType: "const char*", pName: "filesystemtype"}, param{pType: "unsigned long", pName: "mountflags"}, param{pType: "const void*", pName: "data"}},
	UmountEventID:              []param{param{pType: "const char*", pName: "target"}, param{pType: "int", pName: "flags"}},
	SwaponEventID:              []param{param{pType: "const char*", pName: "path"}, param{pType: "int", pName: "swapflags"}},
	SwapoffEventID:             []param{param{pType: "const char*", pName: "path"}},
	RebootEventID:              []param{param{pType: "int", pName: "magic"}, param{pType: "int", pName: "magic2"}, param{pType: "int", pName: "cmd"}, param{pType: "void*", pName: "arg"}},
	SethostnameEventID:         []param{param{pType: "const char*", pName: "name"}, param{pType: "size_t", pName: "len"}},
	SetdomainnameEventID:       []param{param{pType: "const char*", pName: "name"}, param{pType: "size_t", pName: "len"}},
	IoplEventID:                []param{param{pType: "int", pName: "level"}},
	IopermEventID:              []param{param{pType: "unsigned long", pName: "from"}, param{pType: "unsigned long", pName: "num"}, param{pType: "int", pName: "turn_on"}},
	InitModuleEventID:          []param{param{pType: "void*", pName: "module_image"}, param{pType: "unsigned long", pName: "len"}, param{pType: "const char*", pName: "param_values"}},
	DeleteModuleEventID:        []param{param{pType: "const char*", pName: "name"}, param{pType: "int", pName: "flags"}},
	QuotactlEventID:            []param{param{pType: "int", pName: "cmd"}, param{pType: "const char*", pName: "special"}, param{pType: "int", pName: "id"}, param{pType: "void*", pName: "addr"}},
	GettidEventID:              []param{},
	ReadaheadEventID:           []param{param{pType: "int", pName: "fd"}, param{pType: "off_t", pName: "offset"}, param{pType: "size_t", pName: "count"}},
	SetxattrEventID:            []param{param{pType: "const char*", pName: "path"}, param{pType: "const char*", pName: "name"}, param{pType: "const void*", pName: "value"}, param{pType: "size_t", pName: "size"}, param{pType: "int", pName: "flags"}},
	LsetxattrEventID:           []param{param{pType: "const char*", pName: "path"}, param{pType: "const char*", pName: "name"}, param{pType: "const void*", pName: "value"}, param{pType: "size_t", pName: "size"}, param{pType: "int", pName: "flags"}},
	FsetxattrEventID:           []param{param{pType: "int", pName: "fd"}, param{pType: "const char*", pName: "name"}, param{pType: "const void*", pName: "value"}, param{pType: "size_t", pName: "size"}, param{pType: "int", pName: "flags"}},
	GetxattrEventID:            []param{param{pType: "const char*", pName: "path"}, param{pType: "const char*", pName: "name"}, param{pType: "void*", pName: "value"}, param{pType: "size_t", pName: "size"}},
	LgetxattrEventID:           []param{param{pType: "const char*", pName: "path"}, param{pType: "const char*", pName: "name"}, param{pType: "void*", pName: "value"}, param{pType: "size_t", pName: "size"}},
	FgetxattrEventID:           []param{param{pType: "int", pName: "fd"}, param{pType: "const char*", pName: "name"}, param{pType: "void*", pName: "value"}, param{pType: "size_t", pName: "size"}},
	ListxattrEventID:           []param{param{pType: "const char*", pName: "path"}, param{pType: "char*", pName: "list"}, param{pType: "size_t", pName: "size"}},
	LlistxattrEventID:          []param{param{pType: "const char*", pName: "path"}, param{pType: "char*", pName: "list"}, param{pType: "size_t", pName: "size"}},
	FlistxattrEventID:          []param{param{pType: "int", pName: "fd"}, param{pType: "char*", pName: "list"}, param{pType: "size_t", pName: "size"}},
	RemovexattrEventID:         []param{param{pType: "const char*", pName: "path"}, param{pType: "const char*", pName: "name"}},
	LremovexattrEventID:        []param{param{pType: "const char*", pName: "path"}, param{pType: "const char*", pName: "name"}},
	FremovexattrEventID:        []param{param{pType: "int", pName: "fd"}, param{pType: "const char*", pName: "name"}},
	TkillEventID:               []param{param{pType: "int", pName: "tid"}, param{pType: "int", pName: "sig"}},
	TimeEventID:                []param{param{pType: "time_t*", pName: "tloc"}},
	FutexEventID:               []param{param{pType: "int*", pName: "uaddr"}, param{pType: "int", pName: "futex_op"}, param{pType: "int", pName: "val"}, param{pType: "const struct timespec*", pName: "timeout"}, param{pType: "int*", pName: "uaddr2"}, param{pType: "int", pName: "val3"}},
	SchedSetaffinityEventID:    []param{param{pType: "pid_t", pName: "pid"}, param{pType: "size_t", pName: "cpusetsize"}, param{pType: "unsigned long*", pName: "mask"}},
	SchedGetaffinityEventID:    []param{param{pType: "pid_t", pName: "pid"}, param{pType: "size_t", pName: "cpusetsize"}, param{pType: "unsigned long*", pName: "mask"}},
	SetThreadAreaEventID:       []param{param{pType: "struct user_desc*", pName: "u_info"}},
	IoSetupEventID:             []param{param{pType: "unsigned int", pName: "nr_events"}, param{pType: "io_context_t*", pName: "ctx_idp"}},
	IoDestroyEventID:           []param{param{pType: "io_context_t", pName: "ctx_id"}},
	IoGeteventsEventID:         []param{param{pType: "io_context_t", pName: "ctx_id"}, param{pType: "long", pName: "min_nr"}, param{pType: "long", pName: "nr"}, param{pType: "struct io_event*", pName: "events"}, param{pType: "struct timespec*", pName: "timeout"}},
	IoSubmitEventID:            []param{param{pType: "io_context_t", pName: "ctx_id"}, param{pType: "long", pName: "nr"}, param{pType: "struct iocb**", pName: "iocbpp"}},
	IoCancelEventID:            []param{param{pType: "io_context_t", pName: "ctx_id"}, param{pType: "struct iocb*", pName: "iocb"}, param{pType: "struct io_event*", pName: "result"}},
	GetThreadAreaEventID:       []param{param{pType: "struct user_desc*", pName: "u_info"}},
	LookupDcookieEventID:       []param{param{pType: "u64", pName: "cookie"}, param{pType: "char*", pName: "buffer"}, param{pType: "size_t", pName: "len"}},
	EpollCreateEventID:         []param{param{pType: "int", pName: "size"}},
	RemapFilePagesEventID:      []param{param{pType: "void*", pName: "addr"}, param{pType: "size_t", pName: "size"}, param{pType: "int", pName: "prot"}, param{pType: "size_t", pName: "pgoff"}, param{pType: "int", pName: "flags"}},
	Getdents64EventID:          []param{param{pType: "unsigned int", pName: "fd"}, param{pType: "struct linux_dirent64*", pName: "dirp"}, param{pType: "unsigned int", pName: "count"}},
	SetTidAddressEventID:       []param{param{pType: "int*", pName: "tidptr"}},
	RestartSyscallEventID:      []param{},
	SemtimedopEventID:          []param{param{pType: "int", pName: "semid"}, param{pType: "struct sembuf*", pName: "sops"}, param{pType: "size_t", pName: "nsops"}, param{pType: "const struct timespec*", pName: "timeout"}},
	Fadvise64EventID:           []param{param{pType: "int", pName: "fd"}, param{pType: "off_t", pName: "offset"}, param{pType: "size_t", pName: "len"}, param{pType: "int", pName: "advice"}},
	TimerCreateEventID:         []param{param{pType: "const clockid_t", pName: "clockid"}, param{pType: "struct sigevent*", pName: "sevp"}, param{pType: "timer_t*", pName: "timer_id"}},
	TimerSettimeEventID:        []param{param{pType: "timer_t", pName: "timer_id"}, param{pType: "int", pName: "flags"}, param{pType: "const struct itimerspec*", pName: "new_value"}, param{pType: "struct itimerspec*", pName: "old_value"}},
	TimerGettimeEventID:        []param{param{pType: "timer_t", pName: "timer_id"}, param{pType: "struct itimerspec*", pName: "curr_value"}},
	TimerGetoverrunEventID:     []param{param{pType: "timer_t", pName: "timer_id"}},
	TimerDeleteEventID:         []param{param{pType: "timer_t", pName: "timer_id"}},
	ClockSettimeEventID:        []param{param{pType: "const clockid_t", pName: "clockid"}, param{pType: "const struct timespec*", pName: "tp"}},
	ClockGettimeEventID:        []param{param{pType: "const clockid_t", pName: "clockid"}, param{pType: "struct timespec*", pName: "tp"}},
	ClockGetresEventID:         []param{param{pType: "const clockid_t", pName: "clockid"}, param{pType: "struct timespec*", pName: "res"}},
	ClockNanosleepEventID:      []param{param{pType: "const clockid_t", pName: "clockid"}, param{pType: "int", pName: "flags"}, param{pType: "const struct timespec*", pName: "request"}, param{pType: "struct timespec*", pName: "remain"}},
	ExitGroupEventID:           []param{param{pType: "int", pName: "status"}},
	EpollWaitEventID:           []param{param{pType: "int", pName: "epfd"}, param{pType: "struct epoll_event*", pName: "events"}, param{pType: "int", pName: "maxevents"}, param{pType: "int", pName: "timeout"}},
	EpollCtlEventID:            []param{param{pType: "int", pName: "epfd"}, param{pType: "int", pName: "op"}, param{pType: "int", pName: "fd"}, param{pType: "struct epoll_event*", pName: "event"}},
	TgkillEventID:              []param{param{pType: "int", pName: "tgid"}, param{pType: "int", pName: "tid"}, param{pType: "int", pName: "sig"}},
	UtimesEventID:              []param{param{pType: "char*", pName: "filename"}, param{pType: "struct timeval*", pName: "times"}},
	MbindEventID:               []param{param{pType: "void*", pName: "addr"}, param{pType: "unsigned long", pName: "len"}, param{pType: "int", pName: "mode"}, param{pType: "const unsigned long*", pName: "nodemask"}, param{pType: "unsigned long", pName: "maxnode"}, param{pType: "unsigned int", pName: "flags"}},
	SetMempolicyEventID:        []param{param{pType: "int", pName: "mode"}, param{pType: "const unsigned long*", pName: "nodemask"}, param{pType: "unsigned long", pName: "maxnode"}},
	GetMempolicyEventID:        []param{param{pType: "int*", pName: "mode"}, param{pType: "unsigned long*", pName: "nodemask"}, param{pType: "unsigned long", pName: "maxnode"}, param{pType: "void*", pName: "addr"}, param{pType: "unsigned long", pName: "flags"}},
	MqOpenEventID:              []param{param{pType: "const char*", pName: "name"}, param{pType: "int", pName: "oflag"}, param{pType: "mode_t", pName: "mode"}, param{pType: "struct mq_attr*", pName: "attr"}},
	MqUnlinkEventID:            []param{param{pType: "const char*", pName: "name"}},
	MqTimedsendEventID:         []param{param{pType: "mqd_t", pName: "mqdes"}, param{pType: "const char*", pName: "msg_ptr"}, param{pType: "size_t", pName: "msg_len"}, param{pType: "unsigned int", pName: "msg_prio"}, param{pType: "const struct timespec*", pName: "abs_timeout"}},
	MqTimedreceiveEventID:      []param{param{pType: "mqd_t", pName: "mqdes"}, param{pType: "char*", pName: "msg_ptr"}, param{pType: "size_t", pName: "msg_len"}, param{pType: "unsigned int*", pName: "msg_prio"}, param{pType: "const struct timespec*", pName: "abs_timeout"}},
	MqNotifyEventID:            []param{param{pType: "mqd_t", pName: "mqdes"}, param{pType: "const struct sigevent*", pName: "sevp"}},
	MqGetsetattrEventID:        []param{param{pType: "mqd_t", pName: "mqdes"}, param{pType: "const struct mq_attr*", pName: "newattr"}, param{pType: "struct mq_attr*", pName: "oldattr"}},
	KexecLoadEventID:           []param{param{pType: "unsigned long", pName: "entry"}, param{pType: "unsigned long", pName: "nr_segments"}, param{pType: "struct kexec_segment*", pName: "segments"}, param{pType: "unsigned long", pName: "flags"}},
	WaitidEventID:              []param{param{pType: "int", pName: "idtype"}, param{pType: "pid_t", pName: "id"}, param{pType: "struct siginfo*", pName: "infop"}, param{pType: "int", pName: "options"}, param{pType: "struct rusage*", pName: "rusage"}},
	AddKeyEventID:              []param{param{pType: "const char*", pName: "type"}, param{pType: "const char*", pName: "description"}, param{pType: "const void*", pName: "payload"}, param{pType: "size_t", pName: "plen"}, param{pType: "key_serial_t", pName: "keyring"}},
	RequestKeyEventID:          []param{param{pType: "const char*", pName: "type"}, param{pType: "const char*", pName: "description"}, param{pType: "const char*", pName: "callout_info"}, param{pType: "key_serial_t", pName: "dest_keyring"}},
	KeyctlEventID:              []param{param{pType: "int", pName: "operation"}, param{pType: "unsigned long", pName: "arg2"}, param{pType: "unsigned long", pName: "arg3"}, param{pType: "unsigned long", pName: "arg4"}, param{pType: "unsigned long", pName: "arg5"}},
	IoprioSetEventID:           []param{param{pType: "int", pName: "which"}, param{pType: "int", pName: "who"}, param{pType: "int", pName: "ioprio"}},
	IoprioGetEventID:           []param{param{pType: "int", pName: "which"}, param{pType: "int", pName: "who"}},
	InotifyInitEventID:         []param{},
	InotifyAddWatchEventID:     []param{param{pType: "int", pName: "fd"}, param{pType: "const char*", pName: "pathname"}, param{pType: "u32", pName: "mask"}},
	InotifyRmWatchEventID:      []param{param{pType: "int", pName: "fd"}, param{pType: "int", pName: "wd"}},
	MigratePagesEventID:        []param{param{pType: "int", pName: "pid"}, param{pType: "unsigned long", pName: "maxnode"}, param{pType: "const unsigned long*", pName: "old_nodes"}, param{pType: "const unsigned long*", pName: "new_nodes"}},
	OpenatEventID:              []param{param{pType: "int", pName: "dirfd"}, param{pType: "const char*", pName: "pathname"}, param{pType: "int", pName: "flags"}, param{pType: "mode_t", pName: "mode"}},
	MkdiratEventID:             []param{param{pType: "int", pName: "dirfd"}, param{pType: "const char*", pName: "pathname"}, param{pType: "mode_t", pName: "mode"}},
	MknodatEventID:             []param{param{pType: "int", pName: "dirfd"}, param{pType: "const char*", pName: "pathname"}, param{pType: "mode_t", pName: "mode"}, param{pType: "dev_t", pName: "dev"}},
	FchownatEventID:            []param{param{pType: "int", pName: "dirfd"}, param{pType: "const char*", pName: "pathname"}, param{pType: "uid_t", pName: "owner"}, param{pType: "gid_t", pName: "group"}, param{pType: "int", pName: "flags"}},
	FutimesatEventID:           []param{param{pType: "int", pName: "dirfd"}, param{pType: "const char*", pName: "pathname"}, param{pType: "struct timeval*", pName: "times"}},
	NewfstatatEventID:          []param{param{pType: "int", pName: "dirfd"}, param{pType: "const char*", pName: "pathname"}, param{pType: "struct stat*", pName: "statbuf"}, param{pType: "int", pName: "flags"}},
	UnlinkatEventID:            []param{param{pType: "int", pName: "dirfd"}, param{pType: "const char*", pName: "pathname"}, param{pType: "int", pName: "flags"}},
	RenameatEventID:            []param{param{pType: "int", pName: "olddirfd"}, param{pType: "const char*", pName: "oldpath"}, param{pType: "int", pName: "newdirfd"}, param{pType: "const char*", pName: "newpath"}},
	LinkatEventID:              []param{param{pType: "int", pName: "olddirfd"}, param{pType: "const char*", pName: "oldpath"}, param{pType: "int", pName: "newdirfd"}, param{pType: "const char*", pName: "newpath"}, param{pType: "unsigned int", pName: "flags"}},
	SymlinkatEventID:           []param{param{pType: "const char*", pName: "target"}, param{pType: "int", pName: "newdirfd"}, param{pType: "const char*", pName: "linkpath"}},
	ReadlinkatEventID:          []param{param{pType: "int", pName: "dirfd"}, param{pType: "const char*", pName: "pathname"}, param{pType: "char*", pName: "buf"}, param{pType: "int", pName: "bufsiz"}},
	FchmodatEventID:            []param{param{pType: "int", pName: "dirfd"}, param{pType: "const char*", pName: "pathname"}, param{pType: "mode_t", pName: "mode"}, param{pType: "int", pName: "flags"}},
	FaccessatEventID:           []param{param{pType: "int", pName: "dirfd"}, param{pType: "const char*", pName: "pathname"}, param{pType: "int", pName: "mode"}, param{pType: "int", pName: "flags"}},
	Pselect6EventID:            []param{param{pType: "int", pName: "nfds"}, param{pType: "fd_set*", pName: "readfds"}, param{pType: "fd_set*", pName: "writefds"}, param{pType: "fd_set*", pName: "exceptfds"}, param{pType: "struct timespec*", pName: "timeout"}, param{pType: "void*", pName: "sigmask"}},
	PpollEventID:               []param{param{pType: "struct pollfd*", pName: "fds"}, param{pType: "unsigned int", pName: "nfds"}, param{pType: "struct timespec*", pName: "tmo_p"}, param{pType: "const sigset_t*", pName: "sigmask"}, param{pType: "size_t", pName: "sigsetsize"}},
	UnshareEventID:             []param{param{pType: "int", pName: "flags"}},
	SetRobustListEventID:       []param{param{pType: "struct robust_list_head*", pName: "head"}, param{pType: "size_t", pName: "len"}},
	GetRobustListEventID:       []param{param{pType: "int", pName: "pid"}, param{pType: "struct robust_list_head**", pName: "head_ptr"}, param{pType: "size_t*", pName: "len_ptr"}},
	SpliceEventID:              []param{param{pType: "int", pName: "fd_in"}, param{pType: "off_t*", pName: "off_in"}, param{pType: "int", pName: "fd_out"}, param{pType: "off_t*", pName: "off_out"}, param{pType: "size_t", pName: "len"}, param{pType: "unsigned int", pName: "flags"}},
	TeeEventID:                 []param{param{pType: "int", pName: "fd_in"}, param{pType: "int", pName: "fd_out"}, param{pType: "size_t", pName: "len"}, param{pType: "unsigned int", pName: "flags"}},
	SyncFileRangeEventID:       []param{param{pType: "int", pName: "fd"}, param{pType: "off_t", pName: "offset"}, param{pType: "off_t", pName: "nbytes"}, param{pType: "unsigned int", pName: "flags"}},
	VmspliceEventID:            []param{param{pType: "int", pName: "fd"}, param{pType: "const struct iovec*", pName: "iov"}, param{pType: "unsigned long", pName: "nr_segs"}, param{pType: "unsigned int", pName: "flags"}},
	MovePagesEventID:           []param{param{pType: "int", pName: "pid"}, param{pType: "unsigned long", pName: "count"}, param{pType: "const void**", pName: "pages"}, param{pType: "const int*", pName: "nodes"}, param{pType: "int*", pName: "status"}, param{pType: "int", pName: "flags"}},
	UtimensatEventID:           []param{param{pType: "int", pName: "dirfd"}, param{pType: "const char*", pName: "pathname"}, param{pType: "struct timespec*", pName: "times"}, param{pType: "int", pName: "flags"}},
	EpollPwaitEventID:          []param{param{pType: "int", pName: "epfd"}, param{pType: "struct epoll_event*", pName: "events"}, param{pType: "int", pName: "maxevents"}, param{pType: "int", pName: "timeout"}, param{pType: "const sigset_t*", pName: "sigmask"}, param{pType: "size_t", pName: "sigsetsize"}},
	SignalfdEventID:            []param{param{pType: "int", pName: "fd"}, param{pType: "sigset_t*", pName: "mask"}, param{pType: "int", pName: "flags"}},
	TimerfdCreateEventID:       []param{param{pType: "int", pName: "clockid"}, param{pType: "int", pName: "flags"}},
	EventfdEventID:             []param{param{pType: "unsigned int", pName: "initval"}, param{pType: "int", pName: "flags"}},
	FallocateEventID:           []param{param{pType: "int", pName: "fd"}, param{pType: "int", pName: "mode"}, param{pType: "off_t", pName: "offset"}, param{pType: "off_t", pName: "len"}},
	TimerfdSettimeEventID:      []param{param{pType: "int", pName: "fd"}, param{pType: "int", pName: "flags"}, param{pType: "const struct itimerspec*", pName: "new_value"}, param{pType: "struct itimerspec*", pName: "old_value"}},
	TimerfdGettimeEventID:      []param{param{pType: "int", pName: "fd"}, param{pType: "struct itimerspec*", pName: "curr_value"}},
	Accept4EventID:             []param{param{pType: "int", pName: "sockfd"}, param{pType: "struct sockaddr*", pName: "addr"}, param{pType: "int*", pName: "addrlen"}, param{pType: "int", pName: "flags"}},
	Signalfd4EventID:           []param{param{pType: "int", pName: "fd"}, param{pType: "const sigset_t*", pName: "mask"}, param{pType: "size_t", pName: "sizemask"}, param{pType: "int", pName: "flags"}},
	Eventfd2EventID:            []param{param{pType: "unsigned int", pName: "initval"}, param{pType: "int", pName: "flags"}},
	EpollCreate1EventID:        []param{param{pType: "int", pName: "flags"}},
	Dup3EventID:                []param{param{pType: "int", pName: "oldfd"}, param{pType: "int", pName: "newfd"}, param{pType: "int", pName: "flags"}},
	Pipe2EventID:               []param{param{pType: "int*", pName: "pipefd"}, param{pType: "int", pName: "flags"}},
	InotifyInit1EventID:        []param{param{pType: "int", pName: "flags"}},
	PreadvEventID:              []param{param{pType: "int", pName: "fd"}, param{pType: "const struct iovec*", pName: "iov"}, param{pType: "unsigned long", pName: "iovcnt"}, param{pType: "unsigned long", pName: "pos_l"}, param{pType: "unsigned long", pName: "pos_h"}},
	PwritevEventID:             []param{param{pType: "int", pName: "fd"}, param{pType: "const struct iovec*", pName: "iov"}, param{pType: "unsigned long", pName: "iovcnt"}, param{pType: "unsigned long", pName: "pos_l"}, param{pType: "unsigned long", pName: "pos_h"}},
	RtTgsigqueueinfoEventID:    []param{param{pType: "pid_t", pName: "tgid"}, param{pType: "pid_t", pName: "tid"}, param{pType: "int", pName: "sig"}, param{pType: "siginfo_t*", pName: "info"}},
	PerfEventOpenEventID:       []param{param{pType: "struct perf_event_attr*", pName: "attr"}, param{pType: "pid_t", pName: "pid"}, param{pType: "int", pName: "cpu"}, param{pType: "int", pName: "group_fd"}, param{pType: "unsigned long", pName: "flags"}},
	RecvmmsgEventID:            []param{param{pType: "int", pName: "sockfd"}, param{pType: "struct mmsghdr*", pName: "msgvec"}, param{pType: "unsigned int", pName: "vlen"}, param{pType: "int", pName: "flags"}, param{pType: "struct timespec*", pName: "timeout"}},
	FanotifyInitEventID:        []param{param{pType: "unsigned int", pName: "flags"}, param{pType: "unsigned int", pName: "event_f_flags"}},
	FanotifyMarkEventID:        []param{param{pType: "int", pName: "fanotify_fd"}, param{pType: "unsigned int", pName: "flags"}, param{pType: "u64", pName: "mask"}, param{pType: "int", pName: "dirfd"}, param{pType: "const char*", pName: "pathname"}},
	Prlimit64EventID:           []param{param{pType: "pid_t", pName: "pid"}, param{pType: "int", pName: "resource"}, param{pType: "const struct rlimit64*", pName: "new_limit"}, param{pType: "struct rlimit64*", pName: "old_limit"}},
	NameToHandleAtEventID:      []param{param{pType: "int", pName: "dirfd"}, param{pType: "const char*", pName: "pathname"}, param{pType: "struct file_handle*", pName: "handle"}, param{pType: "int*", pName: "mount_id"}, param{pType: "int", pName: "flags"}},
	OpenByHandleAtEventID:      []param{param{pType: "int", pName: "mount_fd"}, param{pType: "struct file_handle*", pName: "handle"}, param{pType: "int", pName: "flags"}},
	ClockAdjtimeEventID:        []param{param{pType: "const clockid_t", pName: "clk_id"}, param{pType: "struct timex*", pName: "buf"}},
	SyncfsEventID:              []param{param{pType: "int", pName: "fd"}},
	SendmmsgEventID:            []param{param{pType: "int", pName: "sockfd"}, param{pType: "struct mmsghdr*", pName: "msgvec"}, param{pType: "unsigned int", pName: "vlen"}, param{pType: "int", pName: "flags"}},
	SetnsEventID:               []param{param{pType: "int", pName: "fd"}, param{pType: "int", pName: "nstype"}},
	GetcpuEventID:              []param{param{pType: "unsigned int*", pName: "cpu"}, param{pType: "unsigned int*", pName: "node"}, param{pType: "struct getcpu_cache*", pName: "tcache"}},
	ProcessVmReadvEventID:      []param{param{pType: "pid_t", pName: "pid"}, param{pType: "const struct iovec*", pName: "local_iov"}, param{pType: "unsigned long", pName: "liovcnt"}, param{pType: "const struct iovec*", pName: "remote_iov"}, param{pType: "unsigned long", pName: "riovcnt"}, param{pType: "unsigned long", pName: "flags"}},
	ProcessVmWritevEventID:     []param{param{pType: "pid_t", pName: "pid"}, param{pType: "const struct iovec*", pName: "local_iov"}, param{pType: "unsigned long", pName: "liovcnt"}, param{pType: "const struct iovec*", pName: "remote_iov"}, param{pType: "unsigned long", pName: "riovcnt"}, param{pType: "unsigned long", pName: "flags"}},
	KcmpEventID:                []param{param{pType: "pid_t", pName: "pid1"}, param{pType: "pid_t", pName: "pid2"}, param{pType: "int", pName: "type"}, param{pType: "unsigned long", pName: "idx1"}, param{pType: "unsigned long", pName: "idx2"}},
	FinitModuleEventID:         []param{param{pType: "int", pName: "fd"}, param{pType: "const char*", pName: "param_values"}, param{pType: "int", pName: "flags"}},
	SchedSetattrEventID:        []param{param{pType: "pid_t", pName: "pid"}, param{pType: "struct sched_attr*", pName: "attr"}, param{pType: "unsigned int", pName: "flags"}},
	SchedGetattrEventID:        []param{param{pType: "pid_t", pName: "pid"}, param{pType: "struct sched_attr*", pName: "attr"}, param{pType: "unsigned int", pName: "size"}, param{pType: "unsigned int", pName: "flags"}},
	Renameat2EventID:           []param{param{pType: "int", pName: "olddirfd"}, param{pType: "const char*", pName: "oldpath"}, param{pType: "int", pName: "newdirfd"}, param{pType: "const char*", pName: "newpath"}, param{pType: "unsigned int", pName: "flags"}},
	SeccompEventID:             []param{param{pType: "unsigned int", pName: "operation"}, param{pType: "unsigned int", pName: "flags"}, param{pType: "const void*", pName: "args"}},
	GetrandomEventID:           []param{param{pType: "void*", pName: "buf"}, param{pType: "size_t", pName: "buflen"}, param{pType: "unsigned int", pName: "flags"}},
	MemfdCreateEventID:         []param{param{pType: "const char*", pName: "name"}, param{pType: "unsigned int", pName: "flags"}},
	KexecFileLoadEventID:       []param{param{pType: "int", pName: "kernel_fd"}, param{pType: "int", pName: "initrd_fd"}, param{pType: "unsigned long", pName: "cmdline_len"}, param{pType: "const char*", pName: "cmdline"}, param{pType: "unsigned long", pName: "flags"}},
	BpfEventID:                 []param{param{pType: "int", pName: "cmd"}, param{pType: "union bpf_attr*", pName: "attr"}, param{pType: "unsigned int", pName: "size"}},
	ExecveatEventID:            []param{param{pType: "int", pName: "dirfd"}, param{pType: "const char*", pName: "pathname"}, param{pType: "const char*const*", pName: "argv"}, param{pType: "const char*const*", pName: "envp"}, param{pType: "int", pName: "flags"}},
	UserfaultfdEventID:         []param{param{pType: "int", pName: "flags"}},
	MembarrierEventID:          []param{param{pType: "int", pName: "cmd"}, param{pType: "int", pName: "flags"}},
	Mlock2EventID:              []param{param{pType: "const void*", pName: "addr"}, param{pType: "size_t", pName: "len"}, param{pType: "int", pName: "flags"}},
	CopyFileRangeEventID:       []param{param{pType: "int", pName: "fd_in"}, param{pType: "off_t*", pName: "off_in"}, param{pType: "int", pName: "fd_out"}, param{pType: "off_t*", pName: "off_out"}, param{pType: "size_t", pName: "len"}, param{pType: "unsigned int", pName: "flags"}},
	Preadv2EventID:             []param{param{pType: "int", pName: "fd"}, param{pType: "const struct iovec*", pName: "iov"}, param{pType: "unsigned long", pName: "iovcnt"}, param{pType: "unsigned long", pName: "pos_l"}, param{pType: "unsigned long", pName: "pos_h"}, param{pType: "int", pName: "flags"}},
	Pwritev2EventID:            []param{param{pType: "int", pName: "fd"}, param{pType: "const struct iovec*", pName: "iov"}, param{pType: "unsigned long", pName: "iovcnt"}, param{pType: "unsigned long", pName: "pos_l"}, param{pType: "unsigned long", pName: "pos_h"}, param{pType: "int", pName: "flags"}},
	PkeyMprotectEventID:        []param{param{pType: "void*", pName: "addr"}, param{pType: "size_t", pName: "len"}, param{pType: "int", pName: "prot"}, param{pType: "int", pName: "pkey"}},
	PkeyAllocEventID:           []param{param{pType: "unsigned int", pName: "flags"}, param{pType: "unsigned long", pName: "access_rights"}},
	PkeyFreeEventID:            []param{param{pType: "int", pName: "pkey"}},
	StatxEventID:               []param{param{pType: "int", pName: "dirfd"}, param{pType: "const char*", pName: "pathname"}, param{pType: "int", pName: "flags"}, param{pType: "unsigned int", pName: "mask"}, param{pType: "struct statx*", pName: "statxbuf"}},
	IoPgeteventsEventID:        []param{param{pType: "aio_context_t", pName: "ctx_id"}, param{pType: "long", pName: "min_nr"}, param{pType: "long", pName: "nr"}, param{pType: "struct io_event*", pName: "events"}, param{pType: "struct timespec*", pName: "timeout"}, param{pType: "const struct __aio_sigset*", pName: "usig"}},
	RseqEventID:                []param{param{pType: "struct rseq*", pName: "rseq"}, param{pType: "u32", pName: "rseq_len"}, param{pType: "int", pName: "flags"}, param{pType: "u32", pName: "sig"}},
	SysEnterEventID:            []param{param{pType: "int", pName: "syscall"}},
	SysExitEventID:             []param{param{pType: "int", pName: "syscall"}},
	DoExitEventID:              []param{},
	CapCapableEventID:          []param{param{pType: "int", pName: "cap"}, param{pType: "int", pName: "syscall"}},
	SecurityBprmCheckEventID:   []param{param{pType: "const char*", pName: "pathname"}, param{pType: "dev_t", pName: "dev"}, param{pType: "unsigned long", pName: "inode"}},
	SecurityFileOpenEventID:    []param{param{pType: "const char*", pName: "pathname"}, param{pType: "int", pName: "flags"}, param{pType: "dev_t", pName: "dev"}, param{pType: "unsigned long", pName: "inode"}},
	VfsWriteEventID:            []param{param{pType: "const char*", pName: "pathname"}, param{pType: "dev_t", pName: "dev"}, param{pType: "unsigned long", pName: "inode"}, param{pType: "size_t", pName: "count"}, param{pType: "off_t", pName: "pos"}},
	VfsWritevEventID:           []param{param{pType: "const char*", pName: "pathname"}, param{pType: "dev_t", pName: "dev"}, param{pType: "unsigned long", pName: "inode"}, param{pType: "unsigned long", pName: "vlen"}, param{pType: "off_t", pName: "pos"}},
	MemProtAlertEventID:        []param{param{pType: "alert_t", pName: "alert"}},
}
