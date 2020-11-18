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
	configFilterByUid
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
	ModeProcessAll uint32 = iota + 1
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
	SchedProcessExitEventID
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
	ReadEventID:                {ID: ReadEventID, ID32Bit: sys32read, Name: "read", Probes: []probe{{event: "read", attach: sysCall, fn: "read"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	WriteEventID:               {ID: WriteEventID, ID32Bit: sys32write, Name: "write", Probes: []probe{{event: "write", attach: sysCall, fn: "write"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	OpenEventID:                {ID: OpenEventID, ID32Bit: sys32open, Name: "open", Probes: []probe{{event: "open", attach: sysCall, fn: "open"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	CloseEventID:               {ID: CloseEventID, ID32Bit: sys32close, Name: "close", Probes: []probe{{event: "close", attach: sysCall, fn: "close"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	StatEventID:                {ID: StatEventID, ID32Bit: sys32stat, Name: "stat", Probes: []probe{{event: "newstat", attach: sysCall, fn: "newstat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	FstatEventID:               {ID: FstatEventID, ID32Bit: sys32fstat, Name: "fstat", Probes: []probe{{event: "newfstat", attach: sysCall, fn: "newfstat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	LstatEventID:               {ID: LstatEventID, ID32Bit: sys32lstat, Name: "lstat", Probes: []probe{{event: "newlstat", attach: sysCall, fn: "newlstat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	PollEventID:                {ID: PollEventID, ID32Bit: sys32poll, Name: "poll", Probes: []probe{{event: "poll", attach: sysCall, fn: "poll"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	LseekEventID:               {ID: LseekEventID, ID32Bit: sys32lseek, Name: "lseek", Probes: []probe{{event: "lseek", attach: sysCall, fn: "lseek"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	MmapEventID:                {ID: MmapEventID, ID32Bit: sys32mmap, Name: "mmap", Probes: []probe{{event: "mmap", attach: sysCall, fn: "mmap"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	MprotectEventID:            {ID: MprotectEventID, ID32Bit: sys32mprotect, Name: "mprotect", Probes: []probe{{event: "mprotect", attach: sysCall, fn: "mprotect"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	MunmapEventID:              {ID: MunmapEventID, ID32Bit: sys32munmap, Name: "munmap", Probes: []probe{{event: "munmap", attach: sysCall, fn: "munmap"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	BrkEventID:                 {ID: BrkEventID, ID32Bit: sys32brk, Name: "brk", Probes: []probe{{event: "brk", attach: sysCall, fn: "brk"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	RtSigactionEventID:         {ID: RtSigactionEventID, ID32Bit: sys32rt_sigaction, Name: "rt_sigaction", Probes: []probe{{event: "rt_sigaction", attach: sysCall, fn: "rt_sigaction"}}, Sets: []string{"syscalls", "signals"}},
	RtSigprocmaskEventID:       {ID: RtSigprocmaskEventID, ID32Bit: sys32rt_sigprocmask, Name: "rt_sigprocmask", Probes: []probe{{event: "rt_sigprocmask", attach: sysCall, fn: "rt_sigprocmask"}}, Sets: []string{"syscalls", "signals"}},
	RtSigreturnEventID:         {ID: RtSigreturnEventID, ID32Bit: sys32rt_sigreturn, Name: "rt_sigreturn", Probes: []probe{{event: "rt_sigreturn", attach: sysCall, fn: "rt_sigreturn"}}, Sets: []string{"syscalls", "signals"}},
	IoctlEventID:               {ID: IoctlEventID, ID32Bit: sys32ioctl, Name: "ioctl", Probes: []probe{{event: "ioctl", attach: sysCall, fn: "ioctl"}}, Sets: []string{"default", "syscalls", "fs", "fs_fd_ops"}},
	Pread64EventID:             {ID: Pread64EventID, ID32Bit: sys32pread64, Name: "pread64", Probes: []probe{{event: "pread64", attach: sysCall, fn: "pread64"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	Pwrite64EventID:            {ID: Pwrite64EventID, ID32Bit: sys32pwrite64, Name: "pwrite64", Probes: []probe{{event: "pwrite64", attach: sysCall, fn: "pwrite64"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	ReadvEventID:               {ID: ReadvEventID, ID32Bit: sys32readv, Name: "readv", Probes: []probe{{event: "readv", attach: sysCall, fn: "readv"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	WritevEventID:              {ID: WritevEventID, ID32Bit: sys32writev, Name: "writev", Probes: []probe{{event: "writev", attach: sysCall, fn: "writev"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	AccessEventID:              {ID: AccessEventID, ID32Bit: sys32access, Name: "access", Probes: []probe{{event: "access", attach: sysCall, fn: "access"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	PipeEventID:                {ID: PipeEventID, ID32Bit: sys32pipe, Name: "pipe", Probes: []probe{{event: "pipe", attach: sysCall, fn: "pipe"}}, Sets: []string{"syscalls", "ipc", "ipc_pipe"}},
	SelectEventID:              {ID: SelectEventID, ID32Bit: sys32select, Name: "select", Probes: []probe{{event: "select", attach: sysCall, fn: "select"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	SchedYieldEventID:          {ID: SchedYieldEventID, ID32Bit: sys32sched_yield, Name: "sched_yield", Probes: []probe{{event: "sched_yield", attach: sysCall, fn: "sched_yield"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	MremapEventID:              {ID: MremapEventID, ID32Bit: sys32mremap, Name: "mremap", Probes: []probe{{event: "mremap", attach: sysCall, fn: "mremap"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	MsyncEventID:               {ID: MsyncEventID, ID32Bit: sys32msync, Name: "msync", Probes: []probe{{event: "msync", attach: sysCall, fn: "msync"}}, Sets: []string{"syscalls", "fs", "fs_sync"}},
	MincoreEventID:             {ID: MincoreEventID, ID32Bit: sys32mincore, Name: "mincore", Probes: []probe{{event: "mincore", attach: sysCall, fn: "mincore"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	MadviseEventID:             {ID: MadviseEventID, ID32Bit: sys32madvise, Name: "madvise", Probes: []probe{{event: "madvise", attach: sysCall, fn: "madvise"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	ShmgetEventID:              {ID: ShmgetEventID, ID32Bit: sys32shmget, Name: "shmget", Probes: []probe{{event: "shmget", attach: sysCall, fn: "shmget"}}, Sets: []string{"syscalls", "ipc", "ipc_shm"}},
	ShmatEventID:               {ID: ShmatEventID, ID32Bit: sys32shmat, Name: "shmat", Probes: []probe{{event: "shmat", attach: sysCall, fn: "shmat"}}, Sets: []string{"syscalls", "ipc", "ipc_shm"}},
	ShmctlEventID:              {ID: ShmctlEventID, ID32Bit: sys32shmctl, Name: "shmctl", Probes: []probe{{event: "shmctl", attach: sysCall, fn: "shmctl"}}, Sets: []string{"syscalls", "ipc", "ipc_shm"}},
	DupEventID:                 {ID: DupEventID, ID32Bit: sys32dup, Name: "dup", Probes: []probe{{event: "dup", attach: sysCall, fn: "dup"}}, Sets: []string{"default", "syscalls", "fs", "fs_fd_ops"}},
	Dup2EventID:                {ID: Dup2EventID, ID32Bit: sys32dup2, Name: "dup2", Probes: []probe{{event: "dup2", attach: sysCall, fn: "dup2"}}, Sets: []string{"default", "syscalls", "fs", "fs_fd_ops"}},
	PauseEventID:               {ID: PauseEventID, ID32Bit: sys32pause, Name: "pause", Probes: []probe{{event: "pause", attach: sysCall, fn: "pause"}}, Sets: []string{"syscalls", "signals"}},
	NanosleepEventID:           {ID: NanosleepEventID, ID32Bit: sys32nanosleep, Name: "nanosleep", Probes: []probe{{event: "nanosleep", attach: sysCall, fn: "nanosleep"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	GetitimerEventID:           {ID: GetitimerEventID, ID32Bit: sys32getitimer, Name: "getitimer", Probes: []probe{{event: "getitimer", attach: sysCall, fn: "getitimer"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	AlarmEventID:               {ID: AlarmEventID, ID32Bit: sys32alarm, Name: "alarm", Probes: []probe{{event: "alarm", attach: sysCall, fn: "alarm"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	SetitimerEventID:           {ID: SetitimerEventID, ID32Bit: sys32setitimer, Name: "setitimer", Probes: []probe{{event: "setitimer", attach: sysCall, fn: "setitimer"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	GetpidEventID:              {ID: GetpidEventID, ID32Bit: sys32getpid, Name: "getpid", Probes: []probe{{event: "getpid", attach: sysCall, fn: "getpid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SendfileEventID:            {ID: SendfileEventID, ID32Bit: sys32sendfile, Name: "sendfile", Probes: []probe{{event: "sendfile", attach: sysCall, fn: "sendfile"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	SocketEventID:              {ID: SocketEventID, ID32Bit: sys32socket, Name: "socket", Probes: []probe{{event: "socket", attach: sysCall, fn: "socket"}}, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	ConnectEventID:             {ID: ConnectEventID, ID32Bit: sys32connect, Name: "connect", Probes: []probe{{event: "connect", attach: sysCall, fn: "connect"}}, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	AcceptEventID:              {ID: AcceptEventID, ID32Bit: sys32undefined, Name: "accept", Probes: []probe{{event: "accept", attach: sysCall, fn: "accept"}}, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	SendtoEventID:              {ID: SendtoEventID, ID32Bit: sys32sendto, Name: "sendto", Probes: []probe{{event: "sendto", attach: sysCall, fn: "sendto"}}, Sets: []string{"syscalls", "net", "net_snd_rcv"}},
	RecvfromEventID:            {ID: RecvfromEventID, ID32Bit: sys32recvfrom, Name: "recvfrom", Probes: []probe{{event: "recvfrom", attach: sysCall, fn: "recvfrom"}}, Sets: []string{"syscalls", "net", "net_snd_rcv"}},
	SendmsgEventID:             {ID: SendmsgEventID, ID32Bit: sys32sendmsg, Name: "sendmsg", Probes: []probe{{event: "sendmsg", attach: sysCall, fn: "sendmsg"}}, Sets: []string{"syscalls", "net", "net_snd_rcv"}},
	RecvmsgEventID:             {ID: RecvmsgEventID, ID32Bit: sys32recvmsg, Name: "recvmsg", Probes: []probe{{event: "recvmsg", attach: sysCall, fn: "recvmsg"}}, Sets: []string{"syscalls", "net", "net_snd_rcv"}},
	ShutdownEventID:            {ID: ShutdownEventID, ID32Bit: sys32shutdown, Name: "shutdown", Probes: []probe{{event: "shutdown", attach: sysCall, fn: "shutdown"}}, Sets: []string{"syscalls", "net", "net_sock"}},
	BindEventID:                {ID: BindEventID, ID32Bit: sys32bind, Name: "bind", Probes: []probe{{event: "bind", attach: sysCall, fn: "bind"}}, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	ListenEventID:              {ID: ListenEventID, ID32Bit: sys32listen, Name: "listen", Probes: []probe{{event: "listen", attach: sysCall, fn: "listen"}}, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	GetsocknameEventID:         {ID: GetsocknameEventID, ID32Bit: sys32getsockname, Name: "getsockname", Probes: []probe{{event: "getsockname", attach: sysCall, fn: "getsockname"}}, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	GetpeernameEventID:         {ID: GetpeernameEventID, ID32Bit: sys32getpeername, Name: "getpeername", Probes: []probe{{event: "getpeername", attach: sysCall, fn: "getpeername"}}, Sets: []string{"syscalls", "net", "net_sock"}},
	SocketpairEventID:          {ID: SocketpairEventID, ID32Bit: sys32socketpair, Name: "socketpair", Probes: []probe{{event: "socketpair", attach: sysCall, fn: "socketpair"}}, Sets: []string{"syscalls", "net", "net_sock"}},
	SetsockoptEventID:          {ID: SetsockoptEventID, ID32Bit: sys32setsockopt, Name: "setsockopt", Probes: []probe{{event: "setsockopt", attach: sysCall, fn: "setsockopt"}}, Sets: []string{"syscalls", "net", "net_sock"}},
	GetsockoptEventID:          {ID: GetsockoptEventID, ID32Bit: sys32getsockopt, Name: "getsockopt", Probes: []probe{{event: "getsockopt", attach: sysCall, fn: "getsockopt"}}, Sets: []string{"syscalls", "net", "net_sock"}},
	CloneEventID:               {ID: CloneEventID, ID32Bit: sys32clone, Name: "clone", Probes: []probe{{event: "clone", attach: sysCall, fn: "clone"}}, Sets: []string{"default", "syscalls", "proc", "proc_life"}},
	ForkEventID:                {ID: ForkEventID, ID32Bit: sys32fork, Name: "fork", Probes: []probe{{event: "fork", attach: sysCall, fn: "fork"}}, Sets: []string{"default", "syscalls", "proc", "proc_life"}},
	VforkEventID:               {ID: VforkEventID, ID32Bit: sys32vfork, Name: "vfork", Probes: []probe{{event: "vfork", attach: sysCall, fn: "vfork"}}, Sets: []string{"default", "syscalls", "proc", "proc_life"}},
	ExecveEventID:              {ID: ExecveEventID, ID32Bit: sys32execve, Name: "execve", Probes: []probe{{event: "execve", attach: sysCall, fn: "execve"}}, Sets: []string{"default", "syscalls", "proc", "proc_life"}},
	ExitEventID:                {ID: ExitEventID, ID32Bit: sys32exit, Name: "exit", Probes: []probe{{event: "exit", attach: sysCall, fn: "exit"}}, Sets: []string{"syscalls", "proc", "proc_life"}},
	Wait4EventID:               {ID: Wait4EventID, ID32Bit: sys32wait4, Name: "wait4", Probes: []probe{{event: "wait4", attach: sysCall, fn: "wait4"}}, Sets: []string{"syscalls", "proc", "proc_life"}},
	KillEventID:                {ID: KillEventID, ID32Bit: sys32kill, Name: "kill", Probes: []probe{{event: "kill", attach: sysCall, fn: "kill"}}, Sets: []string{"default", "syscalls", "signals"}},
	UnameEventID:               {ID: UnameEventID, ID32Bit: sys32uname, Name: "uname", Probes: []probe{{event: "uname", attach: sysCall, fn: "uname"}}, Sets: []string{"syscalls", "system"}},
	SemgetEventID:              {ID: SemgetEventID, ID32Bit: sys32semget, Name: "semget", Probes: []probe{{event: "semget", attach: sysCall, fn: "semget"}}, Sets: []string{"syscalls", "ipc", "ipc_sem"}},
	SemopEventID:               {ID: SemopEventID, ID32Bit: sys32undefined, Name: "semop", Probes: []probe{{event: "semop", attach: sysCall, fn: "semop"}}, Sets: []string{"syscalls", "ipc", "ipc_sem"}},
	SemctlEventID:              {ID: SemctlEventID, ID32Bit: sys32semctl, Name: "semctl", Probes: []probe{{event: "semctl", attach: sysCall, fn: "semctl"}}, Sets: []string{"syscalls", "ipc", "ipc_sem"}},
	ShmdtEventID:               {ID: ShmdtEventID, ID32Bit: sys32shmdt, Name: "shmdt", Probes: []probe{{event: "shmdt", attach: sysCall, fn: "shmdt"}}, Sets: []string{"syscalls", "ipc", "ipc_shm"}},
	MsggetEventID:              {ID: MsggetEventID, ID32Bit: sys32msgget, Name: "msgget", Probes: []probe{{event: "msgget", attach: sysCall, fn: "msgget"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	MsgsndEventID:              {ID: MsgsndEventID, ID32Bit: sys32msgsnd, Name: "msgsnd", Probes: []probe{{event: "msgsnd", attach: sysCall, fn: "msgsnd"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	MsgrcvEventID:              {ID: MsgrcvEventID, ID32Bit: sys32msgrcv, Name: "msgrcv", Probes: []probe{{event: "msgrcv", attach: sysCall, fn: "msgrcv"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	MsgctlEventID:              {ID: MsgctlEventID, ID32Bit: sys32msgctl, Name: "msgctl", Probes: []probe{{event: "msgctl", attach: sysCall, fn: "msgctl"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	FcntlEventID:               {ID: FcntlEventID, ID32Bit: sys32fcntl, Name: "fcntl", Probes: []probe{{event: "fcntl", attach: sysCall, fn: "fcntl"}}, Sets: []string{"syscalls", "fs", "fs_fd_ops"}},
	FlockEventID:               {ID: FlockEventID, ID32Bit: sys32flock, Name: "flock", Probes: []probe{{event: "flock", attach: sysCall, fn: "flock"}}, Sets: []string{"syscalls", "fs", "fs_fd_ops"}},
	FsyncEventID:               {ID: FsyncEventID, ID32Bit: sys32fsync, Name: "fsync", Probes: []probe{{event: "fsync", attach: sysCall, fn: "fsync"}}, Sets: []string{"syscalls", "fs", "fs_sync"}},
	FdatasyncEventID:           {ID: FdatasyncEventID, ID32Bit: sys32fdatasync, Name: "fdatasync", Probes: []probe{{event: "fdatasync", attach: sysCall, fn: "fdatasync"}}, Sets: []string{"syscalls", "fs", "fs_sync"}},
	TruncateEventID:            {ID: TruncateEventID, ID32Bit: sys32truncate, Name: "truncate", Probes: []probe{{event: "truncate", attach: sysCall, fn: "truncate"}}, Sets: []string{"syscalls", "fs", "fs_file_ops"}},
	FtruncateEventID:           {ID: FtruncateEventID, ID32Bit: sys32ftruncate, Name: "ftruncate", Probes: []probe{{event: "ftruncate", attach: sysCall, fn: "ftruncate"}}, Sets: []string{"syscalls", "fs", "fs_file_ops"}},
	GetdentsEventID:            {ID: GetdentsEventID, ID32Bit: sys32getdents, Name: "getdents", Probes: []probe{{event: "getdents", attach: sysCall, fn: "getdents"}}, Sets: []string{"default", "syscalls", "fs", "fs_dir_ops"}},
	GetcwdEventID:              {ID: GetcwdEventID, ID32Bit: sys32getcwd, Name: "getcwd", Probes: []probe{{event: "getcwd", attach: sysCall, fn: "getcwd"}}, Sets: []string{"syscalls", "fs", "fs_dir_ops"}},
	ChdirEventID:               {ID: ChdirEventID, ID32Bit: sys32chdir, Name: "chdir", Probes: []probe{{event: "chdir", attach: sysCall, fn: "chdir"}}, Sets: []string{"syscalls", "fs", "fs_dir_ops"}},
	FchdirEventID:              {ID: FchdirEventID, ID32Bit: sys32fchdir, Name: "fchdir", Probes: []probe{{event: "fchdir", attach: sysCall, fn: "fchdir"}}, Sets: []string{"syscalls", "fs", "fs_dir_ops"}},
	RenameEventID:              {ID: RenameEventID, ID32Bit: sys32rename, Name: "rename", Probes: []probe{{event: "rename", attach: sysCall, fn: "rename"}}, Sets: []string{"syscalls", "fs", "fs_file_ops"}},
	MkdirEventID:               {ID: MkdirEventID, ID32Bit: sys32mkdir, Name: "mkdir", Probes: []probe{{event: "mkdir", attach: sysCall, fn: "mkdir"}}, Sets: []string{"syscalls", "fs", "fs_dir_ops"}},
	RmdirEventID:               {ID: RmdirEventID, ID32Bit: sys32rmdir, Name: "rmdir", Probes: []probe{{event: "rmdir", attach: sysCall, fn: "rmdir"}}, Sets: []string{"syscalls", "fs", "fs_dir_ops"}},
	CreatEventID:               {ID: CreatEventID, ID32Bit: sys32creat, Name: "creat", Probes: []probe{{event: "creat", attach: sysCall, fn: "creat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	LinkEventID:                {ID: LinkEventID, ID32Bit: sys32link, Name: "link", Probes: []probe{{event: "link", attach: sysCall, fn: "link"}}, Sets: []string{"syscalls", "fs", "fs_link_ops"}},
	UnlinkEventID:              {ID: UnlinkEventID, ID32Bit: sys32unlink, Name: "unlink", Probes: []probe{{event: "unlink", attach: sysCall, fn: "unlink"}}, Sets: []string{"default", "syscalls", "fs", "fs_link_ops"}},
	SymlinkEventID:             {ID: SymlinkEventID, ID32Bit: sys32symlink, Name: "symlink", Probes: []probe{{event: "symlink", attach: sysCall, fn: "symlink"}}, Sets: []string{"default", "syscalls", "fs", "fs_link_ops"}},
	ReadlinkEventID:            {ID: ReadlinkEventID, ID32Bit: sys32readlink, Name: "readlink", Probes: []probe{{event: "readlink", attach: sysCall, fn: "readlink"}}, Sets: []string{"syscalls", "fs", "fs_link_ops"}},
	ChmodEventID:               {ID: ChmodEventID, ID32Bit: sys32chmod, Name: "chmod", Probes: []probe{{event: "chmod", attach: sysCall, fn: "chmod"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	FchmodEventID:              {ID: FchmodEventID, ID32Bit: sys32fchmod, Name: "fchmod", Probes: []probe{{event: "fchmod", attach: sysCall, fn: "fchmod"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	ChownEventID:               {ID: ChownEventID, ID32Bit: sys32chown, Name: "chown", Probes: []probe{{event: "chown", attach: sysCall, fn: "chown"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	FchownEventID:              {ID: FchownEventID, ID32Bit: sys32fchown, Name: "fchown", Probes: []probe{{event: "fchown", attach: sysCall, fn: "fchown"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	LchownEventID:              {ID: LchownEventID, ID32Bit: sys32lchown, Name: "lchown", Probes: []probe{{event: "lchown", attach: sysCall, fn: "lchown"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	UmaskEventID:               {ID: UmaskEventID, ID32Bit: sys32umask, Name: "umask", Probes: []probe{{event: "umask", attach: sysCall, fn: "umask"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	GettimeofdayEventID:        {ID: GettimeofdayEventID, ID32Bit: sys32gettimeofday, Name: "gettimeofday", Probes: []probe{{event: "gettimeofday", attach: sysCall, fn: "gettimeofday"}}, Sets: []string{"syscalls", "time", "time_tod"}},
	GetrlimitEventID:           {ID: GetrlimitEventID, ID32Bit: sys32getrlimit, Name: "getrlimit", Probes: []probe{{event: "getrlimit", attach: sysCall, fn: "getrlimit"}}, Sets: []string{"syscalls", "proc"}},
	GetrusageEventID:           {ID: GetrusageEventID, ID32Bit: sys32getrusage, Name: "getrusage", Probes: []probe{{event: "getrusage", attach: sysCall, fn: "getrusage"}}, Sets: []string{"syscalls", "proc"}},
	SysinfoEventID:             {ID: SysinfoEventID, ID32Bit: sys32sysinfo, Name: "sysinfo", Probes: []probe{{event: "sysinfo", attach: sysCall, fn: "sysinfo"}}, Sets: []string{"syscalls", "system"}},
	TimesEventID:               {ID: TimesEventID, ID32Bit: sys32times, Name: "times", Probes: []probe{{event: "times", attach: sysCall, fn: "times"}}, Sets: []string{"syscalls", "proc"}},
	PtraceEventID:              {ID: PtraceEventID, ID32Bit: sys32ptrace, Name: "ptrace", Probes: []probe{{event: "ptrace", attach: sysCall, fn: "ptrace"}}, Sets: []string{"default", "syscalls", "proc"}},
	GetuidEventID:              {ID: GetuidEventID, ID32Bit: sys32getuid, Name: "getuid", Probes: []probe{{event: "getuid", attach: sysCall, fn: "getuid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SyslogEventID:              {ID: SyslogEventID, ID32Bit: sys32syslog, Name: "syslog", Probes: []probe{{event: "syslog", attach: sysCall, fn: "syslog"}}, Sets: []string{"syscalls", "system"}},
	GetgidEventID:              {ID: GetgidEventID, ID32Bit: sys32getgid, Name: "getgid", Probes: []probe{{event: "getgid", attach: sysCall, fn: "getgid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SetuidEventID:              {ID: SetuidEventID, ID32Bit: sys32setuid, Name: "setuid", Probes: []probe{{event: "setuid", attach: sysCall, fn: "setuid"}}, Sets: []string{"default", "syscalls", "proc", "proc_ids"}},
	SetgidEventID:              {ID: SetgidEventID, ID32Bit: sys32setgid, Name: "setgid", Probes: []probe{{event: "setgid", attach: sysCall, fn: "setgid"}}, Sets: []string{"default", "syscalls", "proc", "proc_ids"}},
	GeteuidEventID:             {ID: GeteuidEventID, ID32Bit: sys32geteuid, Name: "geteuid", Probes: []probe{{event: "geteuid", attach: sysCall, fn: "geteuid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	GetegidEventID:             {ID: GetegidEventID, ID32Bit: sys32getegid, Name: "getegid", Probes: []probe{{event: "getegid", attach: sysCall, fn: "getegid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SetpgidEventID:             {ID: SetpgidEventID, ID32Bit: sys32setpgid, Name: "setpgid", Probes: []probe{{event: "setpgid", attach: sysCall, fn: "setpgid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	GetppidEventID:             {ID: GetppidEventID, ID32Bit: sys32getppid, Name: "getppid", Probes: []probe{{event: "getppid", attach: sysCall, fn: "getppid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	GetpgrpEventID:             {ID: GetpgrpEventID, ID32Bit: sys32getpgrp, Name: "getpgrp", Probes: []probe{{event: "getpgrp", attach: sysCall, fn: "getpgrp"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SetsidEventID:              {ID: SetsidEventID, ID32Bit: sys32setsid, Name: "setsid", Probes: []probe{{event: "setsid", attach: sysCall, fn: "setsid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SetreuidEventID:            {ID: SetreuidEventID, ID32Bit: sys32setreuid, Name: "setreuid", Probes: []probe{{event: "setreuid", attach: sysCall, fn: "setreuid"}}, Sets: []string{"default", "syscalls", "proc", "proc_ids"}},
	SetregidEventID:            {ID: SetregidEventID, ID32Bit: sys32setregid, Name: "setregid", Probes: []probe{{event: "setregid", attach: sysCall, fn: "setregid"}}, Sets: []string{"default", "syscalls", "proc", "proc_ids"}},
	GetgroupsEventID:           {ID: GetgroupsEventID, ID32Bit: sys32getgroups, Name: "getgroups", Probes: []probe{{event: "getgroups", attach: sysCall, fn: "getgroups"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SetgroupsEventID:           {ID: SetgroupsEventID, ID32Bit: sys32setgroups, Name: "setgroups", Probes: []probe{{event: "setgroups", attach: sysCall, fn: "setgroups"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SetresuidEventID:           {ID: SetresuidEventID, ID32Bit: sys32setresuid, Name: "setresuid", Probes: []probe{{event: "setresuid", attach: sysCall, fn: "setresuid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	GetresuidEventID:           {ID: GetresuidEventID, ID32Bit: sys32getresuid, Name: "getresuid", Probes: []probe{{event: "getresuid", attach: sysCall, fn: "getresuid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SetresgidEventID:           {ID: SetresgidEventID, ID32Bit: sys32setresgid, Name: "setresgid", Probes: []probe{{event: "setresgid", attach: sysCall, fn: "setresgid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	GetresgidEventID:           {ID: GetresgidEventID, ID32Bit: sys32getresgid, Name: "getresgid", Probes: []probe{{event: "getresgid", attach: sysCall, fn: "getresgid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	GetpgidEventID:             {ID: GetpgidEventID, ID32Bit: sys32getpgid, Name: "getpgid", Probes: []probe{{event: "getpgid", attach: sysCall, fn: "getpgid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	SetfsuidEventID:            {ID: SetfsuidEventID, ID32Bit: sys32setfsuid, Name: "setfsuid", Probes: []probe{{event: "setfsuid", attach: sysCall, fn: "setfsuid"}}, Sets: []string{"default", "syscalls", "proc", "proc_ids"}},
	SetfsgidEventID:            {ID: SetfsgidEventID, ID32Bit: sys32setfsgid, Name: "setfsgid", Probes: []probe{{event: "setfsgid", attach: sysCall, fn: "setfsgid"}}, Sets: []string{"default", "syscalls", "proc", "proc_ids"}},
	GetsidEventID:              {ID: GetsidEventID, ID32Bit: sys32getsid, Name: "getsid", Probes: []probe{{event: "getsid", attach: sysCall, fn: "getsid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	CapgetEventID:              {ID: CapgetEventID, ID32Bit: sys32capget, Name: "capget", Probes: []probe{{event: "capget", attach: sysCall, fn: "capget"}}, Sets: []string{"syscalls", "proc"}},
	CapsetEventID:              {ID: CapsetEventID, ID32Bit: sys32capset, Name: "capset", Probes: []probe{{event: "capset", attach: sysCall, fn: "capset"}}, Sets: []string{"syscalls", "proc"}},
	RtSigpendingEventID:        {ID: RtSigpendingEventID, ID32Bit: sys32rt_sigpending, Name: "rt_sigpending", Probes: []probe{{event: "rt_sigpending", attach: sysCall, fn: "rt_sigpending"}}, Sets: []string{"syscalls", "signals"}},
	RtSigtimedwaitEventID:      {ID: RtSigtimedwaitEventID, ID32Bit: sys32rt_sigtimedwait, Name: "rt_sigtimedwait", Probes: []probe{{event: "rt_sigtimedwait", attach: sysCall, fn: "rt_sigtimedwait"}}, Sets: []string{"syscalls", "signals"}},
	RtSigqueueinfoEventID:      {ID: RtSigqueueinfoEventID, ID32Bit: sys32rt_sigqueueinfo, Name: "rt_sigqueueinfo", Probes: []probe{{event: "rt_sigqueueinfo", attach: sysCall, fn: "rt_sigqueueinfo"}}, Sets: []string{"syscalls", "signals"}},
	RtSigsuspendEventID:        {ID: RtSigsuspendEventID, ID32Bit: sys32rt_sigsuspend, Name: "rt_sigsuspend", Probes: []probe{{event: "rt_sigsuspend", attach: sysCall, fn: "rt_sigsuspend"}}, Sets: []string{"syscalls", "signals"}},
	SigaltstackEventID:         {ID: SigaltstackEventID, ID32Bit: sys32sigaltstack, Name: "sigaltstack", Probes: []probe{{event: "sigaltstack", attach: sysCall, fn: "sigaltstack"}}, Sets: []string{"syscalls", "signals"}},
	UtimeEventID:               {ID: UtimeEventID, ID32Bit: sys32utime, Name: "utime", Probes: []probe{{event: "utime", attach: sysCall, fn: "utime"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	MknodEventID:               {ID: MknodEventID, ID32Bit: sys32mknod, Name: "mknod", Probes: []probe{{event: "mknod", attach: sysCall, fn: "mknod"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	UselibEventID:              {ID: UselibEventID, ID32Bit: sys32uselib, Name: "uselib", Probes: []probe{{event: "uselib", attach: sysCall, fn: "uselib"}}, Sets: []string{"syscalls", "proc"}},
	PersonalityEventID:         {ID: PersonalityEventID, ID32Bit: sys32personality, Name: "personality", Probes: []probe{{event: "personality", attach: sysCall, fn: "personality"}}, Sets: []string{"syscalls", "system"}},
	UstatEventID:               {ID: UstatEventID, ID32Bit: sys32ustat, Name: "ustat", Probes: []probe{{event: "ustat", attach: sysCall, fn: "ustat"}}, Sets: []string{"syscalls", "fs", "fs_info"}},
	StatfsEventID:              {ID: StatfsEventID, ID32Bit: sys32statfs, Name: "statfs", Probes: []probe{{event: "statfs", attach: sysCall, fn: "statfs"}}, Sets: []string{"syscalls", "fs", "fs_info"}},
	FstatfsEventID:             {ID: FstatfsEventID, ID32Bit: sys32fstatfs, Name: "fstatfs", Probes: []probe{{event: "fstatfs", attach: sysCall, fn: "fstatfs"}}, Sets: []string{"syscalls", "fs", "fs_info"}},
	SysfsEventID:               {ID: SysfsEventID, ID32Bit: sys32sysfs, Name: "sysfs", Probes: []probe{{event: "sysfs", attach: sysCall, fn: "sysfs"}}, Sets: []string{"syscalls", "fs", "fs_info"}},
	GetpriorityEventID:         {ID: GetpriorityEventID, ID32Bit: sys32getpriority, Name: "getpriority", Probes: []probe{{event: "getpriority", attach: sysCall, fn: "getpriority"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SetpriorityEventID:         {ID: SetpriorityEventID, ID32Bit: sys32setpriority, Name: "setpriority", Probes: []probe{{event: "setpriority", attach: sysCall, fn: "setpriority"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedSetparamEventID:       {ID: SchedSetparamEventID, ID32Bit: sys32sched_setparam, Name: "sched_setparam", Probes: []probe{{event: "sched_setparam", attach: sysCall, fn: "sched_setparam"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedGetparamEventID:       {ID: SchedGetparamEventID, ID32Bit: sys32sched_getparam, Name: "sched_getparam", Probes: []probe{{event: "sched_getparam", attach: sysCall, fn: "sched_getparam"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedSetschedulerEventID:   {ID: SchedSetschedulerEventID, ID32Bit: sys32sched_setscheduler, Name: "sched_setscheduler", Probes: []probe{{event: "sched_setscheduler", attach: sysCall, fn: "sched_setscheduler"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedGetschedulerEventID:   {ID: SchedGetschedulerEventID, ID32Bit: sys32sched_getscheduler, Name: "sched_getscheduler", Probes: []probe{{event: "sched_getscheduler", attach: sysCall, fn: "sched_getscheduler"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedGetPriorityMaxEventID: {ID: SchedGetPriorityMaxEventID, ID32Bit: sys32sched_get_priority_max, Name: "sched_get_priority_max", Probes: []probe{{event: "sched_get_priority_max", attach: sysCall, fn: "sched_get_priority_max"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedGetPriorityMinEventID: {ID: SchedGetPriorityMinEventID, ID32Bit: sys32sched_get_priority_min, Name: "sched_get_priority_min", Probes: []probe{{event: "sched_get_priority_min", attach: sysCall, fn: "sched_get_priority_min"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedRrGetIntervalEventID:  {ID: SchedRrGetIntervalEventID, ID32Bit: sys32sched_rr_get_interval, Name: "sched_rr_get_interval", Probes: []probe{{event: "sched_rr_get_interval", attach: sysCall, fn: "sched_rr_get_interval"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	MlockEventID:               {ID: MlockEventID, ID32Bit: sys32mlock, Name: "mlock", Probes: []probe{{event: "mlock", attach: sysCall, fn: "mlock"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	MunlockEventID:             {ID: MunlockEventID, ID32Bit: sys32munlock, Name: "munlock", Probes: []probe{{event: "munlock", attach: sysCall, fn: "munlock"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	MlockallEventID:            {ID: MlockallEventID, ID32Bit: sys32mlockall, Name: "mlockall", Probes: []probe{{event: "mlockall", attach: sysCall, fn: "mlockall"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	MunlockallEventID:          {ID: MunlockallEventID, ID32Bit: sys32munlockall, Name: "munlockall", Probes: []probe{{event: "munlockall", attach: sysCall, fn: "munlockall"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	VhangupEventID:             {ID: VhangupEventID, ID32Bit: sys32vhangup, Name: "vhangup", Probes: []probe{{event: "vhangup", attach: sysCall, fn: "vhangup"}}, Sets: []string{"syscalls", "system"}},
	ModifyLdtEventID:           {ID: ModifyLdtEventID, ID32Bit: sys32modify_ldt, Name: "modify_ldt", Probes: []probe{{event: "modify_ldt", attach: sysCall, fn: "modify_ldt"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	PivotRootEventID:           {ID: PivotRootEventID, ID32Bit: sys32pivot_root, Name: "pivot_root", Probes: []probe{{event: "pivot_root", attach: sysCall, fn: "pivot_root"}}, Sets: []string{"syscalls", "fs"}},
	SysctlEventID:              {ID: SysctlEventID, ID32Bit: sys32undefined, Name: "sysctl", Probes: []probe{{event: "sysctl", attach: sysCall, fn: "sysctl"}}, Sets: []string{"syscalls", "system"}},
	PrctlEventID:               {ID: PrctlEventID, ID32Bit: sys32prctl, Name: "prctl", Probes: []probe{{event: "prctl", attach: sysCall, fn: "prctl"}}, Sets: []string{"default", "syscalls", "proc"}},
	ArchPrctlEventID:           {ID: ArchPrctlEventID, ID32Bit: sys32arch_prctl, Name: "arch_prctl", Probes: []probe{{event: "arch_prctl", attach: sysCall, fn: "arch_prctl"}}, Sets: []string{"syscalls", "proc"}},
	AdjtimexEventID:            {ID: AdjtimexEventID, ID32Bit: sys32adjtimex, Name: "adjtimex", Probes: []probe{{event: "adjtimex", attach: sysCall, fn: "adjtimex"}}, Sets: []string{"syscalls", "time", "time_clock"}},
	SetrlimitEventID:           {ID: SetrlimitEventID, ID32Bit: sys32setrlimit, Name: "setrlimit", Probes: []probe{{event: "setrlimit", attach: sysCall, fn: "setrlimit"}}, Sets: []string{"syscalls", "proc"}},
	ChrootEventID:              {ID: ChrootEventID, ID32Bit: sys32chroot, Name: "chroot", Probes: []probe{{event: "chroot", attach: sysCall, fn: "chroot"}}, Sets: []string{"syscalls", "fs", "fs_dir_ops"}},
	SyncEventID:                {ID: SyncEventID, ID32Bit: sys32sync, Name: "sync", Probes: []probe{{event: "sync", attach: sysCall, fn: "sync"}}, Sets: []string{"syscalls", "fs", "fs_sync"}},
	AcctEventID:                {ID: AcctEventID, ID32Bit: sys32acct, Name: "acct", Probes: []probe{{event: "acct", attach: sysCall, fn: "acct"}}, Sets: []string{"syscalls", "system"}},
	SettimeofdayEventID:        {ID: SettimeofdayEventID, ID32Bit: sys32settimeofday, Name: "settimeofday", Probes: []probe{{event: "settimeofday", attach: sysCall, fn: "settimeofday"}}, Sets: []string{"syscalls", "time", "time_tod"}},
	MountEventID:               {ID: MountEventID, ID32Bit: sys32mount, Name: "mount", Probes: []probe{{event: "mount", attach: sysCall, fn: "mount"}}, Sets: []string{"default", "syscalls", "fs"}},
	UmountEventID:              {ID: UmountEventID, ID32Bit: sys32umount, Name: "umount", Probes: []probe{{event: "umount", attach: sysCall, fn: "umount"}}, Sets: []string{"default", "syscalls", "fs"}},
	SwaponEventID:              {ID: SwaponEventID, ID32Bit: sys32swapon, Name: "swapon", Probes: []probe{{event: "swapon", attach: sysCall, fn: "swapon"}}, Sets: []string{"syscalls", "fs"}},
	SwapoffEventID:             {ID: SwapoffEventID, ID32Bit: sys32swapoff, Name: "swapoff", Probes: []probe{{event: "swapoff", attach: sysCall, fn: "swapoff"}}, Sets: []string{"syscalls", "fs"}},
	RebootEventID:              {ID: RebootEventID, ID32Bit: sys32reboot, Name: "reboot", Probes: []probe{{event: "reboot", attach: sysCall, fn: "reboot"}}, Sets: []string{"syscalls", "system"}},
	SethostnameEventID:         {ID: SethostnameEventID, ID32Bit: sys32sethostname, Name: "sethostname", Probes: []probe{{event: "sethostname", attach: sysCall, fn: "sethostname"}}, Sets: []string{"syscalls", "net"}},
	SetdomainnameEventID:       {ID: SetdomainnameEventID, ID32Bit: sys32setdomainname, Name: "setdomainname", Probes: []probe{{event: "setdomainname", attach: sysCall, fn: "setdomainname"}}, Sets: []string{"syscalls", "net"}},
	IoplEventID:                {ID: IoplEventID, ID32Bit: sys32iopl, Name: "iopl", Probes: []probe{{event: "iopl", attach: sysCall, fn: "iopl"}}, Sets: []string{"syscalls", "system"}},
	IopermEventID:              {ID: IopermEventID, ID32Bit: sys32ioperm, Name: "ioperm", Probes: []probe{{event: "ioperm", attach: sysCall, fn: "ioperm"}}, Sets: []string{"syscalls", "system"}},
	CreateModuleEventID:        {ID: CreateModuleEventID, ID32Bit: sys32create_module, Name: "create_module", Probes: []probe{{event: "create_module", attach: sysCall, fn: "create_module"}}, Sets: []string{"syscalls", "system", "system_module"}},
	InitModuleEventID:          {ID: InitModuleEventID, ID32Bit: sys32init_module, Name: "init_module", Probes: []probe{{event: "init_module", attach: sysCall, fn: "init_module"}}, Sets: []string{"default", "syscalls", "system", "system_module"}},
	DeleteModuleEventID:        {ID: DeleteModuleEventID, ID32Bit: sys32delete_module, Name: "delete_module", Probes: []probe{{event: "delete_module", attach: sysCall, fn: "delete_module"}}, Sets: []string{"default", "syscalls", "system", "system_module"}},
	GetKernelSymsEventID:       {ID: GetKernelSymsEventID, ID32Bit: sys32get_kernel_syms, Name: "get_kernel_syms", Probes: []probe{{event: "get_kernel_syms", attach: sysCall, fn: "get_kernel_syms"}}, Sets: []string{"syscalls", "system", "system_module"}},
	QueryModuleEventID:         {ID: QueryModuleEventID, ID32Bit: sys32query_module, Name: "query_module", Probes: []probe{{event: "query_module", attach: sysCall, fn: "query_module"}}, Sets: []string{"syscalls", "system", "system_module"}},
	QuotactlEventID:            {ID: QuotactlEventID, ID32Bit: sys32quotactl, Name: "quotactl", Probes: []probe{{event: "quotactl", attach: sysCall, fn: "quotactl"}}, Sets: []string{"syscalls", "system"}},
	NfsservctlEventID:          {ID: NfsservctlEventID, ID32Bit: sys32nfsservctl, Name: "nfsservctl", Probes: []probe{{event: "nfsservctl", attach: sysCall, fn: "nfsservctl"}}, Sets: []string{"syscalls", "fs"}},
	GetpmsgEventID:             {ID: GetpmsgEventID, ID32Bit: sys32getpmsg, Name: "getpmsg", Probes: []probe{{event: "getpmsg", attach: sysCall, fn: "getpmsg"}}, Sets: []string{"syscalls"}},
	PutpmsgEventID:             {ID: PutpmsgEventID, ID32Bit: sys32putpmsg, Name: "putpmsg", Probes: []probe{{event: "putpmsg", attach: sysCall, fn: "putpmsg"}}, Sets: []string{"syscalls"}},
	AfsEventID:                 {ID: AfsEventID, ID32Bit: sys32undefined, Name: "afs", Probes: []probe{{event: "afs", attach: sysCall, fn: "afs"}}, Sets: []string{"syscalls"}},
	TuxcallEventID:             {ID: TuxcallEventID, ID32Bit: sys32undefined, Name: "tuxcall", Probes: []probe{{event: "tuxcall", attach: sysCall, fn: "tuxcall"}}, Sets: []string{"syscalls"}},
	SecurityEventID:            {ID: SecurityEventID, ID32Bit: sys32undefined, Name: "security", Probes: []probe{{event: "security", attach: sysCall, fn: "security"}}, Sets: []string{"syscalls"}},
	GettidEventID:              {ID: GettidEventID, ID32Bit: sys32gettid, Name: "gettid", Probes: []probe{{event: "gettid", attach: sysCall, fn: "gettid"}}, Sets: []string{"syscalls", "proc", "proc_ids"}},
	ReadaheadEventID:           {ID: ReadaheadEventID, ID32Bit: sys32readahead, Name: "readahead", Probes: []probe{{event: "readahead", attach: sysCall, fn: "readahead"}}, Sets: []string{"syscalls", "fs"}},
	SetxattrEventID:            {ID: SetxattrEventID, ID32Bit: sys32setxattr, Name: "setxattr", Probes: []probe{{event: "setxattr", attach: sysCall, fn: "setxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	LsetxattrEventID:           {ID: LsetxattrEventID, ID32Bit: sys32lsetxattr, Name: "lsetxattr", Probes: []probe{{event: "lsetxattr", attach: sysCall, fn: "lsetxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	FsetxattrEventID:           {ID: FsetxattrEventID, ID32Bit: sys32fsetxattr, Name: "fsetxattr", Probes: []probe{{event: "fsetxattr", attach: sysCall, fn: "fsetxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	GetxattrEventID:            {ID: GetxattrEventID, ID32Bit: sys32getxattr, Name: "getxattr", Probes: []probe{{event: "getxattr", attach: sysCall, fn: "getxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	LgetxattrEventID:           {ID: LgetxattrEventID, ID32Bit: sys32lgetxattr, Name: "lgetxattr", Probes: []probe{{event: "lgetxattr", attach: sysCall, fn: "lgetxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	FgetxattrEventID:           {ID: FgetxattrEventID, ID32Bit: sys32fgetxattr, Name: "fgetxattr", Probes: []probe{{event: "fgetxattr", attach: sysCall, fn: "fgetxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	ListxattrEventID:           {ID: ListxattrEventID, ID32Bit: sys32listxattr, Name: "listxattr", Probes: []probe{{event: "listxattr", attach: sysCall, fn: "listxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	LlistxattrEventID:          {ID: LlistxattrEventID, ID32Bit: sys32llistxattr, Name: "llistxattr", Probes: []probe{{event: "llistxattr", attach: sysCall, fn: "llistxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	FlistxattrEventID:          {ID: FlistxattrEventID, ID32Bit: sys32flistxattr, Name: "flistxattr", Probes: []probe{{event: "flistxattr", attach: sysCall, fn: "flistxattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	RemovexattrEventID:         {ID: RemovexattrEventID, ID32Bit: sys32removexattr, Name: "removexattr", Probes: []probe{{event: "removexattr", attach: sysCall, fn: "removexattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	LremovexattrEventID:        {ID: LremovexattrEventID, ID32Bit: sys32lremovexattr, Name: "lremovexattr", Probes: []probe{{event: "lremovexattr", attach: sysCall, fn: "lremovexattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	FremovexattrEventID:        {ID: FremovexattrEventID, ID32Bit: sys32fremovexattr, Name: "fremovexattr", Probes: []probe{{event: "fremovexattr", attach: sysCall, fn: "fremovexattr"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	TkillEventID:               {ID: TkillEventID, ID32Bit: sys32tkill, Name: "tkill", Probes: []probe{{event: "tkill", attach: sysCall, fn: "tkill"}}, Sets: []string{"syscalls", "signals"}},
	TimeEventID:                {ID: TimeEventID, ID32Bit: sys32time, Name: "time", Probes: []probe{{event: "time", attach: sysCall, fn: "time"}}, Sets: []string{"syscalls", "time", "time_tod"}},
	FutexEventID:               {ID: FutexEventID, ID32Bit: sys32futex, Name: "futex", Probes: []probe{{event: "futex", attach: sysCall, fn: "futex"}}, Sets: []string{"syscalls", "ipc", "ipc_futex"}},
	SchedSetaffinityEventID:    {ID: SchedSetaffinityEventID, ID32Bit: sys32sched_setaffinity, Name: "sched_setaffinity", Probes: []probe{{event: "sched_setaffinity", attach: sysCall, fn: "sched_setaffinity"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedGetaffinityEventID:    {ID: SchedGetaffinityEventID, ID32Bit: sys32sched_getaffinity, Name: "sched_getaffinity", Probes: []probe{{event: "sched_getaffinity", attach: sysCall, fn: "sched_getaffinity"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SetThreadAreaEventID:       {ID: SetThreadAreaEventID, ID32Bit: sys32set_thread_area, Name: "set_thread_area", Probes: []probe{{event: "set_thread_area", attach: sysCall, fn: "set_thread_area"}}, Sets: []string{"syscalls", "proc"}},
	IoSetupEventID:             {ID: IoSetupEventID, ID32Bit: sys32io_setup, Name: "io_setup", Probes: []probe{{event: "io_setup", attach: sysCall, fn: "io_setup"}}, Sets: []string{"syscalls", "fs", "fs_async_io"}},
	IoDestroyEventID:           {ID: IoDestroyEventID, ID32Bit: sys32io_destroy, Name: "io_destroy", Probes: []probe{{event: "io_destroy", attach: sysCall, fn: "io_destroy"}}, Sets: []string{"syscalls", "fs", "fs_async_io"}},
	IoGeteventsEventID:         {ID: IoGeteventsEventID, ID32Bit: sys32io_getevents, Name: "io_getevents", Probes: []probe{{event: "io_getevents", attach: sysCall, fn: "io_getevents"}}, Sets: []string{"syscalls", "fs", "fs_async_io"}},
	IoSubmitEventID:            {ID: IoSubmitEventID, ID32Bit: sys32io_submit, Name: "io_submit", Probes: []probe{{event: "io_submit", attach: sysCall, fn: "io_submit"}}, Sets: []string{"syscalls", "fs", "fs_async_io"}},
	IoCancelEventID:            {ID: IoCancelEventID, ID32Bit: sys32io_cancel, Name: "io_cancel", Probes: []probe{{event: "io_cancel", attach: sysCall, fn: "io_cancel"}}, Sets: []string{"syscalls", "fs", "fs_async_io"}},
	GetThreadAreaEventID:       {ID: GetThreadAreaEventID, ID32Bit: sys32get_thread_area, Name: "get_thread_area", Probes: []probe{{event: "get_thread_area", attach: sysCall, fn: "get_thread_area"}}, Sets: []string{"syscalls", "proc"}},
	LookupDcookieEventID:       {ID: LookupDcookieEventID, ID32Bit: sys32lookup_dcookie, Name: "lookup_dcookie", Probes: []probe{{event: "lookup_dcookie", attach: sysCall, fn: "lookup_dcookie"}}, Sets: []string{"syscalls", "fs", "fs_dir_ops"}},
	EpollCreateEventID:         {ID: EpollCreateEventID, ID32Bit: sys32epoll_create, Name: "epoll_create", Probes: []probe{{event: "epoll_create", attach: sysCall, fn: "epoll_create"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	EpollCtlOldEventID:         {ID: EpollCtlOldEventID, ID32Bit: sys32undefined, Name: "epoll_ctl_old", Probes: []probe{{event: "epoll_ctl_old", attach: sysCall, fn: "epoll_ctl_old"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	EpollWaitOldEventID:        {ID: EpollWaitOldEventID, ID32Bit: sys32undefined, Name: "epoll_wait_old", Probes: []probe{{event: "epoll_wait_old", attach: sysCall, fn: "epoll_wait_old"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	RemapFilePagesEventID:      {ID: RemapFilePagesEventID, ID32Bit: sys32remap_file_pages, Name: "remap_file_pages", Probes: []probe{{event: "remap_file_pages", attach: sysCall, fn: "remap_file_pages"}}, Sets: []string{"syscalls"}},
	Getdents64EventID:          {ID: Getdents64EventID, ID32Bit: sys32getdents64, Name: "getdents64", Probes: []probe{{event: "getdents64", attach: sysCall, fn: "getdents64"}}, Sets: []string{"default", "syscalls", "fs", "fs_dir_ops"}},
	SetTidAddressEventID:       {ID: SetTidAddressEventID, ID32Bit: sys32set_tid_address, Name: "set_tid_address", Probes: []probe{{event: "set_tid_address", attach: sysCall, fn: "set_tid_address"}}, Sets: []string{"syscalls", "proc"}},
	RestartSyscallEventID:      {ID: RestartSyscallEventID, ID32Bit: sys32restart_syscall, Name: "restart_syscall", Probes: []probe{{event: "restart_syscall", attach: sysCall, fn: "restart_syscall"}}, Sets: []string{"syscalls", "signals"}},
	SemtimedopEventID:          {ID: SemtimedopEventID, ID32Bit: sys32semtimedop_time64, Name: "semtimedop", Probes: []probe{{event: "semtimedop", attach: sysCall, fn: "semtimedop"}}, Sets: []string{"syscalls", "ipc", "ipc_sem"}},
	Fadvise64EventID:           {ID: Fadvise64EventID, ID32Bit: sys32fadvise64, Name: "fadvise64", Probes: []probe{{event: "fadvise64", attach: sysCall, fn: "fadvise64"}}, Sets: []string{"syscalls", "fs"}},
	TimerCreateEventID:         {ID: TimerCreateEventID, ID32Bit: sys32timer_create, Name: "timer_create", Probes: []probe{{event: "timer_create", attach: sysCall, fn: "timer_create"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	TimerSettimeEventID:        {ID: TimerSettimeEventID, ID32Bit: sys32timer_settime, Name: "timer_settime", Probes: []probe{{event: "timer_settime", attach: sysCall, fn: "timer_settime"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	TimerGettimeEventID:        {ID: TimerGettimeEventID, ID32Bit: sys32timer_gettime, Name: "timer_gettime", Probes: []probe{{event: "timer_gettime", attach: sysCall, fn: "timer_gettime"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	TimerGetoverrunEventID:     {ID: TimerGetoverrunEventID, ID32Bit: sys32timer_getoverrun, Name: "timer_getoverrun", Probes: []probe{{event: "timer_getoverrun", attach: sysCall, fn: "timer_getoverrun"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	TimerDeleteEventID:         {ID: TimerDeleteEventID, ID32Bit: sys32timer_delete, Name: "timer_delete", Probes: []probe{{event: "timer_delete", attach: sysCall, fn: "timer_delete"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	ClockSettimeEventID:        {ID: ClockSettimeEventID, ID32Bit: sys32clock_settime, Name: "clock_settime", Probes: []probe{{event: "clock_settime", attach: sysCall, fn: "clock_settime"}}, Sets: []string{"syscalls", "time", "time_clock"}},
	ClockGettimeEventID:        {ID: ClockGettimeEventID, ID32Bit: sys32clock_gettime, Name: "clock_gettime", Probes: []probe{{event: "clock_gettime", attach: sysCall, fn: "clock_gettime"}}, Sets: []string{"syscalls", "time", "time_clock"}},
	ClockGetresEventID:         {ID: ClockGetresEventID, ID32Bit: sys32clock_getres, Name: "clock_getres", Probes: []probe{{event: "clock_getres", attach: sysCall, fn: "clock_getres"}}, Sets: []string{"syscalls", "time", "time_clock"}},
	ClockNanosleepEventID:      {ID: ClockNanosleepEventID, ID32Bit: sys32clock_nanosleep, Name: "clock_nanosleep", Probes: []probe{{event: "clock_nanosleep", attach: sysCall, fn: "clock_nanosleep"}}, Sets: []string{"syscalls", "time", "time_clock"}},
	ExitGroupEventID:           {ID: ExitGroupEventID, ID32Bit: sys32exit_group, Name: "exit_group", Probes: []probe{{event: "exit_group", attach: sysCall, fn: "exit_group"}}, Sets: []string{"syscalls", "proc", "proc_life"}},
	EpollWaitEventID:           {ID: EpollWaitEventID, ID32Bit: sys32epoll_wait, Name: "epoll_wait", Probes: []probe{{event: "epoll_wait", attach: sysCall, fn: "epoll_wait"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	EpollCtlEventID:            {ID: EpollCtlEventID, ID32Bit: sys32epoll_ctl, Name: "epoll_ctl", Probes: []probe{{event: "epoll_ctl", attach: sysCall, fn: "epoll_ctl"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	TgkillEventID:              {ID: TgkillEventID, ID32Bit: sys32tgkill, Name: "tgkill", Probes: []probe{{event: "tgkill", attach: sysCall, fn: "tgkill"}}, Sets: []string{"syscalls", "signals"}},
	UtimesEventID:              {ID: UtimesEventID, ID32Bit: sys32utimes, Name: "utimes", Probes: []probe{{event: "utimes", attach: sysCall, fn: "utimes"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	VserverEventID:             {ID: VserverEventID, ID32Bit: sys32vserver, Name: "vserver", Probes: []probe{{event: "vserver", attach: sysCall, fn: "vserver"}}, Sets: []string{"syscalls"}},
	MbindEventID:               {ID: MbindEventID, ID32Bit: sys32mbind, Name: "mbind", Probes: []probe{{event: "mbind", attach: sysCall, fn: "mbind"}}, Sets: []string{"syscalls", "system", "system_numa"}},
	SetMempolicyEventID:        {ID: SetMempolicyEventID, ID32Bit: sys32set_mempolicy, Name: "set_mempolicy", Probes: []probe{{event: "set_mempolicy", attach: sysCall, fn: "set_mempolicy"}}, Sets: []string{"syscalls", "system", "system_numa"}},
	GetMempolicyEventID:        {ID: GetMempolicyEventID, ID32Bit: sys32get_mempolicy, Name: "get_mempolicy", Probes: []probe{{event: "get_mempolicy", attach: sysCall, fn: "get_mempolicy"}}, Sets: []string{"syscalls", "system", "system_numa"}},
	MqOpenEventID:              {ID: MqOpenEventID, ID32Bit: sys32mq_open, Name: "mq_open", Probes: []probe{{event: "mq_open", attach: sysCall, fn: "mq_open"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	MqUnlinkEventID:            {ID: MqUnlinkEventID, ID32Bit: sys32mq_unlink, Name: "mq_unlink", Probes: []probe{{event: "mq_unlink", attach: sysCall, fn: "mq_unlink"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	MqTimedsendEventID:         {ID: MqTimedsendEventID, ID32Bit: sys32mq_timedsend, Name: "mq_timedsend", Probes: []probe{{event: "mq_timedsend", attach: sysCall, fn: "mq_timedsend"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	MqTimedreceiveEventID:      {ID: MqTimedreceiveEventID, ID32Bit: sys32mq_timedreceive, Name: "mq_timedreceive", Probes: []probe{{event: "mq_timedreceive", attach: sysCall, fn: "mq_timedreceive"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	MqNotifyEventID:            {ID: MqNotifyEventID, ID32Bit: sys32mq_notify, Name: "mq_notify", Probes: []probe{{event: "mq_notify", attach: sysCall, fn: "mq_notify"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	MqGetsetattrEventID:        {ID: MqGetsetattrEventID, ID32Bit: sys32mq_getsetattr, Name: "mq_getsetattr", Probes: []probe{{event: "mq_getsetattr", attach: sysCall, fn: "mq_getsetattr"}}, Sets: []string{"syscalls", "ipc", "ipc_msgq"}},
	KexecLoadEventID:           {ID: KexecLoadEventID, ID32Bit: sys32kexec_load, Name: "kexec_load", Probes: []probe{{event: "kexec_load", attach: sysCall, fn: "kexec_load"}}, Sets: []string{"syscalls", "system"}},
	WaitidEventID:              {ID: WaitidEventID, ID32Bit: sys32waitid, Name: "waitid", Probes: []probe{{event: "waitid", attach: sysCall, fn: "waitid"}}, Sets: []string{"syscalls", "proc", "proc_life"}},
	AddKeyEventID:              {ID: AddKeyEventID, ID32Bit: sys32add_key, Name: "add_key", Probes: []probe{{event: "add_key", attach: sysCall, fn: "add_key"}}, Sets: []string{"syscalls", "system", "system_keys"}},
	RequestKeyEventID:          {ID: RequestKeyEventID, ID32Bit: sys32request_key, Name: "request_key", Probes: []probe{{event: "request_key", attach: sysCall, fn: "request_key"}}, Sets: []string{"syscalls", "system", "system_keys"}},
	KeyctlEventID:              {ID: KeyctlEventID, ID32Bit: sys32keyctl, Name: "keyctl", Probes: []probe{{event: "keyctl", attach: sysCall, fn: "keyctl"}}, Sets: []string{"syscalls", "system", "system_keys"}},
	IoprioSetEventID:           {ID: IoprioSetEventID, ID32Bit: sys32ioprio_set, Name: "ioprio_set", Probes: []probe{{event: "ioprio_set", attach: sysCall, fn: "ioprio_set"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	IoprioGetEventID:           {ID: IoprioGetEventID, ID32Bit: sys32ioprio_get, Name: "ioprio_get", Probes: []probe{{event: "ioprio_get", attach: sysCall, fn: "ioprio_get"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	InotifyInitEventID:         {ID: InotifyInitEventID, ID32Bit: sys32inotify_init, Name: "inotify_init", Probes: []probe{{event: "inotify_init", attach: sysCall, fn: "inotify_init"}}, Sets: []string{"syscalls", "fs", "fs_monitor"}},
	InotifyAddWatchEventID:     {ID: InotifyAddWatchEventID, ID32Bit: sys32inotify_add_watch, Name: "inotify_add_watch", Probes: []probe{{event: "inotify_add_watch", attach: sysCall, fn: "inotify_add_watch"}}, Sets: []string{"syscalls", "fs", "fs_monitor"}},
	InotifyRmWatchEventID:      {ID: InotifyRmWatchEventID, ID32Bit: sys32inotify_rm_watch, Name: "inotify_rm_watch", Probes: []probe{{event: "inotify_rm_watch", attach: sysCall, fn: "inotify_rm_watch"}}, Sets: []string{"syscalls", "fs", "fs_monitor"}},
	MigratePagesEventID:        {ID: MigratePagesEventID, ID32Bit: sys32migrate_pages, Name: "migrate_pages", Probes: []probe{{event: "migrate_pages", attach: sysCall, fn: "migrate_pages"}}, Sets: []string{"syscalls", "system", "system_numa"}},
	OpenatEventID:              {ID: OpenatEventID, ID32Bit: sys32openat, Name: "openat", Probes: []probe{{event: "openat", attach: sysCall, fn: "openat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	MkdiratEventID:             {ID: MkdiratEventID, ID32Bit: sys32mkdirat, Name: "mkdirat", Probes: []probe{{event: "mkdirat", attach: sysCall, fn: "mkdirat"}}, Sets: []string{"syscalls", "fs", "fs_dir_ops"}},
	MknodatEventID:             {ID: MknodatEventID, ID32Bit: sys32mknodat, Name: "mknodat", Probes: []probe{{event: "mknodat", attach: sysCall, fn: "mknodat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	FchownatEventID:            {ID: FchownatEventID, ID32Bit: sys32fchownat, Name: "fchownat", Probes: []probe{{event: "fchownat", attach: sysCall, fn: "fchownat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	FutimesatEventID:           {ID: FutimesatEventID, ID32Bit: sys32futimesat, Name: "futimesat", Probes: []probe{{event: "futimesat", attach: sysCall, fn: "futimesat"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	NewfstatatEventID:          {ID: NewfstatatEventID, ID32Bit: sys32fstatat64, Name: "newfstatat", Probes: []probe{{event: "newfstatat", attach: sysCall, fn: "newfstatat"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	UnlinkatEventID:            {ID: UnlinkatEventID, ID32Bit: sys32unlinkat, Name: "unlinkat", Probes: []probe{{event: "unlinkat", attach: sysCall, fn: "unlinkat"}}, Sets: []string{"default", "syscalls", "fs", "fs_link_ops"}},
	RenameatEventID:            {ID: RenameatEventID, ID32Bit: sys32renameat, Name: "renameat", Probes: []probe{{event: "renameat", attach: sysCall, fn: "renameat"}}, Sets: []string{"syscalls", "fs", "fs_file_ops"}},
	LinkatEventID:              {ID: LinkatEventID, ID32Bit: sys32linkat, Name: "linkat", Probes: []probe{{event: "linkat", attach: sysCall, fn: "linkat"}}, Sets: []string{"syscalls", "fs", "fs_link_ops"}},
	SymlinkatEventID:           {ID: SymlinkatEventID, ID32Bit: sys32symlinkat, Name: "symlinkat", Probes: []probe{{event: "symlinkat", attach: sysCall, fn: "symlinkat"}}, Sets: []string{"default", "syscalls", "fs", "fs_link_ops"}},
	ReadlinkatEventID:          {ID: ReadlinkatEventID, ID32Bit: sys32readlinkat, Name: "readlinkat", Probes: []probe{{event: "readlinkat", attach: sysCall, fn: "readlinkat"}}, Sets: []string{"syscalls", "fs", "fs_link_ops"}},
	FchmodatEventID:            {ID: FchmodatEventID, ID32Bit: sys32fchmodat, Name: "fchmodat", Probes: []probe{{event: "fchmodat", attach: sysCall, fn: "fchmodat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	FaccessatEventID:           {ID: FaccessatEventID, ID32Bit: sys32faccessat, Name: "faccessat", Probes: []probe{{event: "faccessat", attach: sysCall, fn: "faccessat"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_attr"}},
	Pselect6EventID:            {ID: Pselect6EventID, ID32Bit: sys32pselect6, Name: "pselect6", Probes: []probe{{event: "pselect6", attach: sysCall, fn: "pselect6"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	PpollEventID:               {ID: PpollEventID, ID32Bit: sys32ppoll, Name: "ppoll", Probes: []probe{{event: "ppoll", attach: sysCall, fn: "ppoll"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	UnshareEventID:             {ID: UnshareEventID, ID32Bit: sys32unshare, Name: "unshare", Probes: []probe{{event: "unshare", attach: sysCall, fn: "unshare"}}, Sets: []string{"syscalls", "proc"}},
	SetRobustListEventID:       {ID: SetRobustListEventID, ID32Bit: sys32set_robust_list, Name: "set_robust_list", Probes: []probe{{event: "set_robust_list", attach: sysCall, fn: "set_robust_list"}}, Sets: []string{"syscalls", "ipc", "ipc_futex"}},
	GetRobustListEventID:       {ID: GetRobustListEventID, ID32Bit: sys32get_robust_list, Name: "get_robust_list", Probes: []probe{{event: "get_robust_list", attach: sysCall, fn: "get_robust_list"}}, Sets: []string{"syscalls", "ipc", "ipc_futex"}},
	SpliceEventID:              {ID: SpliceEventID, ID32Bit: sys32splice, Name: "splice", Probes: []probe{{event: "splice", attach: sysCall, fn: "splice"}}, Sets: []string{"syscalls", "ipc", "ipc_pipe"}},
	TeeEventID:                 {ID: TeeEventID, ID32Bit: sys32tee, Name: "tee", Probes: []probe{{event: "tee", attach: sysCall, fn: "tee"}}, Sets: []string{"syscalls", "ipc", "ipc_pipe"}},
	SyncFileRangeEventID:       {ID: SyncFileRangeEventID, ID32Bit: sys32sync_file_range, Name: "sync_file_range", Probes: []probe{{event: "sync_file_range", attach: sysCall, fn: "sync_file_range"}}, Sets: []string{"syscalls", "fs", "fs_sync"}},
	VmspliceEventID:            {ID: VmspliceEventID, ID32Bit: sys32vmsplice, Name: "vmsplice", Probes: []probe{{event: "vmsplice", attach: sysCall, fn: "vmsplice"}}, Sets: []string{"syscalls", "ipc", "ipc_pipe"}},
	MovePagesEventID:           {ID: MovePagesEventID, ID32Bit: sys32move_pages, Name: "move_pages", Probes: []probe{{event: "move_pages", attach: sysCall, fn: "move_pages"}}, Sets: []string{"syscalls", "system", "system_numa"}},
	UtimensatEventID:           {ID: UtimensatEventID, ID32Bit: sys32utimensat, Name: "utimensat", Probes: []probe{{event: "utimensat", attach: sysCall, fn: "utimensat"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	EpollPwaitEventID:          {ID: EpollPwaitEventID, ID32Bit: sys32epoll_pwait, Name: "epoll_pwait", Probes: []probe{{event: "epoll_pwait", attach: sysCall, fn: "epoll_pwait"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	SignalfdEventID:            {ID: SignalfdEventID, ID32Bit: sys32signalfd, Name: "signalfd", Probes: []probe{{event: "signalfd", attach: sysCall, fn: "signalfd"}}, Sets: []string{"syscalls", "signals"}},
	TimerfdCreateEventID:       {ID: TimerfdCreateEventID, ID32Bit: sys32timerfd_create, Name: "timerfd_create", Probes: []probe{{event: "timerfd_create", attach: sysCall, fn: "timerfd_create"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	EventfdEventID:             {ID: EventfdEventID, ID32Bit: sys32eventfd, Name: "eventfd", Probes: []probe{{event: "eventfd", attach: sysCall, fn: "eventfd"}}, Sets: []string{"syscalls", "signals"}},
	FallocateEventID:           {ID: FallocateEventID, ID32Bit: sys32fallocate, Name: "fallocate", Probes: []probe{{event: "fallocate", attach: sysCall, fn: "fallocate"}}, Sets: []string{"syscalls", "fs", "fs_file_ops"}},
	TimerfdSettimeEventID:      {ID: TimerfdSettimeEventID, ID32Bit: sys32timerfd_settime, Name: "timerfd_settime", Probes: []probe{{event: "timerfd_settime", attach: sysCall, fn: "timerfd_settime"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	TimerfdGettimeEventID:      {ID: TimerfdGettimeEventID, ID32Bit: sys32timerfd_gettime, Name: "timerfd_gettime", Probes: []probe{{event: "timerfd_gettime", attach: sysCall, fn: "timerfd_gettime"}}, Sets: []string{"syscalls", "time", "time_timer"}},
	Accept4EventID:             {ID: Accept4EventID, ID32Bit: sys32accept4, Name: "accept4", Probes: []probe{{event: "accept4", attach: sysCall, fn: "accept4"}}, Sets: []string{"default", "syscalls", "net", "net_sock"}},
	Signalfd4EventID:           {ID: Signalfd4EventID, ID32Bit: sys32signalfd4, Name: "signalfd4", Probes: []probe{{event: "signalfd4", attach: sysCall, fn: "signalfd4"}}, Sets: []string{"syscalls", "signals"}},
	Eventfd2EventID:            {ID: Eventfd2EventID, ID32Bit: sys32eventfd2, Name: "eventfd2", Probes: []probe{{event: "eventfd2", attach: sysCall, fn: "eventfd2"}}, Sets: []string{"syscalls", "signals"}},
	EpollCreate1EventID:        {ID: EpollCreate1EventID, ID32Bit: sys32epoll_create1, Name: "epoll_create1", Probes: []probe{{event: "epoll_create1", attach: sysCall, fn: "epoll_create1"}}, Sets: []string{"syscalls", "fs", "fs_mux_io"}},
	Dup3EventID:                {ID: Dup3EventID, ID32Bit: sys32dup3, Name: "dup3", Probes: []probe{{event: "dup3", attach: sysCall, fn: "dup3"}}, Sets: []string{"default", "syscalls", "fs", "fs_fd_ops"}},
	Pipe2EventID:               {ID: Pipe2EventID, ID32Bit: sys32pipe2, Name: "pipe2", Probes: []probe{{event: "pipe2", attach: sysCall, fn: "pipe2"}}, Sets: []string{"syscalls", "ipc", "ipc_pipe"}},
	InotifyInit1EventID:        {ID: InotifyInit1EventID, ID32Bit: sys32inotify_init1, Name: "inotify_init1", Probes: []probe{{event: "inotify_init1", attach: sysCall, fn: "inotify_init1"}}, Sets: []string{"syscalls", "fs", "fs_monitor"}},
	PreadvEventID:              {ID: PreadvEventID, ID32Bit: sys32preadv, Name: "preadv", Probes: []probe{{event: "preadv", attach: sysCall, fn: "preadv"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	PwritevEventID:             {ID: PwritevEventID, ID32Bit: sys32pwritev, Name: "pwritev", Probes: []probe{{event: "pwritev", attach: sysCall, fn: "pwritev"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	RtTgsigqueueinfoEventID:    {ID: RtTgsigqueueinfoEventID, ID32Bit: sys32rt_tgsigqueueinfo, Name: "rt_tgsigqueueinfo", Probes: []probe{{event: "rt_tgsigqueueinfo", attach: sysCall, fn: "rt_tgsigqueueinfo"}}, Sets: []string{"syscalls", "signals"}},
	PerfEventOpenEventID:       {ID: PerfEventOpenEventID, ID32Bit: sys32perf_event_open, Name: "perf_event_open", Probes: []probe{{event: "perf_event_open", attach: sysCall, fn: "perf_event_open"}}, Sets: []string{"syscalls", "system"}},
	RecvmmsgEventID:            {ID: RecvmmsgEventID, ID32Bit: sys32recvmmsg, Name: "recvmmsg", Probes: []probe{{event: "recvmmsg", attach: sysCall, fn: "recvmmsg"}}, Sets: []string{"syscalls", "net", "net_snd_rcv"}},
	FanotifyInitEventID:        {ID: FanotifyInitEventID, ID32Bit: sys32fanotify_init, Name: "fanotify_init", Probes: []probe{{event: "fanotify_init", attach: sysCall, fn: "fanotify_init"}}, Sets: []string{"syscalls", "fs", "fs_monitor"}},
	FanotifyMarkEventID:        {ID: FanotifyMarkEventID, ID32Bit: sys32fanotify_mark, Name: "fanotify_mark", Probes: []probe{{event: "fanotify_mark", attach: sysCall, fn: "fanotify_mark"}}, Sets: []string{"syscalls", "fs", "fs_monitor"}},
	Prlimit64EventID:           {ID: Prlimit64EventID, ID32Bit: sys32prlimit64, Name: "prlimit64", Probes: []probe{{event: "prlimit64", attach: sysCall, fn: "prlimit64"}}, Sets: []string{"syscalls", "proc"}},
	NameToHandleAtEventID:      {ID: NameToHandleAtEventID, ID32Bit: sys32name_to_handle_at, Name: "name_to_handle_at", Probes: []probe{{event: "name_to_handle_at", attach: sysCall, fn: "name_to_handle_at"}}, Sets: []string{"syscalls", "fs", "fs_file_ops"}},
	OpenByHandleAtEventID:      {ID: OpenByHandleAtEventID, ID32Bit: sys32open_by_handle_at, Name: "open_by_handle_at", Probes: []probe{{event: "open_by_handle_at", attach: sysCall, fn: "open_by_handle_at"}}, Sets: []string{"syscalls", "fs", "fs_file_ops"}},
	ClockAdjtimeEventID:        {ID: ClockAdjtimeEventID, ID32Bit: sys32clock_adjtime, Name: "clock_adjtime", Probes: []probe{{event: "clock_adjtime", attach: sysCall, fn: "clock_adjtime"}}, Sets: []string{"syscalls", "time", "time_clock"}},
	SyncfsEventID:              {ID: SyncfsEventID, ID32Bit: sys32syncfs, Name: "syncfs", Probes: []probe{{event: "syncfs", attach: sysCall, fn: "syncfs"}}, Sets: []string{"syscalls", "fs", "fs_sync"}},
	SendmmsgEventID:            {ID: SendmmsgEventID, ID32Bit: sys32sendmmsg, Name: "sendmmsg", Probes: []probe{{event: "sendmmsg", attach: sysCall, fn: "sendmmsg"}}, Sets: []string{"syscalls", "net", "net_snd_rcv"}},
	SetnsEventID:               {ID: SetnsEventID, ID32Bit: sys32setns, Name: "setns", Probes: []probe{{event: "setns", attach: sysCall, fn: "setns"}}, Sets: []string{"syscalls", "proc"}},
	GetcpuEventID:              {ID: GetcpuEventID, ID32Bit: sys32getcpu, Name: "getcpu", Probes: []probe{{event: "getcpu", attach: sysCall, fn: "getcpu"}}, Sets: []string{"syscalls", "system", "system_numa"}},
	ProcessVmReadvEventID:      {ID: ProcessVmReadvEventID, ID32Bit: sys32process_vm_readv, Name: "process_vm_readv", Probes: []probe{{event: "process_vm_readv", attach: sysCall, fn: "process_vm_readv"}}, Sets: []string{"default", "syscalls", "proc"}},
	ProcessVmWritevEventID:     {ID: ProcessVmWritevEventID, ID32Bit: sys32process_vm_writev, Name: "process_vm_writev", Probes: []probe{{event: "process_vm_writev", attach: sysCall, fn: "process_vm_writev"}}, Sets: []string{"default", "syscalls", "proc"}},
	KcmpEventID:                {ID: KcmpEventID, ID32Bit: sys32kcmp, Name: "kcmp", Probes: []probe{{event: "kcmp", attach: sysCall, fn: "kcmp"}}, Sets: []string{"syscalls", "proc"}},
	FinitModuleEventID:         {ID: FinitModuleEventID, ID32Bit: sys32finit_module, Name: "finit_module", Probes: []probe{{event: "finit_module", attach: sysCall, fn: "finit_module"}}, Sets: []string{"default", "syscalls", "system", "system_module"}},
	SchedSetattrEventID:        {ID: SchedSetattrEventID, ID32Bit: sys32sched_setattr, Name: "sched_setattr", Probes: []probe{{event: "sched_setattr", attach: sysCall, fn: "sched_setattr"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	SchedGetattrEventID:        {ID: SchedGetattrEventID, ID32Bit: sys32sched_getattr, Name: "sched_getattr", Probes: []probe{{event: "sched_getattr", attach: sysCall, fn: "sched_getattr"}}, Sets: []string{"syscalls", "proc", "proc_sched"}},
	Renameat2EventID:           {ID: Renameat2EventID, ID32Bit: sys32renameat2, Name: "renameat2", Probes: []probe{{event: "renameat2", attach: sysCall, fn: "renameat2"}}, Sets: []string{"syscalls", "fs", "fs_file_ops"}},
	SeccompEventID:             {ID: SeccompEventID, ID32Bit: sys32seccomp, Name: "seccomp", Probes: []probe{{event: "seccomp", attach: sysCall, fn: "seccomp"}}, Sets: []string{"syscalls", "proc"}},
	GetrandomEventID:           {ID: GetrandomEventID, ID32Bit: sys32getrandom, Name: "getrandom", Probes: []probe{{event: "getrandom", attach: sysCall, fn: "getrandom"}}, Sets: []string{"syscalls", "fs"}},
	MemfdCreateEventID:         {ID: MemfdCreateEventID, ID32Bit: sys32memfd_create, Name: "memfd_create", Probes: []probe{{event: "memfd_create", attach: sysCall, fn: "memfd_create"}}, Sets: []string{"default", "syscalls", "fs", "fs_file_ops"}},
	KexecFileLoadEventID:       {ID: KexecFileLoadEventID, ID32Bit: sys32undefined, Name: "kexec_file_load", Probes: []probe{{event: "kexec_file_load", attach: sysCall, fn: "kexec_file_load"}}, Sets: []string{"syscalls", "system"}},
	BpfEventID:                 {ID: BpfEventID, ID32Bit: sys32bpf, Name: "bpf", Probes: []probe{{event: "bpf", attach: sysCall, fn: "bpf"}}, Sets: []string{"syscalls", "system"}},
	ExecveatEventID:            {ID: ExecveatEventID, ID32Bit: sys32execveat, Name: "execveat", Probes: []probe{{event: "execveat", attach: sysCall, fn: "execveat"}}, Sets: []string{"default", "syscalls", "proc", "proc_life"}},
	UserfaultfdEventID:         {ID: UserfaultfdEventID, ID32Bit: sys32userfaultfd, Name: "userfaultfd", Probes: []probe{{event: "userfaultfd", attach: sysCall, fn: "userfaultfd"}}, Sets: []string{"syscalls", "system"}},
	MembarrierEventID:          {ID: MembarrierEventID, ID32Bit: sys32membarrier, Name: "membarrier", Probes: []probe{{event: "membarrier", attach: sysCall, fn: "membarrier"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	Mlock2EventID:              {ID: Mlock2EventID, ID32Bit: sys32mlock2, Name: "mlock2", Probes: []probe{{event: "mlock2", attach: sysCall, fn: "mlock2"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	CopyFileRangeEventID:       {ID: CopyFileRangeEventID, ID32Bit: sys32copy_file_range, Name: "copy_file_range", Probes: []probe{{event: "copy_file_range", attach: sysCall, fn: "copy_file_range"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	Preadv2EventID:             {ID: Preadv2EventID, ID32Bit: sys32preadv2, Name: "preadv2", Probes: []probe{{event: "preadv2", attach: sysCall, fn: "preadv2"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	Pwritev2EventID:            {ID: Pwritev2EventID, ID32Bit: sys32pwritev2, Name: "pwritev2", Probes: []probe{{event: "pwritev2", attach: sysCall, fn: "pwritev2"}}, Sets: []string{"syscalls", "fs", "fs_read_write"}},
	PkeyMprotectEventID:        {ID: PkeyMprotectEventID, ID32Bit: sys32pkey_mprotect, Name: "pkey_mprotect", Probes: []probe{{event: "pkey_mprotect", attach: sysCall, fn: "pkey_mprotect"}}, Sets: []string{"default", "syscalls", "proc", "proc_mem"}},
	PkeyAllocEventID:           {ID: PkeyAllocEventID, ID32Bit: sys32pkey_alloc, Name: "pkey_alloc", Probes: []probe{{event: "pkey_alloc", attach: sysCall, fn: "pkey_alloc"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	PkeyFreeEventID:            {ID: PkeyFreeEventID, ID32Bit: sys32pkey_free, Name: "pkey_free", Probes: []probe{{event: "pkey_free", attach: sysCall, fn: "pkey_free"}}, Sets: []string{"syscalls", "proc", "proc_mem"}},
	StatxEventID:               {ID: StatxEventID, ID32Bit: sys32statx, Name: "statx", Probes: []probe{{event: "statx", attach: sysCall, fn: "statx"}}, Sets: []string{"syscalls", "fs", "fs_file_attr"}},
	IoPgeteventsEventID:        {ID: IoPgeteventsEventID, ID32Bit: sys32io_pgetevents, Name: "io_pgetevents", Probes: []probe{{event: "io_pgetevents", attach: sysCall, fn: "io_pgetevents"}}, Sets: []string{"syscalls", "fs", "fs_async_io"}},
	RseqEventID:                {ID: RseqEventID, ID32Bit: sys32rseq, Name: "rseq", Probes: []probe{{event: "rseq", attach: sysCall, fn: "rseq"}}, Sets: []string{"syscalls"}},
	SysEnterEventID:            {ID: SysEnterEventID, ID32Bit: sys32undefined, Name: "sys_enter", Probes: []probe{{event: "raw_syscalls:sys_enter", attach: rawTracepoint, fn: "tracepoint__raw_syscalls__sys_enter"}}, EssentialEvent: true, Sets: []string{}},
	SysExitEventID:             {ID: SysExitEventID, ID32Bit: sys32undefined, Name: "sys_exit", Probes: []probe{{event: "raw_syscalls:sys_exit", attach: rawTracepoint, fn: "tracepoint__raw_syscalls__sys_exit"}}, EssentialEvent: true, Sets: []string{}},
	DoExitEventID:              {ID: DoExitEventID, ID32Bit: sys32undefined, Name: "do_exit", Probes: []probe{{event: "do_exit", attach: kprobe, fn: "trace_do_exit"}}, Sets: []string{"proc", "proc_life"}},
	CapCapableEventID:          {ID: CapCapableEventID, ID32Bit: sys32undefined, Name: "cap_capable", Probes: []probe{{event: "cap_capable", attach: kprobe, fn: "trace_cap_capable"}}, Sets: []string{"default"}},
	SecurityBprmCheckEventID:   {ID: SecurityBprmCheckEventID, ID32Bit: sys32undefined, Name: "security_bprm_check", Probes: []probe{{event: "security_bprm_check", attach: kprobe, fn: "trace_security_bprm_check"}}, Sets: []string{"default"}},
	SecurityFileOpenEventID:    {ID: SecurityFileOpenEventID, ID32Bit: sys32undefined, Name: "security_file_open", Probes: []probe{{event: "security_file_open", attach: kprobe, fn: "trace_security_file_open"}}, Sets: []string{"default"}},
	VfsWriteEventID:            {ID: VfsWriteEventID, ID32Bit: sys32undefined, Name: "vfs_write", Probes: []probe{{event: "vfs_write", attach: kprobe, fn: "trace_vfs_write"}, {event: "vfs_write", attach: kretprobe, fn: "trace_ret_vfs_write"}}, Sets: []string{"default"}},
	VfsWritevEventID:           {ID: VfsWritevEventID, ID32Bit: sys32undefined, Name: "vfs_writev", Probes: []probe{{event: "vfs_writev", attach: kprobe, fn: "trace_vfs_writev"}, {event: "vfs_writev", attach: kretprobe, fn: "trace_ret_vfs_writev"}}, Sets: []string{"default"}},
	MemProtAlertEventID:        {ID: MemProtAlertEventID, ID32Bit: sys32undefined, Name: "mem_prot_alert", Probes: []probe{{event: "security_mmap_addr", attach: kprobe, fn: "trace_mmap_alert"}, {event: "security_file_mprotect", attach: kprobe, fn: "trace_mprotect_alert"}}, Sets: []string{}},
	SchedProcessExitEventID:    {ID: SchedProcessExitEventID, ID32Bit: sys32undefined, Name: "sched_process_exit", Probes: []probe{{event: "sched:sched_process_exit", attach: rawTracepoint, fn: "tracepoint__sched__sched_process_exit"}}, EssentialEvent: true, Sets: []string{"default", "proc", "proc_life"}},
}

type param struct {
	pType string
	pName string
}

// EventsIDToParams is list of the parameters (name and type) used by the events
var EventsIDToParams = map[int32][]param{
	ReadEventID:                {{pType: "int", pName: "fd"}, {pType: "void*", pName: "buf"}, {pType: "size_t", pName: "count"}},
	WriteEventID:               {{pType: "int", pName: "fd"}, {pType: "void*", pName: "buf"}, {pType: "size_t", pName: "count"}},
	OpenEventID:                {{pType: "const char*", pName: "pathname"}, {pType: "int", pName: "flags"}, {pType: "mode_t", pName: "mode"}},
	CloseEventID:               {{pType: "int", pName: "fd"}},
	StatEventID:                {{pType: "const char*", pName: "pathname"}, {pType: "struct stat*", pName: "statbuf"}},
	FstatEventID:               {{pType: "int", pName: "fd"}, {pType: "struct stat*", pName: "statbuf"}},
	LstatEventID:               {{pType: "const char*", pName: "pathname"}, {pType: "struct stat*", pName: "statbuf"}},
	PollEventID:                {{pType: "struct pollfd*", pName: "fds"}, {pType: "unsigned int", pName: "nfds"}, {pType: "int", pName: "timeout"}},
	LseekEventID:               {{pType: "int", pName: "fd"}, {pType: "off_t", pName: "offset"}, {pType: "unsigned int", pName: "whence"}},
	MmapEventID:                {{pType: "void*", pName: "addr"}, {pType: "size_t", pName: "length"}, {pType: "int", pName: "prot"}, {pType: "int", pName: "flags"}, {pType: "int", pName: "fd"}, {pType: "off_t", pName: "off"}},
	MprotectEventID:            {{pType: "void*", pName: "addr"}, {pType: "size_t", pName: "len"}, {pType: "int", pName: "prot"}},
	MunmapEventID:              {{pType: "void*", pName: "addr"}, {pType: "size_t", pName: "length"}},
	BrkEventID:                 {{pType: "void*", pName: "addr"}},
	RtSigactionEventID:         {{pType: "int", pName: "signum"}, {pType: "const struct sigaction*", pName: "act"}, {pType: "struct sigaction*", pName: "oldact"}, {pType: "size_t", pName: "sigsetsize"}},
	RtSigprocmaskEventID:       {{pType: "int", pName: "how"}, {pType: "sigset_t*", pName: "set"}, {pType: "sigset_t*", pName: "oldset"}, {pType: "size_t", pName: "sigsetsize"}},
	RtSigreturnEventID:         {},
	IoctlEventID:               {{pType: "int", pName: "fd"}, {pType: "unsigned long", pName: "request"}, {pType: "unsigned long", pName: "arg"}},
	Pread64EventID:             {{pType: "int", pName: "fd"}, {pType: "void*", pName: "buf"}, {pType: "size_t", pName: "count"}, {pType: "off_t", pName: "offset"}},
	Pwrite64EventID:            {{pType: "int", pName: "fd"}, {pType: "const void*", pName: "buf"}, {pType: "size_t", pName: "count"}, {pType: "off_t", pName: "offset"}},
	ReadvEventID:               {{pType: "int", pName: "fd"}, {pType: "const struct iovec*", pName: "iov"}, {pType: "int", pName: "iovcnt"}},
	WritevEventID:              {{pType: "int", pName: "fd"}, {pType: "const struct iovec*", pName: "iov"}, {pType: "int", pName: "iovcnt"}},
	AccessEventID:              {{pType: "const char*", pName: "pathname"}, {pType: "int", pName: "mode"}},
	PipeEventID:                {{pType: "int[2]", pName: "pipefd"}},
	SelectEventID:              {{pType: "int", pName: "nfds"}, {pType: "fd_set*", pName: "readfds"}, {pType: "fd_set*", pName: "writefds"}, {pType: "fd_set*", pName: "exceptfds"}, {pType: "struct timeval*", pName: "timeout"}},
	SchedYieldEventID:          {},
	MremapEventID:              {{pType: "void*", pName: "old_address"}, {pType: "size_t", pName: "old_size"}, {pType: "size_t", pName: "new_size"}, {pType: "int", pName: "flags"}, {pType: "void*", pName: "new_address"}},
	MsyncEventID:               {{pType: "void*", pName: "addr"}, {pType: "size_t", pName: "length"}, {pType: "int", pName: "flags"}},
	MincoreEventID:             {{pType: "void*", pName: "addr"}, {pType: "size_t", pName: "length"}, {pType: "unsigned char*", pName: "vec"}},
	MadviseEventID:             {{pType: "void*", pName: "addr"}, {pType: "size_t", pName: "length"}, {pType: "int", pName: "advice"}},
	ShmgetEventID:              {{pType: "key_t", pName: "key"}, {pType: "size_t", pName: "size"}, {pType: "int", pName: "shmflg"}},
	ShmatEventID:               {{pType: "int", pName: "shmid"}, {pType: "const void*", pName: "shmaddr"}, {pType: "int", pName: "shmflg"}},
	ShmctlEventID:              {{pType: "int", pName: "shmid"}, {pType: "int", pName: "cmd"}, {pType: "struct shmid_ds*", pName: "buf"}},
	DupEventID:                 {{pType: "int", pName: "oldfd"}},
	Dup2EventID:                {{pType: "int", pName: "oldfd"}, {pType: "int", pName: "newfd"}},
	PauseEventID:               {},
	NanosleepEventID:           {{pType: "const struct timespec*", pName: "req"}, {pType: "struct timespec*", pName: "rem"}},
	GetitimerEventID:           {{pType: "int", pName: "which"}, {pType: "struct itimerval*", pName: "curr_value"}},
	AlarmEventID:               {{pType: "unsigned int", pName: "seconds"}},
	SetitimerEventID:           {{pType: "int", pName: "which"}, {pType: "struct itimerval*", pName: "new_value"}, {pType: "struct itimerval*", pName: "old_value"}},
	GetpidEventID:              {},
	SendfileEventID:            {{pType: "int", pName: "out_fd"}, {pType: "int", pName: "in_fd"}, {pType: "off_t*", pName: "offset"}, {pType: "size_t", pName: "count"}},
	SocketEventID:              {{pType: "int", pName: "domain"}, {pType: "int", pName: "type"}, {pType: "int", pName: "protocol"}},
	ConnectEventID:             {{pType: "int", pName: "sockfd"}, {pType: "struct sockaddr*", pName: "addr"}, {pType: "int", pName: "addrlen"}},
	AcceptEventID:              {{pType: "int", pName: "sockfd"}, {pType: "struct sockaddr*", pName: "addr"}, {pType: "int*", pName: "addrlen"}},
	SendtoEventID:              {{pType: "int", pName: "sockfd"}, {pType: "void*", pName: "buf"}, {pType: "size_t", pName: "len"}, {pType: "int", pName: "flags"}, {pType: "struct sockaddr*", pName: "dest_addr"}, {pType: "int", pName: "addrlen"}},
	RecvfromEventID:            {{pType: "int", pName: "sockfd"}, {pType: "void*", pName: "buf"}, {pType: "size_t", pName: "len"}, {pType: "int", pName: "flags"}, {pType: "struct sockaddr*", pName: "src_addr"}, {pType: "int*", pName: "addrlen"}},
	SendmsgEventID:             {{pType: "int", pName: "sockfd"}, {pType: "struct msghdr*", pName: "msg"}, {pType: "int", pName: "flags"}},
	RecvmsgEventID:             {{pType: "int", pName: "sockfd"}, {pType: "struct msghdr*", pName: "msg"}, {pType: "int", pName: "flags"}},
	ShutdownEventID:            {{pType: "int", pName: "sockfd"}, {pType: "int", pName: "how"}},
	BindEventID:                {{pType: "int", pName: "sockfd"}, {pType: "struct sockaddr*", pName: "addr"}, {pType: "int", pName: "addrlen"}},
	ListenEventID:              {{pType: "int", pName: "sockfd"}, {pType: "int", pName: "backlog"}},
	GetsocknameEventID:         {{pType: "int", pName: "sockfd"}, {pType: "struct sockaddr*", pName: "addr"}, {pType: "int*", pName: "addrlen"}},
	GetpeernameEventID:         {{pType: "int", pName: "sockfd"}, {pType: "struct sockaddr*", pName: "addr"}, {pType: "int*", pName: "addrlen"}},
	SocketpairEventID:          {{pType: "int", pName: "domain"}, {pType: "int", pName: "type"}, {pType: "int", pName: "protocol"}, {pType: "int[2]", pName: "sv"}},
	SetsockoptEventID:          {{pType: "int", pName: "sockfd"}, {pType: "int", pName: "level"}, {pType: "int", pName: "optname"}, {pType: "const void*", pName: "optval"}, {pType: "int", pName: "optlen"}},
	GetsockoptEventID:          {{pType: "int", pName: "sockfd"}, {pType: "int", pName: "level"}, {pType: "int", pName: "optname"}, {pType: "char*", pName: "optval"}, {pType: "int*", pName: "optlen"}},
	CloneEventID:               {{pType: "unsigned long", pName: "flags"}, {pType: "void*", pName: "stack"}, {pType: "int*", pName: "parent_tid"}, {pType: "int*", pName: "child_tid"}, {pType: "unsigned long", pName: "tls"}},
	ForkEventID:                {},
	VforkEventID:               {},
	ExecveEventID:              {{pType: "const char*", pName: "pathname"}, {pType: "const char*const*", pName: "argv"}, {pType: "const char*const*", pName: "envp"}},
	ExitEventID:                {{pType: "int", pName: "status"}},
	Wait4EventID:               {{pType: "pid_t", pName: "pid"}, {pType: "int*", pName: "wstatus"}, {pType: "int", pName: "options"}, {pType: "struct rusage*", pName: "rusage"}},
	KillEventID:                {{pType: "pid_t", pName: "pid"}, {pType: "int", pName: "sig"}},
	UnameEventID:               {{pType: "struct utsname*", pName: "buf"}},
	SemgetEventID:              {{pType: "key_t", pName: "key"}, {pType: "int", pName: "nsems"}, {pType: "int", pName: "semflg"}},
	SemopEventID:               {{pType: "int", pName: "semid"}, {pType: "struct sembuf*", pName: "sops"}, {pType: "size_t", pName: "nsops"}},
	SemctlEventID:              {{pType: "int", pName: "semid"}, {pType: "int", pName: "semnum"}, {pType: "int", pName: "cmd"}, {pType: "unsigned long", pName: "arg"}},
	ShmdtEventID:               {{pType: "const void*", pName: "shmaddr"}},
	MsggetEventID:              {{pType: "key_t", pName: "key"}, {pType: "int", pName: "msgflg"}},
	MsgsndEventID:              {{pType: "int", pName: "msqid"}, {pType: "struct msgbuf*", pName: "msgp"}, {pType: "size_t", pName: "msgsz"}, {pType: "int", pName: "msgflg"}},
	MsgrcvEventID:              {{pType: "int", pName: "msqid"}, {pType: "struct msgbuf*", pName: "msgp"}, {pType: "size_t", pName: "msgsz"}, {pType: "long", pName: "msgtyp"}, {pType: "int", pName: "msgflg"}},
	MsgctlEventID:              {{pType: "int", pName: "msqid"}, {pType: "int", pName: "cmd"}, {pType: "struct msqid_ds*", pName: "buf"}},
	FcntlEventID:               {{pType: "int", pName: "fd"}, {pType: "int", pName: "cmd"}, {pType: "unsigned long", pName: "arg"}},
	FlockEventID:               {{pType: "int", pName: "fd"}, {pType: "int", pName: "operation"}},
	FsyncEventID:               {{pType: "int", pName: "fd"}},
	FdatasyncEventID:           {{pType: "int", pName: "fd"}},
	TruncateEventID:            {{pType: "const char*", pName: "path"}, {pType: "off_t", pName: "length"}},
	FtruncateEventID:           {{pType: "int", pName: "fd"}, {pType: "off_t", pName: "length"}},
	GetdentsEventID:            {{pType: "int", pName: "fd"}, {pType: "struct linux_dirent*", pName: "dirp"}, {pType: "unsigned int", pName: "count"}},
	GetcwdEventID:              {{pType: "char*", pName: "buf"}, {pType: "size_t", pName: "size"}},
	ChdirEventID:               {{pType: "const char*", pName: "path"}},
	FchdirEventID:              {{pType: "int", pName: "fd"}},
	RenameEventID:              {{pType: "const char*", pName: "oldpath"}, {pType: "const char*", pName: "newpath"}},
	MkdirEventID:               {{pType: "const char*", pName: "pathname"}, {pType: "mode_t", pName: "mode"}},
	RmdirEventID:               {{pType: "const char*", pName: "pathname"}},
	CreatEventID:               {{pType: "const char*", pName: "pathname"}, {pType: "mode_t", pName: "mode"}},
	LinkEventID:                {{pType: "const char*", pName: "oldpath"}, {pType: "const char*", pName: "newpath"}},
	UnlinkEventID:              {{pType: "const char*", pName: "pathname"}},
	SymlinkEventID:             {{pType: "const char*", pName: "target"}, {pType: "const char*", pName: "linkpath"}},
	ReadlinkEventID:            {{pType: "const char*", pName: "pathname"}, {pType: "char*", pName: "buf"}, {pType: "size_t", pName: "bufsiz"}},
	ChmodEventID:               {{pType: "const char*", pName: "pathname"}, {pType: "mode_t", pName: "mode"}},
	FchmodEventID:              {{pType: "int", pName: "fd"}, {pType: "mode_t", pName: "mode"}},
	ChownEventID:               {{pType: "const char*", pName: "pathname"}, {pType: "uid_t", pName: "owner"}, {pType: "gid_t", pName: "group"}},
	FchownEventID:              {{pType: "int", pName: "fd"}, {pType: "uid_t", pName: "owner"}, {pType: "gid_t", pName: "group"}},
	LchownEventID:              {{pType: "const char*", pName: "pathname"}, {pType: "uid_t", pName: "owner"}, {pType: "gid_t", pName: "group"}},
	UmaskEventID:               {{pType: "mode_t", pName: "mask"}},
	GettimeofdayEventID:        {{pType: "struct timeval*", pName: "tv"}, {pType: "struct timezone*", pName: "tz"}},
	GetrlimitEventID:           {{pType: "int", pName: "resource"}, {pType: "struct rlimit*", pName: "rlim"}},
	GetrusageEventID:           {{pType: "int", pName: "who"}, {pType: "struct rusage*", pName: "usage"}},
	SysinfoEventID:             {{pType: "struct sysinfo*", pName: "info"}},
	TimesEventID:               {{pType: "struct tms*", pName: "buf"}},
	PtraceEventID:              {{pType: "long", pName: "request"}, {pType: "pid_t", pName: "pid"}, {pType: "void*", pName: "addr"}, {pType: "void*", pName: "data"}},
	GetuidEventID:              {},
	SyslogEventID:              {{pType: "int", pName: "type"}, {pType: "char*", pName: "bufp"}, {pType: "int", pName: "len"}},
	GetgidEventID:              {},
	SetuidEventID:              {{pType: "uid_t", pName: "uid"}},
	SetgidEventID:              {{pType: "gid_t", pName: "gid"}},
	GeteuidEventID:             {},
	GetegidEventID:             {},
	SetpgidEventID:             {{pType: "pid_t", pName: "pid"}, {pType: "pid_t", pName: "pgid"}},
	GetppidEventID:             {},
	GetpgrpEventID:             {},
	SetsidEventID:              {},
	SetreuidEventID:            {{pType: "uid_t", pName: "ruid"}, {pType: "uid_t", pName: "euid"}},
	SetregidEventID:            {{pType: "gid_t", pName: "rgid"}, {pType: "gid_t", pName: "egid"}},
	GetgroupsEventID:           {{pType: "int", pName: "size"}, {pType: "gid_t*", pName: "list"}},
	SetgroupsEventID:           {{pType: "int", pName: "size"}, {pType: "gid_t*", pName: "list"}},
	SetresuidEventID:           {{pType: "uid_t", pName: "ruid"}, {pType: "uid_t", pName: "euid"}, {pType: "uid_t", pName: "suid"}},
	GetresuidEventID:           {{pType: "uid_t*", pName: "ruid"}, {pType: "uid_t*", pName: "euid"}, {pType: "uid_t*", pName: "suid"}},
	SetresgidEventID:           {{pType: "gid_t", pName: "rgid"}, {pType: "gid_t", pName: "egid"}, {pType: "gid_t", pName: "sgid"}},
	GetresgidEventID:           {{pType: "gid_t*", pName: "rgid"}, {pType: "gid_t*", pName: "egid"}, {pType: "gid_t*", pName: "sgid"}},
	GetpgidEventID:             {{pType: "pid_t", pName: "pid"}},
	SetfsuidEventID:            {{pType: "uid_t", pName: "fsuid"}},
	SetfsgidEventID:            {{pType: "gid_t", pName: "fsgid"}},
	GetsidEventID:              {{pType: "pid_t", pName: "pid"}},
	CapgetEventID:              {{pType: "cap_user_header_t", pName: "hdrp"}, {pType: "cap_user_data_t", pName: "datap"}},
	CapsetEventID:              {{pType: "cap_user_header_t", pName: "hdrp"}, {pType: "const cap_user_data_t", pName: "datap"}},
	RtSigpendingEventID:        {{pType: "sigset_t*", pName: "set"}, {pType: "size_t", pName: "sigsetsize"}},
	RtSigtimedwaitEventID:      {{pType: "const sigset_t*", pName: "set"}, {pType: "siginfo_t*", pName: "info"}, {pType: "const struct timespec*", pName: "timeout"}, {pType: "size_t", pName: "sigsetsize"}},
	RtSigqueueinfoEventID:      {{pType: "pid_t", pName: "tgid"}, {pType: "int", pName: "sig"}, {pType: "siginfo_t*", pName: "info"}},
	RtSigsuspendEventID:        {{pType: "sigset_t*", pName: "mask"}, {pType: "size_t", pName: "sigsetsize"}},
	SigaltstackEventID:         {{pType: "const stack_t*", pName: "ss"}, {pType: "stack_t*", pName: "old_ss"}},
	UtimeEventID:               {{pType: "const char*", pName: "filename"}, {pType: "const struct utimbuf*", pName: "times"}},
	MknodEventID:               {{pType: "const char*", pName: "pathname"}, {pType: "mode_t", pName: "mode"}, {pType: "dev_t", pName: "dev"}},
	UselibEventID:              {{pType: "const char*", pName: "library"}},
	PersonalityEventID:         {{pType: "unsigned long", pName: "persona"}},
	UstatEventID:               {{pType: "dev_t", pName: "dev"}, {pType: "struct ustat*", pName: "ubuf"}},
	StatfsEventID:              {{pType: "const char*", pName: "path"}, {pType: "struct statfs*", pName: "buf"}},
	FstatfsEventID:             {{pType: "int", pName: "fd"}, {pType: "struct statfs*", pName: "buf"}},
	SysfsEventID:               {{pType: "int", pName: "option"}},
	GetpriorityEventID:         {{pType: "int", pName: "which"}, {pType: "int", pName: "who"}},
	SetpriorityEventID:         {{pType: "int", pName: "which"}, {pType: "int", pName: "who"}, {pType: "int", pName: "prio"}},
	SchedSetparamEventID:       {{pType: "pid_t", pName: "pid"}, {pType: "struct sched_param*", pName: "param"}},
	SchedGetparamEventID:       {{pType: "pid_t", pName: "pid"}, {pType: "struct sched_param*", pName: "param"}},
	SchedSetschedulerEventID:   {{pType: "pid_t", pName: "pid"}, {pType: "int", pName: "policy"}, {pType: "struct sched_param*", pName: "param"}},
	SchedGetschedulerEventID:   {{pType: "pid_t", pName: "pid"}},
	SchedGetPriorityMaxEventID: {{pType: "int", pName: "policy"}},
	SchedGetPriorityMinEventID: {{pType: "int", pName: "policy"}},
	SchedRrGetIntervalEventID:  {{pType: "pid_t", pName: "pid"}, {pType: "struct timespec*", pName: "tp"}},
	MlockEventID:               {{pType: "const void*", pName: "addr"}, {pType: "size_t", pName: "len"}},
	MunlockEventID:             {{pType: "const void*", pName: "addr"}, {pType: "size_t", pName: "len"}},
	MlockallEventID:            {{pType: "int", pName: "flags"}},
	MunlockallEventID:          {},
	VhangupEventID:             {},
	ModifyLdtEventID:           {{pType: "int", pName: "func"}, {pType: "void*", pName: "ptr"}, {pType: "unsigned long", pName: "bytecount"}},
	PivotRootEventID:           {{pType: "const char*", pName: "new_root"}, {pType: "const char*", pName: "put_old"}},
	SysctlEventID:              {{pType: "struct __sysctl_args*", pName: "args"}},
	PrctlEventID:               {{pType: "int", pName: "option"}, {pType: "unsigned long", pName: "arg2"}, {pType: "unsigned long", pName: "arg3"}, {pType: "unsigned long", pName: "arg4"}, {pType: "unsigned long", pName: "arg5"}},
	ArchPrctlEventID:           {{pType: "int", pName: "option"}, {pType: "unsigned long", pName: "addr"}},
	AdjtimexEventID:            {{pType: "struct timex*", pName: "buf"}},
	SetrlimitEventID:           {{pType: "int", pName: "resource"}, {pType: "const struct rlimit*", pName: "rlim"}},
	ChrootEventID:              {{pType: "const char*", pName: "path"}},
	SyncEventID:                {},
	AcctEventID:                {{pType: "const char*", pName: "filename"}},
	SettimeofdayEventID:        {{pType: "const struct timeval*", pName: "tv"}, {pType: "const struct timezone*", pName: "tz"}},
	MountEventID:               {{pType: "const char*", pName: "source"}, {pType: "const char*", pName: "target"}, {pType: "const char*", pName: "filesystemtype"}, {pType: "unsigned long", pName: "mountflags"}, {pType: "const void*", pName: "data"}},
	UmountEventID:              {{pType: "const char*", pName: "target"}, {pType: "int", pName: "flags"}},
	SwaponEventID:              {{pType: "const char*", pName: "path"}, {pType: "int", pName: "swapflags"}},
	SwapoffEventID:             {{pType: "const char*", pName: "path"}},
	RebootEventID:              {{pType: "int", pName: "magic"}, {pType: "int", pName: "magic2"}, {pType: "int", pName: "cmd"}, {pType: "void*", pName: "arg"}},
	SethostnameEventID:         {{pType: "const char*", pName: "name"}, {pType: "size_t", pName: "len"}},
	SetdomainnameEventID:       {{pType: "const char*", pName: "name"}, {pType: "size_t", pName: "len"}},
	IoplEventID:                {{pType: "int", pName: "level"}},
	IopermEventID:              {{pType: "unsigned long", pName: "from"}, {pType: "unsigned long", pName: "num"}, {pType: "int", pName: "turn_on"}},
	InitModuleEventID:          {{pType: "void*", pName: "module_image"}, {pType: "unsigned long", pName: "len"}, {pType: "const char*", pName: "param_values"}},
	DeleteModuleEventID:        {{pType: "const char*", pName: "name"}, {pType: "int", pName: "flags"}},
	QuotactlEventID:            {{pType: "int", pName: "cmd"}, {pType: "const char*", pName: "special"}, {pType: "int", pName: "id"}, {pType: "void*", pName: "addr"}},
	GettidEventID:              {},
	ReadaheadEventID:           {{pType: "int", pName: "fd"}, {pType: "off_t", pName: "offset"}, {pType: "size_t", pName: "count"}},
	SetxattrEventID:            {{pType: "const char*", pName: "path"}, {pType: "const char*", pName: "name"}, {pType: "const void*", pName: "value"}, {pType: "size_t", pName: "size"}, {pType: "int", pName: "flags"}},
	LsetxattrEventID:           {{pType: "const char*", pName: "path"}, {pType: "const char*", pName: "name"}, {pType: "const void*", pName: "value"}, {pType: "size_t", pName: "size"}, {pType: "int", pName: "flags"}},
	FsetxattrEventID:           {{pType: "int", pName: "fd"}, {pType: "const char*", pName: "name"}, {pType: "const void*", pName: "value"}, {pType: "size_t", pName: "size"}, {pType: "int", pName: "flags"}},
	GetxattrEventID:            {{pType: "const char*", pName: "path"}, {pType: "const char*", pName: "name"}, {pType: "void*", pName: "value"}, {pType: "size_t", pName: "size"}},
	LgetxattrEventID:           {{pType: "const char*", pName: "path"}, {pType: "const char*", pName: "name"}, {pType: "void*", pName: "value"}, {pType: "size_t", pName: "size"}},
	FgetxattrEventID:           {{pType: "int", pName: "fd"}, {pType: "const char*", pName: "name"}, {pType: "void*", pName: "value"}, {pType: "size_t", pName: "size"}},
	ListxattrEventID:           {{pType: "const char*", pName: "path"}, {pType: "char*", pName: "list"}, {pType: "size_t", pName: "size"}},
	LlistxattrEventID:          {{pType: "const char*", pName: "path"}, {pType: "char*", pName: "list"}, {pType: "size_t", pName: "size"}},
	FlistxattrEventID:          {{pType: "int", pName: "fd"}, {pType: "char*", pName: "list"}, {pType: "size_t", pName: "size"}},
	RemovexattrEventID:         {{pType: "const char*", pName: "path"}, {pType: "const char*", pName: "name"}},
	LremovexattrEventID:        {{pType: "const char*", pName: "path"}, {pType: "const char*", pName: "name"}},
	FremovexattrEventID:        {{pType: "int", pName: "fd"}, {pType: "const char*", pName: "name"}},
	TkillEventID:               {{pType: "int", pName: "tid"}, {pType: "int", pName: "sig"}},
	TimeEventID:                {{pType: "time_t*", pName: "tloc"}},
	FutexEventID:               {{pType: "int*", pName: "uaddr"}, {pType: "int", pName: "futex_op"}, {pType: "int", pName: "val"}, {pType: "const struct timespec*", pName: "timeout"}, {pType: "int*", pName: "uaddr2"}, {pType: "int", pName: "val3"}},
	SchedSetaffinityEventID:    {{pType: "pid_t", pName: "pid"}, {pType: "size_t", pName: "cpusetsize"}, {pType: "unsigned long*", pName: "mask"}},
	SchedGetaffinityEventID:    {{pType: "pid_t", pName: "pid"}, {pType: "size_t", pName: "cpusetsize"}, {pType: "unsigned long*", pName: "mask"}},
	SetThreadAreaEventID:       {{pType: "struct user_desc*", pName: "u_info"}},
	IoSetupEventID:             {{pType: "unsigned int", pName: "nr_events"}, {pType: "io_context_t*", pName: "ctx_idp"}},
	IoDestroyEventID:           {{pType: "io_context_t", pName: "ctx_id"}},
	IoGeteventsEventID:         {{pType: "io_context_t", pName: "ctx_id"}, {pType: "long", pName: "min_nr"}, {pType: "long", pName: "nr"}, {pType: "struct io_event*", pName: "events"}, {pType: "struct timespec*", pName: "timeout"}},
	IoSubmitEventID:            {{pType: "io_context_t", pName: "ctx_id"}, {pType: "long", pName: "nr"}, {pType: "struct iocb**", pName: "iocbpp"}},
	IoCancelEventID:            {{pType: "io_context_t", pName: "ctx_id"}, {pType: "struct iocb*", pName: "iocb"}, {pType: "struct io_event*", pName: "result"}},
	GetThreadAreaEventID:       {{pType: "struct user_desc*", pName: "u_info"}},
	LookupDcookieEventID:       {{pType: "u64", pName: "cookie"}, {pType: "char*", pName: "buffer"}, {pType: "size_t", pName: "len"}},
	EpollCreateEventID:         {{pType: "int", pName: "size"}},
	RemapFilePagesEventID:      {{pType: "void*", pName: "addr"}, {pType: "size_t", pName: "size"}, {pType: "int", pName: "prot"}, {pType: "size_t", pName: "pgoff"}, {pType: "int", pName: "flags"}},
	Getdents64EventID:          {{pType: "unsigned int", pName: "fd"}, {pType: "struct linux_dirent64*", pName: "dirp"}, {pType: "unsigned int", pName: "count"}},
	SetTidAddressEventID:       {{pType: "int*", pName: "tidptr"}},
	RestartSyscallEventID:      {},
	SemtimedopEventID:          {{pType: "int", pName: "semid"}, {pType: "struct sembuf*", pName: "sops"}, {pType: "size_t", pName: "nsops"}, {pType: "const struct timespec*", pName: "timeout"}},
	Fadvise64EventID:           {{pType: "int", pName: "fd"}, {pType: "off_t", pName: "offset"}, {pType: "size_t", pName: "len"}, {pType: "int", pName: "advice"}},
	TimerCreateEventID:         {{pType: "const clockid_t", pName: "clockid"}, {pType: "struct sigevent*", pName: "sevp"}, {pType: "timer_t*", pName: "timer_id"}},
	TimerSettimeEventID:        {{pType: "timer_t", pName: "timer_id"}, {pType: "int", pName: "flags"}, {pType: "const struct itimerspec*", pName: "new_value"}, {pType: "struct itimerspec*", pName: "old_value"}},
	TimerGettimeEventID:        {{pType: "timer_t", pName: "timer_id"}, {pType: "struct itimerspec*", pName: "curr_value"}},
	TimerGetoverrunEventID:     {{pType: "timer_t", pName: "timer_id"}},
	TimerDeleteEventID:         {{pType: "timer_t", pName: "timer_id"}},
	ClockSettimeEventID:        {{pType: "const clockid_t", pName: "clockid"}, {pType: "const struct timespec*", pName: "tp"}},
	ClockGettimeEventID:        {{pType: "const clockid_t", pName: "clockid"}, {pType: "struct timespec*", pName: "tp"}},
	ClockGetresEventID:         {{pType: "const clockid_t", pName: "clockid"}, {pType: "struct timespec*", pName: "res"}},
	ClockNanosleepEventID:      {{pType: "const clockid_t", pName: "clockid"}, {pType: "int", pName: "flags"}, {pType: "const struct timespec*", pName: "request"}, {pType: "struct timespec*", pName: "remain"}},
	ExitGroupEventID:           {{pType: "int", pName: "status"}},
	EpollWaitEventID:           {{pType: "int", pName: "epfd"}, {pType: "struct epoll_event*", pName: "events"}, {pType: "int", pName: "maxevents"}, {pType: "int", pName: "timeout"}},
	EpollCtlEventID:            {{pType: "int", pName: "epfd"}, {pType: "int", pName: "op"}, {pType: "int", pName: "fd"}, {pType: "struct epoll_event*", pName: "event"}},
	TgkillEventID:              {{pType: "int", pName: "tgid"}, {pType: "int", pName: "tid"}, {pType: "int", pName: "sig"}},
	UtimesEventID:              {{pType: "char*", pName: "filename"}, {pType: "struct timeval*", pName: "times"}},
	MbindEventID:               {{pType: "void*", pName: "addr"}, {pType: "unsigned long", pName: "len"}, {pType: "int", pName: "mode"}, {pType: "const unsigned long*", pName: "nodemask"}, {pType: "unsigned long", pName: "maxnode"}, {pType: "unsigned int", pName: "flags"}},
	SetMempolicyEventID:        {{pType: "int", pName: "mode"}, {pType: "const unsigned long*", pName: "nodemask"}, {pType: "unsigned long", pName: "maxnode"}},
	GetMempolicyEventID:        {{pType: "int*", pName: "mode"}, {pType: "unsigned long*", pName: "nodemask"}, {pType: "unsigned long", pName: "maxnode"}, {pType: "void*", pName: "addr"}, {pType: "unsigned long", pName: "flags"}},
	MqOpenEventID:              {{pType: "const char*", pName: "name"}, {pType: "int", pName: "oflag"}, {pType: "mode_t", pName: "mode"}, {pType: "struct mq_attr*", pName: "attr"}},
	MqUnlinkEventID:            {{pType: "const char*", pName: "name"}},
	MqTimedsendEventID:         {{pType: "mqd_t", pName: "mqdes"}, {pType: "const char*", pName: "msg_ptr"}, {pType: "size_t", pName: "msg_len"}, {pType: "unsigned int", pName: "msg_prio"}, {pType: "const struct timespec*", pName: "abs_timeout"}},
	MqTimedreceiveEventID:      {{pType: "mqd_t", pName: "mqdes"}, {pType: "char*", pName: "msg_ptr"}, {pType: "size_t", pName: "msg_len"}, {pType: "unsigned int*", pName: "msg_prio"}, {pType: "const struct timespec*", pName: "abs_timeout"}},
	MqNotifyEventID:            {{pType: "mqd_t", pName: "mqdes"}, {pType: "const struct sigevent*", pName: "sevp"}},
	MqGetsetattrEventID:        {{pType: "mqd_t", pName: "mqdes"}, {pType: "const struct mq_attr*", pName: "newattr"}, {pType: "struct mq_attr*", pName: "oldattr"}},
	KexecLoadEventID:           {{pType: "unsigned long", pName: "entry"}, {pType: "unsigned long", pName: "nr_segments"}, {pType: "struct kexec_segment*", pName: "segments"}, {pType: "unsigned long", pName: "flags"}},
	WaitidEventID:              {{pType: "int", pName: "idtype"}, {pType: "pid_t", pName: "id"}, {pType: "struct siginfo*", pName: "infop"}, {pType: "int", pName: "options"}, {pType: "struct rusage*", pName: "rusage"}},
	AddKeyEventID:              {{pType: "const char*", pName: "type"}, {pType: "const char*", pName: "description"}, {pType: "const void*", pName: "payload"}, {pType: "size_t", pName: "plen"}, {pType: "key_serial_t", pName: "keyring"}},
	RequestKeyEventID:          {{pType: "const char*", pName: "type"}, {pType: "const char*", pName: "description"}, {pType: "const char*", pName: "callout_info"}, {pType: "key_serial_t", pName: "dest_keyring"}},
	KeyctlEventID:              {{pType: "int", pName: "operation"}, {pType: "unsigned long", pName: "arg2"}, {pType: "unsigned long", pName: "arg3"}, {pType: "unsigned long", pName: "arg4"}, {pType: "unsigned long", pName: "arg5"}},
	IoprioSetEventID:           {{pType: "int", pName: "which"}, {pType: "int", pName: "who"}, {pType: "int", pName: "ioprio"}},
	IoprioGetEventID:           {{pType: "int", pName: "which"}, {pType: "int", pName: "who"}},
	InotifyInitEventID:         {},
	InotifyAddWatchEventID:     {{pType: "int", pName: "fd"}, {pType: "const char*", pName: "pathname"}, {pType: "u32", pName: "mask"}},
	InotifyRmWatchEventID:      {{pType: "int", pName: "fd"}, {pType: "int", pName: "wd"}},
	MigratePagesEventID:        {{pType: "int", pName: "pid"}, {pType: "unsigned long", pName: "maxnode"}, {pType: "const unsigned long*", pName: "old_nodes"}, {pType: "const unsigned long*", pName: "new_nodes"}},
	OpenatEventID:              {{pType: "int", pName: "dirfd"}, {pType: "const char*", pName: "pathname"}, {pType: "int", pName: "flags"}, {pType: "mode_t", pName: "mode"}},
	MkdiratEventID:             {{pType: "int", pName: "dirfd"}, {pType: "const char*", pName: "pathname"}, {pType: "mode_t", pName: "mode"}},
	MknodatEventID:             {{pType: "int", pName: "dirfd"}, {pType: "const char*", pName: "pathname"}, {pType: "mode_t", pName: "mode"}, {pType: "dev_t", pName: "dev"}},
	FchownatEventID:            {{pType: "int", pName: "dirfd"}, {pType: "const char*", pName: "pathname"}, {pType: "uid_t", pName: "owner"}, {pType: "gid_t", pName: "group"}, {pType: "int", pName: "flags"}},
	FutimesatEventID:           {{pType: "int", pName: "dirfd"}, {pType: "const char*", pName: "pathname"}, {pType: "struct timeval*", pName: "times"}},
	NewfstatatEventID:          {{pType: "int", pName: "dirfd"}, {pType: "const char*", pName: "pathname"}, {pType: "struct stat*", pName: "statbuf"}, {pType: "int", pName: "flags"}},
	UnlinkatEventID:            {{pType: "int", pName: "dirfd"}, {pType: "const char*", pName: "pathname"}, {pType: "int", pName: "flags"}},
	RenameatEventID:            {{pType: "int", pName: "olddirfd"}, {pType: "const char*", pName: "oldpath"}, {pType: "int", pName: "newdirfd"}, {pType: "const char*", pName: "newpath"}},
	LinkatEventID:              {{pType: "int", pName: "olddirfd"}, {pType: "const char*", pName: "oldpath"}, {pType: "int", pName: "newdirfd"}, {pType: "const char*", pName: "newpath"}, {pType: "unsigned int", pName: "flags"}},
	SymlinkatEventID:           {{pType: "const char*", pName: "target"}, {pType: "int", pName: "newdirfd"}, {pType: "const char*", pName: "linkpath"}},
	ReadlinkatEventID:          {{pType: "int", pName: "dirfd"}, {pType: "const char*", pName: "pathname"}, {pType: "char*", pName: "buf"}, {pType: "int", pName: "bufsiz"}},
	FchmodatEventID:            {{pType: "int", pName: "dirfd"}, {pType: "const char*", pName: "pathname"}, {pType: "mode_t", pName: "mode"}, {pType: "int", pName: "flags"}},
	FaccessatEventID:           {{pType: "int", pName: "dirfd"}, {pType: "const char*", pName: "pathname"}, {pType: "int", pName: "mode"}, {pType: "int", pName: "flags"}},
	Pselect6EventID:            {{pType: "int", pName: "nfds"}, {pType: "fd_set*", pName: "readfds"}, {pType: "fd_set*", pName: "writefds"}, {pType: "fd_set*", pName: "exceptfds"}, {pType: "struct timespec*", pName: "timeout"}, {pType: "void*", pName: "sigmask"}},
	PpollEventID:               {{pType: "struct pollfd*", pName: "fds"}, {pType: "unsigned int", pName: "nfds"}, {pType: "struct timespec*", pName: "tmo_p"}, {pType: "const sigset_t*", pName: "sigmask"}, {pType: "size_t", pName: "sigsetsize"}},
	UnshareEventID:             {{pType: "int", pName: "flags"}},
	SetRobustListEventID:       {{pType: "struct robust_list_head*", pName: "head"}, {pType: "size_t", pName: "len"}},
	GetRobustListEventID:       {{pType: "int", pName: "pid"}, {pType: "struct robust_list_head**", pName: "head_ptr"}, {pType: "size_t*", pName: "len_ptr"}},
	SpliceEventID:              {{pType: "int", pName: "fd_in"}, {pType: "off_t*", pName: "off_in"}, {pType: "int", pName: "fd_out"}, {pType: "off_t*", pName: "off_out"}, {pType: "size_t", pName: "len"}, {pType: "unsigned int", pName: "flags"}},
	TeeEventID:                 {{pType: "int", pName: "fd_in"}, {pType: "int", pName: "fd_out"}, {pType: "size_t", pName: "len"}, {pType: "unsigned int", pName: "flags"}},
	SyncFileRangeEventID:       {{pType: "int", pName: "fd"}, {pType: "off_t", pName: "offset"}, {pType: "off_t", pName: "nbytes"}, {pType: "unsigned int", pName: "flags"}},
	VmspliceEventID:            {{pType: "int", pName: "fd"}, {pType: "const struct iovec*", pName: "iov"}, {pType: "unsigned long", pName: "nr_segs"}, {pType: "unsigned int", pName: "flags"}},
	MovePagesEventID:           {{pType: "int", pName: "pid"}, {pType: "unsigned long", pName: "count"}, {pType: "const void**", pName: "pages"}, {pType: "const int*", pName: "nodes"}, {pType: "int*", pName: "status"}, {pType: "int", pName: "flags"}},
	UtimensatEventID:           {{pType: "int", pName: "dirfd"}, {pType: "const char*", pName: "pathname"}, {pType: "struct timespec*", pName: "times"}, {pType: "int", pName: "flags"}},
	EpollPwaitEventID:          {{pType: "int", pName: "epfd"}, {pType: "struct epoll_event*", pName: "events"}, {pType: "int", pName: "maxevents"}, {pType: "int", pName: "timeout"}, {pType: "const sigset_t*", pName: "sigmask"}, {pType: "size_t", pName: "sigsetsize"}},
	SignalfdEventID:            {{pType: "int", pName: "fd"}, {pType: "sigset_t*", pName: "mask"}, {pType: "int", pName: "flags"}},
	TimerfdCreateEventID:       {{pType: "int", pName: "clockid"}, {pType: "int", pName: "flags"}},
	EventfdEventID:             {{pType: "unsigned int", pName: "initval"}, {pType: "int", pName: "flags"}},
	FallocateEventID:           {{pType: "int", pName: "fd"}, {pType: "int", pName: "mode"}, {pType: "off_t", pName: "offset"}, {pType: "off_t", pName: "len"}},
	TimerfdSettimeEventID:      {{pType: "int", pName: "fd"}, {pType: "int", pName: "flags"}, {pType: "const struct itimerspec*", pName: "new_value"}, {pType: "struct itimerspec*", pName: "old_value"}},
	TimerfdGettimeEventID:      {{pType: "int", pName: "fd"}, {pType: "struct itimerspec*", pName: "curr_value"}},
	Accept4EventID:             {{pType: "int", pName: "sockfd"}, {pType: "struct sockaddr*", pName: "addr"}, {pType: "int*", pName: "addrlen"}, {pType: "int", pName: "flags"}},
	Signalfd4EventID:           {{pType: "int", pName: "fd"}, {pType: "const sigset_t*", pName: "mask"}, {pType: "size_t", pName: "sizemask"}, {pType: "int", pName: "flags"}},
	Eventfd2EventID:            {{pType: "unsigned int", pName: "initval"}, {pType: "int", pName: "flags"}},
	EpollCreate1EventID:        {{pType: "int", pName: "flags"}},
	Dup3EventID:                {{pType: "int", pName: "oldfd"}, {pType: "int", pName: "newfd"}, {pType: "int", pName: "flags"}},
	Pipe2EventID:               {{pType: "int*", pName: "pipefd"}, {pType: "int", pName: "flags"}},
	InotifyInit1EventID:        {{pType: "int", pName: "flags"}},
	PreadvEventID:              {{pType: "int", pName: "fd"}, {pType: "const struct iovec*", pName: "iov"}, {pType: "unsigned long", pName: "iovcnt"}, {pType: "unsigned long", pName: "pos_l"}, {pType: "unsigned long", pName: "pos_h"}},
	PwritevEventID:             {{pType: "int", pName: "fd"}, {pType: "const struct iovec*", pName: "iov"}, {pType: "unsigned long", pName: "iovcnt"}, {pType: "unsigned long", pName: "pos_l"}, {pType: "unsigned long", pName: "pos_h"}},
	RtTgsigqueueinfoEventID:    {{pType: "pid_t", pName: "tgid"}, {pType: "pid_t", pName: "tid"}, {pType: "int", pName: "sig"}, {pType: "siginfo_t*", pName: "info"}},
	PerfEventOpenEventID:       {{pType: "struct perf_event_attr*", pName: "attr"}, {pType: "pid_t", pName: "pid"}, {pType: "int", pName: "cpu"}, {pType: "int", pName: "group_fd"}, {pType: "unsigned long", pName: "flags"}},
	RecvmmsgEventID:            {{pType: "int", pName: "sockfd"}, {pType: "struct mmsghdr*", pName: "msgvec"}, {pType: "unsigned int", pName: "vlen"}, {pType: "int", pName: "flags"}, {pType: "struct timespec*", pName: "timeout"}},
	FanotifyInitEventID:        {{pType: "unsigned int", pName: "flags"}, {pType: "unsigned int", pName: "event_f_flags"}},
	FanotifyMarkEventID:        {{pType: "int", pName: "fanotify_fd"}, {pType: "unsigned int", pName: "flags"}, {pType: "u64", pName: "mask"}, {pType: "int", pName: "dirfd"}, {pType: "const char*", pName: "pathname"}},
	Prlimit64EventID:           {{pType: "pid_t", pName: "pid"}, {pType: "int", pName: "resource"}, {pType: "const struct rlimit64*", pName: "new_limit"}, {pType: "struct rlimit64*", pName: "old_limit"}},
	NameToHandleAtEventID:      {{pType: "int", pName: "dirfd"}, {pType: "const char*", pName: "pathname"}, {pType: "struct file_handle*", pName: "handle"}, {pType: "int*", pName: "mount_id"}, {pType: "int", pName: "flags"}},
	OpenByHandleAtEventID:      {{pType: "int", pName: "mount_fd"}, {pType: "struct file_handle*", pName: "handle"}, {pType: "int", pName: "flags"}},
	ClockAdjtimeEventID:        {{pType: "const clockid_t", pName: "clk_id"}, {pType: "struct timex*", pName: "buf"}},
	SyncfsEventID:              {{pType: "int", pName: "fd"}},
	SendmmsgEventID:            {{pType: "int", pName: "sockfd"}, {pType: "struct mmsghdr*", pName: "msgvec"}, {pType: "unsigned int", pName: "vlen"}, {pType: "int", pName: "flags"}},
	SetnsEventID:               {{pType: "int", pName: "fd"}, {pType: "int", pName: "nstype"}},
	GetcpuEventID:              {{pType: "unsigned int*", pName: "cpu"}, {pType: "unsigned int*", pName: "node"}, {pType: "struct getcpu_cache*", pName: "tcache"}},
	ProcessVmReadvEventID:      {{pType: "pid_t", pName: "pid"}, {pType: "const struct iovec*", pName: "local_iov"}, {pType: "unsigned long", pName: "liovcnt"}, {pType: "const struct iovec*", pName: "remote_iov"}, {pType: "unsigned long", pName: "riovcnt"}, {pType: "unsigned long", pName: "flags"}},
	ProcessVmWritevEventID:     {{pType: "pid_t", pName: "pid"}, {pType: "const struct iovec*", pName: "local_iov"}, {pType: "unsigned long", pName: "liovcnt"}, {pType: "const struct iovec*", pName: "remote_iov"}, {pType: "unsigned long", pName: "riovcnt"}, {pType: "unsigned long", pName: "flags"}},
	KcmpEventID:                {{pType: "pid_t", pName: "pid1"}, {pType: "pid_t", pName: "pid2"}, {pType: "int", pName: "type"}, {pType: "unsigned long", pName: "idx1"}, {pType: "unsigned long", pName: "idx2"}},
	FinitModuleEventID:         {{pType: "int", pName: "fd"}, {pType: "const char*", pName: "param_values"}, {pType: "int", pName: "flags"}},
	SchedSetattrEventID:        {{pType: "pid_t", pName: "pid"}, {pType: "struct sched_attr*", pName: "attr"}, {pType: "unsigned int", pName: "flags"}},
	SchedGetattrEventID:        {{pType: "pid_t", pName: "pid"}, {pType: "struct sched_attr*", pName: "attr"}, {pType: "unsigned int", pName: "size"}, {pType: "unsigned int", pName: "flags"}},
	Renameat2EventID:           {{pType: "int", pName: "olddirfd"}, {pType: "const char*", pName: "oldpath"}, {pType: "int", pName: "newdirfd"}, {pType: "const char*", pName: "newpath"}, {pType: "unsigned int", pName: "flags"}},
	SeccompEventID:             {{pType: "unsigned int", pName: "operation"}, {pType: "unsigned int", pName: "flags"}, {pType: "const void*", pName: "args"}},
	GetrandomEventID:           {{pType: "void*", pName: "buf"}, {pType: "size_t", pName: "buflen"}, {pType: "unsigned int", pName: "flags"}},
	MemfdCreateEventID:         {{pType: "const char*", pName: "name"}, {pType: "unsigned int", pName: "flags"}},
	KexecFileLoadEventID:       {{pType: "int", pName: "kernel_fd"}, {pType: "int", pName: "initrd_fd"}, {pType: "unsigned long", pName: "cmdline_len"}, {pType: "const char*", pName: "cmdline"}, {pType: "unsigned long", pName: "flags"}},
	BpfEventID:                 {{pType: "int", pName: "cmd"}, {pType: "union bpf_attr*", pName: "attr"}, {pType: "unsigned int", pName: "size"}},
	ExecveatEventID:            {{pType: "int", pName: "dirfd"}, {pType: "const char*", pName: "pathname"}, {pType: "const char*const*", pName: "argv"}, {pType: "const char*const*", pName: "envp"}, {pType: "int", pName: "flags"}},
	UserfaultfdEventID:         {{pType: "int", pName: "flags"}},
	MembarrierEventID:          {{pType: "int", pName: "cmd"}, {pType: "int", pName: "flags"}},
	Mlock2EventID:              {{pType: "const void*", pName: "addr"}, {pType: "size_t", pName: "len"}, {pType: "int", pName: "flags"}},
	CopyFileRangeEventID:       {{pType: "int", pName: "fd_in"}, {pType: "off_t*", pName: "off_in"}, {pType: "int", pName: "fd_out"}, {pType: "off_t*", pName: "off_out"}, {pType: "size_t", pName: "len"}, {pType: "unsigned int", pName: "flags"}},
	Preadv2EventID:             {{pType: "int", pName: "fd"}, {pType: "const struct iovec*", pName: "iov"}, {pType: "unsigned long", pName: "iovcnt"}, {pType: "unsigned long", pName: "pos_l"}, {pType: "unsigned long", pName: "pos_h"}, {pType: "int", pName: "flags"}},
	Pwritev2EventID:            {{pType: "int", pName: "fd"}, {pType: "const struct iovec*", pName: "iov"}, {pType: "unsigned long", pName: "iovcnt"}, {pType: "unsigned long", pName: "pos_l"}, {pType: "unsigned long", pName: "pos_h"}, {pType: "int", pName: "flags"}},
	PkeyMprotectEventID:        {{pType: "void*", pName: "addr"}, {pType: "size_t", pName: "len"}, {pType: "int", pName: "prot"}, {pType: "int", pName: "pkey"}},
	PkeyAllocEventID:           {{pType: "unsigned int", pName: "flags"}, {pType: "unsigned long", pName: "access_rights"}},
	PkeyFreeEventID:            {{pType: "int", pName: "pkey"}},
	StatxEventID:               {{pType: "int", pName: "dirfd"}, {pType: "const char*", pName: "pathname"}, {pType: "int", pName: "flags"}, {pType: "unsigned int", pName: "mask"}, {pType: "struct statx*", pName: "statxbuf"}},
	IoPgeteventsEventID:        {{pType: "aio_context_t", pName: "ctx_id"}, {pType: "long", pName: "min_nr"}, {pType: "long", pName: "nr"}, {pType: "struct io_event*", pName: "events"}, {pType: "struct timespec*", pName: "timeout"}, {pType: "const struct __aio_sigset*", pName: "usig"}},
	RseqEventID:                {{pType: "struct rseq*", pName: "rseq"}, {pType: "u32", pName: "rseq_len"}, {pType: "int", pName: "flags"}, {pType: "u32", pName: "sig"}},
	SysEnterEventID:            {{pType: "int", pName: "syscall"}},
	SysExitEventID:             {{pType: "int", pName: "syscall"}},
	DoExitEventID:              {},
	CapCapableEventID:          {{pType: "int", pName: "cap"}, {pType: "int", pName: "syscall"}},
	SecurityBprmCheckEventID:   {{pType: "const char*", pName: "pathname"}, {pType: "dev_t", pName: "dev"}, {pType: "unsigned long", pName: "inode"}},
	SecurityFileOpenEventID:    {{pType: "const char*", pName: "pathname"}, {pType: "int", pName: "flags"}, {pType: "dev_t", pName: "dev"}, {pType: "unsigned long", pName: "inode"}},
	VfsWriteEventID:            {{pType: "const char*", pName: "pathname"}, {pType: "dev_t", pName: "dev"}, {pType: "unsigned long", pName: "inode"}, {pType: "size_t", pName: "count"}, {pType: "off_t", pName: "pos"}},
	VfsWritevEventID:           {{pType: "const char*", pName: "pathname"}, {pType: "dev_t", pName: "dev"}, {pType: "unsigned long", pName: "inode"}, {pType: "unsigned long", pName: "vlen"}, {pType: "off_t", pName: "pos"}},
	MemProtAlertEventID:        {{pType: "alert_t", pName: "alert"}},
	SchedProcessExitEventID:    {},
}
