// +build arm64

package tracee

// ARM64 syscall numbers
// Also used as event IDs
// https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/unistd.h
const (
	IoSetupEventID             int32 = 0
	IoDestroyEventID           int32 = 1
	IoSubmitEventID            int32 = 2
	IoCancelEventID            int32 = 3
	IoGeteventsEventID         int32 = 4
	SetxattrEventID            int32 = 5
	LsetxattrEventID           int32 = 6
	FsetxattrEventID           int32 = 7
	GetxattrEventID            int32 = 8
	LgetxattrEventID           int32 = 9
	FgetxattrEventID           int32 = 10
	ListxattrEventID           int32 = 11
	LlistxattrEventID          int32 = 12
	FlistxattrEventID          int32 = 13
	RemovexattrEventID         int32 = 14
	LremovexattrEventID        int32 = 15
	FremovexattrEventID        int32 = 16
	GetcwdEventID              int32 = 17
	LookupDcookieEventID       int32 = 18
	Eventfd2EventID            int32 = 19
	EpollCreate1EventID        int32 = 20
	EpollCtlEventID            int32 = 21
	EpollPwaitEventID          int32 = 22
	DupEventID                 int32 = 23
	Dup3EventID                int32 = 24
	FcntlEventID               int32 = 25
	InotifyInit1EventID        int32 = 26
	InotifyAddWatchEventID     int32 = 27
	InotifyRmWatchEventID      int32 = 28
	IoctlEventID               int32 = 29
	IoprioSetEventID           int32 = 30
	IoprioGetEventID           int32 = 31
	FlockEventID               int32 = 32
	MknodatEventID             int32 = 33
	MkdiratEventID             int32 = 34
	UnlinkatEventID            int32 = 35
	SymlinkatEventID           int32 = 36
	LinkatEventID              int32 = 37
	RenameatEventID            int32 = 38
	Umount2EventID             int32 = 39
	MountEventID               int32 = 40
	PivotRootEventID           int32 = 41
	NfsservctlEventID          int32 = 42
	StatfsEventID              int32 = 43
	FstatfsEventID             int32 = 44
	TruncateEventID            int32 = 45
	FtruncateEventID           int32 = 46
	FallocateEventID           int32 = 47
	FaccessatEventID           int32 = 48
	ChdirEventID               int32 = 49
	FchdirEventID              int32 = 50
	ChrootEventID              int32 = 51
	FchmodEventID              int32 = 52
	FchmodatEventID            int32 = 53
	FchownatEventID            int32 = 54
	FchownEventID              int32 = 55
	OpenatEventID              int32 = 56
	CloseEventID               int32 = 57
	VhangupEventID             int32 = 58
	Pipe2EventID               int32 = 59
	QuotactlEventID            int32 = 60
	Getdents64EventID          int32 = 61
	LseekEventID               int32 = 62
	ReadEventID                int32 = 63
	WriteEventID               int32 = 64
	ReadvEventID               int32 = 65
	WritevEventID              int32 = 66
	Pread64EventID             int32 = 67
	Pwrite64EventID            int32 = 68
	PreadvEventID              int32 = 69
	PwritevEventID             int32 = 70
	SendfileEventID            int32 = 71
	Pselect6EventID            int32 = 72
	PpollEventID               int32 = 73
	Signalfd4EventID           int32 = 74
	VmspliceEventID            int32 = 75
	SpliceEventID              int32 = 76
	TeeEventID                 int32 = 77
	ReadlinkatEventID          int32 = 78
	NewfstatatEventID          int32 = 79
	FstatEventID               int32 = 80
	SyncEventID                int32 = 81
	FsyncEventID               int32 = 82
	FdatasyncEventID           int32 = 83
	SyncFileRangeEventID       int32 = 84
	TimerfdCreateEventID       int32 = 85
	TimerfdSettimeEventID      int32 = 86
	TimerfdGettimeEventID      int32 = 87
	UtimensatEventID           int32 = 88
	AcctEventID                int32 = 89
	CapgetEventID              int32 = 90
	CapsetEventID              int32 = 91
	PersonalityEventID         int32 = 92
	ExitEventID                int32 = 93
	ExitGroupEventID           int32 = 94
	WaitidEventID              int32 = 95
	SetTidAddressEventID       int32 = 96
	UnshareEventID             int32 = 97
	FutexEventID               int32 = 98
	SetRobustListEventID       int32 = 99
	GetRobustListEventID       int32 = 100
	NanosleepEventID           int32 = 101
	GetitimerEventID           int32 = 102
	SetitimerEventID           int32 = 103
	KexecLoadEventID           int32 = 104
	InitModuleEventID          int32 = 105
	DeleteModuleEventID        int32 = 106
	TimerCreateEventID         int32 = 107
	TimerGettimeEventID        int32 = 108
	TimerGetoverrunEventID     int32 = 109
	TimerSettimeEventID        int32 = 110
	TimerDeleteEventID         int32 = 111
	ClockSettimeEventID        int32 = 112
	ClockGettimeEventID        int32 = 113
	ClockGetresEventID         int32 = 114
	ClockNanosleepEventID      int32 = 115
	SyslogEventID              int32 = 116
	PtraceEventID              int32 = 117
	SchedSetparamEventID       int32 = 118
	SchedSetschedulerEventID   int32 = 119
	SchedGetschedulerEventID   int32 = 120
	SchedGetparamEventID       int32 = 121
	SchedSetaffinityEventID    int32 = 122
	SchedGetaffinityEventID    int32 = 123
	SchedYieldEventID          int32 = 124
	SchedGetPriorityMaxEventID int32 = 125
	SchedGetPriorityMinEventID int32 = 126
	SchedRrGetIntervalEventID  int32 = 127
	RestartSyscallEventID      int32 = 128
	KillEventID                int32 = 129
	TkillEventID               int32 = 130
	TgkillEventID              int32 = 131
	SigaltstackEventID         int32 = 132
	RtSigsuspendEventID        int32 = 133
	RtSigactionEventID         int32 = 134
	RtSigprocmaskEventID       int32 = 135
	RtSigpendingEventID        int32 = 136
	RtSigtimedwaitEventID      int32 = 137
	RtSigqueueinfoEventID      int32 = 138
	RtSigreturnEventID         int32 = 139
	SetpriorityEventID         int32 = 140
	GetpriorityEventID         int32 = 141
	RebootEventID              int32 = 142
	SetregidEventID            int32 = 143
	SetgidEventID              int32 = 144
	SetreuidEventID            int32 = 145
	SetuidEventID              int32 = 146
	SetresuidEventID           int32 = 147
	GetresuidEventID           int32 = 148
	SetresgidEventID           int32 = 149
	GetresgidEventID           int32 = 150
	SetfsuidEventID            int32 = 151
	SetfsgidEventID            int32 = 152
	TimesEventID               int32 = 153
	SetpgidEventID             int32 = 154
	GetpgidEventID             int32 = 155
	GetsidEventID              int32 = 156
	SetsidEventID              int32 = 157
	GetgroupsEventID           int32 = 158
	SetgroupsEventID           int32 = 159
	UnameEventID               int32 = 160
	SethostnameEventID         int32 = 161
	SetdomainnameEventID       int32 = 162
	GetrlimitEventID           int32 = 163
	SetrlimitEventID           int32 = 164
	GetrusageEventID           int32 = 165
	UmaskEventID               int32 = 166
	PrctlEventID               int32 = 167
	GetcpuEventID              int32 = 168
	GettimeofdayEventID        int32 = 169
	SettimeofdayEventID        int32 = 170
	AdjtimexEventID            int32 = 171
	GetpidEventID              int32 = 172
	GetppidEventID             int32 = 173
	GetuidEventID              int32 = 174
	GeteuidEventID             int32 = 175
	GetgidEventID              int32 = 176
	GetegidEventID             int32 = 177
	GettidEventID              int32 = 178
	SysinfoEventID             int32 = 179
	MqOpenEventID              int32 = 180
	MqUnlinkEventID            int32 = 181
	MqTimedsendEventID         int32 = 182
	MqTimedreceiveEventID      int32 = 183
	MqNotifyEventID            int32 = 184
	MqGetsetattrEventID        int32 = 185
	MsggetEventID              int32 = 186
	MsgctlEventID              int32 = 187
	MsgrcvEventID              int32 = 188
	MsgsndEventID              int32 = 189
	SemgetEventID              int32 = 190
	SemctlEventID              int32 = 191
	SemtimedopEventID          int32 = 192
	SemopEventID               int32 = 193
	ShmgetEventID              int32 = 194
	ShmctlEventID              int32 = 195
	ShmatEventID               int32 = 196
	ShmdtEventID               int32 = 197
	SocketEventID              int32 = 198
	SocketpairEventID          int32 = 199
	BindEventID                int32 = 200
	ListenEventID              int32 = 201
	AcceptEventID              int32 = 202
	ConnectEventID             int32 = 203
	GetsocknameEventID         int32 = 204
	GetpeernameEventID         int32 = 205
	SendtoEventID              int32 = 206
	RecvfromEventID            int32 = 207
	SetsockoptEventID          int32 = 208
	GetsockoptEventID          int32 = 209
	ShutdownEventID            int32 = 210
	SendmsgEventID             int32 = 211
	RecvmsgEventID             int32 = 212
	ReadaheadEventID           int32 = 213
	BrkEventID                 int32 = 214
	MunmapEventID              int32 = 215
	MremapEventID              int32 = 216
	AddKeyEventID              int32 = 217
	RequestKeyEventID          int32 = 218
	KeyctlEventID              int32 = 219
	CloneEventID               int32 = 220
	ExecveEventID              int32 = 221
	MmapEventID                int32 = 222
	Fadvise64EventID           int32 = 223
	SwaponEventID              int32 = 224
	SwapoffEventID             int32 = 225
	MprotectEventID            int32 = 226
	MsyncEventID               int32 = 227
	MlockEventID               int32 = 228
	MunlockEventID             int32 = 229
	MlockallEventID            int32 = 230
	MunlockallEventID          int32 = 231
	MincoreEventID             int32 = 232
	MadviseEventID             int32 = 233
	RemapFilePagesEventID      int32 = 234
	MbindEventID               int32 = 235
	GetMempolicyEventID        int32 = 236
	SetMempolicyEventID        int32 = 237
	MigratePagesEventID        int32 = 238
	MovePagesEventID           int32 = 239
	RtTgsigqueueinfoEventID    int32 = 240
	PerfEventOpenEventID       int32 = 241
	Accept4EventID             int32 = 242
	RecvmmsgEventID            int32 = 243
	Sys244EventID              int32 = 244
	Sys245EventID              int32 = 245
	Sys246EventID              int32 = 246
	Sys247EventID              int32 = 247
	Sys248EventID              int32 = 248
	Sys249EventID              int32 = 249
	Sys250EventID              int32 = 250
	Sys251EventID              int32 = 251
	Sys252EventID              int32 = 252
	Sys253EventID              int32 = 253
	Sys254EventID              int32 = 254
	Sys255EventID              int32 = 255
	Sys256EventID              int32 = 256
	Sys257EventID              int32 = 257
	Sys258EventID              int32 = 258
	Sys259EventID              int32 = 259
	Wait4EventID               int32 = 260
	Prlimit64EventID           int32 = 261
	FanotifyInitEventID        int32 = 262
	FanotifyMarkEventID        int32 = 263
	NameToHandleAtEventID      int32 = 264
	OpenByHandleAtEventID      int32 = 265
	ClockAdjtimeEventID        int32 = 266
	SyncfsEventID              int32 = 267
	SetnsEventID               int32 = 268
	SendmmsgEventID            int32 = 269
	ProcessVmReadvEventID      int32 = 270
	ProcessVmWritevEventID     int32 = 271
	KcmpEventID                int32 = 272
	FinitModuleEventID         int32 = 273
	SchedSetattrEventID        int32 = 274
	SchedGetattrEventID        int32 = 275
	Renameat2EventID           int32 = 276
	SeccompEventID             int32 = 277
	GetrandomEventID           int32 = 278
	MemfdCreateEventID         int32 = 279
	BpfEventID                 int32 = 280
	ExecveatEventID            int32 = 281
	UserfaultfdEventID         int32 = 282
	MembarrierEventID          int32 = 283
	Mlock2EventID              int32 = 284
	CopyFileRangeEventID       int32 = 285
	Preadv2EventID             int32 = 286
	Pwritev2EventID            int32 = 287
	PkeyMprotectEventID        int32 = 288
	PkeyAllocEventID           int32 = 289
	PkeyFreeEventID            int32 = 290
	StatxEventID               int32 = 291
	IoPgeteventsEventID        int32 = 292
	RseqEventID                int32 = 293
	KexecFileLoadEventID       int32 = 294
	// 295 through 402 are unassigned to sync up with generic numbers
	ClockGettime64           int32 = 403
	ClockSettime64           int32 = 404
	ClockAdjtime64           int32 = 405
	ClockGetresTime64        int32 = 406
	ClockNanosleepTime64     int32 = 407
	TimerGettime64           int32 = 408
	TimerSettime64           int32 = 409
	TimerfdGettime64         int32 = 410
	TimerfdSettime64         int32 = 411
	UtimensatTime64          int32 = 412
	Pselect6Time64           int32 = 413
	PpollTime64              int32 = 414
	IoPgeteventsTime64       int32 = 416
	RecvmmsgTime64           int32 = 417
	MqTimedsendTime64        int32 = 418
	MqTimedreceiveTime64     int32 = 419
	SemtimedopTime64         int32 = 420
	RtSigtimedwaitTime64     int32 = 421
	FutexTime64              int32 = 422
	SchedRrGetIntervalTime64 int32 = 423
	PidfdSendSignal          int32 = 424
	IoUringSetup             int32 = 425
	IoUringEnter             int32 = 426
	IoUringRegister          int32 = 427
	OpenTree                 int32 = 428
	MoveMount                int32 = 429
	Fsopen                   int32 = 430
	Fsconfig                 int32 = 431
	Fsmount                  int32 = 432
	Fspick                   int32 = 433
	PidfdOpen                int32 = 434
	Clone3                   int32 = 435
	CloseRange               int32 = 436
	Openat2                  int32 = 437
	PidfdGetfd               int32 = 438
	Faccessat2               int32 = 439
	ProcessMadvise           int32 = 440
	EpollPwait2              int32 = 441
)

// following syscalls are undefined on arm64
const (
	OpenEventID int32 = iota + 10000
	StatEventID
	LstatEventID
	PollEventID
	AccessEventID
	PipeEventID
	SelectEventID
	Dup2EventID
	PauseEventID
	AlarmEventID
	ForkEventID
	VforkEventID
	GetdentsEventID
	RenameEventID
	MkdirEventID
	RmdirEventID
	CreatEventID
	LinkEventID
	UnlinkEventID
	SymlinkEventID
	ReadlinkEventID
	ChmodEventID
	ChownEventID
	LchownEventID
	GetpgrpEventID
	UtimeEventID
	MknodEventID
	UselibEventID
	UstatEventID
	SysfsEventID
	ModifyLdtEventID
	SysctlEventID
	ArchPrctlEventID
	UmountEventID
	IoplEventID
	IopermEventID
	CreateModuleEventID
	GetKernelSymsEventID
	QueryModuleEventID
	GetpmsgEventID
	PutpmsgEventID
	AfsEventID
	TuxcallEventID
	SecurityEventID
	TimeEventID
	SetThreadAreaEventID
	GetThreadAreaEventID
	EpollCreateEventID
	EpollCtlOldEventID
	EpollWaitOldEventID
	EpollWaitEventID
	UtimesEventID
	VserverEventID
	InotifyInitEventID
	FutimesatEventID
	SignalfdEventID
	EventfdEventID
)

// ARM 32bit syscall numbers
// Used for compatibility mode
// https://github.com/torvalds/linux/blob/master/arch/arm/tools/syscall.tbl
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
	sys32syscall                      int32 = 113
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
	sys32_188Res                      int32 = 188
	sys32_189Res                      int32 = 189
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
	sys32_222Res                      int32 = 222
	sys32_223Res                      int32 = 223
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
	sys32io_setup                     int32 = 243
	sys32io_destroy                   int32 = 244
	sys32io_getevents                 int32 = 245
	sys32io_submit                    int32 = 246
	sys32io_cancel                    int32 = 247
	sys32exit_group                   int32 = 248
	sys32lookup_dcookie               int32 = 249
	sys32epoll_create                 int32 = 250
	sys32epoll_ctl                    int32 = 251
	sys32epoll_wait                   int32 = 252
	sys32remap_file_pages             int32 = 253
	sys32_254Res                      int32 = 254
	sys32_255Res                      int32 = 255
	sys32set_tid_address              int32 = 256
	sys32timer_create                 int32 = 257
	sys32timer_settime                int32 = 258
	sys32timer_gettime                int32 = 259
	sys32timer_getoverrun             int32 = 260
	sys32timer_delete                 int32 = 261
	sys32clock_settime                int32 = 262
	sys32clock_gettime                int32 = 263
	sys32clock_getres                 int32 = 264
	sys32clock_nanosleep              int32 = 265
	sys32statfs64                     int32 = 266
	sys32fstatfs64                    int32 = 267
	sys32tgkill                       int32 = 268
	sys32utimes                       int32 = 269
	sys32arm_fadvise64_64             int32 = 270
	sys32pciconfig_iobase             int32 = 271
	sys32pciconfig_read               int32 = 272
	sys32pciconfig_write              int32 = 273
	sys32mq_open                      int32 = 274
	sys32mq_unlink                    int32 = 275
	sys32mq_timedsend                 int32 = 276
	sys32mq_timedreceive              int32 = 277
	sys32mq_notify                    int32 = 278
	sys32mq_getsetattr                int32 = 279
	sys32waitid                       int32 = 280
	sys32socket                       int32 = 281
	sys32bind                         int32 = 282
	sys32connect                      int32 = 283
	sys32listen                       int32 = 284
	sys32accept                       int32 = 285
	sys32getsockname                  int32 = 286
	sys32getpeername                  int32 = 287
	sys32socketpair                   int32 = 288
	sys32send                         int32 = 289
	sys32sendto                       int32 = 290
	sys32recv                         int32 = 291
	sys32recvfrom                     int32 = 292
	sys32shutdown                     int32 = 293
	sys32setsockopt                   int32 = 294
	sys32getsockopt                   int32 = 295
	sys32sendmsg                      int32 = 296
	sys32recvmsg                      int32 = 297
	sys32semop                        int32 = 298
	sys32semget                       int32 = 299
	sys32semctl                       int32 = 300
	sys32msgsnd                       int32 = 301
	sys32msgrcv                       int32 = 302
	sys32msgget                       int32 = 303
	sys32msgctl                       int32 = 304
	sys32shmat                        int32 = 305
	sys32shmdt                        int32 = 306
	sys32shmget                       int32 = 307
	sys32shmctl                       int32 = 308
	sys32add_key                      int32 = 309
	sys32request_key                  int32 = 310
	sys32keyctl                       int32 = 311
	sys32semtimedop                   int32 = 312
	sys32vserver                      int32 = 313
	sys32ioprio_set                   int32 = 314
	sys32ioprio_get                   int32 = 315
	sys32inotify_init                 int32 = 316
	sys32inotify_add_watch            int32 = 317
	sys32inotify_rm_watch             int32 = 318
	sys32mbind                        int32 = 319
	sys32get_mempolicy                int32 = 320
	sys32set_mempolicy                int32 = 321
	sys32openat                       int32 = 322
	sys32mkdirat                      int32 = 323
	sys32mknodat                      int32 = 324
	sys32fchownat                     int32 = 325
	sys32futimesat                    int32 = 326
	sys32fstatat64                    int32 = 327
	sys32unlinkat                     int32 = 328
	sys32renameat                     int32 = 329
	sys32linkat                       int32 = 330
	sys32symlinkat                    int32 = 331
	sys32readlinkat                   int32 = 332
	sys32fchmodat                     int32 = 333
	sys32faccessat                    int32 = 334
	sys32pselect6                     int32 = 335
	sys32ppoll                        int32 = 336
	sys32unshare                      int32 = 337
	sys32set_robust_list              int32 = 338
	sys32get_robust_list              int32 = 339
	sys32splice                       int32 = 340
	sys32arm_sync_file_range          int32 = 341
	sys32tee                          int32 = 342
	sys32vmsplice                     int32 = 343
	sys32move_pages                   int32 = 344
	sys32getcpu                       int32 = 345
	sys32epoll_pwait                  int32 = 346
	sys32kexec_load                   int32 = 347
	sys32utimensat                    int32 = 348
	sys32signalfd                     int32 = 349
	sys32timerfd_create               int32 = 350
	sys32eventfd                      int32 = 351
	sys32fallocate                    int32 = 352
	sys32timerfd_settime              int32 = 353
	sys32timerfd_gettime              int32 = 354
	sys32signalfd4                    int32 = 355
	sys32eventfd2                     int32 = 356
	sys32epoll_create1                int32 = 357
	sys32dup3                         int32 = 358
	sys32pipe2                        int32 = 359
	sys32inotify_init1                int32 = 360
	sys32preadv                       int32 = 361
	sys32pwritev                      int32 = 362
	sys32rt_tgsigqueueinfo            int32 = 363
	sys32perf_event_open              int32 = 364
	sys32recvmmsg                     int32 = 365
	sys32accept4                      int32 = 366
	sys32fanotify_init                int32 = 367
	sys32fanotify_mark                int32 = 368
	sys32prlimit64                    int32 = 369
	sys32name_to_handle_at            int32 = 370
	sys32open_by_handle_at            int32 = 371
	sys32clock_adjtime                int32 = 372
	sys32syncfs                       int32 = 373
	sys32sendmmsg                     int32 = 374
	sys32setns                        int32 = 375
	sys32process_vm_readv             int32 = 376
	sys32process_vm_writev            int32 = 377
	sys32kcmp                         int32 = 378
	sys32finit_module                 int32 = 379
	sys32sched_setattr                int32 = 380
	sys32sched_getattr                int32 = 381
	sys32renameat2                    int32 = 382
	sys32seccomp                      int32 = 383
	sys32getrandom                    int32 = 384
	sys32memfd_create                 int32 = 385
	sys32bpf                          int32 = 386
	sys32execveat                     int32 = 387
	sys32userfaultfd                  int32 = 388
	sys32membarrier                   int32 = 389
	sys32mlock2                       int32 = 390
	sys32copy_file_range              int32 = 391
	sys32preadv2                      int32 = 392
	sys32pwritev2                     int32 = 393
	sys32pkey_mprotect                int32 = 394
	sys32pkey_alloc                   int32 = 395
	sys32pkey_free                    int32 = 396
	sys32statx                        int32 = 397
	sys32rseq                         int32 = 398
	sys32io_pgetevents                int32 = 399
	sys32migrate_pages                int32 = 400
	sys32kexec_file_load              int32 = 401
	sys32_402Res                      int32 = 402
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
	sys32close_range                  int32 = 436
	sys32openat2                      int32 = 437
	sys32pidfd_getfd                  int32 = 438
	sys32faccessat2                   int32 = 439
	sys32process_madvise              int32 = 440
	sys32epoll_pwait2                 int32 = 441
	sys32undefined                    int32 = 10000
)

// following syscalls are undefined on arm32
const (
	sys32arch_prctl int32 = iota + 10000
	sys32getpmsg
	sys32putpmsg
	sys32set_thread_area
	sys32get_thread_area
	sys32fadvise64
	sys32sync_file_range
)
