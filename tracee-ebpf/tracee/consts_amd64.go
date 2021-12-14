//go:build amd64
// +build amd64

package tracee

// x86 64bit syscall numbers
// Also used as event IDs
// https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl
const (
	ReadEventID                int32 = 0
	WriteEventID               int32 = 1
	OpenEventID                int32 = 2
	CloseEventID               int32 = 3
	StatEventID                int32 = 4
	FstatEventID               int32 = 5
	LstatEventID               int32 = 6
	PollEventID                int32 = 7
	LseekEventID               int32 = 8
	MmapEventID                int32 = 9
	MprotectEventID            int32 = 10
	MunmapEventID              int32 = 11
	BrkEventID                 int32 = 12
	RtSigactionEventID         int32 = 13
	RtSigprocmaskEventID       int32 = 14
	RtSigreturnEventID         int32 = 15
	IoctlEventID               int32 = 16
	Pread64EventID             int32 = 17
	Pwrite64EventID            int32 = 18
	ReadvEventID               int32 = 19
	WritevEventID              int32 = 20
	AccessEventID              int32 = 21
	PipeEventID                int32 = 22
	SelectEventID              int32 = 23
	SchedYieldEventID          int32 = 24
	MremapEventID              int32 = 25
	MsyncEventID               int32 = 26
	MincoreEventID             int32 = 27
	MadviseEventID             int32 = 28
	ShmgetEventID              int32 = 29
	ShmatEventID               int32 = 30
	ShmctlEventID              int32 = 31
	DupEventID                 int32 = 32
	Dup2EventID                int32 = 33
	PauseEventID               int32 = 34
	NanosleepEventID           int32 = 35
	GetitimerEventID           int32 = 36
	AlarmEventID               int32 = 37
	SetitimerEventID           int32 = 38
	GetpidEventID              int32 = 39
	SendfileEventID            int32 = 40
	SocketEventID              int32 = 41
	ConnectEventID             int32 = 42
	AcceptEventID              int32 = 43
	SendtoEventID              int32 = 44
	RecvfromEventID            int32 = 45
	SendmsgEventID             int32 = 46
	RecvmsgEventID             int32 = 47
	ShutdownEventID            int32 = 48
	BindEventID                int32 = 49
	ListenEventID              int32 = 50
	GetsocknameEventID         int32 = 51
	GetpeernameEventID         int32 = 52
	SocketpairEventID          int32 = 53
	SetsockoptEventID          int32 = 54
	GetsockoptEventID          int32 = 55
	CloneEventID               int32 = 56
	ForkEventID                int32 = 57
	VforkEventID               int32 = 58
	ExecveEventID              int32 = 59
	ExitEventID                int32 = 60
	Wait4EventID               int32 = 61
	KillEventID                int32 = 62
	UnameEventID               int32 = 63
	SemgetEventID              int32 = 64
	SemopEventID               int32 = 65
	SemctlEventID              int32 = 66
	ShmdtEventID               int32 = 67
	MsggetEventID              int32 = 68
	MsgsndEventID              int32 = 69
	MsgrcvEventID              int32 = 70
	MsgctlEventID              int32 = 71
	FcntlEventID               int32 = 72
	FlockEventID               int32 = 73
	FsyncEventID               int32 = 74
	FdatasyncEventID           int32 = 75
	TruncateEventID            int32 = 76
	FtruncateEventID           int32 = 77
	GetdentsEventID            int32 = 78
	GetcwdEventID              int32 = 79
	ChdirEventID               int32 = 80
	FchdirEventID              int32 = 81
	RenameEventID              int32 = 82
	MkdirEventID               int32 = 83
	RmdirEventID               int32 = 84
	CreatEventID               int32 = 85
	LinkEventID                int32 = 86
	UnlinkEventID              int32 = 87
	SymlinkEventID             int32 = 88
	ReadlinkEventID            int32 = 89
	ChmodEventID               int32 = 90
	FchmodEventID              int32 = 91
	ChownEventID               int32 = 92
	FchownEventID              int32 = 93
	LchownEventID              int32 = 94
	UmaskEventID               int32 = 95
	GettimeofdayEventID        int32 = 96
	GetrlimitEventID           int32 = 97
	GetrusageEventID           int32 = 98
	SysinfoEventID             int32 = 99
	TimesEventID               int32 = 100
	PtraceEventID              int32 = 101
	GetuidEventID              int32 = 102
	SyslogEventID              int32 = 103
	GetgidEventID              int32 = 104
	SetuidEventID              int32 = 105
	SetgidEventID              int32 = 106
	GeteuidEventID             int32 = 107
	GetegidEventID             int32 = 108
	SetpgidEventID             int32 = 109
	GetppidEventID             int32 = 110
	GetpgrpEventID             int32 = 111
	SetsidEventID              int32 = 112
	SetreuidEventID            int32 = 113
	SetregidEventID            int32 = 114
	GetgroupsEventID           int32 = 115
	SetgroupsEventID           int32 = 116
	SetresuidEventID           int32 = 117
	GetresuidEventID           int32 = 118
	SetresgidEventID           int32 = 119
	GetresgidEventID           int32 = 120
	GetpgidEventID             int32 = 121
	SetfsuidEventID            int32 = 122
	SetfsgidEventID            int32 = 123
	GetsidEventID              int32 = 124
	CapgetEventID              int32 = 125
	CapsetEventID              int32 = 126
	RtSigpendingEventID        int32 = 127
	RtSigtimedwaitEventID      int32 = 128
	RtSigqueueinfoEventID      int32 = 129
	RtSigsuspendEventID        int32 = 130
	SigaltstackEventID         int32 = 131
	UtimeEventID               int32 = 132
	MknodEventID               int32 = 133
	UselibEventID              int32 = 134
	PersonalityEventID         int32 = 135
	UstatEventID               int32 = 136
	StatfsEventID              int32 = 137
	FstatfsEventID             int32 = 138
	SysfsEventID               int32 = 139
	GetpriorityEventID         int32 = 140
	SetpriorityEventID         int32 = 141
	SchedSetparamEventID       int32 = 142
	SchedGetparamEventID       int32 = 143
	SchedSetschedulerEventID   int32 = 144
	SchedGetschedulerEventID   int32 = 145
	SchedGetPriorityMaxEventID int32 = 146
	SchedGetPriorityMinEventID int32 = 147
	SchedRrGetIntervalEventID  int32 = 148
	MlockEventID               int32 = 149
	MunlockEventID             int32 = 150
	MlockallEventID            int32 = 151
	MunlockallEventID          int32 = 152
	VhangupEventID             int32 = 153
	ModifyLdtEventID           int32 = 154
	PivotRootEventID           int32 = 155
	SysctlEventID              int32 = 156
	PrctlEventID               int32 = 157
	ArchPrctlEventID           int32 = 158
	AdjtimexEventID            int32 = 159
	SetrlimitEventID           int32 = 160
	ChrootEventID              int32 = 161
	SyncEventID                int32 = 162
	AcctEventID                int32 = 163
	SettimeofdayEventID        int32 = 164
	MountEventID               int32 = 165
	Umount2EventID             int32 = 166
	SwaponEventID              int32 = 167
	SwapoffEventID             int32 = 168
	RebootEventID              int32 = 169
	SethostnameEventID         int32 = 170
	SetdomainnameEventID       int32 = 171
	IoplEventID                int32 = 172
	IopermEventID              int32 = 173
	CreateModuleEventID        int32 = 174
	InitModuleEventID          int32 = 175
	DeleteModuleEventID        int32 = 176
	GetKernelSymsEventID       int32 = 177
	QueryModuleEventID         int32 = 178
	QuotactlEventID            int32 = 179
	NfsservctlEventID          int32 = 180
	GetpmsgEventID             int32 = 181
	PutpmsgEventID             int32 = 182
	AfsEventID                 int32 = 183
	TuxcallEventID             int32 = 184
	SecurityEventID            int32 = 185
	GettidEventID              int32 = 186
	ReadaheadEventID           int32 = 187
	SetxattrEventID            int32 = 188
	LsetxattrEventID           int32 = 189
	FsetxattrEventID           int32 = 190
	GetxattrEventID            int32 = 191
	LgetxattrEventID           int32 = 192
	FgetxattrEventID           int32 = 193
	ListxattrEventID           int32 = 194
	LlistxattrEventID          int32 = 195
	FlistxattrEventID          int32 = 196
	RemovexattrEventID         int32 = 197
	LremovexattrEventID        int32 = 198
	FremovexattrEventID        int32 = 199
	TkillEventID               int32 = 200
	TimeEventID                int32 = 201
	FutexEventID               int32 = 202
	SchedSetaffinityEventID    int32 = 203
	SchedGetaffinityEventID    int32 = 204
	SetThreadAreaEventID       int32 = 205
	IoSetupEventID             int32 = 206
	IoDestroyEventID           int32 = 207
	IoGeteventsEventID         int32 = 208
	IoSubmitEventID            int32 = 209
	IoCancelEventID            int32 = 210
	GetThreadAreaEventID       int32 = 211
	LookupDcookieEventID       int32 = 212
	EpollCreateEventID         int32 = 213
	EpollCtlOldEventID         int32 = 214
	EpollWaitOldEventID        int32 = 215
	RemapFilePagesEventID      int32 = 216
	Getdents64EventID          int32 = 217
	SetTidAddressEventID       int32 = 218
	RestartSyscallEventID      int32 = 219
	SemtimedopEventID          int32 = 220
	Fadvise64EventID           int32 = 221
	TimerCreateEventID         int32 = 222
	TimerSettimeEventID        int32 = 223
	TimerGettimeEventID        int32 = 224
	TimerGetoverrunEventID     int32 = 225
	TimerDeleteEventID         int32 = 226
	ClockSettimeEventID        int32 = 227
	ClockGettimeEventID        int32 = 228
	ClockGetresEventID         int32 = 229
	ClockNanosleepEventID      int32 = 230
	ExitGroupEventID           int32 = 231
	EpollWaitEventID           int32 = 232
	EpollCtlEventID            int32 = 233
	TgkillEventID              int32 = 234
	UtimesEventID              int32 = 235
	VserverEventID             int32 = 236
	MbindEventID               int32 = 237
	SetMempolicyEventID        int32 = 238
	GetMempolicyEventID        int32 = 239
	MqOpenEventID              int32 = 240
	MqUnlinkEventID            int32 = 241
	MqTimedsendEventID         int32 = 242
	MqTimedreceiveEventID      int32 = 243
	MqNotifyEventID            int32 = 244
	MqGetsetattrEventID        int32 = 245
	KexecLoadEventID           int32 = 246
	WaitidEventID              int32 = 247
	AddKeyEventID              int32 = 248
	RequestKeyEventID          int32 = 249
	KeyctlEventID              int32 = 250
	IoprioSetEventID           int32 = 251
	IoprioGetEventID           int32 = 252
	InotifyInitEventID         int32 = 253
	InotifyAddWatchEventID     int32 = 254
	InotifyRmWatchEventID      int32 = 255
	MigratePagesEventID        int32 = 256
	OpenatEventID              int32 = 257
	MkdiratEventID             int32 = 258
	MknodatEventID             int32 = 259
	FchownatEventID            int32 = 260
	FutimesatEventID           int32 = 261
	NewfstatatEventID          int32 = 262
	UnlinkatEventID            int32 = 263
	RenameatEventID            int32 = 264
	LinkatEventID              int32 = 265
	SymlinkatEventID           int32 = 266
	ReadlinkatEventID          int32 = 267
	FchmodatEventID            int32 = 268
	FaccessatEventID           int32 = 269
	Pselect6EventID            int32 = 270
	PpollEventID               int32 = 271
	UnshareEventID             int32 = 272
	SetRobustListEventID       int32 = 273
	GetRobustListEventID       int32 = 274
	SpliceEventID              int32 = 275
	TeeEventID                 int32 = 276
	SyncFileRangeEventID       int32 = 277
	VmspliceEventID            int32 = 278
	MovePagesEventID           int32 = 279
	UtimensatEventID           int32 = 280
	EpollPwaitEventID          int32 = 281
	SignalfdEventID            int32 = 282
	TimerfdCreateEventID       int32 = 283
	EventfdEventID             int32 = 284
	FallocateEventID           int32 = 285
	TimerfdSettimeEventID      int32 = 286
	TimerfdGettimeEventID      int32 = 287
	Accept4EventID             int32 = 288
	Signalfd4EventID           int32 = 289
	Eventfd2EventID            int32 = 290
	EpollCreate1EventID        int32 = 291
	Dup3EventID                int32 = 292
	Pipe2EventID               int32 = 293
	InotifyInit1EventID        int32 = 294
	PreadvEventID              int32 = 295
	PwritevEventID             int32 = 296
	RtTgsigqueueinfoEventID    int32 = 297
	PerfEventOpenEventID       int32 = 298
	RecvmmsgEventID            int32 = 299
	FanotifyInitEventID        int32 = 300
	FanotifyMarkEventID        int32 = 301
	Prlimit64EventID           int32 = 302
	NameToHandleAtEventID      int32 = 303
	OpenByHandleAtEventID      int32 = 304
	ClockAdjtimeEventID        int32 = 305
	SyncfsEventID              int32 = 306
	SendmmsgEventID            int32 = 307
	SetnsEventID               int32 = 308
	GetcpuEventID              int32 = 309
	ProcessVmReadvEventID      int32 = 310
	ProcessVmWritevEventID     int32 = 311
	KcmpEventID                int32 = 312
	FinitModuleEventID         int32 = 313
	SchedSetattrEventID        int32 = 314
	SchedGetattrEventID        int32 = 315
	Renameat2EventID           int32 = 316
	SeccompEventID             int32 = 317
	GetrandomEventID           int32 = 318
	MemfdCreateEventID         int32 = 319
	KexecFileLoadEventID       int32 = 320
	BpfEventID                 int32 = 321
	ExecveatEventID            int32 = 322
	UserfaultfdEventID         int32 = 323
	MembarrierEventID          int32 = 324
	Mlock2EventID              int32 = 325
	CopyFileRangeEventID       int32 = 326
	Preadv2EventID             int32 = 327
	Pwritev2EventID            int32 = 328
	PkeyMprotectEventID        int32 = 329
	PkeyAllocEventID           int32 = 330
	PkeyFreeEventID            int32 = 331
	StatxEventID               int32 = 332
	IoPgeteventsEventID        int32 = 333
	RseqEventID                int32 = 334
	// 335 through 423 are unassigned to sync up with generic numbers
	PidfdSendSignalEventID       int32 = 424
	IoUringSetupEventID          int32 = 425
	IoUringEnterEventID          int32 = 426
	IoUringRegisterEventID       int32 = 427
	OpenTreeEventID              int32 = 428
	MoveMountEventID             int32 = 429
	FsopenEventID                int32 = 430
	FsconfigEventID              int32 = 431
	FsmountEventID               int32 = 432
	FspickEventID                int32 = 433
	PidfdOpenEventID             int32 = 434
	Clone3EventID                int32 = 435
	CloseRangeEventID            int32 = 436
	Openat2EventID               int32 = 437
	PidfdGetfdEventID            int32 = 438
	Faccessat2EventID            int32 = 439
	ProcessMadviseEventID        int32 = 440
	EpollPwait2EventID           int32 = 441
	MountSetattEventID           int32 = 442
	QuotactlFdEventID            int32 = 443
	LandlockCreateRulesetEventID int32 = 444
	LandlockAddRuleEventID       int32 = 445
	LandloclRestrictSetEventID   int32 = 446
	MemfdSecretEventID           int32 = 447
	ProcessMreleaseEventID       int32 = 448
)

// Set of events IDs for 32bit syscalls which have no parallel 64bit syscall
const (
	WaitpidEventID int32 = iota + Unique32BitSyscallsStartID
	OldfstatEventID
	BreakEventID
	OldstatEventID
	UmountEventID
	StimeEventID
	SttyEventID
	GttyEventID
	NiceEventID
	FtimeEventID
	ProfEventID
	SignalEventID
	LockEventID
	MpxEventID
	UlimitEventID
	OldoldunameEventID
	SigactionEventID
	SgetmaskEventID
	SsetmaskEventID
	SigsuspendEventID
	SigpendingEventID
	OldlstatEventID
	ReaddirEventID
	ProfilEventID
	SocketcallEventID
	OldunameEventID
	IdleEventID
	Vm86oldEventID
	IpcEventID
	SigreturnEventID
	SigprocmaskEventID
	BdflushEventID
	Afs_syscallEventID
	LlseekEventID
	OldSelectEventID
	Vm86EventID
	OldGetrlimitEventID
	Mmap2EventID
	Truncate64EventID
	Ftruncate64EventID
	Stat64EventID
	Lstat64EventID
	Fstat64EventID
	Lchown16EventID
	Getuid16EventID
	Getgid16EventID
	Geteuid16EventID
	Getegid16EventID
	Setreuid16EventID
	Setregid16EventID
	Getgroups16EventID
	Setgroups16EventID
	Fchown16EventID
	Setresuid16EventID
	Getresuid16EventID
	Setresgid16EventID
	Getresgid16EventID
	Chown16EventID
	Setuid16EventID
	Setgid16EventID
	Setfsuid16EventID
	Setfsgid16EventID
	Fcntl64EventID
	Sendfile32EventID
	Statfs64EventID
	Fstatfs64EventID
	Fadvise64_64EventID
	ClockGettime32EventID
	ClockSettime32EventID
	ClockAdjtime64EventID
	ClockGetresTime32EventID
	ClockNanosleepTime32EventID
	TimerGettime32EventID
	TimerSettime32EventID
	TimerfdGettime32EventID
	TimerfdSettime32EventID
	UtimensatTime32EventID
	Pselect6Time32EventID
	PpollTime32EventID
	IoPgeteventsTime32EventID
	RecvmmsgTime32EventID
	MqTimedsendTime32EventID
	MqTimedreceiveTime32EventID
	RtSigtimedwaitTime32EventID
	FutexTime32EventID
	SchedRrGetInterval32EventID
	Unique32BitSyscallsEndID
)

// x86 32bit syscall numbers
// Used for compatibility mode
// https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_32.tbl
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
	sys32close_range                  int32 = 436
	sys32openat2                      int32 = 437
	sys32pidfd_getfd                  int32 = 438
	sys32faccessat2                   int32 = 439
	sys32process_madvise              int32 = 440
	sys32epoll_pwait2                 int32 = 441
	sys32mount_setattr                int32 = 442
	sys32quotactl_fd                  int32 = 443
	sys32landlock_create_ruleset      int32 = 444
	sys32landlock_add_rule            int32 = 445
	sys32landlock_restrict_self       int32 = 446
	sys32memfd_secret                 int32 = 447
	sys32process_mrelease             int32 = 448
	sys32undefined                    int32 = 10000
)
