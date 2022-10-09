//go:build arm64
// +build arm64

package events

// ARM64 syscall numbers
// Also used as event IDs
// https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/unistd.h
const (
	IoSetup                  ID = 0
	IoDestroy                ID = 1
	IoSubmit                 ID = 2
	IoCancel                 ID = 3
	IoGetevents              ID = 4
	Setxattr                 ID = 5
	Lsetxattr                ID = 6
	Fsetxattr                ID = 7
	Getxattr                 ID = 8
	Lgetxattr                ID = 9
	Fgetxattr                ID = 10
	Listxattr                ID = 11
	Llistxattr               ID = 12
	Flistxattr               ID = 13
	Removexattr              ID = 14
	Lremovexattr             ID = 15
	Fremovexattr             ID = 16
	Getcwd                   ID = 17
	LookupDcookie            ID = 18
	Eventfd2                 ID = 19
	EpollCreate1             ID = 20
	EpollCtl                 ID = 21
	EpollPwait               ID = 22
	Dup                      ID = 23
	Dup3                     ID = 24
	Fcntl                    ID = 25
	InotifyInit1             ID = 26
	InotifyAddWatch          ID = 27
	InotifyRmWatch           ID = 28
	Ioctl                    ID = 29
	IoprioSet                ID = 30
	IoprioGet                ID = 31
	Flock                    ID = 32
	Mknodat                  ID = 33
	Mkdirat                  ID = 34
	Unlinkat                 ID = 35
	Symlinkat                ID = 36
	Linkat                   ID = 37
	Renameat                 ID = 38
	Umount2                  ID = 39
	Mount                    ID = 40
	PivotRoot                ID = 41
	Nfsservctl               ID = 42
	Statfs                   ID = 43
	Fstatfs                  ID = 44
	Truncate                 ID = 45
	Ftruncate                ID = 46
	Fallocate                ID = 47
	Faccessat                ID = 48
	Chdir                    ID = 49
	Fchdir                   ID = 50
	Chroot                   ID = 51
	Fchmod                   ID = 52
	Fchmodat                 ID = 53
	Fchownat                 ID = 54
	Fchown                   ID = 55
	Openat                   ID = 56
	Close                    ID = 57
	Vhangup                  ID = 58
	Pipe2                    ID = 59
	Quotactl                 ID = 60
	Getdents64               ID = 61
	Lseek                    ID = 62
	Read                     ID = 63
	Write                    ID = 64
	Readv                    ID = 65
	Writev                   ID = 66
	Pread64                  ID = 67
	Pwrite64                 ID = 68
	Preadv                   ID = 69
	Pwritev                  ID = 70
	Sendfile                 ID = 71
	Pselect6                 ID = 72
	Ppoll                    ID = 73
	Signalfd4                ID = 74
	Vmsplice                 ID = 75
	Splice                   ID = 76
	Tee                      ID = 77
	Readlinkat               ID = 78
	Newfstatat               ID = 79
	Fstat                    ID = 80
	Sync                     ID = 81
	Fsync                    ID = 82
	Fdatasync                ID = 83
	SyncFileRange            ID = 84
	TimerfdCreate            ID = 85
	TimerfdSettime           ID = 86
	TimerfdGettime           ID = 87
	Utimensat                ID = 88
	Acct                     ID = 89
	Capget                   ID = 90
	Capset                   ID = 91
	Personality              ID = 92
	Exit                     ID = 93
	ExitGroup                ID = 94
	Waitid                   ID = 95
	SetTidAddress            ID = 96
	Unshare                  ID = 97
	Futex                    ID = 98
	SetRobustList            ID = 99
	GetRobustList            ID = 100
	Nanosleep                ID = 101
	Getitimer                ID = 102
	Setitimer                ID = 103
	KexecLoad                ID = 104
	InitModule               ID = 105
	DeleteModule             ID = 106
	TimerCreate              ID = 107
	TimerGettime             ID = 108
	TimerGetoverrun          ID = 109
	TimerSettime             ID = 110
	TimerDelete              ID = 111
	ClockSettime             ID = 112
	ClockGettime             ID = 113
	ClockGetres              ID = 114
	ClockNanosleep           ID = 115
	Syslog                   ID = 116
	Ptrace                   ID = 117
	SchedSetparam            ID = 118
	SchedSetscheduler        ID = 119
	SchedGetscheduler        ID = 120
	SchedGetparam            ID = 121
	SchedSetaffinity         ID = 122
	SchedGetaffinity         ID = 123
	SchedYield               ID = 124
	SchedGetPriorityMax      ID = 125
	SchedGetPriorityMin      ID = 126
	SchedRrGetInterval       ID = 127
	RestartSyscall           ID = 128
	Kill                     ID = 129
	Tkill                    ID = 130
	Tgkill                   ID = 131
	Sigaltstack              ID = 132
	RtSigsuspend             ID = 133
	RtSigaction              ID = 134
	RtSigprocmask            ID = 135
	RtSigpending             ID = 136
	RtSigtimedwait           ID = 137
	RtSigqueueinfo           ID = 138
	RtSigreturn              ID = 139
	Setpriority              ID = 140
	Getpriority              ID = 141
	Reboot                   ID = 142
	Setregid                 ID = 143
	Setgid                   ID = 144
	Setreuid                 ID = 145
	Setuid                   ID = 146
	Setresuid                ID = 147
	Getresuid                ID = 148
	Setresgid                ID = 149
	Getresgid                ID = 150
	Setfsuid                 ID = 151
	Setfsgid                 ID = 152
	Times                    ID = 153
	Setpgid                  ID = 154
	Getpgid                  ID = 155
	Getsid                   ID = 156
	Setsid                   ID = 157
	Getgroups                ID = 158
	Setgroups                ID = 159
	Uname                    ID = 160
	Sethostname              ID = 161
	Setdomainname            ID = 162
	Getrlimit                ID = 163
	Setrlimit                ID = 164
	Getrusage                ID = 165
	Umask                    ID = 166
	Prctl                    ID = 167
	Getcpu                   ID = 168
	Gettimeofday             ID = 169
	Settimeofday             ID = 170
	Adjtimex                 ID = 171
	Getpid                   ID = 172
	Getppid                  ID = 173
	Getuid                   ID = 174
	Geteuid                  ID = 175
	Getgid                   ID = 176
	Getegid                  ID = 177
	Gettid                   ID = 178
	Sysinfo                  ID = 179
	MqOpen                   ID = 180
	MqUnlink                 ID = 181
	MqTimedsend              ID = 182
	MqTimedreceive           ID = 183
	MqNotify                 ID = 184
	MqGetsetattr             ID = 185
	Msgget                   ID = 186
	Msgctl                   ID = 187
	Msgrcv                   ID = 188
	Msgsnd                   ID = 189
	Semget                   ID = 190
	Semctl                   ID = 191
	Semtimedop               ID = 192
	Semop                    ID = 193
	Shmget                   ID = 194
	Shmctl                   ID = 195
	Shmat                    ID = 196
	Shmdt                    ID = 197
	Socket                   ID = 198
	Socketpair               ID = 199
	Bind                     ID = 200
	Listen                   ID = 201
	Accept                   ID = 202
	Connect                  ID = 203
	Getsockname              ID = 204
	Getpeername              ID = 205
	Sendto                   ID = 206
	Recvfrom                 ID = 207
	Setsockopt               ID = 208
	Getsockopt               ID = 209
	Shutdown                 ID = 210
	Sendmsg                  ID = 211
	Recvmsg                  ID = 212
	Readahead                ID = 213
	Brk                      ID = 214
	Munmap                   ID = 215
	Mremap                   ID = 216
	AddKey                   ID = 217
	RequestKey               ID = 218
	Keyctl                   ID = 219
	Clone                    ID = 220
	Execve                   ID = 221
	Mmap                     ID = 222
	Fadvise64                ID = 223
	Swapon                   ID = 224
	Swapoff                  ID = 225
	Mprotect                 ID = 226
	Msync                    ID = 227
	Mlock                    ID = 228
	Munlock                  ID = 229
	Mlockall                 ID = 230
	Munlockall               ID = 231
	Mincore                  ID = 232
	Madvise                  ID = 233
	RemapFilePages           ID = 234
	Mbind                    ID = 235
	GetMempolicy             ID = 236
	SetMempolicy             ID = 237
	MigratePages             ID = 238
	MovePages                ID = 239
	RtTgsigqueueinfo         ID = 240
	PerfEventOpen            ID = 241
	Accept4                  ID = 242
	Recvmmsg                 ID = 243
	Sys244                   ID = 244
	Sys245                   ID = 245
	Sys246                   ID = 246
	Sys247                   ID = 247
	Sys248                   ID = 248
	Sys249                   ID = 249
	Sys250                   ID = 250
	Sys251                   ID = 251
	Sys252                   ID = 252
	Sys253                   ID = 253
	Sys254                   ID = 254
	Sys255                   ID = 255
	Sys256                   ID = 256
	Sys257                   ID = 257
	Sys258                   ID = 258
	Sys259                   ID = 259
	Wait4                    ID = 260
	Prlimit64                ID = 261
	FanotifyInit             ID = 262
	FanotifyMark             ID = 263
	NameToHandleAt           ID = 264
	OpenByHandleAt           ID = 265
	ClockAdjtime             ID = 266
	Syncfs                   ID = 267
	Setns                    ID = 268
	Sendmmsg                 ID = 269
	ProcessVmReadv           ID = 270
	ProcessVmWritev          ID = 271
	Kcmp                     ID = 272
	FinitModule              ID = 273
	SchedSetattr             ID = 274
	SchedGetattr             ID = 275
	Renameat2                ID = 276
	Seccomp                  ID = 277
	Getrandom                ID = 278
	MemfdCreate              ID = 279
	Bpf                      ID = 280
	Execveat                 ID = 281
	Userfaultfd              ID = 282
	Membarrier               ID = 283
	Mlock2                   ID = 284
	CopyFileRange            ID = 285
	Preadv2                  ID = 286
	Pwritev2                 ID = 287
	PkeyMprotect             ID = 288
	PkeyAlloc                ID = 289
	PkeyFree                 ID = 290
	Statx                    ID = 291
	IoPgetevents             ID = 292
	Rseq                     ID = 293
	KexecFileLoad            ID = 294
	ClockGettime64           ID = 403 // 295 -> 402 unassigned to sync up with generic numbers
	ClockSettime64           ID = 404
	ClockAdjtime64           ID = 405
	ClockGetresTime64        ID = 406
	ClockNanosleepTime64     ID = 407
	TimerGettime64           ID = 408
	TimerSettime64           ID = 409
	TimerfdGettime64         ID = 410
	TimerfdSettime64         ID = 411
	UtimensatTime64          ID = 412
	Pselect6Time64           ID = 413
	PpollTime64              ID = 414
	IoPgeteventsTime64       ID = 416
	RecvmmsgTime64           ID = 417
	MqTimedsendTime64        ID = 418
	MqTimedreceiveTime64     ID = 419
	SemtimedopTime64         ID = 420
	RtSigtimedwaitTime64     ID = 421
	FutexTime64              ID = 422
	SchedRrGetIntervalTime64 ID = 423
	PidfdSendSignal          ID = 424
	IoUringSetup             ID = 425
	IoUringEnter             ID = 426
	IoUringRegister          ID = 427
	OpenTree                 ID = 428
	MoveMount                ID = 429
	Fsopen                   ID = 430
	Fsconfig                 ID = 431
	Fsmount                  ID = 432
	Fspick                   ID = 433
	PidfdOpen                ID = 434
	Clone3                   ID = 435
	CloseRange               ID = 436
	Openat2                  ID = 437
	PidfdGetfd               ID = 438
	Faccessat2               ID = 439
	ProcessMadvise           ID = 440
	EpollPwait2              ID = 441
	MountSetatt              ID = 442
	QuotactlFd               ID = 443
	LandlockCreateRuleset    ID = 444
	LandlockAddRule          ID = 445
	LandloclRestrictSet      ID = 446
	MemfdSecret              ID = 447
	ProcessMrelease          ID = 448
	MaxSyscallID             ID = 449
	// TODO: Compile list of unique 32bit syscalls for arm64
)

// following syscalls are undefined on arm64
const (
	Open ID = iota + 10000
	Stat
	Lstat
	Poll
	Access
	Pipe
	Select
	Dup2
	Pause
	Alarm
	Fork
	Vfork
	Getdents
	Rename
	Mkdir
	Rmdir
	Creat
	Link
	Unlink
	Symlink
	Readlink
	Chmod
	Chown
	Lchown
	Getpgrp
	Utime
	Mknod
	Uselib
	Ustat
	Sysfs
	ModifyLdt
	Sysctl
	ArchPrctl
	Umount
	Iopl
	Ioperm
	CreateModule
	GetKernelSyms
	QueryModule
	Getpmsg
	Putpmsg
	Afs
	Tuxcall
	Security
	Time
	SetThreadArea
	GetThreadArea
	EpollCreate
	EpollCtlOld
	EpollWaitOld
	EpollWait
	Utimes
	Vserver
	InotifyInit
	Futimesat
	Signalfd
	Eventfd
	Waitpid
	Oldfstat
	Break
	Oldstat
	Stime
	Stty
	Gtty
	Nice
	Ftime
	Prof
	Signal
	Lock
	Mpx
	Ulimit
	Oldolduname
	Sigaction
	Sgetmask
	Ssetmask
	Sigsuspend
	Sigpending
	Oldlstat
	Readdir
	Profil
	Socketcall
	Olduname
	Idle
	Vm86old
	Ipc
	Sigreturn
	Sigprocmask
	Bdflush
	Afs_syscall
	Llseek
	OldSelect
	Vm86
	OldGetrlimit
	Mmap2
	Truncate64
	Ftruncate64
	Stat64
	Lstat64
	Fstat64
	Lchown16
	Getuid16
	Getgid16
	Geteuid16
	Getegid16
	Setreuid16
	Setregid16
	Getgroups16
	Setgroups16
	Fchown16
	Setresuid16
	Getresuid16
	Setresgid16
	Getresgid16
	Chown16
	Setuid16
	Setgid16
	Setfsuid16
	Setfsgid16
	Fcntl64
	Sendfile32
	Statfs64
	Fstatfs64
	Fadvise64_64
	ClockGettime32
	ClockSettime32
	ClockGetresTime32
	ClockNanosleepTime32
	TimerGettime32
	TimerSettime32
	TimerfdGettime32
	TimerfdSettime32
	UtimensatTime32
	Pselect6Time32
	PpollTime32
	IoPgeteventsTime32
	RecvmmsgTime32
	MqTimedsendTime32
	MqTimedreceiveTime32
	RtSigtimedwaitTime32
	FutexTime32
	SchedRrGetInterval32
	sys32vm86old
	sys32fadvise64_64
)

// ARM 32bit syscall numbers
// Used for compatibility mode
// https://github.com/torvalds/linux/blob/master/arch/arm/tools/syscall.tbl
const (
	sys32restart_syscall              ID = 0
	sys32exit                         ID = 1
	sys32fork                         ID = 2
	sys32read                         ID = 3
	sys32write                        ID = 4
	sys32open                         ID = 5
	sys32close                        ID = 6
	sys32waitpid                      ID = 7
	sys32creat                        ID = 8
	sys32link                         ID = 9
	sys32unlink                       ID = 10
	sys32execve                       ID = 11
	sys32chdir                        ID = 12
	sys32time                         ID = 13
	sys32mknod                        ID = 14
	sys32chmod                        ID = 15
	sys32lchown                       ID = 16
	sys32break                        ID = 17
	sys32oldstat                      ID = 18
	sys32lseek                        ID = 19
	sys32getpid                       ID = 20
	sys32mount                        ID = 21
	sys32umount                       ID = 22
	sys32setuid                       ID = 23
	sys32getuid                       ID = 24
	sys32stime                        ID = 25
	sys32ptrace                       ID = 26
	sys32alarm                        ID = 27
	sys32oldfstat                     ID = 28
	sys32pause                        ID = 29
	sys32utime                        ID = 30
	sys32stty                         ID = 31
	sys32gtty                         ID = 32
	sys32access                       ID = 33
	sys32nice                         ID = 34
	sys32ftime                        ID = 35
	sys32sync                         ID = 36
	sys32kill                         ID = 37
	sys32rename                       ID = 38
	sys32mkdir                        ID = 39
	sys32rmdir                        ID = 40
	sys32dup                          ID = 41
	sys32pipe                         ID = 42
	sys32times                        ID = 43
	sys32prof                         ID = 44
	sys32brk                          ID = 45
	sys32setgid                       ID = 46
	sys32getgid                       ID = 47
	sys32signal                       ID = 48
	sys32geteuid                      ID = 49
	sys32getegid                      ID = 50
	sys32acct                         ID = 51
	sys32umount2                      ID = 52
	sys32lock                         ID = 53
	sys32ioctl                        ID = 54
	sys32fcntl                        ID = 55
	sys32mpx                          ID = 56
	sys32setpgid                      ID = 57
	sys32ulimit                       ID = 58
	sys32oldolduname                  ID = 59
	sys32umask                        ID = 60
	sys32chroot                       ID = 61
	sys32ustat                        ID = 62
	sys32dup2                         ID = 63
	sys32getppid                      ID = 64
	sys32getpgrp                      ID = 65
	sys32setsid                       ID = 66
	sys32sigaction                    ID = 67
	sys32sgetmask                     ID = 68
	sys32ssetmask                     ID = 69
	sys32setreuid                     ID = 70
	sys32setregid                     ID = 71
	sys32sigsuspend                   ID = 72
	sys32sigpending                   ID = 73
	sys32sethostname                  ID = 74
	sys32setrlimit                    ID = 75
	sys32getrlimit                    ID = 76
	sys32getrusage                    ID = 77
	sys32gettimeofday                 ID = 78
	sys32settimeofday                 ID = 79
	sys32getgroups                    ID = 80
	sys32setgroups                    ID = 81
	sys32select                       ID = 82
	sys32symlink                      ID = 83
	sys32oldlstat                     ID = 84
	sys32readlink                     ID = 85
	sys32uselib                       ID = 86
	sys32swapon                       ID = 87
	sys32reboot                       ID = 88
	sys32readdir                      ID = 89
	sys32mmap                         ID = 90
	sys32munmap                       ID = 91
	sys32truncate                     ID = 92
	sys32ftruncate                    ID = 93
	sys32fchmod                       ID = 94
	sys32fchown                       ID = 95
	sys32getpriority                  ID = 96
	sys32setpriority                  ID = 97
	sys32profil                       ID = 98
	sys32statfs                       ID = 99
	sys32fstatfs                      ID = 100
	sys32ioperm                       ID = 101
	sys32socketcall                   ID = 102
	sys32syslog                       ID = 103
	sys32setitimer                    ID = 104
	sys32getitimer                    ID = 105
	sys32stat                         ID = 106
	sys32lstat                        ID = 107
	sys32fstat                        ID = 108
	sys32olduname                     ID = 109
	sys32iopl                         ID = 110
	sys32vhangup                      ID = 111
	sys32idle                         ID = 112
	sys32syscall                      ID = 113
	sys32wait4                        ID = 114
	sys32swapoff                      ID = 115
	sys32sysinfo                      ID = 116
	sys32ipc                          ID = 117
	sys32fsync                        ID = 118
	sys32sigreturn                    ID = 119
	sys32clone                        ID = 120
	sys32setdomainname                ID = 121
	sys32uname                        ID = 122
	sys32modify_ldt                   ID = 123
	sys32adjtimex                     ID = 124
	sys32mprotect                     ID = 125
	sys32sigprocmask                  ID = 126
	sys32create_module                ID = 127
	sys32init_module                  ID = 128
	sys32delete_module                ID = 129
	sys32get_kernel_syms              ID = 130
	sys32quotactl                     ID = 131
	sys32getpgid                      ID = 132
	sys32fchdir                       ID = 133
	sys32bdflush                      ID = 134
	sys32sysfs                        ID = 135
	sys32personality                  ID = 136
	sys32afs_syscall                  ID = 137
	sys32setfsuid                     ID = 138
	sys32setfsgid                     ID = 139
	sys32_llseek                      ID = 140
	sys32getdents                     ID = 141
	sys32_newselect                   ID = 142
	sys32flock                        ID = 143
	sys32msync                        ID = 144
	sys32readv                        ID = 145
	sys32writev                       ID = 146
	sys32getsid                       ID = 147
	sys32fdatasync                    ID = 148
	sys32_sysctl                      ID = 149
	sys32mlock                        ID = 150
	sys32munlock                      ID = 151
	sys32mlockall                     ID = 152
	sys32munlockall                   ID = 153
	sys32sched_setparam               ID = 154
	sys32sched_getparam               ID = 155
	sys32sched_setscheduler           ID = 156
	sys32sched_getscheduler           ID = 157
	sys32sched_yield                  ID = 158
	sys32sched_get_priority_max       ID = 159
	sys32sched_get_priority_min       ID = 160
	sys32sched_rr_get_interval        ID = 161
	sys32nanosleep                    ID = 162
	sys32mremap                       ID = 163
	sys32setresuid                    ID = 164
	sys32getresuid                    ID = 165
	sys32vm86                         ID = 166
	sys32query_module                 ID = 167
	sys32poll                         ID = 168
	sys32nfsservctl                   ID = 169
	sys32setresgid                    ID = 170
	sys32getresgid                    ID = 171
	sys32prctl                        ID = 172
	sys32rt_sigreturn                 ID = 173
	sys32rt_sigaction                 ID = 174
	sys32rt_sigprocmask               ID = 175
	sys32rt_sigpending                ID = 176
	sys32rt_sigtimedwait              ID = 177
	sys32rt_sigqueueinfo              ID = 178
	sys32rt_sigsuspend                ID = 179
	sys32pread64                      ID = 180
	sys32pwrite64                     ID = 181
	sys32chown                        ID = 182
	sys32getcwd                       ID = 183
	sys32capget                       ID = 184
	sys32capset                       ID = 185
	sys32sigaltstack                  ID = 186
	sys32sendfile                     ID = 187
	sys32_188Res                      ID = 188
	sys32_189Res                      ID = 189
	sys32vfork                        ID = 190
	sys32ugetrlimit                   ID = 191
	sys32mmap2                        ID = 192
	sys32truncate64                   ID = 193
	sys32ftruncate64                  ID = 194
	sys32stat64                       ID = 195
	sys32lstat64                      ID = 196
	sys32fstat64                      ID = 197
	sys32lchown32                     ID = 198
	sys32getuid32                     ID = 199
	sys32getgid32                     ID = 200
	sys32geteuid32                    ID = 201
	sys32getegid32                    ID = 202
	sys32setreuid32                   ID = 203
	sys32setregid32                   ID = 204
	sys32getgroups32                  ID = 205
	sys32setgroups32                  ID = 206
	sys32fchown32                     ID = 207
	sys32setresuid32                  ID = 208
	sys32getresuid32                  ID = 209
	sys32setresgid32                  ID = 210
	sys32getresgid32                  ID = 211
	sys32chown32                      ID = 212
	sys32setuid32                     ID = 213
	sys32setgid32                     ID = 214
	sys32setfsuid32                   ID = 215
	sys32setfsgid32                   ID = 216
	sys32pivot_root                   ID = 217
	sys32mincore                      ID = 218
	sys32madvise                      ID = 219
	sys32getdents64                   ID = 220
	sys32fcntl64                      ID = 221
	sys32_222Res                      ID = 222
	sys32_223Res                      ID = 223
	sys32gettid                       ID = 224
	sys32readahead                    ID = 225
	sys32setxattr                     ID = 226
	sys32lsetxattr                    ID = 227
	sys32fsetxattr                    ID = 228
	sys32getxattr                     ID = 229
	sys32lgetxattr                    ID = 230
	sys32fgetxattr                    ID = 231
	sys32listxattr                    ID = 232
	sys32llistxattr                   ID = 233
	sys32flistxattr                   ID = 234
	sys32removexattr                  ID = 235
	sys32lremovexattr                 ID = 236
	sys32fremovexattr                 ID = 237
	sys32tkill                        ID = 238
	sys32sendfile64                   ID = 239
	sys32futex                        ID = 240
	sys32sched_setaffinity            ID = 241
	sys32sched_getaffinity            ID = 242
	sys32io_setup                     ID = 243
	sys32io_destroy                   ID = 244
	sys32io_getevents                 ID = 245
	sys32io_submit                    ID = 246
	sys32io_cancel                    ID = 247
	sys32exit_group                   ID = 248
	sys32lookup_dcookie               ID = 249
	sys32epoll_create                 ID = 250
	sys32epoll_ctl                    ID = 251
	sys32epoll_wait                   ID = 252
	sys32remap_file_pages             ID = 253
	sys32_254Res                      ID = 254
	sys32_255Res                      ID = 255
	sys32set_tid_address              ID = 256
	sys32timer_create                 ID = 257
	sys32timer_settime                ID = 258
	sys32timer_gettime                ID = 259
	sys32timer_getoverrun             ID = 260
	sys32timer_delete                 ID = 261
	sys32clock_settime                ID = 262
	sys32clock_gettime                ID = 263
	sys32clock_getres                 ID = 264
	sys32clock_nanosleep              ID = 265
	sys32statfs64                     ID = 266
	sys32fstatfs64                    ID = 267
	sys32tgkill                       ID = 268
	sys32utimes                       ID = 269
	sys32arm_fadvise64_64             ID = 270
	sys32pciconfig_iobase             ID = 271
	sys32pciconfig_read               ID = 272
	sys32pciconfig_write              ID = 273
	sys32mq_open                      ID = 274
	sys32mq_unlink                    ID = 275
	sys32mq_timedsend                 ID = 276
	sys32mq_timedreceive              ID = 277
	sys32mq_notify                    ID = 278
	sys32mq_getsetattr                ID = 279
	sys32waitid                       ID = 280
	sys32socket                       ID = 281
	sys32bind                         ID = 282
	sys32connect                      ID = 283
	sys32listen                       ID = 284
	sys32accept                       ID = 285
	sys32getsockname                  ID = 286
	sys32getpeername                  ID = 287
	sys32socketpair                   ID = 288
	sys32send                         ID = 289
	sys32sendto                       ID = 290
	sys32recv                         ID = 291
	sys32recvfrom                     ID = 292
	sys32shutdown                     ID = 293
	sys32setsockopt                   ID = 294
	sys32getsockopt                   ID = 295
	sys32sendmsg                      ID = 296
	sys32recvmsg                      ID = 297
	sys32semop                        ID = 298
	sys32semget                       ID = 299
	sys32semctl                       ID = 300
	sys32msgsnd                       ID = 301
	sys32msgrcv                       ID = 302
	sys32msgget                       ID = 303
	sys32msgctl                       ID = 304
	sys32shmat                        ID = 305
	sys32shmdt                        ID = 306
	sys32shmget                       ID = 307
	sys32shmctl                       ID = 308
	sys32add_key                      ID = 309
	sys32request_key                  ID = 310
	sys32keyctl                       ID = 311
	sys32semtimedop                   ID = 312
	sys32vserver                      ID = 313
	sys32ioprio_set                   ID = 314
	sys32ioprio_get                   ID = 315
	sys32inotify_init                 ID = 316
	sys32inotify_add_watch            ID = 317
	sys32inotify_rm_watch             ID = 318
	sys32mbind                        ID = 319
	sys32get_mempolicy                ID = 320
	sys32set_mempolicy                ID = 321
	sys32openat                       ID = 322
	sys32mkdirat                      ID = 323
	sys32mknodat                      ID = 324
	sys32fchownat                     ID = 325
	sys32futimesat                    ID = 326
	sys32fstatat64                    ID = 327
	sys32unlinkat                     ID = 328
	sys32renameat                     ID = 329
	sys32linkat                       ID = 330
	sys32symlinkat                    ID = 331
	sys32readlinkat                   ID = 332
	sys32fchmodat                     ID = 333
	sys32faccessat                    ID = 334
	sys32pselect6                     ID = 335
	sys32ppoll                        ID = 336
	sys32unshare                      ID = 337
	sys32set_robust_list              ID = 338
	sys32get_robust_list              ID = 339
	sys32splice                       ID = 340
	sys32arm_sync_file_range          ID = 341
	sys32tee                          ID = 342
	sys32vmsplice                     ID = 343
	sys32move_pages                   ID = 344
	sys32getcpu                       ID = 345
	sys32epoll_pwait                  ID = 346
	sys32kexec_load                   ID = 347
	sys32utimensat                    ID = 348
	sys32signalfd                     ID = 349
	sys32timerfd_create               ID = 350
	sys32eventfd                      ID = 351
	sys32fallocate                    ID = 352
	sys32timerfd_settime              ID = 353
	sys32timerfd_gettime              ID = 354
	sys32signalfd4                    ID = 355
	sys32eventfd2                     ID = 356
	sys32epoll_create1                ID = 357
	sys32dup3                         ID = 358
	sys32pipe2                        ID = 359
	sys32inotify_init1                ID = 360
	sys32preadv                       ID = 361
	sys32pwritev                      ID = 362
	sys32rt_tgsigqueueinfo            ID = 363
	sys32perf_event_open              ID = 364
	sys32recvmmsg                     ID = 365
	sys32accept4                      ID = 366
	sys32fanotify_init                ID = 367
	sys32fanotify_mark                ID = 368
	sys32prlimit64                    ID = 369
	sys32name_to_handle_at            ID = 370
	sys32open_by_handle_at            ID = 371
	sys32clock_adjtime                ID = 372
	sys32syncfs                       ID = 373
	sys32sendmmsg                     ID = 374
	sys32setns                        ID = 375
	sys32process_vm_readv             ID = 376
	sys32process_vm_writev            ID = 377
	sys32kcmp                         ID = 378
	sys32finit_module                 ID = 379
	sys32sched_setattr                ID = 380
	sys32sched_getattr                ID = 381
	sys32renameat2                    ID = 382
	sys32seccomp                      ID = 383
	sys32getrandom                    ID = 384
	sys32memfd_create                 ID = 385
	sys32bpf                          ID = 386
	sys32execveat                     ID = 387
	sys32userfaultfd                  ID = 388
	sys32membarrier                   ID = 389
	sys32mlock2                       ID = 390
	sys32copy_file_range              ID = 391
	sys32preadv2                      ID = 392
	sys32pwritev2                     ID = 393
	sys32pkey_mprotect                ID = 394
	sys32pkey_alloc                   ID = 395
	sys32pkey_free                    ID = 396
	sys32statx                        ID = 397
	sys32rseq                         ID = 398
	sys32io_pgetevents                ID = 399
	sys32migrate_pages                ID = 400
	sys32kexec_file_load              ID = 401
	sys32_402Res                      ID = 402
	sys32clock_gettime64              ID = 403
	sys32clock_settime64              ID = 404
	sys32clock_adjtime64              ID = 405
	sys32clock_getres_time64          ID = 406
	sys32clock_nanosleep_time64       ID = 407
	sys32timer_gettime64              ID = 408
	sys32timer_settime64              ID = 409
	sys32timerfd_gettime64            ID = 410
	sys32timerfd_settime64            ID = 411
	sys32utimensat_time64             ID = 412
	sys32pselect6_time64              ID = 413
	sys32ppoll_time64                 ID = 414
	sys32io_pgetevents_time64         ID = 416
	sys32recvmmsg_time64              ID = 417
	sys32mq_timedsend_time64          ID = 418
	sys32mq_timedreceive_time64       ID = 419
	sys32semtimedop_time64            ID = 420
	sys32rt_sigtimedwait_time64       ID = 421
	sys32futex_time64                 ID = 422
	sys32sched_rr_get_interval_time64 ID = 423
	sys32pidfd_send_signal            ID = 424
	sys32io_uring_setup               ID = 425
	sys32io_uring_enter               ID = 426
	sys32io_uring_register            ID = 427
	sys32open_tree                    ID = 428
	sys32move_mount                   ID = 429
	sys32fsopen                       ID = 430
	sys32fsconfig                     ID = 431
	sys32fsmount                      ID = 432
	sys32fspick                       ID = 433
	sys32pidfd_open                   ID = 434
	sys32clone3                       ID = 435
	sys32close_range                  ID = 436
	sys32openat2                      ID = 437
	sys32pidfd_getfd                  ID = 438
	sys32faccessat2                   ID = 439
	sys32process_madvise              ID = 440
	sys32epoll_pwait2                 ID = 441
	sys32mount_setattr                ID = 442
	sys32quotactl_fd                  ID = 443
	sys32landlock_create_ruleset      ID = 444
	sys32landlock_add_rule            ID = 445
	sys32landlock_restrict_self       ID = 446
	sys32memfd_secret                 ID = 447
	sys32process_mrelease             ID = 448
	sys32undefined                    ID = 10000
)

// following syscalls are undefined on arm32
const (
	sys32arch_prctl ID = iota + 10000
	sys32getpmsg
	sys32putpmsg
	sys32set_thread_area
	sys32get_thread_area
	sys32fadvise64
	sys32sync_file_range
)

func SyscallsToCheck() []ID {
	return []ID{
		Ioctl,
		Openat,
		Close,
		Getdents64,
		Read,
		Write,
		Ptrace,
		Kill,
		Socket,
		Execveat,
		Sendto,
		Recvfrom,
		Sendmsg,
		Recvmsg,
		Execve,
		Bpf,
	}
}
