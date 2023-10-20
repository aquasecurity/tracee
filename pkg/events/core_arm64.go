//go:build arm64
// +build arm64

package events

// arm64 64bit syscall numbers (used as event IDs for the Syscall Events)
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
	Open ID = iota + Unsupported
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
	Sys32vm86old
	Sys32fadvise64_64
)

// ARM 32bit syscall numbers
// Used for compatibility mode
// https://github.com/torvalds/linux/blob/master/arch/arm/tools/syscall.tbl
const (
	Sys32restart_syscall              ID = 0
	Sys32exit                         ID = 1
	Sys32fork                         ID = 2
	Sys32read                         ID = 3
	Sys32write                        ID = 4
	Sys32open                         ID = 5
	Sys32close                        ID = 6
	Sys32waitpid                      ID = 7
	Sys32creat                        ID = 8
	Sys32link                         ID = 9
	Sys32unlink                       ID = 10
	Sys32execve                       ID = 11
	Sys32chdir                        ID = 12
	Sys32time                         ID = 13
	Sys32mknod                        ID = 14
	Sys32chmod                        ID = 15
	Sys32lchown                       ID = 16
	Sys32break                        ID = 17
	Sys32oldstat                      ID = 18
	Sys32lseek                        ID = 19
	Sys32getpid                       ID = 20
	Sys32mount                        ID = 21
	Sys32umount                       ID = 22
	Sys32setuid                       ID = 23
	Sys32getuid                       ID = 24
	Sys32stime                        ID = 25
	Sys32ptrace                       ID = 26
	Sys32alarm                        ID = 27
	Sys32oldfstat                     ID = 28
	Sys32pause                        ID = 29
	Sys32utime                        ID = 30
	Sys32stty                         ID = 31
	Sys32gtty                         ID = 32
	Sys32access                       ID = 33
	Sys32nice                         ID = 34
	Sys32ftime                        ID = 35
	Sys32sync                         ID = 36
	Sys32kill                         ID = 37
	Sys32rename                       ID = 38
	Sys32mkdir                        ID = 39
	Sys32rmdir                        ID = 40
	Sys32dup                          ID = 41
	Sys32pipe                         ID = 42
	Sys32times                        ID = 43
	Sys32prof                         ID = 44
	Sys32brk                          ID = 45
	Sys32setgid                       ID = 46
	Sys32getgid                       ID = 47
	Sys32signal                       ID = 48
	Sys32geteuid                      ID = 49
	Sys32getegid                      ID = 50
	Sys32acct                         ID = 51
	Sys32umount2                      ID = 52
	Sys32lock                         ID = 53
	Sys32ioctl                        ID = 54
	Sys32fcntl                        ID = 55
	Sys32mpx                          ID = 56
	Sys32setpgid                      ID = 57
	Sys32ulimit                       ID = 58
	Sys32oldolduname                  ID = 59
	Sys32umask                        ID = 60
	Sys32chroot                       ID = 61
	Sys32ustat                        ID = 62
	Sys32dup2                         ID = 63
	Sys32getppid                      ID = 64
	Sys32getpgrp                      ID = 65
	Sys32setsid                       ID = 66
	Sys32sigaction                    ID = 67
	Sys32sgetmask                     ID = 68
	Sys32ssetmask                     ID = 69
	Sys32setreuid                     ID = 70
	Sys32setregid                     ID = 71
	Sys32sigsuspend                   ID = 72
	Sys32sigpending                   ID = 73
	Sys32sethostname                  ID = 74
	Sys32setrlimit                    ID = 75
	Sys32getrlimit                    ID = 76
	Sys32getrusage                    ID = 77
	Sys32gettimeofday                 ID = 78
	Sys32settimeofday                 ID = 79
	Sys32getgroups                    ID = 80
	Sys32setgroups                    ID = 81
	Sys32select                       ID = 82
	Sys32symlink                      ID = 83
	Sys32oldlstat                     ID = 84
	Sys32readlink                     ID = 85
	Sys32uselib                       ID = 86
	Sys32swapon                       ID = 87
	Sys32reboot                       ID = 88
	Sys32readdir                      ID = 89
	Sys32mmap                         ID = 90
	Sys32munmap                       ID = 91
	Sys32truncate                     ID = 92
	Sys32ftruncate                    ID = 93
	Sys32fchmod                       ID = 94
	Sys32fchown                       ID = 95
	Sys32getpriority                  ID = 96
	Sys32setpriority                  ID = 97
	Sys32profil                       ID = 98
	Sys32statfs                       ID = 99
	Sys32fstatfs                      ID = 100
	Sys32ioperm                       ID = 101
	Sys32socketcall                   ID = 102
	Sys32syslog                       ID = 103
	Sys32setitimer                    ID = 104
	Sys32getitimer                    ID = 105
	Sys32stat                         ID = 106
	Sys32lstat                        ID = 107
	Sys32fstat                        ID = 108
	Sys32olduname                     ID = 109
	Sys32iopl                         ID = 110
	Sys32vhangup                      ID = 111
	Sys32idle                         ID = 112
	Sys32syscall                      ID = 113
	Sys32wait4                        ID = 114
	Sys32swapoff                      ID = 115
	Sys32sysinfo                      ID = 116
	Sys32ipc                          ID = 117
	Sys32fsync                        ID = 118
	Sys32sigreturn                    ID = 119
	Sys32clone                        ID = 120
	Sys32setdomainname                ID = 121
	Sys32uname                        ID = 122
	Sys32modify_ldt                   ID = 123
	Sys32adjtimex                     ID = 124
	Sys32mprotect                     ID = 125
	Sys32sigprocmask                  ID = 126
	Sys32create_module                ID = 127
	Sys32init_module                  ID = 128
	Sys32delete_module                ID = 129
	Sys32get_kernel_syms              ID = 130
	Sys32quotactl                     ID = 131
	Sys32getpgid                      ID = 132
	Sys32fchdir                       ID = 133
	Sys32bdflush                      ID = 134
	Sys32sysfs                        ID = 135
	Sys32personality                  ID = 136
	Sys32afs_syscall                  ID = 137
	Sys32setfsuid                     ID = 138
	Sys32setfsgid                     ID = 139
	Sys32_llseek                      ID = 140
	Sys32getdents                     ID = 141
	Sys32_newselect                   ID = 142
	Sys32flock                        ID = 143
	Sys32msync                        ID = 144
	Sys32readv                        ID = 145
	Sys32writev                       ID = 146
	Sys32getsid                       ID = 147
	Sys32fdatasync                    ID = 148
	Sys32_sysctl                      ID = 149
	Sys32mlock                        ID = 150
	Sys32munlock                      ID = 151
	Sys32mlockall                     ID = 152
	Sys32munlockall                   ID = 153
	Sys32sched_setparam               ID = 154
	Sys32sched_getparam               ID = 155
	Sys32sched_setscheduler           ID = 156
	Sys32sched_getscheduler           ID = 157
	Sys32sched_yield                  ID = 158
	Sys32sched_get_priority_max       ID = 159
	Sys32sched_get_priority_min       ID = 160
	Sys32sched_rr_get_interval        ID = 161
	Sys32nanosleep                    ID = 162
	Sys32mremap                       ID = 163
	Sys32setresuid                    ID = 164
	Sys32getresuid                    ID = 165
	Sys32vm86                         ID = 166
	Sys32query_module                 ID = 167
	Sys32poll                         ID = 168
	Sys32nfsservctl                   ID = 169
	Sys32setresgid                    ID = 170
	Sys32getresgid                    ID = 171
	Sys32prctl                        ID = 172
	Sys32rt_sigreturn                 ID = 173
	Sys32rt_sigaction                 ID = 174
	Sys32rt_sigprocmask               ID = 175
	Sys32rt_sigpending                ID = 176
	Sys32rt_sigtimedwait              ID = 177
	Sys32rt_sigqueueinfo              ID = 178
	Sys32rt_sigsuspend                ID = 179
	Sys32pread64                      ID = 180
	Sys32pwrite64                     ID = 181
	Sys32chown                        ID = 182
	Sys32getcwd                       ID = 183
	Sys32capget                       ID = 184
	Sys32capset                       ID = 185
	Sys32sigaltstack                  ID = 186
	Sys32sendfile                     ID = 187
	Sys32_188Res                      ID = 188
	Sys32_189Res                      ID = 189
	Sys32vfork                        ID = 190
	Sys32ugetrlimit                   ID = 191
	Sys32mmap2                        ID = 192
	Sys32truncate64                   ID = 193
	Sys32ftruncate64                  ID = 194
	Sys32stat64                       ID = 195
	Sys32lstat64                      ID = 196
	Sys32fstat64                      ID = 197
	Sys32lchown32                     ID = 198
	Sys32getuid32                     ID = 199
	Sys32getgid32                     ID = 200
	Sys32geteuid32                    ID = 201
	Sys32getegid32                    ID = 202
	Sys32setreuid32                   ID = 203
	Sys32setregid32                   ID = 204
	Sys32getgroups32                  ID = 205
	Sys32setgroups32                  ID = 206
	Sys32fchown32                     ID = 207
	Sys32setresuid32                  ID = 208
	Sys32getresuid32                  ID = 209
	Sys32setresgid32                  ID = 210
	Sys32getresgid32                  ID = 211
	Sys32chown32                      ID = 212
	Sys32setuid32                     ID = 213
	Sys32setgid32                     ID = 214
	Sys32setfsuid32                   ID = 215
	Sys32setfsgid32                   ID = 216
	Sys32pivot_root                   ID = 217
	Sys32mincore                      ID = 218
	Sys32madvise                      ID = 219
	Sys32getdents64                   ID = 220
	Sys32fcntl64                      ID = 221
	Sys32_222Res                      ID = 222
	Sys32_223Res                      ID = 223
	Sys32gettid                       ID = 224
	Sys32readahead                    ID = 225
	Sys32setxattr                     ID = 226
	Sys32lsetxattr                    ID = 227
	Sys32fsetxattr                    ID = 228
	Sys32getxattr                     ID = 229
	Sys32lgetxattr                    ID = 230
	Sys32fgetxattr                    ID = 231
	Sys32listxattr                    ID = 232
	Sys32llistxattr                   ID = 233
	Sys32flistxattr                   ID = 234
	Sys32removexattr                  ID = 235
	Sys32lremovexattr                 ID = 236
	Sys32fremovexattr                 ID = 237
	Sys32tkill                        ID = 238
	Sys32sendfile64                   ID = 239
	Sys32futex                        ID = 240
	Sys32sched_setaffinity            ID = 241
	Sys32sched_getaffinity            ID = 242
	Sys32io_setup                     ID = 243
	Sys32io_destroy                   ID = 244
	Sys32io_getevents                 ID = 245
	Sys32io_submit                    ID = 246
	Sys32io_cancel                    ID = 247
	Sys32exit_group                   ID = 248
	Sys32lookup_dcookie               ID = 249
	Sys32epoll_create                 ID = 250
	Sys32epoll_ctl                    ID = 251
	Sys32epoll_wait                   ID = 252
	Sys32remap_file_pages             ID = 253
	Sys32_254Res                      ID = 254
	Sys32_255Res                      ID = 255
	Sys32set_tid_address              ID = 256
	Sys32timer_create                 ID = 257
	Sys32timer_settime                ID = 258
	Sys32timer_gettime                ID = 259
	Sys32timer_getoverrun             ID = 260
	Sys32timer_delete                 ID = 261
	Sys32clock_settime                ID = 262
	Sys32clock_gettime                ID = 263
	Sys32clock_getres                 ID = 264
	Sys32clock_nanosleep              ID = 265
	Sys32statfs64                     ID = 266
	Sys32fstatfs64                    ID = 267
	Sys32tgkill                       ID = 268
	Sys32utimes                       ID = 269
	Sys32arm_fadvise64_64             ID = 270
	Sys32pciconfig_iobase             ID = 271
	Sys32pciconfig_read               ID = 272
	Sys32pciconfig_write              ID = 273
	Sys32mq_open                      ID = 274
	Sys32mq_unlink                    ID = 275
	Sys32mq_timedsend                 ID = 276
	Sys32mq_timedreceive              ID = 277
	Sys32mq_notify                    ID = 278
	Sys32mq_getsetattr                ID = 279
	Sys32waitid                       ID = 280
	Sys32socket                       ID = 281
	Sys32bind                         ID = 282
	Sys32connect                      ID = 283
	Sys32listen                       ID = 284
	Sys32accept                       ID = 285
	Sys32getsockname                  ID = 286
	Sys32getpeername                  ID = 287
	Sys32socketpair                   ID = 288
	Sys32send                         ID = 289
	Sys32sendto                       ID = 290
	Sys32recv                         ID = 291
	Sys32recvfrom                     ID = 292
	Sys32shutdown                     ID = 293
	Sys32setsockopt                   ID = 294
	Sys32getsockopt                   ID = 295
	Sys32sendmsg                      ID = 296
	Sys32recvmsg                      ID = 297
	Sys32semop                        ID = 298
	Sys32semget                       ID = 299
	Sys32semctl                       ID = 300
	Sys32msgsnd                       ID = 301
	Sys32msgrcv                       ID = 302
	Sys32msgget                       ID = 303
	Sys32msgctl                       ID = 304
	Sys32shmat                        ID = 305
	Sys32shmdt                        ID = 306
	Sys32shmget                       ID = 307
	Sys32shmctl                       ID = 308
	Sys32add_key                      ID = 309
	Sys32request_key                  ID = 310
	Sys32keyctl                       ID = 311
	Sys32semtimedop                   ID = 312
	Sys32vserver                      ID = 313
	Sys32ioprio_set                   ID = 314
	Sys32ioprio_get                   ID = 315
	Sys32inotify_init                 ID = 316
	Sys32inotify_add_watch            ID = 317
	Sys32inotify_rm_watch             ID = 318
	Sys32mbind                        ID = 319
	Sys32get_mempolicy                ID = 320
	Sys32set_mempolicy                ID = 321
	Sys32openat                       ID = 322
	Sys32mkdirat                      ID = 323
	Sys32mknodat                      ID = 324
	Sys32fchownat                     ID = 325
	Sys32futimesat                    ID = 326
	Sys32fstatat64                    ID = 327
	Sys32unlinkat                     ID = 328
	Sys32renameat                     ID = 329
	Sys32linkat                       ID = 330
	Sys32symlinkat                    ID = 331
	Sys32readlinkat                   ID = 332
	Sys32fchmodat                     ID = 333
	Sys32faccessat                    ID = 334
	Sys32pselect6                     ID = 335
	Sys32ppoll                        ID = 336
	Sys32unshare                      ID = 337
	Sys32set_robust_list              ID = 338
	Sys32get_robust_list              ID = 339
	Sys32splice                       ID = 340
	Sys32arm_sync_file_range          ID = 341
	Sys32tee                          ID = 342
	Sys32vmsplice                     ID = 343
	Sys32move_pages                   ID = 344
	Sys32getcpu                       ID = 345
	Sys32epoll_pwait                  ID = 346
	Sys32kexec_load                   ID = 347
	Sys32utimensat                    ID = 348
	Sys32signalfd                     ID = 349
	Sys32timerfd_create               ID = 350
	Sys32eventfd                      ID = 351
	Sys32fallocate                    ID = 352
	Sys32timerfd_settime              ID = 353
	Sys32timerfd_gettime              ID = 354
	Sys32signalfd4                    ID = 355
	Sys32eventfd2                     ID = 356
	Sys32epoll_create1                ID = 357
	Sys32dup3                         ID = 358
	Sys32pipe2                        ID = 359
	Sys32inotify_init1                ID = 360
	Sys32preadv                       ID = 361
	Sys32pwritev                      ID = 362
	Sys32rt_tgsigqueueinfo            ID = 363
	Sys32perf_event_open              ID = 364
	Sys32recvmmsg                     ID = 365
	Sys32accept4                      ID = 366
	Sys32fanotify_init                ID = 367
	Sys32fanotify_mark                ID = 368
	Sys32prlimit64                    ID = 369
	Sys32name_to_handle_at            ID = 370
	Sys32open_by_handle_at            ID = 371
	Sys32clock_adjtime                ID = 372
	Sys32syncfs                       ID = 373
	Sys32sendmmsg                     ID = 374
	Sys32setns                        ID = 375
	Sys32process_vm_readv             ID = 376
	Sys32process_vm_writev            ID = 377
	Sys32kcmp                         ID = 378
	Sys32finit_module                 ID = 379
	Sys32sched_setattr                ID = 380
	Sys32sched_getattr                ID = 381
	Sys32renameat2                    ID = 382
	Sys32seccomp                      ID = 383
	Sys32getrandom                    ID = 384
	Sys32memfd_create                 ID = 385
	Sys32bpf                          ID = 386
	Sys32execveat                     ID = 387
	Sys32userfaultfd                  ID = 388
	Sys32membarrier                   ID = 389
	Sys32mlock2                       ID = 390
	Sys32copy_file_range              ID = 391
	Sys32preadv2                      ID = 392
	Sys32pwritev2                     ID = 393
	Sys32pkey_mprotect                ID = 394
	Sys32pkey_alloc                   ID = 395
	Sys32pkey_free                    ID = 396
	Sys32statx                        ID = 397
	Sys32rseq                         ID = 398
	Sys32io_pgetevents                ID = 399
	Sys32migrate_pages                ID = 400
	Sys32kexec_file_load              ID = 401
	Sys32_402Res                      ID = 402
	Sys32clock_gettime64              ID = 403
	Sys32clock_settime64              ID = 404
	Sys32clock_adjtime64              ID = 405
	Sys32clock_getres_time64          ID = 406
	Sys32clock_nanosleep_time64       ID = 407
	Sys32timer_gettime64              ID = 408
	Sys32timer_settime64              ID = 409
	Sys32timerfd_gettime64            ID = 410
	Sys32timerfd_settime64            ID = 411
	Sys32utimensat_time64             ID = 412
	Sys32pselect6_time64              ID = 413
	Sys32ppoll_time64                 ID = 414
	Sys32io_pgetevents_time64         ID = 416
	Sys32recvmmsg_time64              ID = 417
	Sys32mq_timedsend_time64          ID = 418
	Sys32mq_timedreceive_time64       ID = 419
	Sys32semtimedop_time64            ID = 420
	Sys32rt_sigtimedwait_time64       ID = 421
	Sys32futex_time64                 ID = 422
	Sys32sched_rr_get_interval_time64 ID = 423
	Sys32pidfd_send_signal            ID = 424
	Sys32io_uring_setup               ID = 425
	Sys32io_uring_enter               ID = 426
	Sys32io_uring_register            ID = 427
	Sys32open_tree                    ID = 428
	Sys32move_mount                   ID = 429
	Sys32fsopen                       ID = 430
	Sys32fsconfig                     ID = 431
	Sys32fsmount                      ID = 432
	Sys32fspick                       ID = 433
	Sys32pidfd_open                   ID = 434
	Sys32clone3                       ID = 435
	Sys32close_range                  ID = 436
	Sys32openat2                      ID = 437
	Sys32pidfd_getfd                  ID = 438
	Sys32faccessat2                   ID = 439
	Sys32process_madvise              ID = 440
	Sys32epoll_pwait2                 ID = 441
	Sys32mount_setattr                ID = 442
	Sys32quotactl_fd                  ID = 443
	Sys32landlock_create_ruleset      ID = 444
	Sys32landlock_add_rule            ID = 445
	Sys32landlock_restrict_self       ID = 446
	Sys32memfd_secret                 ID = 447
	Sys32process_mrelease             ID = 448
)

// following syscalls are undefined on arm32
const (
	Sys32arch_prctl ID = iota + Unsupported
	Sys32getpmsg
	Sys32putpmsg
	Sys32set_thread_area
	Sys32get_thread_area
	Sys32fadvise64
	Sys32sync_file_range
)

func DefaultSyscallsToCheck() []string {
	return []string{
		"ioctl",
		"openat",
		"close",
		"getdents64",
		"read",
		"write",
		"ptrace",
		"kill",
		"socket",
		"execveat",
		"sendto",
		"recvfrom",
		"sendmsg",
		"recvmsg",
		"execve",
		"bpf",
	}
}
