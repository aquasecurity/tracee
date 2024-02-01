//go:build arm64
// +build arm64

package extensions

// arm64 64bit syscall numbers (used as event IDs for the Syscall Events)
// https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/unistd.h

const (
	IoSetup                  int = 0
	IoDestroy                int = 1
	IoSubmit                 int = 2
	IoCancel                 int = 3
	IoGetevents              int = 4
	Setxattr                 int = 5
	Lsetxattr                int = 6
	Fsetxattr                int = 7
	Getxattr                 int = 8
	Lgetxattr                int = 9
	Fgetxattr                int = 10
	Listxattr                int = 11
	Llistxattr               int = 12
	Flistxattr               int = 13
	Removexattr              int = 14
	Lremovexattr             int = 15
	Fremovexattr             int = 16
	Getcwd                   int = 17
	LookupDcookie            int = 18
	Eventfd2                 int = 19
	EpollCreate1             int = 20
	EpollCtl                 int = 21
	EpollPwait               int = 22
	Dup                      int = 23
	Dup3                     int = 24
	Fcntl                    int = 25
	InotifyInit1             int = 26
	InotifyAddWatch          int = 27
	InotifyRmWatch           int = 28
	Ioctl                    int = 29
	IoprioSet                int = 30
	IoprioGet                int = 31
	Flock                    int = 32
	Mknodat                  int = 33
	Mkdirat                  int = 34
	Unlinkat                 int = 35
	Symlinkat                int = 36
	Linkat                   int = 37
	Renameat                 int = 38
	Umount2                  int = 39
	Mount                    int = 40
	PivotRoot                int = 41
	Nfsservctl               int = 42
	Statfs                   int = 43
	Fstatfs                  int = 44
	Truncate                 int = 45
	Ftruncate                int = 46
	Fallocate                int = 47
	Faccessat                int = 48
	Chdir                    int = 49
	Fchdir                   int = 50
	Chroot                   int = 51
	Fchmod                   int = 52
	Fchmodat                 int = 53
	Fchownat                 int = 54
	Fchown                   int = 55
	Openat                   int = 56
	Close                    int = 57
	Vhangup                  int = 58
	Pipe2                    int = 59
	Quotactl                 int = 60
	Getdents64               int = 61
	Lseek                    int = 62
	Read                     int = 63
	Write                    int = 64
	Readv                    int = 65
	Writev                   int = 66
	Pread64                  int = 67
	Pwrite64                 int = 68
	Preadv                   int = 69
	Pwritev                  int = 70
	Sendfile                 int = 71
	Pselect6                 int = 72
	Ppoll                    int = 73
	Signalfd4                int = 74
	Vmsplice                 int = 75
	Splice                   int = 76
	Tee                      int = 77
	Readlinkat               int = 78
	Newfstatat               int = 79
	Fstat                    int = 80
	Sync                     int = 81
	Fsync                    int = 82
	Fdatasync                int = 83
	SyncFileRange            int = 84
	TimerfdCreate            int = 85
	TimerfdSettime           int = 86
	TimerfdGettime           int = 87
	Utimensat                int = 88
	Acct                     int = 89
	Capget                   int = 90
	Capset                   int = 91
	Personality              int = 92
	Exit                     int = 93
	ExitGroup                int = 94
	Waitid                   int = 95
	SetTidAddress            int = 96
	Unshare                  int = 97
	Futex                    int = 98
	SetRobustList            int = 99
	GetRobustList            int = 100
	Nanosleep                int = 101
	Getitimer                int = 102
	Setitimer                int = 103
	KexecLoad                int = 104
	InitModule               int = 105
	DeleteModule             int = 106
	TimerCreate              int = 107
	TimerGettime             int = 108
	TimerGetoverrun          int = 109
	TimerSettime             int = 110
	TimerDelete              int = 111
	ClockSettime             int = 112
	ClockGettime             int = 113
	ClockGetres              int = 114
	ClockNanosleep           int = 115
	Syslog                   int = 116
	Ptrace                   int = 117
	SchedSetparam            int = 118
	SchedSetscheduler        int = 119
	SchedGetscheduler        int = 120
	SchedGetparam            int = 121
	SchedSetaffinity         int = 122
	SchedGetaffinity         int = 123
	SchedYield               int = 124
	SchedGetPriorityMax      int = 125
	SchedGetPriorityMin      int = 126
	SchedRrGetInterval       int = 127
	RestartSyscall           int = 128
	Kill                     int = 129
	Tkill                    int = 130
	Tgkill                   int = 131
	Sigaltstack              int = 132
	RtSigsuspend             int = 133
	RtSigaction              int = 134
	RtSigprocmask            int = 135
	RtSigpending             int = 136
	RtSigtimedwait           int = 137
	RtSigqueueinfo           int = 138
	RtSigreturn              int = 139
	Setpriority              int = 140
	Getpriority              int = 141
	Reboot                   int = 142
	Setregid                 int = 143
	Setgid                   int = 144
	Setreuid                 int = 145
	Setuid                   int = 146
	Setresuid                int = 147
	Getresuid                int = 148
	Setresgid                int = 149
	Getresgid                int = 150
	Setfsuid                 int = 151
	Setfsgid                 int = 152
	Times                    int = 153
	Setpgid                  int = 154
	Getpgid                  int = 155
	Getsid                   int = 156
	Setsid                   int = 157
	Getgroups                int = 158
	Setgroups                int = 159
	Uname                    int = 160
	Sethostname              int = 161
	Setdomainname            int = 162
	Getrlimit                int = 163
	Setrlimit                int = 164
	Getrusage                int = 165
	Umask                    int = 166
	Prctl                    int = 167
	Getcpu                   int = 168
	Gettimeofday             int = 169
	Settimeofday             int = 170
	Adjtimex                 int = 171
	Getpid                   int = 172
	Getppid                  int = 173
	Getuid                   int = 174
	Geteuid                  int = 175
	Getgid                   int = 176
	Getegid                  int = 177
	Gettid                   int = 178
	Sysinfo                  int = 179
	MqOpen                   int = 180
	MqUnlink                 int = 181
	MqTimedsend              int = 182
	MqTimedreceive           int = 183
	MqNotify                 int = 184
	MqGetsetattr             int = 185
	Msgget                   int = 186
	Msgctl                   int = 187
	Msgrcv                   int = 188
	Msgsnd                   int = 189
	Semget                   int = 190
	Semctl                   int = 191
	Semtimedop               int = 192
	Semop                    int = 193
	Shmget                   int = 194
	Shmctl                   int = 195
	Shmat                    int = 196
	Shmdt                    int = 197
	Socket                   int = 198
	Socketpair               int = 199
	Bind                     int = 200
	Listen                   int = 201
	Accept                   int = 202
	Connect                  int = 203
	Getsockname              int = 204
	Getpeername              int = 205
	Sendto                   int = 206
	Recvfrom                 int = 207
	Setsockopt               int = 208
	Getsockopt               int = 209
	Shutdown                 int = 210
	Sendmsg                  int = 211
	Recvmsg                  int = 212
	Readahead                int = 213
	Brk                      int = 214
	Munmap                   int = 215
	Mremap                   int = 216
	AddKey                   int = 217
	RequestKey               int = 218
	Keyctl                   int = 219
	Clone                    int = 220
	Execve                   int = 221
	Mmap                     int = 222
	Fadvise64                int = 223
	Swapon                   int = 224
	Swapoff                  int = 225
	Mprotect                 int = 226
	Msync                    int = 227
	Mlock                    int = 228
	Munlock                  int = 229
	Mlockall                 int = 230
	Munlockall               int = 231
	Mincore                  int = 232
	Madvise                  int = 233
	RemapFilePages           int = 234
	Mbind                    int = 235
	GetMempolicy             int = 236
	SetMempolicy             int = 237
	MigratePages             int = 238
	MovePages                int = 239
	RtTgsigqueueinfo         int = 240
	PerfEventOpen            int = 241
	Accept4                  int = 242
	Recvmmsg                 int = 243
	Sys244                   int = 244
	Sys245                   int = 245
	Sys246                   int = 246
	Sys247                   int = 247
	Sys248                   int = 248
	Sys249                   int = 249
	Sys250                   int = 250
	Sys251                   int = 251
	Sys252                   int = 252
	Sys253                   int = 253
	Sys254                   int = 254
	Sys255                   int = 255
	Sys256                   int = 256
	Sys257                   int = 257
	Sys258                   int = 258
	Sys259                   int = 259
	Wait4                    int = 260
	Prlimit64                int = 261
	FanotifyInit             int = 262
	FanotifyMark             int = 263
	NameToHandleAt           int = 264
	OpenByHandleAt           int = 265
	ClockAdjtime             int = 266
	Syncfs                   int = 267
	Setns                    int = 268
	Sendmmsg                 int = 269
	ProcessVmReadv           int = 270
	ProcessVmWritev          int = 271
	Kcmp                     int = 272
	FinitModule              int = 273
	SchedSetattr             int = 274
	SchedGetattr             int = 275
	Renameat2                int = 276
	Seccomp                  int = 277
	Getrandom                int = 278
	MemfdCreate              int = 279
	Bpf                      int = 280
	Execveat                 int = 281
	Userfaultfd              int = 282
	Membarrier               int = 283
	Mlock2                   int = 284
	CopyFileRange            int = 285
	Preadv2                  int = 286
	Pwritev2                 int = 287
	PkeyMprotect             int = 288
	PkeyAlloc                int = 289
	PkeyFree                 int = 290
	Statx                    int = 291
	IoPgetevents             int = 292
	Rseq                     int = 293
	KexecFileLoad            int = 294
	ClockGettime64           int = 403 // 295 -> 402 unassigned to sync up with generic numbers
	ClockSettime64           int = 404
	ClockAdjtime64           int = 405
	ClockGetresTime64        int = 406
	ClockNanosleepTime64     int = 407
	TimerGettime64           int = 408
	TimerSettime64           int = 409
	TimerfdGettime64         int = 410
	TimerfdSettime64         int = 411
	UtimensatTime64          int = 412
	Pselect6Time64           int = 413
	PpollTime64              int = 414
	IoPgeteventsTime64       int = 416
	RecvmmsgTime64           int = 417
	MqTimedsendTime64        int = 418
	MqTimedreceiveTime64     int = 419
	SemtimedopTime64         int = 420
	RtSigtimedwaitTime64     int = 421
	FutexTime64              int = 422
	SchedRrGetIntervalTime64 int = 423
	PidfdSendSignal          int = 424
	IoUringSetup             int = 425
	IoUringEnter             int = 426
	IoUringRegister          int = 427
	OpenTree                 int = 428
	MoveMount                int = 429
	Fsopen                   int = 430
	Fsconfig                 int = 431
	Fsmount                  int = 432
	Fspick                   int = 433
	PidfdOpen                int = 434
	Clone3                   int = 435
	CloseRange               int = 436
	Openat2                  int = 437
	PidfdGetfd               int = 438
	Faccessat2               int = 439
	ProcessMadvise           int = 440
	EpollPwait2              int = 441
	MountSetattr             int = 442
	QuotactlFd               int = 443
	LandlockCreateRuleset    int = 444
	LandlockAddRule          int = 445
	LandlockRestrictSelf     int = 446
	MemfdSecret              int = 447
	ProcessMrelease          int = 448
	MaxSyscallID             int = 449
	// TODO: Compile list of unique 32bit syscalls for arm64
)

// following syscalls are undefined on arm64
const (
	Open int = iota + Unsupported
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
	Sys32restart_syscall              int = 0
	Sys32exit                         int = 1
	Sys32fork                         int = 2
	Sys32read                         int = 3
	Sys32write                        int = 4
	Sys32open                         int = 5
	Sys32close                        int = 6
	Sys32waitpid                      int = 7
	Sys32creat                        int = 8
	Sys32link                         int = 9
	Sys32unlink                       int = 10
	Sys32execve                       int = 11
	Sys32chdir                        int = 12
	Sys32time                         int = 13
	Sys32mknod                        int = 14
	Sys32chmod                        int = 15
	Sys32lchown                       int = 16
	Sys32break                        int = 17
	Sys32oldstat                      int = 18
	Sys32lseek                        int = 19
	Sys32getpid                       int = 20
	Sys32mount                        int = 21
	Sys32umount                       int = 22
	Sys32setuid                       int = 23
	Sys32getuid                       int = 24
	Sys32stime                        int = 25
	Sys32ptrace                       int = 26
	Sys32alarm                        int = 27
	Sys32oldfstat                     int = 28
	Sys32pause                        int = 29
	Sys32utime                        int = 30
	Sys32stty                         int = 31
	Sys32gtty                         int = 32
	Sys32access                       int = 33
	Sys32nice                         int = 34
	Sys32ftime                        int = 35
	Sys32sync                         int = 36
	Sys32kill                         int = 37
	Sys32rename                       int = 38
	Sys32mkdir                        int = 39
	Sys32rmdir                        int = 40
	Sys32dup                          int = 41
	Sys32pipe                         int = 42
	Sys32times                        int = 43
	Sys32prof                         int = 44
	Sys32brk                          int = 45
	Sys32setgid                       int = 46
	Sys32getgid                       int = 47
	Sys32signal                       int = 48
	Sys32geteuid                      int = 49
	Sys32getegid                      int = 50
	Sys32acct                         int = 51
	Sys32umount2                      int = 52
	Sys32lock                         int = 53
	Sys32ioctl                        int = 54
	Sys32fcntl                        int = 55
	Sys32mpx                          int = 56
	Sys32setpgid                      int = 57
	Sys32ulimit                       int = 58
	Sys32oldolduname                  int = 59
	Sys32umask                        int = 60
	Sys32chroot                       int = 61
	Sys32ustat                        int = 62
	Sys32dup2                         int = 63
	Sys32getppid                      int = 64
	Sys32getpgrp                      int = 65
	Sys32setsid                       int = 66
	Sys32sigaction                    int = 67
	Sys32sgetmask                     int = 68
	Sys32ssetmask                     int = 69
	Sys32setreuid                     int = 70
	Sys32setregid                     int = 71
	Sys32sigsuspend                   int = 72
	Sys32sigpending                   int = 73
	Sys32sethostname                  int = 74
	Sys32setrlimit                    int = 75
	Sys32getrlimit                    int = 76
	Sys32getrusage                    int = 77
	Sys32gettimeofday                 int = 78
	Sys32settimeofday                 int = 79
	Sys32getgroups                    int = 80
	Sys32setgroups                    int = 81
	Sys32select                       int = 82
	Sys32symlink                      int = 83
	Sys32oldlstat                     int = 84
	Sys32readlink                     int = 85
	Sys32uselib                       int = 86
	Sys32swapon                       int = 87
	Sys32reboot                       int = 88
	Sys32readdir                      int = 89
	Sys32mmap                         int = 90
	Sys32munmap                       int = 91
	Sys32truncate                     int = 92
	Sys32ftruncate                    int = 93
	Sys32fchmod                       int = 94
	Sys32fchown                       int = 95
	Sys32getpriority                  int = 96
	Sys32setpriority                  int = 97
	Sys32profil                       int = 98
	Sys32statfs                       int = 99
	Sys32fstatfs                      int = 100
	Sys32ioperm                       int = 101
	Sys32socketcall                   int = 102
	Sys32syslog                       int = 103
	Sys32setitimer                    int = 104
	Sys32getitimer                    int = 105
	Sys32stat                         int = 106
	Sys32lstat                        int = 107
	Sys32fstat                        int = 108
	Sys32olduname                     int = 109
	Sys32iopl                         int = 110
	Sys32vhangup                      int = 111
	Sys32idle                         int = 112
	Sys32syscall                      int = 113
	Sys32wait4                        int = 114
	Sys32swapoff                      int = 115
	Sys32sysinfo                      int = 116
	Sys32ipc                          int = 117
	Sys32fsync                        int = 118
	Sys32sigreturn                    int = 119
	Sys32clone                        int = 120
	Sys32setdomainname                int = 121
	Sys32uname                        int = 122
	Sys32modify_ldt                   int = 123
	Sys32adjtimex                     int = 124
	Sys32mprotect                     int = 125
	Sys32sigprocmask                  int = 126
	Sys32create_module                int = 127
	Sys32init_module                  int = 128
	Sys32delete_module                int = 129
	Sys32get_kernel_syms              int = 130
	Sys32quotactl                     int = 131
	Sys32getpgid                      int = 132
	Sys32fchdir                       int = 133
	Sys32bdflush                      int = 134
	Sys32sysfs                        int = 135
	Sys32personality                  int = 136
	Sys32afs_syscall                  int = 137
	Sys32setfsuid                     int = 138
	Sys32setfsgid                     int = 139
	Sys32_llseek                      int = 140
	Sys32getdents                     int = 141
	Sys32_newselect                   int = 142
	Sys32flock                        int = 143
	Sys32msync                        int = 144
	Sys32readv                        int = 145
	Sys32writev                       int = 146
	Sys32getsid                       int = 147
	Sys32fdatasync                    int = 148
	Sys32_sysctl                      int = 149
	Sys32mlock                        int = 150
	Sys32munlock                      int = 151
	Sys32mlockall                     int = 152
	Sys32munlockall                   int = 153
	Sys32sched_setparam               int = 154
	Sys32sched_getparam               int = 155
	Sys32sched_setscheduler           int = 156
	Sys32sched_getscheduler           int = 157
	Sys32sched_yield                  int = 158
	Sys32sched_get_priority_max       int = 159
	Sys32sched_get_priority_min       int = 160
	Sys32sched_rr_get_interval        int = 161
	Sys32nanosleep                    int = 162
	Sys32mremap                       int = 163
	Sys32setresuid                    int = 164
	Sys32getresuid                    int = 165
	Sys32vm86                         int = 166
	Sys32query_module                 int = 167
	Sys32poll                         int = 168
	Sys32nfsservctl                   int = 169
	Sys32setresgid                    int = 170
	Sys32getresgid                    int = 171
	Sys32prctl                        int = 172
	Sys32rt_sigreturn                 int = 173
	Sys32rt_sigaction                 int = 174
	Sys32rt_sigprocmask               int = 175
	Sys32rt_sigpending                int = 176
	Sys32rt_sigtimedwait              int = 177
	Sys32rt_sigqueueinfo              int = 178
	Sys32rt_sigsuspend                int = 179
	Sys32pread64                      int = 180
	Sys32pwrite64                     int = 181
	Sys32chown                        int = 182
	Sys32getcwd                       int = 183
	Sys32capget                       int = 184
	Sys32capset                       int = 185
	Sys32sigaltstack                  int = 186
	Sys32sendfile                     int = 187
	Sys32_188Res                      int = 188
	Sys32_189Res                      int = 189
	Sys32vfork                        int = 190
	Sys32ugetrlimit                   int = 191
	Sys32mmap2                        int = 192
	Sys32truncate64                   int = 193
	Sys32ftruncate64                  int = 194
	Sys32stat64                       int = 195
	Sys32lstat64                      int = 196
	Sys32fstat64                      int = 197
	Sys32lchown32                     int = 198
	Sys32getuid32                     int = 199
	Sys32getgid32                     int = 200
	Sys32geteuid32                    int = 201
	Sys32getegid32                    int = 202
	Sys32setreuid32                   int = 203
	Sys32setregid32                   int = 204
	Sys32getgroups32                  int = 205
	Sys32setgroups32                  int = 206
	Sys32fchown32                     int = 207
	Sys32setresuid32                  int = 208
	Sys32getresuid32                  int = 209
	Sys32setresgid32                  int = 210
	Sys32getresgid32                  int = 211
	Sys32chown32                      int = 212
	Sys32setuid32                     int = 213
	Sys32setgid32                     int = 214
	Sys32setfsuid32                   int = 215
	Sys32setfsgid32                   int = 216
	Sys32pivot_root                   int = 217
	Sys32mincore                      int = 218
	Sys32madvise                      int = 219
	Sys32getdents64                   int = 220
	Sys32fcntl64                      int = 221
	Sys32_222Res                      int = 222
	Sys32_223Res                      int = 223
	Sys32gettid                       int = 224
	Sys32readahead                    int = 225
	Sys32setxattr                     int = 226
	Sys32lsetxattr                    int = 227
	Sys32fsetxattr                    int = 228
	Sys32getxattr                     int = 229
	Sys32lgetxattr                    int = 230
	Sys32fgetxattr                    int = 231
	Sys32listxattr                    int = 232
	Sys32llistxattr                   int = 233
	Sys32flistxattr                   int = 234
	Sys32removexattr                  int = 235
	Sys32lremovexattr                 int = 236
	Sys32fremovexattr                 int = 237
	Sys32tkill                        int = 238
	Sys32sendfile64                   int = 239
	Sys32futex                        int = 240
	Sys32sched_setaffinity            int = 241
	Sys32sched_getaffinity            int = 242
	Sys32io_setup                     int = 243
	Sys32io_destroy                   int = 244
	Sys32io_getevents                 int = 245
	Sys32io_submit                    int = 246
	Sys32io_cancel                    int = 247
	Sys32exit_group                   int = 248
	Sys32lookup_dcookie               int = 249
	Sys32epoll_create                 int = 250
	Sys32epoll_ctl                    int = 251
	Sys32epoll_wait                   int = 252
	Sys32remap_file_pages             int = 253
	Sys32_254Res                      int = 254
	Sys32_255Res                      int = 255
	Sys32set_tid_address              int = 256
	Sys32timer_create                 int = 257
	Sys32timer_settime                int = 258
	Sys32timer_gettime                int = 259
	Sys32timer_getoverrun             int = 260
	Sys32timer_delete                 int = 261
	Sys32clock_settime                int = 262
	Sys32clock_gettime                int = 263
	Sys32clock_getres                 int = 264
	Sys32clock_nanosleep              int = 265
	Sys32statfs64                     int = 266
	Sys32fstatfs64                    int = 267
	Sys32tgkill                       int = 268
	Sys32utimes                       int = 269
	Sys32arm_fadvise64_64             int = 270
	Sys32pciconfig_iobase             int = 271
	Sys32pciconfig_read               int = 272
	Sys32pciconfig_write              int = 273
	Sys32mq_open                      int = 274
	Sys32mq_unlink                    int = 275
	Sys32mq_timedsend                 int = 276
	Sys32mq_timedreceive              int = 277
	Sys32mq_notify                    int = 278
	Sys32mq_getsetattr                int = 279
	Sys32waitid                       int = 280
	Sys32socket                       int = 281
	Sys32bind                         int = 282
	Sys32connect                      int = 283
	Sys32listen                       int = 284
	Sys32accept                       int = 285
	Sys32getsockname                  int = 286
	Sys32getpeername                  int = 287
	Sys32socketpair                   int = 288
	Sys32send                         int = 289
	Sys32sendto                       int = 290
	Sys32recv                         int = 291
	Sys32recvfrom                     int = 292
	Sys32shutdown                     int = 293
	Sys32setsockopt                   int = 294
	Sys32getsockopt                   int = 295
	Sys32sendmsg                      int = 296
	Sys32recvmsg                      int = 297
	Sys32semop                        int = 298
	Sys32semget                       int = 299
	Sys32semctl                       int = 300
	Sys32msgsnd                       int = 301
	Sys32msgrcv                       int = 302
	Sys32msgget                       int = 303
	Sys32msgctl                       int = 304
	Sys32shmat                        int = 305
	Sys32shmdt                        int = 306
	Sys32shmget                       int = 307
	Sys32shmctl                       int = 308
	Sys32add_key                      int = 309
	Sys32request_key                  int = 310
	Sys32keyctl                       int = 311
	Sys32semtimedop                   int = 312
	Sys32vserver                      int = 313
	Sys32ioprio_set                   int = 314
	Sys32ioprio_get                   int = 315
	Sys32inotify_init                 int = 316
	Sys32inotify_add_watch            int = 317
	Sys32inotify_rm_watch             int = 318
	Sys32mbind                        int = 319
	Sys32get_mempolicy                int = 320
	Sys32set_mempolicy                int = 321
	Sys32openat                       int = 322
	Sys32mkdirat                      int = 323
	Sys32mknodat                      int = 324
	Sys32fchownat                     int = 325
	Sys32futimesat                    int = 326
	Sys32fstatat64                    int = 327
	Sys32unlinkat                     int = 328
	Sys32renameat                     int = 329
	Sys32linkat                       int = 330
	Sys32symlinkat                    int = 331
	Sys32readlinkat                   int = 332
	Sys32fchmodat                     int = 333
	Sys32faccessat                    int = 334
	Sys32pselect6                     int = 335
	Sys32ppoll                        int = 336
	Sys32unshare                      int = 337
	Sys32set_robust_list              int = 338
	Sys32get_robust_list              int = 339
	Sys32splice                       int = 340
	Sys32arm_sync_file_range          int = 341
	Sys32tee                          int = 342
	Sys32vmsplice                     int = 343
	Sys32move_pages                   int = 344
	Sys32getcpu                       int = 345
	Sys32epoll_pwait                  int = 346
	Sys32kexec_load                   int = 347
	Sys32utimensat                    int = 348
	Sys32signalfd                     int = 349
	Sys32timerfd_create               int = 350
	Sys32eventfd                      int = 351
	Sys32fallocate                    int = 352
	Sys32timerfd_settime              int = 353
	Sys32timerfd_gettime              int = 354
	Sys32signalfd4                    int = 355
	Sys32eventfd2                     int = 356
	Sys32epoll_create1                int = 357
	Sys32dup3                         int = 358
	Sys32pipe2                        int = 359
	Sys32inotify_init1                int = 360
	Sys32preadv                       int = 361
	Sys32pwritev                      int = 362
	Sys32rt_tgsigqueueinfo            int = 363
	Sys32perf_event_open              int = 364
	Sys32recvmmsg                     int = 365
	Sys32accept4                      int = 366
	Sys32fanotify_init                int = 367
	Sys32fanotify_mark                int = 368
	Sys32prlimit64                    int = 369
	Sys32name_to_handle_at            int = 370
	Sys32open_by_handle_at            int = 371
	Sys32clock_adjtime                int = 372
	Sys32syncfs                       int = 373
	Sys32sendmmsg                     int = 374
	Sys32setns                        int = 375
	Sys32process_vm_readv             int = 376
	Sys32process_vm_writev            int = 377
	Sys32kcmp                         int = 378
	Sys32finit_module                 int = 379
	Sys32sched_setattr                int = 380
	Sys32sched_getattr                int = 381
	Sys32renameat2                    int = 382
	Sys32seccomp                      int = 383
	Sys32getrandom                    int = 384
	Sys32memfd_create                 int = 385
	Sys32bpf                          int = 386
	Sys32execveat                     int = 387
	Sys32userfaultfd                  int = 388
	Sys32membarrier                   int = 389
	Sys32mlock2                       int = 390
	Sys32copy_file_range              int = 391
	Sys32preadv2                      int = 392
	Sys32pwritev2                     int = 393
	Sys32pkey_mprotect                int = 394
	Sys32pkey_alloc                   int = 395
	Sys32pkey_free                    int = 396
	Sys32statx                        int = 397
	Sys32rseq                         int = 398
	Sys32io_pgetevents                int = 399
	Sys32migrate_pages                int = 400
	Sys32kexec_file_load              int = 401
	Sys32_402Res                      int = 402
	Sys32clock_gettime64              int = 403
	Sys32clock_settime64              int = 404
	Sys32clock_adjtime64              int = 405
	Sys32clock_getres_time64          int = 406
	Sys32clock_nanosleep_time64       int = 407
	Sys32timer_gettime64              int = 408
	Sys32timer_settime64              int = 409
	Sys32timerfd_gettime64            int = 410
	Sys32timerfd_settime64            int = 411
	Sys32utimensat_time64             int = 412
	Sys32pselect6_time64              int = 413
	Sys32ppoll_time64                 int = 414
	Sys32io_pgetevents_time64         int = 416
	Sys32recvmmsg_time64              int = 417
	Sys32mq_timedsend_time64          int = 418
	Sys32mq_timedreceive_time64       int = 419
	Sys32semtimedop_time64            int = 420
	Sys32rt_sigtimedwait_time64       int = 421
	Sys32futex_time64                 int = 422
	Sys32sched_rr_get_interval_time64 int = 423
	Sys32pidfd_send_signal            int = 424
	Sys32io_uring_setup               int = 425
	Sys32io_uring_enter               int = 426
	Sys32io_uring_register            int = 427
	Sys32open_tree                    int = 428
	Sys32move_mount                   int = 429
	Sys32fsopen                       int = 430
	Sys32fsconfig                     int = 431
	Sys32fsmount                      int = 432
	Sys32fspick                       int = 433
	Sys32pidfd_open                   int = 434
	Sys32clone3                       int = 435
	Sys32close_range                  int = 436
	Sys32openat2                      int = 437
	Sys32pidfd_getfd                  int = 438
	Sys32faccessat2                   int = 439
	Sys32process_madvise              int = 440
	Sys32epoll_pwait2                 int = 441
	Sys32mount_setattr                int = 442
	Sys32quotactl_fd                  int = 443
	Sys32landlock_create_ruleset      int = 444
	Sys32landlock_add_rule            int = 445
	Sys32landlock_restrict_self       int = 446
	Sys32memfd_secret                 int = 447
	Sys32process_mrelease             int = 448
)

// following syscalls are undefined on arm32
const (
	Sys32arch_prctl int = iota + Unsupported
	Sys32getpmsg
	Sys32putpmsg
	Sys32set_thread_area
	Sys32get_thread_area
	Sys32fadvise64
	Sys32sync_file_range
)

const SyscallPrefix = "__arm64_sys_"
const SyscallNotImplemented = "NOT_IMPLEMENTED"

type KernelRestrictions struct {
	Below string
	Above string
	Name  string
}

// Order matters
var SyscallSymbolNames = map[int][]KernelRestrictions{
	0:   {{Name: "io_setup"}},
	1:   {{Name: "io_destroy"}},
	2:   {{Name: "io_submit"}},
	3:   {{Name: "io_cancel"}},
	4:   {{Name: "io_getevents"}},
	5:   {{Name: "setxattr"}},
	6:   {{Name: "lsetxattr"}},
	7:   {{Name: "fsetxattr"}},
	8:   {{Name: "getxattr"}},
	9:   {{Name: "lgetxattr"}},
	10:  {{Name: "fgetxattr"}},
	11:  {{Name: "listxattr"}},
	12:  {{Name: "llistxattr"}},
	13:  {{Name: "flistxattr"}},
	14:  {{Name: "removexattr"}},
	15:  {{Name: "lremovexattr"}},
	16:  {{Name: "fremovexattr"}},
	17:  {{Name: "getcwd"}},
	18:  {{Name: "lookup_dcookie"}},
	19:  {{Name: "eventfd2"}},
	20:  {{Name: "epoll_create1"}},
	21:  {{Name: "epoll_ctl"}},
	22:  {{Name: "epoll_pwait"}},
	23:  {{Name: "dup"}},
	24:  {{Name: "dup3"}},
	25:  {{Name: "fcntl"}},
	26:  {{Name: "inotify_init1"}},
	27:  {{Name: "inotify_add_watch"}},
	28:  {{Name: "inotify_rm_watch"}},
	29:  {{Name: "ioctl"}},
	30:  {{Name: "ioprio_set"}},
	31:  {{Name: "ioprio_get"}},
	32:  {{Name: "flock"}},
	33:  {{Name: "mknodat"}},
	34:  {{Name: "mkdirat"}},
	35:  {{Name: "unlinkat"}},
	36:  {{Name: "symlinkat"}},
	37:  {{Name: "linkat"}},
	38:  {{Name: "renameat"}},
	39:  {{Name: "umount"}},
	40:  {{Name: "mount"}},
	41:  {{Name: "pivot_root"}},
	42:  {{Name: SyscallNotImplemented + "nfsservctl"}},
	43:  {{Name: "statfs"}},
	44:  {{Name: "fstatfs"}},
	45:  {{Name: "truncate"}},
	46:  {{Name: "ftruncate"}},
	47:  {{Name: "fallocate"}},
	48:  {{Name: "faccessat"}},
	49:  {{Name: "chdir"}},
	50:  {{Name: "fchdir"}},
	51:  {{Name: "chroot"}},
	52:  {{Name: "fchmod"}},
	53:  {{Name: "fchmodat"}},
	54:  {{Name: "fchownat"}},
	55:  {{Name: "fchown"}},
	56:  {{Name: "openat"}},
	57:  {{Name: "close"}},
	58:  {{Name: "vhangup"}},
	59:  {{Name: "pipe2"}},
	60:  {{Name: "quotactl"}},
	61:  {{Name: "getdents64"}},
	62:  {{Name: "lseek"}},
	63:  {{Name: "read"}},
	64:  {{Name: "write"}},
	65:  {{Name: "readv"}},
	66:  {{Name: "writev"}},
	67:  {{Name: "pread64"}},
	68:  {{Name: "pwrite64"}},
	69:  {{Name: "preadv"}},
	70:  {{Name: "pwritev"}},
	71:  {{Name: "sendfile64"}},
	72:  {{Name: "pselect6"}},
	73:  {{Name: "ppoll"}},
	74:  {{Name: "signalfd4"}},
	75:  {{Name: "vmsplice"}},
	76:  {{Name: "splice"}},
	77:  {{Name: "tee"}},
	78:  {{Name: "readlinkat"}},
	79:  {{Name: "newfstatat"}},
	80:  {{Name: "newfstat"}},
	81:  {{Name: "sync"}},
	82:  {{Name: "fsync"}},
	83:  {{Name: "fdatasync"}},
	84:  {{Name: "sync_file_range"}},
	85:  {{Name: "timerfd_create"}},
	86:  {{Name: "timerfd_settime"}},
	87:  {{Name: "timerfd_gettime"}},
	88:  {{Name: "utimensat"}},
	89:  {{Name: "acct"}},
	90:  {{Name: "capget"}},
	91:  {{Name: "capset"}},
	92:  {{Name: "arm64_personality"}},
	93:  {{Name: "exit"}},
	94:  {{Name: "exit_group"}},
	95:  {{Name: "waitid"}},
	96:  {{Name: "set_tid_address"}},
	97:  {{Name: "unshare"}},
	98:  {{Name: "futex"}},
	99:  {{Name: "set_robust_list"}},
	100: {{Name: "get_robust_list"}},
	101: {{Name: "nanosleep"}},
	102: {{Name: "getitimer"}},
	103: {{Name: "setitimer"}},
	104: {{Name: "kexec_load"}},
	105: {{Name: "init_module"}},
	106: {{Name: "delete_module"}},
	107: {{Name: "timer_create"}},
	108: {{Name: "timer_gettime"}},
	109: {{Name: "timer_getoverrun"}},
	110: {{Name: "timer_settime"}},
	111: {{Name: "timer_delete"}},
	112: {{Name: "clock_settime"}},
	113: {{Name: "clock_gettime"}},
	114: {{Name: "clock_getres"}},
	115: {{Name: "clock_nanosleep"}},
	116: {{Name: "syslog"}},
	117: {{Name: "ptrace"}},
	118: {{Name: "sched_setparam"}},
	119: {{Name: "sched_setscheduler"}},
	120: {{Name: "sched_getscheduler"}},
	121: {{Name: "sched_getparam"}},
	122: {{Name: "sched_setaffinity"}},
	123: {{Name: "sched_getaffinity"}},
	124: {{Name: "sched_yield"}},
	125: {{Name: "sched_get_priority_max"}},
	126: {{Name: "sched_get_priority_min"}},
	127: {{Name: "sched_rr_get_interval"}},
	128: {{Name: "restart_syscall"}},
	129: {{Name: "kill"}},
	130: {{Name: "tkill"}},
	131: {{Name: "tgkill"}},
	132: {{Name: "sigaltstack"}},
	133: {{Name: "rt_sigsuspend"}},
	134: {{Name: "rt_sigaction"}},
	135: {{Name: "rt_sigprocmask"}},
	136: {{Name: "rt_sigpending"}},
	137: {{Name: "rt_sigtimedwait"}},
	138: {{Name: "rt_sigqueueinfo"}},
	139: {{Name: "rt_sigreturn"}},
	140: {{Name: "setpriority"}},
	141: {{Name: "getpriority"}},
	142: {{Name: "reboot"}},
	143: {{Name: "setregid"}},
	144: {{Name: "setgid"}},
	145: {{Name: "setreuid"}},
	146: {{Name: "setuid"}},
	147: {{Name: "setresuid"}},
	148: {{Name: "getresuid"}},
	149: {{Name: "setresgid"}},
	150: {{Name: "getresgid"}},
	151: {{Name: "setfsuid"}},
	152: {{Name: "setfsgid"}},
	153: {{Name: "times"}},
	154: {{Name: "setpgid"}},
	155: {{Name: "getpgid"}},
	156: {{Name: "getsid"}},
	157: {{Name: "setsid"}},
	158: {{Name: "getgroups"}},
	159: {{Name: "setgroups"}},
	160: {{Name: "newuname"}},
	161: {{Name: "sethostname"}},
	162: {{Name: "setdomainname"}},
	163: {{Name: "getrlimit"}},
	164: {{Name: "setrlimit"}},
	165: {{Name: "getrusage"}},
	166: {{Name: "umask"}},
	167: {{Name: "prctl"}},
	168: {{Name: "getcpu"}},
	169: {{Name: "gettimeofday"}},
	170: {{Name: "settimeofday"}},
	171: {{Name: "adjtimex"}},
	172: {{Name: "getpid"}},
	173: {{Name: "getppid"}},
	174: {{Name: "getuid"}},
	175: {{Name: "geteuid"}},
	176: {{Name: "getgid"}},
	177: {{Name: "getegid"}},
	178: {{Name: "gettid"}},
	179: {{Name: "sysinfo"}},
	180: {{Name: "mq_open"}},
	181: {{Name: "mq_unlink"}},
	182: {{Name: "mq_timedsend"}},
	183: {{Name: "mq_timedreceive"}},
	184: {{Name: "mq_notify"}},
	185: {{Name: "mq_getsetattr"}},
	186: {{Name: "msgget"}},
	187: {{Name: "msgctl"}},
	188: {{Name: "msgrcv"}},
	189: {{Name: "msgsnd"}},
	190: {{Name: "semget"}},
	191: {{Name: "semctl"}},
	192: {{Name: "semtimedop"}},
	193: {{Name: "semop"}},
	194: {{Name: "shmget"}},
	195: {{Name: "shmctl"}},
	196: {{Name: "shmat"}},
	197: {{Name: "shmdt"}},
	198: {{Name: "socket"}},
	199: {{Name: "socketpair"}},
	200: {{Name: "bind"}},
	201: {{Name: "listen"}},
	202: {{Name: "accept"}},
	203: {{Name: "connect"}},
	204: {{Name: "getsockname"}},
	205: {{Name: "getpeername"}},
	206: {{Name: "sendto"}},
	207: {{Name: "recvfrom"}},
	208: {{Name: "setsockopt"}},
	209: {{Name: "getsockopt"}},
	210: {{Name: "shutdown"}},
	211: {{Name: "sendmsg"}},
	212: {{Name: "recvmsg"}},
	213: {{Name: "readahead"}},
	214: {{Name: "brk"}},
	215: {{Name: "munmap"}},
	216: {{Name: "mremap"}},
	217: {{Name: "add_key"}},
	218: {{Name: "request_key"}},
	219: {{Name: "keyctl"}},
	220: {{Name: "clone"}},
	221: {{Name: "execve"}},
	222: {{Name: "mmap"}},
	223: {{Name: "fadvise64_64"}},
	224: {{Name: "swapon"}},
	225: {{Name: "swapoff"}},
	226: {{Name: "mprotect"}},
	227: {{Name: "msync"}},
	228: {{Name: "mlock"}},
	229: {{Name: "munlock"}},
	230: {{Name: "mlockall"}},
	231: {{Name: "munlockall"}},
	232: {{Name: "mincore"}},
	233: {{Name: "madvise"}},
	234: {{Name: "remap_file_pages"}},
	235: {{Name: "mbind"}},
	236: {{Name: "get_mempolicy"}},
	237: {{Name: "set_mempolicy"}},
	238: {{Name: "migrate_pages"}},
	239: {{Name: "move_pages"}},
	240: {{Name: "rt_tgsigqueueinfo"}},
	241: {{Name: "perf_event_open"}},
	242: {{Name: "accept4"}},
	243: {{Name: "recvmmsg"}},
	244: {{Name: SyscallNotImplemented}},
	245: {{Name: SyscallNotImplemented}},
	246: {{Name: SyscallNotImplemented}},
	247: {{Name: SyscallNotImplemented}},
	248: {{Name: SyscallNotImplemented}},
	249: {{Name: SyscallNotImplemented}},
	250: {{Name: SyscallNotImplemented}},
	251: {{Name: SyscallNotImplemented}},
	252: {{Name: SyscallNotImplemented}},
	253: {{Name: SyscallNotImplemented}},
	254: {{Name: SyscallNotImplemented}},
	255: {{Name: SyscallNotImplemented}},
	256: {{Name: SyscallNotImplemented}},
	257: {{Name: SyscallNotImplemented}},
	258: {{Name: SyscallNotImplemented}},
	259: {{Name: SyscallNotImplemented}},
	260: {{Name: "wait4"}},
	261: {{Name: "prlimit64"}},
	262: {{Name: "fanotify_init"}},
	263: {{Name: "fanotify_mark"}},
	264: {{Name: "name_to_handle_at"}},
	265: {{Name: "open_by_handle_at"}},
	266: {{Name: "clock_adjtime"}},
	267: {{Name: "syncfs"}},
	268: {{Name: "setns"}},
	269: {{Name: "sendmmsg"}},
	270: {{Name: "process_vm_readv"}},
	271: {{Name: "process_vm_writev"}},
	272: {{Name: "kcmp"}},
	273: {{Name: "finit_module"}},
	274: {{Name: "sched_setattr"}},
	275: {{Name: "sched_getattr"}},
	276: {{Name: "renameat2"}},
	277: {{Name: "seccomp"}},
	278: {{Name: "getrandom"}},
	279: {{Name: "memfd_create"}},
	280: {{Name: "bpf"}},
	281: {{Name: "execveat"}},
	282: {{Name: "userfaultfd"}},
	283: {{Name: "membarrier"}},
	284: {{Name: "mlock2"}},
	285: {{Name: "copy_file_range"}},
	286: {{Name: "preadv2"}},
	287: {{Name: "pwritev2"}},
	288: {{Name: "pkey_mprotect"}},
	289: {{Name: "pkey_alloc"}},
	290: {{Name: "pkey_free"}},
	291: {{Name: "statx"}},
	292: {{Name: "io_pgetevents"}},
	293: {{Name: "rseq"}},
	294: {{Name: "kexec_file_load"}},
	295: {{Name: SyscallNotImplemented}},
	296: {{Name: SyscallNotImplemented}},
	297: {{Name: SyscallNotImplemented}},
	298: {{Name: SyscallNotImplemented}},
	299: {{Name: SyscallNotImplemented}},
	300: {{Name: SyscallNotImplemented}},
	301: {{Name: SyscallNotImplemented}},
	302: {{Name: SyscallNotImplemented}},
	303: {{Name: SyscallNotImplemented}},
	304: {{Name: SyscallNotImplemented}},
	305: {{Name: SyscallNotImplemented}},
	306: {{Name: SyscallNotImplemented}},
	307: {{Name: SyscallNotImplemented}},
	308: {{Name: SyscallNotImplemented}},
	309: {{Name: SyscallNotImplemented}},
	310: {{Name: SyscallNotImplemented}},
	311: {{Name: SyscallNotImplemented}},
	312: {{Name: SyscallNotImplemented}},
	313: {{Name: SyscallNotImplemented}},
	314: {{Name: SyscallNotImplemented}},
	315: {{Name: SyscallNotImplemented}},
	316: {{Name: SyscallNotImplemented}},
	317: {{Name: SyscallNotImplemented}},
	318: {{Name: SyscallNotImplemented}},
	319: {{Name: SyscallNotImplemented}},
	320: {{Name: SyscallNotImplemented}},
	321: {{Name: SyscallNotImplemented}},
	322: {{Name: SyscallNotImplemented}},
	323: {{Name: SyscallNotImplemented}},
	324: {{Name: SyscallNotImplemented}},
	325: {{Name: SyscallNotImplemented}},
	326: {{Name: SyscallNotImplemented}},
	327: {{Name: SyscallNotImplemented}},
	328: {{Name: SyscallNotImplemented}},
	329: {{Name: SyscallNotImplemented}},
	330: {{Name: SyscallNotImplemented}},
	331: {{Name: SyscallNotImplemented}},
	332: {{Name: SyscallNotImplemented}},
	333: {{Name: SyscallNotImplemented}},
	334: {{Name: SyscallNotImplemented}},
	335: {{Name: SyscallNotImplemented}},
	336: {{Name: SyscallNotImplemented}},
	337: {{Name: SyscallNotImplemented}},
	338: {{Name: SyscallNotImplemented}},
	339: {{Name: SyscallNotImplemented}},
	340: {{Name: SyscallNotImplemented}},
	341: {{Name: SyscallNotImplemented}},
	342: {{Name: SyscallNotImplemented}},
	343: {{Name: SyscallNotImplemented}},
	344: {{Name: SyscallNotImplemented}},
	345: {{Name: SyscallNotImplemented}},
	346: {{Name: SyscallNotImplemented}},
	347: {{Name: SyscallNotImplemented}},
	348: {{Name: SyscallNotImplemented}},
	349: {{Name: SyscallNotImplemented}},
	350: {{Name: SyscallNotImplemented}},
	351: {{Name: SyscallNotImplemented}},
	352: {{Name: SyscallNotImplemented}},
	353: {{Name: SyscallNotImplemented}},
	354: {{Name: SyscallNotImplemented}},
	355: {{Name: SyscallNotImplemented}},
	356: {{Name: SyscallNotImplemented}},
	357: {{Name: SyscallNotImplemented}},
	358: {{Name: SyscallNotImplemented}},
	359: {{Name: SyscallNotImplemented}},
	360: {{Name: SyscallNotImplemented}},
	361: {{Name: SyscallNotImplemented}},
	362: {{Name: SyscallNotImplemented}},
	363: {{Name: SyscallNotImplemented}},
	364: {{Name: SyscallNotImplemented}},
	365: {{Name: SyscallNotImplemented}},
	366: {{Name: SyscallNotImplemented}},
	367: {{Name: SyscallNotImplemented}},
	368: {{Name: SyscallNotImplemented}},
	369: {{Name: SyscallNotImplemented}},
	370: {{Name: SyscallNotImplemented}},
	371: {{Name: SyscallNotImplemented}},
	372: {{Name: SyscallNotImplemented}},
	373: {{Name: SyscallNotImplemented}},
	374: {{Name: SyscallNotImplemented}},
	375: {{Name: SyscallNotImplemented}},
	376: {{Name: SyscallNotImplemented}},
	377: {{Name: SyscallNotImplemented}},
	378: {{Name: SyscallNotImplemented}},
	379: {{Name: SyscallNotImplemented}},
	380: {{Name: SyscallNotImplemented}},
	381: {{Name: SyscallNotImplemented}},
	382: {{Name: SyscallNotImplemented}},
	383: {{Name: SyscallNotImplemented}},
	384: {{Name: SyscallNotImplemented}},
	385: {{Name: SyscallNotImplemented}},
	386: {{Name: SyscallNotImplemented}},
	387: {{Name: SyscallNotImplemented}},
	388: {{Name: SyscallNotImplemented}},
	389: {{Name: SyscallNotImplemented}},
	390: {{Name: SyscallNotImplemented}},
	391: {{Name: SyscallNotImplemented}},
	392: {{Name: SyscallNotImplemented}},
	393: {{Name: SyscallNotImplemented}},
	394: {{Name: SyscallNotImplemented}},
	395: {{Name: SyscallNotImplemented}},
	396: {{Name: SyscallNotImplemented}},
	397: {{Name: SyscallNotImplemented}},
	398: {{Name: SyscallNotImplemented}},
	399: {{Name: SyscallNotImplemented}},
	400: {{Name: SyscallNotImplemented}},
	401: {{Name: SyscallNotImplemented}},
	402: {{Name: SyscallNotImplemented}},
	403: {{Name: SyscallNotImplemented}},
	404: {{Name: SyscallNotImplemented}},
	405: {{Name: SyscallNotImplemented}},
	406: {{Name: SyscallNotImplemented}},
	407: {{Name: SyscallNotImplemented}},
	408: {{Name: SyscallNotImplemented}},
	409: {{Name: SyscallNotImplemented}},
	410: {{Name: SyscallNotImplemented}},
	411: {{Name: SyscallNotImplemented}},
	412: {{Name: SyscallNotImplemented}},
	413: {{Name: SyscallNotImplemented}},
	414: {{Name: SyscallNotImplemented}},
	415: {{Name: SyscallNotImplemented}},
	416: {{Name: SyscallNotImplemented}},
	417: {{Name: SyscallNotImplemented}},
	418: {{Name: SyscallNotImplemented}},
	419: {{Name: SyscallNotImplemented}},
	420: {{Name: SyscallNotImplemented}},
	421: {{Name: SyscallNotImplemented}},
	422: {{Name: SyscallNotImplemented}},
	423: {{Name: SyscallNotImplemented}},
	424: {{Name: "pidfd_send_signal"}},
	425: {{Name: "io_uring_setup"}},
	426: {{Name: "io_uring_enter"}},
	427: {{Name: "io_uring_register"}},
	428: {{Name: "open_tree"}},
	429: {{Name: "move_mount"}},
	430: {{Name: "fsopen"}},
	431: {{Name: "fsconfig"}},
	432: {{Name: "fsmount"}},
	433: {{Name: "fspick"}},
	434: {{Above: "5.2", Name: "pidfd_open"}},
	435: {{Above: "5.2", Name: "clone3"}},
	436: {{Above: "5.9", Name: "close_range"}},
	437: {{Above: "5.7", Name: "openat2"}},
	438: {{Above: "5.7", Name: "pidfd_getfd"}},
	439: {{Above: "5.8", Name: "faccessat2"}},
	440: {{Above: "5.10", Name: "process_madvise"}},
	441: {{Above: "5.11", Name: "epoll_pwait2"}},
	442: {{Above: "5.12", Name: "mount_setattr"}},
	443: {{Above: "5.14", Name: "quotactl_fd"}},
	444: {{Above: "5.13", Name: "landlock_create_ruleset"}},
	445: {{Above: "5.13", Name: "landlock_add_rule"}},
	446: {{Above: "5.13", Name: "landlock_restrict_self"}},
	447: {{Above: "5.14", Name: "memfd_secret"}},
	448: {{Above: "5.15", Name: "process_mrelease"}},
	449: {{Above: "5.16", Name: "futex_waitv"}},
	450: {{Above: "5.17", Name: "set_mempolicy_home_node"}},
	451: {{Above: "6.5", Name: "cachestat"}},
}
