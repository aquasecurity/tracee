//go:build amd64
// +build amd64

package extensions

// x86 64bit syscall numbers (used as event IDs for the Syscall Events)
// https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl

const (
	Read                int = 0
	Write               int = 1
	Open                int = 2
	Close               int = 3
	Stat                int = 4
	Fstat               int = 5
	Lstat               int = 6
	Poll                int = 7
	Lseek               int = 8
	Mmap                int = 9
	Mprotect            int = 10
	Munmap              int = 11
	Brk                 int = 12
	RtSigaction         int = 13
	RtSigprocmask       int = 14
	RtSigreturn         int = 15
	Ioctl               int = 16
	Pread64             int = 17
	Pwrite64            int = 18
	Readv               int = 19
	Writev              int = 20
	Access              int = 21
	Pipe                int = 22
	Select              int = 23
	SchedYield          int = 24
	Mremap              int = 25
	Msync               int = 26
	Mincore             int = 27
	Madvise             int = 28
	Shmget              int = 29
	Shmat               int = 30
	Shmctl              int = 31
	Dup                 int = 32
	Dup2                int = 33
	Pause               int = 34
	Nanosleep           int = 35
	Getitimer           int = 36
	Alarm               int = 37
	Setitimer           int = 38
	Getpid              int = 39
	Sendfile            int = 40
	Socket              int = 41
	Connect             int = 42
	Accept              int = 43
	Sendto              int = 44
	Recvfrom            int = 45
	Sendmsg             int = 46
	Recvmsg             int = 47
	Shutdown            int = 48
	Bind                int = 49
	Listen              int = 50
	Getsockname         int = 51
	Getpeername         int = 52
	Socketpair          int = 53
	Setsockopt          int = 54
	Getsockopt          int = 55
	Clone               int = 56
	Fork                int = 57
	Vfork               int = 58
	Execve              int = 59
	Exit                int = 60
	Wait4               int = 61
	Kill                int = 62
	Uname               int = 63
	Semget              int = 64
	Semop               int = 65
	Semctl              int = 66
	Shmdt               int = 67
	Msgget              int = 68
	Msgsnd              int = 69
	Msgrcv              int = 70
	Msgctl              int = 71
	Fcntl               int = 72
	Flock               int = 73
	Fsync               int = 74
	Fdatasync           int = 75
	Truncate            int = 76
	Ftruncate           int = 77
	Getdents            int = 78
	Getcwd              int = 79
	Chdir               int = 80
	Fchdir              int = 81
	Rename              int = 82
	Mkdir               int = 83
	Rmdir               int = 84
	Creat               int = 85
	Link                int = 86
	Unlink              int = 87
	Symlink             int = 88
	Readlink            int = 89
	Chmod               int = 90
	Fchmod              int = 91
	Chown               int = 92
	Fchown              int = 93
	Lchown              int = 94
	Umask               int = 95
	Gettimeofday        int = 96
	Getrlimit           int = 97
	Getrusage           int = 98
	Sysinfo             int = 99
	Times               int = 100
	Ptrace              int = 101
	Getuid              int = 102
	Syslog              int = 103
	Getgid              int = 104
	Setuid              int = 105
	Setgid              int = 106
	Geteuid             int = 107
	Getegid             int = 108
	Setpgid             int = 109
	Getppid             int = 110
	Getpgrp             int = 111
	Setsid              int = 112
	Setreuid            int = 113
	Setregid            int = 114
	Getgroups           int = 115
	Setgroups           int = 116
	Setresuid           int = 117
	Getresuid           int = 118
	Setresgid           int = 119
	Getresgid           int = 120
	Getpgid             int = 121
	Setfsuid            int = 122
	Setfsgid            int = 123
	Getsid              int = 124
	Capget              int = 125
	Capset              int = 126
	RtSigpending        int = 127
	RtSigtimedwait      int = 128
	RtSigqueueinfo      int = 129
	RtSigsuspend        int = 130
	Sigaltstack         int = 131
	Utime               int = 132
	Mknod               int = 133
	Uselib              int = 134
	Personality         int = 135
	Ustat               int = 136
	Statfs              int = 137
	Fstatfs             int = 138
	Sysfs               int = 139
	Getpriority         int = 140
	Setpriority         int = 141
	SchedSetparam       int = 142
	SchedGetparam       int = 143
	SchedSetscheduler   int = 144
	SchedGetscheduler   int = 145
	SchedGetPriorityMax int = 146
	SchedGetPriorityMin int = 147
	SchedRrGetInterval  int = 148
	Mlock               int = 149
	Munlock             int = 150
	Mlockall            int = 151
	Munlockall          int = 152
	Vhangup             int = 153
	ModifyLdt           int = 154
	PivotRoot           int = 155
	Sysctl              int = 156
	Prctl               int = 157
	ArchPrctl           int = 158
	Adjtimex            int = 159
	Setrlimit           int = 160
	Chroot              int = 161
	Sync                int = 162
	Acct                int = 163
	Settimeofday        int = 164
	Mount               int = 165
	Umount2             int = 166
	Swapon              int = 167
	Swapoff             int = 168
	Reboot              int = 169
	Sethostname         int = 170
	Setdomainname       int = 171
	Iopl                int = 172
	Ioperm              int = 173
	CreateModule        int = 174
	InitModule          int = 175
	DeleteModule        int = 176
	GetKernelSyms       int = 177
	QueryModule         int = 178
	Quotactl            int = 179
	Nfsservctl          int = 180
	Getpmsg             int = 181
	Putpmsg             int = 182
	Afs                 int = 183
	Tuxcall             int = 184
	Security            int = 185
	Gettid              int = 186
	Readahead           int = 187
	Setxattr            int = 188
	Lsetxattr           int = 189
	Fsetxattr           int = 190
	Getxattr            int = 191
	Lgetxattr           int = 192
	Fgetxattr           int = 193
	Listxattr           int = 194
	Llistxattr          int = 195
	Flistxattr          int = 196
	Removexattr         int = 197
	Lremovexattr        int = 198
	Fremovexattr        int = 199
	Tkill               int = 200
	Time                int = 201
	Futex               int = 202
	SchedSetaffinity    int = 203
	SchedGetaffinity    int = 204
	SetThreadArea       int = 205
	IoSetup             int = 206
	IoDestroy           int = 207
	IoGetevents         int = 208
	IoSubmit            int = 209
	IoCancel            int = 210
	GetThreadArea       int = 211
	LookupDcookie       int = 212
	EpollCreate         int = 213
	EpollCtlOld         int = 214
	EpollWaitOld        int = 215
	RemapFilePages      int = 216
	Getdents64          int = 217
	SetTidAddress       int = 218
	RestartSyscall      int = 219
	Semtimedop          int = 220
	Fadvise64           int = 221
	TimerCreate         int = 222
	TimerSettime        int = 223
	TimerGettime        int = 224
	TimerGetoverrun     int = 225
	TimerDelete         int = 226
	ClockSettime        int = 227
	ClockGettime        int = 228
	ClockGetres         int = 229
	ClockNanosleep      int = 230
	ExitGroup           int = 231
	EpollWait           int = 232
	EpollCtl            int = 233
	Tgkill              int = 234
	Utimes              int = 235
	Vserver             int = 236
	Mbind               int = 237
	SetMempolicy        int = 238
	GetMempolicy        int = 239
	MqOpen              int = 240
	MqUnlink            int = 241
	MqTimedsend         int = 242
	MqTimedreceive      int = 243
	MqNotify            int = 244
	MqGetsetattr        int = 245
	KexecLoad           int = 246
	Waitid              int = 247
	AddKey              int = 248
	RequestKey          int = 249
	Keyctl              int = 250
	IoprioSet           int = 251
	IoprioGet           int = 252
	InotifyInit         int = 253
	InotifyAddWatch     int = 254
	InotifyRmWatch      int = 255
	MigratePages        int = 256
	Openat              int = 257
	Mkdirat             int = 258
	Mknodat             int = 259
	Fchownat            int = 260
	Futimesat           int = 261
	Newfstatat          int = 262
	Unlinkat            int = 263
	Renameat            int = 264
	Linkat              int = 265
	Symlinkat           int = 266
	Readlinkat          int = 267
	Fchmodat            int = 268
	Faccessat           int = 269
	Pselect6            int = 270
	Ppoll               int = 271
	Unshare             int = 272
	SetRobustList       int = 273
	GetRobustList       int = 274
	Splice              int = 275
	Tee                 int = 276
	SyncFileRange       int = 277
	Vmsplice            int = 278
	MovePages           int = 279
	Utimensat           int = 280
	EpollPwait          int = 281
	Signalfd            int = 282
	TimerfdCreate       int = 283
	Eventfd             int = 284
	Fallocate           int = 285
	TimerfdSettime      int = 286
	TimerfdGettime      int = 287
	Accept4             int = 288
	Signalfd4           int = 289
	Eventfd2            int = 290
	EpollCreate1        int = 291
	Dup3                int = 292
	Pipe2               int = 293
	InotifyInit1        int = 294
	Preadv              int = 295
	Pwritev             int = 296
	RtTgsigqueueinfo    int = 297
	PerfEventOpen       int = 298
	Recvmmsg            int = 299
	FanotifyInit        int = 300
	FanotifyMark        int = 301
	Prlimit64           int = 302
	NameToHandleAt      int = 303
	OpenByHandleAt      int = 304
	ClockAdjtime        int = 305
	Syncfs              int = 306
	Sendmmsg            int = 307
	Setns               int = 308
	Getcpu              int = 309
	ProcessVmReadv      int = 310
	ProcessVmWritev     int = 311
	Kcmp                int = 312
	FinitModule         int = 313
	SchedSetattr        int = 314
	SchedGetattr        int = 315
	Renameat2           int = 316
	Seccomp             int = 317
	Getrandom           int = 318
	MemfdCreate         int = 319
	KexecFileLoad       int = 320
	Bpf                 int = 321
	Execveat            int = 322
	Userfaultfd         int = 323
	Membarrier          int = 324
	Mlock2              int = 325
	CopyFileRange       int = 326
	Preadv2             int = 327
	Pwritev2            int = 328
	PkeyMprotect        int = 329
	PkeyAlloc           int = 330
	PkeyFree            int = 331
	Statx               int = 332
	IoPgetevents        int = 333
	Rseq                int = 334
	// 335 through 423 are unassigned to sync up with generic numbers
	PidfdSendSignal int = iota + 89 // iota = 335 here 335 + 89 = 424
	IoUringSetup
	IoUringEnter
	IoUringRegister
	OpenTree
	MoveMount
	Fsopen
	Fsconfig
	Fsmount
	Fspick
	PidfdOpen
	Clone3
	CloseRange
	Openat2
	PidfdGetfd
	Faccessat2
	ProcessMadvise
	EpollPwait2
	MountSetattr
	QuotactlFd
	LandlockCreateRuleset
	LandlockAddRule
	LandlockRestrictSelf
	MemfdSecret
	ProcessMrelease
	// Set of IDs for 32bit syscalls which have no parallel 64bit syscall
	Waitpid
	Oldfstat
	Break
	Oldstat
	Umount
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
	ClockAdjtime64
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
	MaxSyscallID
)

// x86 32bit syscall numbers
// Used for compatibility mode
// https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_32.tbl
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
	Sys32vm86old                      int = 113
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
	Sys32getpmsg                      int = 188
	Sys32putpmsg                      int = 189
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
	Sys32set_thread_area              int = 243
	Sys32get_thread_area              int = 244
	Sys32io_setup                     int = 245
	Sys32io_destroy                   int = 246
	Sys32io_getevents                 int = 247
	Sys32io_submit                    int = 248
	Sys32io_cancel                    int = 249
	Sys32fadvise64                    int = 250
	Sys32exit_group                   int = 252
	Sys32lookup_dcookie               int = 253
	Sys32epoll_create                 int = 254
	Sys32epoll_ctl                    int = 255
	Sys32epoll_wait                   int = 256
	Sys32remap_file_pages             int = 257
	Sys32set_tid_address              int = 258
	Sys32timer_create                 int = 259
	Sys32timer_settime                int = 260
	Sys32timer_gettime                int = 261
	Sys32timer_getoverrun             int = 262
	Sys32timer_delete                 int = 263
	Sys32clock_settime                int = 264
	Sys32clock_gettime                int = 265
	Sys32clock_getres                 int = 266
	Sys32clock_nanosleep              int = 267
	Sys32statfs64                     int = 268
	Sys32fstatfs64                    int = 269
	Sys32tgkill                       int = 270
	Sys32utimes                       int = 271
	Sys32fadvise64_64                 int = 272
	Sys32vserver                      int = 273
	Sys32mbind                        int = 274
	Sys32get_mempolicy                int = 275
	Sys32set_mempolicy                int = 276
	Sys32mq_open                      int = 277
	Sys32mq_unlink                    int = 278
	Sys32mq_timedsend                 int = 279
	Sys32mq_timedreceive              int = 280
	Sys32mq_notify                    int = 281
	Sys32mq_getsetattr                int = 282
	Sys32kexec_load                   int = 283
	Sys32waitid                       int = 284
	Sys32add_key                      int = 286
	Sys32request_key                  int = 287
	Sys32keyctl                       int = 288
	Sys32ioprio_set                   int = 289
	Sys32ioprio_get                   int = 290
	Sys32inotify_init                 int = 291
	Sys32inotify_add_watch            int = 292
	Sys32inotify_rm_watch             int = 293
	Sys32migrate_pages                int = 294
	Sys32openat                       int = 295
	Sys32mkdirat                      int = 296
	Sys32mknodat                      int = 297
	Sys32fchownat                     int = 298
	Sys32futimesat                    int = 299
	Sys32fstatat64                    int = 300
	Sys32unlinkat                     int = 301
	Sys32renameat                     int = 302
	Sys32linkat                       int = 303
	Sys32symlinkat                    int = 304
	Sys32readlinkat                   int = 305
	Sys32fchmodat                     int = 306
	Sys32faccessat                    int = 307
	Sys32pselect6                     int = 308
	Sys32ppoll                        int = 309
	Sys32unshare                      int = 310
	Sys32set_robust_list              int = 311
	Sys32get_robust_list              int = 312
	Sys32splice                       int = 313
	Sys32sync_file_range              int = 314
	Sys32tee                          int = 315
	Sys32vmsplice                     int = 316
	Sys32move_pages                   int = 317
	Sys32getcpu                       int = 318
	Sys32epoll_pwait                  int = 319
	Sys32utimensat                    int = 320
	Sys32signalfd                     int = 321
	Sys32timerfd_create               int = 322
	Sys32eventfd                      int = 323
	Sys32fallocate                    int = 324
	Sys32timerfd_settime              int = 325
	Sys32timerfd_gettime              int = 326
	Sys32signalfd4                    int = 327
	Sys32eventfd2                     int = 328
	Sys32epoll_create1                int = 329
	Sys32dup3                         int = 330
	Sys32pipe2                        int = 331
	Sys32inotify_init1                int = 332
	Sys32preadv                       int = 333
	Sys32pwritev                      int = 334
	Sys32rt_tgsigqueueinfo            int = 335
	Sys32perf_event_open              int = 336
	Sys32recvmmsg                     int = 337
	Sys32fanotify_init                int = 338
	Sys32fanotify_mark                int = 339
	Sys32prlimit64                    int = 340
	Sys32name_to_handle_at            int = 341
	Sys32open_by_handle_at            int = 342
	Sys32clock_adjtime                int = 343
	Sys32syncfs                       int = 344
	Sys32sendmmsg                     int = 345
	Sys32setns                        int = 346
	Sys32process_vm_readv             int = 347
	Sys32process_vm_writev            int = 348
	Sys32kcmp                         int = 349
	Sys32finit_module                 int = 350
	Sys32sched_setattr                int = 351
	Sys32sched_getattr                int = 352
	Sys32renameat2                    int = 353
	Sys32seccomp                      int = 354
	Sys32getrandom                    int = 355
	Sys32memfd_create                 int = 356
	Sys32bpf                          int = 357
	Sys32execveat                     int = 358
	Sys32socket                       int = 359
	Sys32socketpair                   int = 360
	Sys32bind                         int = 361
	Sys32connect                      int = 362
	Sys32listen                       int = 363
	Sys32accept4                      int = 364
	Sys32getsockopt                   int = 365
	Sys32setsockopt                   int = 366
	Sys32getsockname                  int = 367
	Sys32getpeername                  int = 368
	Sys32sendto                       int = 369
	Sys32sendmsg                      int = 370
	Sys32recvfrom                     int = 371
	Sys32recvmsg                      int = 372
	Sys32shutdown                     int = 373
	Sys32userfaultfd                  int = 374
	Sys32membarrier                   int = 375
	Sys32mlock2                       int = 376
	Sys32copy_file_range              int = 377
	Sys32preadv2                      int = 378
	Sys32pwritev2                     int = 379
	Sys32pkey_mprotect                int = 380
	Sys32pkey_alloc                   int = 381
	Sys32pkey_free                    int = 382
	Sys32statx                        int = 383
	Sys32arch_prctl                   int = 384
	Sys32io_pgetevents                int = 385
	Sys32rseq                         int = 386
	Sys32semget                       int = 393
	Sys32semctl                       int = 394
	Sys32shmget                       int = 395
	Sys32shmctl                       int = 396
	Sys32shmat                        int = 397
	Sys32shmdt                        int = 398
	Sys32msgget                       int = 399
	Sys32msgsnd                       int = 400
	Sys32msgrcv                       int = 401
	Sys32msgctl                       int = 402
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

const SyscallPrefix = "__x64_sys_"
const SyscallNotImplemented = "NOT_IMPLEMENTED"

type KernelRestrictions struct {
	Below string
	Above string
	Name  string
}

// SyscallSymbolNames mapping of syscall id to syscall definition name by kernel version.
// Since syscalls can be removed, changed or added - to run on every kernel out there, we need to address
// the changes over the kernel versions.
var SyscallSymbolNames = map[int][]KernelRestrictions{
	0:   {{Name: "read"}},
	1:   {{Name: "write"}},
	2:   {{Name: "open"}},
	3:   {{Name: "close"}},
	4:   {{Name: "newstat"}},
	5:   {{Name: "newfstat"}},
	6:   {{Name: "newlstat"}},
	7:   {{Name: "poll"}},
	8:   {{Name: "lseek"}},
	9:   {{Name: "mmap"}},
	10:  {{Name: "mprotect"}},
	11:  {{Name: "munmap"}},
	12:  {{Name: "brk"}},
	13:  {{Name: "rt_sigaction"}},
	14:  {{Name: "rt_sigprocmask"}},
	15:  {{Name: "rt_sigreturn"}},
	16:  {{Name: "ioctl"}},
	17:  {{Name: "pread64"}},
	18:  {{Name: "pwrite64"}},
	19:  {{Name: "readv"}},
	20:  {{Name: "writev"}},
	21:  {{Name: "access"}},
	22:  {{Name: "pipe"}},
	23:  {{Name: "select"}},
	24:  {{Name: "sched_yield"}},
	25:  {{Name: "mremap"}},
	26:  {{Name: "msync"}},
	27:  {{Name: "mincore"}},
	28:  {{Name: "madvise"}},
	29:  {{Name: "shmget"}},
	30:  {{Name: "shmat"}},
	31:  {{Name: "shmctl"}},
	32:  {{Name: "dup"}},
	33:  {{Name: "dup2"}},
	34:  {{Name: "pause"}},
	35:  {{Name: "nanosleep"}},
	36:  {{Name: "getitimer"}},
	37:  {{Name: "alarm"}},
	38:  {{Name: "setitimer"}},
	39:  {{Name: "getpid"}},
	40:  {{Name: "sendfile64"}},
	41:  {{Name: "socket"}},
	42:  {{Name: "connect"}},
	43:  {{Name: "accept"}},
	44:  {{Name: "sendto"}},
	45:  {{Name: "recvfrom"}},
	46:  {{Name: "sendmsg"}},
	47:  {{Name: "recvmsg"}},
	48:  {{Name: "shutdown"}},
	49:  {{Name: "bind"}},
	50:  {{Name: "listen"}},
	51:  {{Name: "getsockname"}},
	52:  {{Name: "getpeername"}},
	53:  {{Name: "socketpair"}},
	54:  {{Name: "setsockopt"}},
	55:  {{Name: "getsockopt"}},
	56:  {{Name: "clone"}},
	57:  {{Name: "fork"}},
	58:  {{Name: "vfork"}},
	59:  {{Name: "execve"}},
	60:  {{Name: "exit"}},
	61:  {{Name: "wait4"}},
	62:  {{Name: "kill"}},
	63:  {{Name: "newuname"}},
	64:  {{Name: "semget"}},
	65:  {{Name: "semop"}},
	66:  {{Name: "semctl"}},
	67:  {{Name: "shmdt"}},
	68:  {{Name: "msgget"}},
	69:  {{Name: "msgsnd"}},
	70:  {{Name: "msgrcv"}},
	71:  {{Name: "msgctl"}},
	72:  {{Name: "fcntl"}},
	73:  {{Name: "flock"}},
	74:  {{Name: "fsync"}},
	75:  {{Name: "fdatasync"}},
	76:  {{Name: "truncate"}},
	77:  {{Name: "ftruncate"}},
	78:  {{Name: "getdents"}},
	79:  {{Name: "getcwd"}},
	80:  {{Name: "chdir"}},
	81:  {{Name: "fchdir"}},
	82:  {{Name: "rename"}},
	83:  {{Name: "mkdir"}},
	84:  {{Name: "rmdir"}},
	85:  {{Name: "creat"}},
	86:  {{Name: "link"}},
	87:  {{Name: "unlink"}},
	88:  {{Name: "symlink"}},
	89:  {{Name: "readlink"}},
	90:  {{Name: "chmod"}},
	91:  {{Name: "fchmod"}},
	92:  {{Name: "chown"}},
	93:  {{Name: "fchown"}},
	94:  {{Name: "lchown"}},
	95:  {{Name: "umask"}},
	96:  {{Name: "gettimeofday"}},
	97:  {{Name: "getrlimit"}},
	98:  {{Name: "getrusage"}},
	99:  {{Name: "sysinfo"}},
	100: {{Name: "times"}},
	101: {{Name: "ptrace"}},
	102: {{Name: "getuid"}},
	103: {{Name: "syslog"}},
	104: {{Name: "getgid"}},
	105: {{Name: "setuid"}},
	106: {{Name: "setgid"}},
	107: {{Name: "geteuid"}},
	108: {{Name: "getegid"}},
	109: {{Name: "setpgid"}},
	110: {{Name: "getppid"}},
	111: {{Name: "getpgrp"}},
	112: {{Name: "setsid"}},
	113: {{Name: "setreuid"}},
	114: {{Name: "setregid"}},
	115: {{Name: "getgroups"}},
	116: {{Name: "setgroups"}},
	117: {{Name: "setresuid"}},
	118: {{Name: "getresuid"}},
	119: {{Name: "setresgid"}},
	120: {{Name: "getresgid"}},
	121: {{Name: "getpgid"}},
	122: {{Name: "setfsuid"}},
	123: {{Name: "setfsgid"}},
	124: {{Name: "getsid"}},
	125: {{Name: "capget"}},
	126: {{Name: "capset"}},
	127: {{Name: "rt_sigpending"}},
	128: {{Name: "rt_sigtimedwait"}},
	129: {{Name: "rt_sigqueueinfo"}},
	130: {{Name: "rt_sigsuspend"}},
	131: {{Name: "sigaltstack"}},
	132: {{Name: "utime"}},
	133: {{Name: "mknod"}},
	134: {{Name: SyscallNotImplemented + "uselib"}},
	135: {{Name: "personality"}},
	136: {{Name: "ustat"}},
	137: {{Name: "statfs"}},
	138: {{Name: "fstatfs"}},
	139: {{Name: "sysfs"}},
	140: {{Name: "getpriority"}},
	141: {{Name: "setpriority"}},
	142: {{Name: "sched_setparam"}},
	143: {{Name: "sched_getparam"}},
	144: {{Name: "sched_setscheduler"}},
	145: {{Name: "sched_getscheduler"}},
	146: {{Name: "sched_get_priority_max"}},
	147: {{Name: "sched_get_priority_min"}},
	148: {{Name: "sched_rr_get_interval"}},
	149: {{Name: "mlock"}},
	150: {{Name: "munlock"}},
	151: {{Name: "mlockall"}},
	152: {{Name: "munlockall"}},
	153: {{Name: "vhangup"}},
	154: {{Name: "modify_ldt"}},
	155: {{Name: "pivot_root"}},
	156: {{Below: "5.9", Name: "sysctl"}, {Above: "5.9", Name: SyscallNotImplemented}},
	157: {{Name: "prctl"}},
	158: {{Name: "arch_prctl"}},
	159: {{Name: "adjtimex"}},
	160: {{Name: "setrlimit"}},
	161: {{Name: "chroot"}},
	162: {{Name: "sync"}},
	163: {{Name: "acct"}},
	164: {{Name: "settimeofday"}},
	165: {{Name: "mount"}},
	166: {{Name: "umount"}},
	167: {{Name: "swapon"}},
	168: {{Name: "swapoff"}},
	169: {{Name: "reboot"}},
	170: {{Name: "sethostname"}},
	171: {{Name: "setdomainname"}},
	172: {{Name: "iopl"}},
	173: {{Name: "ioperm"}},
	174: {{Name: SyscallNotImplemented + "createmodule"}},
	175: {{Name: "init_module"}},
	176: {{Name: "delete_module"}},
	177: {{Name: SyscallNotImplemented + "getkernelsyms"}},
	178: {{Name: SyscallNotImplemented + "querymodule"}},
	179: {{Name: "quotactl"}},
	180: {{Name: SyscallNotImplemented + "nfsservctl"}},
	181: {{Name: SyscallNotImplemented + "getpmsg"}},
	182: {{Name: SyscallNotImplemented + "putpmsg"}},
	183: {{Name: SyscallNotImplemented + "afs"}},
	184: {{Name: SyscallNotImplemented + "tuxcall"}},
	185: {{Name: SyscallNotImplemented + "security"}},
	186: {{Name: "gettid"}},
	187: {{Name: "readahead"}},
	188: {{Name: "setxattr"}},
	189: {{Name: "lsetxattr"}},
	190: {{Name: "fsetxattr"}},
	191: {{Name: "getxattr"}},
	192: {{Name: "lgetxattr"}},
	193: {{Name: "fgetxattr"}},
	194: {{Name: "listxattr"}},
	195: {{Name: "llistxattr"}},
	196: {{Name: "flistxattr"}},
	197: {{Name: "removexattr"}},
	198: {{Name: "lremovexattr"}},
	199: {{Name: "fremovexattr"}},
	200: {{Name: "tkill"}},
	201: {{Name: "time"}},
	202: {{Name: "futex"}},
	203: {{Name: "sched_setaffinity"}},
	204: {{Name: "sched_getaffinity"}},
	205: {{Name: SyscallNotImplemented + "set_thread_area"}},
	206: {{Name: "io_setup"}},
	207: {{Name: "io_destroy"}},
	208: {{Name: "io_getevents"}},
	209: {{Name: "io_submit"}},
	210: {{Name: "io_cancel"}},
	211: {{Name: SyscallNotImplemented + "get_thread_area"}},
	212: {{Name: "lookup_dcookie"}},
	213: {{Name: "epoll_create"}},
	214: {{Name: SyscallNotImplemented + "epoll_ctl_old"}},
	215: {{Name: SyscallNotImplemented + "epoll_wait_old"}},
	216: {{Name: "remap_file_pages"}},
	217: {{Name: "getdents64"}},
	218: {{Name: "set_tid_address"}},
	219: {{Name: "restart_syscall"}},
	220: {{Name: "semtimedop"}},
	221: {{Name: "fadvise64"}},
	222: {{Name: "timer_create"}},
	223: {{Name: "timer_settime"}},
	224: {{Name: "timer_gettime"}},
	225: {{Name: "timer_getoverrun"}},
	226: {{Name: "timer_delete"}},
	227: {{Name: "clock_settime"}},
	228: {{Name: "clock_gettime"}},
	229: {{Name: "clock_getres"}},
	230: {{Name: "clock_nanosleep"}},
	231: {{Name: "exit_group"}},
	232: {{Name: "epoll_wait"}},
	233: {{Name: "epoll_ctl"}},
	234: {{Name: "tgkill"}},
	235: {{Name: "utimes"}},
	236: {{Name: SyscallNotImplemented + "vserver"}},
	237: {{Name: "mbind"}},
	238: {{Name: "set_mempolicy"}},
	239: {{Name: "get_mempolicy"}},
	240: {{Name: "mq_open"}},
	241: {{Name: "mq_unlink"}},
	242: {{Name: "mq_timedsend"}},
	243: {{Name: "mq_timedreceive"}},
	244: {{Name: "mq_notify"}},
	245: {{Name: "mq_getsetattr"}},
	246: {{Name: "kexec_load"}},
	247: {{Name: "waitid"}},
	248: {{Name: "add_key"}},
	249: {{Name: "request_key"}},
	250: {{Name: "keyctl"}},
	251: {{Name: "ioprio_set"}},
	252: {{Name: "ioprio_get"}},
	253: {{Name: "inotify_init"}},
	254: {{Name: "inotify_add_watch"}},
	255: {{Name: "inotify_rm_watch"}},
	256: {{Name: "migrate_pages"}},
	257: {{Name: "openat"}},
	258: {{Name: "mkdirat"}},
	259: {{Name: "mknodat"}},
	260: {{Name: "fchownat"}},
	261: {{Name: "futimesat"}},
	262: {{Name: "newfstatat"}},
	263: {{Name: "unlinkat"}},
	264: {{Name: "renameat"}},
	265: {{Name: "linkat"}},
	266: {{Name: "symlinkat"}},
	267: {{Name: "readlinkat"}},
	268: {{Name: "fchmodat"}},
	269: {{Name: "faccessat"}},
	270: {{Name: "pselect6"}},
	271: {{Name: "ppoll"}},
	272: {{Name: "unshare"}},
	273: {{Name: "set_robust_list"}},
	274: {{Name: "get_robust_list"}},
	275: {{Name: "splice"}},
	276: {{Name: "tee"}},
	277: {{Name: "sync_file_range"}},
	278: {{Name: "vmsplice"}},
	279: {{Name: "move_pages"}},
	280: {{Name: "utimensat"}},
	281: {{Name: "epoll_pwait"}},
	282: {{Name: "signalfd"}},
	283: {{Name: "timerfd_create"}},
	284: {{Name: "eventfd"}},
	285: {{Name: "fallocate"}},
	286: {{Name: "timerfd_settime"}},
	287: {{Name: "timerfd_gettime"}},
	288: {{Name: "accept4"}},
	289: {{Name: "signalfd4"}},
	290: {{Name: "eventfd2"}},
	291: {{Name: "epoll_create1"}},
	292: {{Name: "dup3"}},
	293: {{Name: "pipe2"}},
	294: {{Name: "inotify_init1"}},
	295: {{Name: "preadv"}},
	296: {{Name: "pwritev"}},
	297: {{Name: "rt_tgsigqueueinfo"}},
	298: {{Name: "perf_event_open"}},
	299: {{Name: "recvmmsg"}},
	300: {{Name: "fanotify_init"}},
	301: {{Name: "fanotify_mark"}},
	302: {{Name: "prlimit64"}},
	303: {{Name: "name_to_handle_at"}},
	304: {{Name: "open_by_handle_at"}},
	305: {{Name: "clock_adjtime"}},
	306: {{Name: "syncfs"}},
	307: {{Name: "sendmmsg"}},
	308: {{Name: "setns"}},
	309: {{Name: "getcpu"}},
	310: {{Name: "process_vm_readv"}},
	311: {{Name: "process_vm_writev"}},
	312: {{Name: "kcmp"}},
	313: {{Name: "finit_module"}},
	314: {{Name: "sched_setattr"}},
	315: {{Name: "sched_getattr"}},
	316: {{Name: "renameat2"}},
	317: {{Name: "seccomp"}},
	318: {{Name: "getrandom"}},
	319: {{Name: "memfd_create"}},
	320: {{Name: "kexec_file_load"}},
	321: {{Name: "bpf"}},
	322: {{Name: "execveat"}},
	323: {{Name: "userfaultfd"}},
	324: {{Name: "membarrier"}},
	325: {{Name: "mlock2"}},
	326: {{Name: "copy_file_range"}},
	327: {{Name: "preadv2"}},
	328: {{Name: "pwritev2"}},
	329: {{Name: "pkey_mprotect"}},
	330: {{Name: "pkey_alloc"}},
	331: {{Name: "pkey_free"}},
	332: {{Name: "statx"}},
	333: {{Name: "io_pgetevents"}},
	334: {{Name: "rseq"}},
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
	437: {{Above: "5.6", Name: "openat2"}},
	438: {{Above: "5.6", Name: "pidfd_getfd"}},
	439: {{Above: "5.8", Name: "faccessat2"}},
	440: {{Above: "5.10", Name: "process_madvise"}},
	441: {{Above: "5.12", Name: "epoll_pwait2"}},
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
