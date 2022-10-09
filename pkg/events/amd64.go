//go:build amd64
// +build amd64

package events

// x86 64bit syscall numbers
// Also used as event IDs
// https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl
const (
	Read                ID = 0
	Write               ID = 1
	Open                ID = 2
	Close               ID = 3
	Stat                ID = 4
	Fstat               ID = 5
	Lstat               ID = 6
	Poll                ID = 7
	Lseek               ID = 8
	Mmap                ID = 9
	Mprotect            ID = 10
	Munmap              ID = 11
	Brk                 ID = 12
	RtSigaction         ID = 13
	RtSigprocmask       ID = 14
	RtSigreturn         ID = 15
	Ioctl               ID = 16
	Pread64             ID = 17
	Pwrite64            ID = 18
	Readv               ID = 19
	Writev              ID = 20
	Access              ID = 21
	Pipe                ID = 22
	Select              ID = 23
	SchedYield          ID = 24
	Mremap              ID = 25
	Msync               ID = 26
	Mincore             ID = 27
	Madvise             ID = 28
	Shmget              ID = 29
	Shmat               ID = 30
	Shmctl              ID = 31
	Dup                 ID = 32
	Dup2                ID = 33
	Pause               ID = 34
	Nanosleep           ID = 35
	Getitimer           ID = 36
	Alarm               ID = 37
	Setitimer           ID = 38
	Getpid              ID = 39
	Sendfile            ID = 40
	Socket              ID = 41
	Connect             ID = 42
	Accept              ID = 43
	Sendto              ID = 44
	Recvfrom            ID = 45
	Sendmsg             ID = 46
	Recvmsg             ID = 47
	Shutdown            ID = 48
	Bind                ID = 49
	Listen              ID = 50
	Getsockname         ID = 51
	Getpeername         ID = 52
	Socketpair          ID = 53
	Setsockopt          ID = 54
	Getsockopt          ID = 55
	Clone               ID = 56
	Fork                ID = 57
	Vfork               ID = 58
	Execve              ID = 59
	Exit                ID = 60
	Wait4               ID = 61
	Kill                ID = 62
	Uname               ID = 63
	Semget              ID = 64
	Semop               ID = 65
	Semctl              ID = 66
	Shmdt               ID = 67
	Msgget              ID = 68
	Msgsnd              ID = 69
	Msgrcv              ID = 70
	Msgctl              ID = 71
	Fcntl               ID = 72
	Flock               ID = 73
	Fsync               ID = 74
	Fdatasync           ID = 75
	Truncate            ID = 76
	Ftruncate           ID = 77
	Getdents            ID = 78
	Getcwd              ID = 79
	Chdir               ID = 80
	Fchdir              ID = 81
	Rename              ID = 82
	Mkdir               ID = 83
	Rmdir               ID = 84
	Creat               ID = 85
	Link                ID = 86
	Unlink              ID = 87
	Symlink             ID = 88
	Readlink            ID = 89
	Chmod               ID = 90
	Fchmod              ID = 91
	Chown               ID = 92
	Fchown              ID = 93
	Lchown              ID = 94
	Umask               ID = 95
	Gettimeofday        ID = 96
	Getrlimit           ID = 97
	Getrusage           ID = 98
	Sysinfo             ID = 99
	Times               ID = 100
	Ptrace              ID = 101
	Getuid              ID = 102
	Syslog              ID = 103
	Getgid              ID = 104
	Setuid              ID = 105
	Setgid              ID = 106
	Geteuid             ID = 107
	Getegid             ID = 108
	Setpgid             ID = 109
	Getppid             ID = 110
	Getpgrp             ID = 111
	Setsid              ID = 112
	Setreuid            ID = 113
	Setregid            ID = 114
	Getgroups           ID = 115
	Setgroups           ID = 116
	Setresuid           ID = 117
	Getresuid           ID = 118
	Setresgid           ID = 119
	Getresgid           ID = 120
	Getpgid             ID = 121
	Setfsuid            ID = 122
	Setfsgid            ID = 123
	Getsid              ID = 124
	Capget              ID = 125
	Capset              ID = 126
	RtSigpending        ID = 127
	RtSigtimedwait      ID = 128
	RtSigqueueinfo      ID = 129
	RtSigsuspend        ID = 130
	Sigaltstack         ID = 131
	Utime               ID = 132
	Mknod               ID = 133
	Uselib              ID = 134
	Personality         ID = 135
	Ustat               ID = 136
	Statfs              ID = 137
	Fstatfs             ID = 138
	Sysfs               ID = 139
	Getpriority         ID = 140
	Setpriority         ID = 141
	SchedSetparam       ID = 142
	SchedGetparam       ID = 143
	SchedSetscheduler   ID = 144
	SchedGetscheduler   ID = 145
	SchedGetPriorityMax ID = 146
	SchedGetPriorityMin ID = 147
	SchedRrGetInterval  ID = 148
	Mlock               ID = 149
	Munlock             ID = 150
	Mlockall            ID = 151
	Munlockall          ID = 152
	Vhangup             ID = 153
	ModifyLdt           ID = 154
	PivotRoot           ID = 155
	Sysctl              ID = 156
	Prctl               ID = 157
	ArchPrctl           ID = 158
	Adjtimex            ID = 159
	Setrlimit           ID = 160
	Chroot              ID = 161
	Sync                ID = 162
	Acct                ID = 163
	Settimeofday        ID = 164
	Mount               ID = 165
	Umount2             ID = 166
	Swapon              ID = 167
	Swapoff             ID = 168
	Reboot              ID = 169
	Sethostname         ID = 170
	Setdomainname       ID = 171
	Iopl                ID = 172
	Ioperm              ID = 173
	CreateModule        ID = 174
	InitModule          ID = 175
	DeleteModule        ID = 176
	GetKernelSyms       ID = 177
	QueryModule         ID = 178
	Quotactl            ID = 179
	Nfsservctl          ID = 180
	Getpmsg             ID = 181
	Putpmsg             ID = 182
	Afs                 ID = 183
	Tuxcall             ID = 184
	Security            ID = 185
	Gettid              ID = 186
	Readahead           ID = 187
	Setxattr            ID = 188
	Lsetxattr           ID = 189
	Fsetxattr           ID = 190
	Getxattr            ID = 191
	Lgetxattr           ID = 192
	Fgetxattr           ID = 193
	Listxattr           ID = 194
	Llistxattr          ID = 195
	Flistxattr          ID = 196
	Removexattr         ID = 197
	Lremovexattr        ID = 198
	Fremovexattr        ID = 199
	Tkill               ID = 200
	Time                ID = 201
	Futex               ID = 202
	SchedSetaffinity    ID = 203
	SchedGetaffinity    ID = 204
	SetThreadArea       ID = 205
	IoSetup             ID = 206
	IoDestroy           ID = 207
	IoGetevents         ID = 208
	IoSubmit            ID = 209
	IoCancel            ID = 210
	GetThreadArea       ID = 211
	LookupDcookie       ID = 212
	EpollCreate         ID = 213
	EpollCtlOld         ID = 214
	EpollWaitOld        ID = 215
	RemapFilePages      ID = 216
	Getdents64          ID = 217
	SetTidAddress       ID = 218
	RestartSyscall      ID = 219
	Semtimedop          ID = 220
	Fadvise64           ID = 221
	TimerCreate         ID = 222
	TimerSettime        ID = 223
	TimerGettime        ID = 224
	TimerGetoverrun     ID = 225
	TimerDelete         ID = 226
	ClockSettime        ID = 227
	ClockGettime        ID = 228
	ClockGetres         ID = 229
	ClockNanosleep      ID = 230
	ExitGroup           ID = 231
	EpollWait           ID = 232
	EpollCtl            ID = 233
	Tgkill              ID = 234
	Utimes              ID = 235
	Vserver             ID = 236
	Mbind               ID = 237
	SetMempolicy        ID = 238
	GetMempolicy        ID = 239
	MqOpen              ID = 240
	MqUnlink            ID = 241
	MqTimedsend         ID = 242
	MqTimedreceive      ID = 243
	MqNotify            ID = 244
	MqGetsetattr        ID = 245
	KexecLoad           ID = 246
	Waitid              ID = 247
	AddKey              ID = 248
	RequestKey          ID = 249
	Keyctl              ID = 250
	IoprioSet           ID = 251
	IoprioGet           ID = 252
	InotifyInit         ID = 253
	InotifyAddWatch     ID = 254
	InotifyRmWatch      ID = 255
	MigratePages        ID = 256
	Openat              ID = 257
	Mkdirat             ID = 258
	Mknodat             ID = 259
	Fchownat            ID = 260
	Futimesat           ID = 261
	Newfstatat          ID = 262
	Unlinkat            ID = 263
	Renameat            ID = 264
	Linkat              ID = 265
	Symlinkat           ID = 266
	Readlinkat          ID = 267
	Fchmodat            ID = 268
	Faccessat           ID = 269
	Pselect6            ID = 270
	Ppoll               ID = 271
	Unshare             ID = 272
	SetRobustList       ID = 273
	GetRobustList       ID = 274
	Splice              ID = 275
	Tee                 ID = 276
	SyncFileRange       ID = 277
	Vmsplice            ID = 278
	MovePages           ID = 279
	Utimensat           ID = 280
	EpollPwait          ID = 281
	Signalfd            ID = 282
	TimerfdCreate       ID = 283
	Eventfd             ID = 284
	Fallocate           ID = 285
	TimerfdSettime      ID = 286
	TimerfdGettime      ID = 287
	Accept4             ID = 288
	Signalfd4           ID = 289
	Eventfd2            ID = 290
	EpollCreate1        ID = 291
	Dup3                ID = 292
	Pipe2               ID = 293
	InotifyInit1        ID = 294
	Preadv              ID = 295
	Pwritev             ID = 296
	RtTgsigqueueinfo    ID = 297
	PerfEventOpen       ID = 298
	Recvmmsg            ID = 299
	FanotifyInit        ID = 300
	FanotifyMark        ID = 301
	Prlimit64           ID = 302
	NameToHandleAt      ID = 303
	OpenByHandleAt      ID = 304
	ClockAdjtime        ID = 305
	Syncfs              ID = 306
	Sendmmsg            ID = 307
	Setns               ID = 308
	Getcpu              ID = 309
	ProcessVmReadv      ID = 310
	ProcessVmWritev     ID = 311
	Kcmp                ID = 312
	FinitModule         ID = 313
	SchedSetattr        ID = 314
	SchedGetattr        ID = 315
	Renameat2           ID = 316
	Seccomp             ID = 317
	Getrandom           ID = 318
	MemfdCreate         ID = 319
	KexecFileLoad       ID = 320
	Bpf                 ID = 321
	Execveat            ID = 322
	Userfaultfd         ID = 323
	Membarrier          ID = 324
	Mlock2              ID = 325
	CopyFileRange       ID = 326
	Preadv2             ID = 327
	Pwritev2            ID = 328
	PkeyMprotect        ID = 329
	PkeyAlloc           ID = 330
	PkeyFree            ID = 331
	Statx               ID = 332
	IoPgetevents        ID = 333
	Rseq                ID = 334
	// 335 through 423 are unassigned to sync up with generic numbers
	PidfdSendSignal ID = iota + 89 // iota = 335 here 335 + 89 = 424
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
	MountSetatt
	QuotactlFd
	LandlockCreateRuleset
	LandlockAddRule
	LandloclRestrictSet
	MemfdSecret
	ProcessMrelease
	// Set of events IDs for 32bit syscalls which have no parallel 64bit syscall
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
	sys32vm86old                      ID = 113
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
	sys32getpmsg                      ID = 188
	sys32putpmsg                      ID = 189
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
	sys32set_thread_area              ID = 243
	sys32get_thread_area              ID = 244
	sys32io_setup                     ID = 245
	sys32io_destroy                   ID = 246
	sys32io_getevents                 ID = 247
	sys32io_submit                    ID = 248
	sys32io_cancel                    ID = 249
	sys32fadvise64                    ID = 250
	sys32exit_group                   ID = 252
	sys32lookup_dcookie               ID = 253
	sys32epoll_create                 ID = 254
	sys32epoll_ctl                    ID = 255
	sys32epoll_wait                   ID = 256
	sys32remap_file_pages             ID = 257
	sys32set_tid_address              ID = 258
	sys32timer_create                 ID = 259
	sys32timer_settime                ID = 260
	sys32timer_gettime                ID = 261
	sys32timer_getoverrun             ID = 262
	sys32timer_delete                 ID = 263
	sys32clock_settime                ID = 264
	sys32clock_gettime                ID = 265
	sys32clock_getres                 ID = 266
	sys32clock_nanosleep              ID = 267
	sys32statfs64                     ID = 268
	sys32fstatfs64                    ID = 269
	sys32tgkill                       ID = 270
	sys32utimes                       ID = 271
	sys32fadvise64_64                 ID = 272
	sys32vserver                      ID = 273
	sys32mbind                        ID = 274
	sys32get_mempolicy                ID = 275
	sys32set_mempolicy                ID = 276
	sys32mq_open                      ID = 277
	sys32mq_unlink                    ID = 278
	sys32mq_timedsend                 ID = 279
	sys32mq_timedreceive              ID = 280
	sys32mq_notify                    ID = 281
	sys32mq_getsetattr                ID = 282
	sys32kexec_load                   ID = 283
	sys32waitid                       ID = 284
	sys32add_key                      ID = 286
	sys32request_key                  ID = 287
	sys32keyctl                       ID = 288
	sys32ioprio_set                   ID = 289
	sys32ioprio_get                   ID = 290
	sys32inotify_init                 ID = 291
	sys32inotify_add_watch            ID = 292
	sys32inotify_rm_watch             ID = 293
	sys32migrate_pages                ID = 294
	sys32openat                       ID = 295
	sys32mkdirat                      ID = 296
	sys32mknodat                      ID = 297
	sys32fchownat                     ID = 298
	sys32futimesat                    ID = 299
	sys32fstatat64                    ID = 300
	sys32unlinkat                     ID = 301
	sys32renameat                     ID = 302
	sys32linkat                       ID = 303
	sys32symlinkat                    ID = 304
	sys32readlinkat                   ID = 305
	sys32fchmodat                     ID = 306
	sys32faccessat                    ID = 307
	sys32pselect6                     ID = 308
	sys32ppoll                        ID = 309
	sys32unshare                      ID = 310
	sys32set_robust_list              ID = 311
	sys32get_robust_list              ID = 312
	sys32splice                       ID = 313
	sys32sync_file_range              ID = 314
	sys32tee                          ID = 315
	sys32vmsplice                     ID = 316
	sys32move_pages                   ID = 317
	sys32getcpu                       ID = 318
	sys32epoll_pwait                  ID = 319
	sys32utimensat                    ID = 320
	sys32signalfd                     ID = 321
	sys32timerfd_create               ID = 322
	sys32eventfd                      ID = 323
	sys32fallocate                    ID = 324
	sys32timerfd_settime              ID = 325
	sys32timerfd_gettime              ID = 326
	sys32signalfd4                    ID = 327
	sys32eventfd2                     ID = 328
	sys32epoll_create1                ID = 329
	sys32dup3                         ID = 330
	sys32pipe2                        ID = 331
	sys32inotify_init1                ID = 332
	sys32preadv                       ID = 333
	sys32pwritev                      ID = 334
	sys32rt_tgsigqueueinfo            ID = 335
	sys32perf_event_open              ID = 336
	sys32recvmmsg                     ID = 337
	sys32fanotify_init                ID = 338
	sys32fanotify_mark                ID = 339
	sys32prlimit64                    ID = 340
	sys32name_to_handle_at            ID = 341
	sys32open_by_handle_at            ID = 342
	sys32clock_adjtime                ID = 343
	sys32syncfs                       ID = 344
	sys32sendmmsg                     ID = 345
	sys32setns                        ID = 346
	sys32process_vm_readv             ID = 347
	sys32process_vm_writev            ID = 348
	sys32kcmp                         ID = 349
	sys32finit_module                 ID = 350
	sys32sched_setattr                ID = 351
	sys32sched_getattr                ID = 352
	sys32renameat2                    ID = 353
	sys32seccomp                      ID = 354
	sys32getrandom                    ID = 355
	sys32memfd_create                 ID = 356
	sys32bpf                          ID = 357
	sys32execveat                     ID = 358
	sys32socket                       ID = 359
	sys32socketpair                   ID = 360
	sys32bind                         ID = 361
	sys32connect                      ID = 362
	sys32listen                       ID = 363
	sys32accept4                      ID = 364
	sys32getsockopt                   ID = 365
	sys32setsockopt                   ID = 366
	sys32getsockname                  ID = 367
	sys32getpeername                  ID = 368
	sys32sendto                       ID = 369
	sys32sendmsg                      ID = 370
	sys32recvfrom                     ID = 371
	sys32recvmsg                      ID = 372
	sys32shutdown                     ID = 373
	sys32userfaultfd                  ID = 374
	sys32membarrier                   ID = 375
	sys32mlock2                       ID = 376
	sys32copy_file_range              ID = 377
	sys32preadv2                      ID = 378
	sys32pwritev2                     ID = 379
	sys32pkey_mprotect                ID = 380
	sys32pkey_alloc                   ID = 381
	sys32pkey_free                    ID = 382
	sys32statx                        ID = 383
	sys32arch_prctl                   ID = 384
	sys32io_pgetevents                ID = 385
	sys32rseq                         ID = 386
	sys32semget                       ID = 393
	sys32semctl                       ID = 394
	sys32shmget                       ID = 395
	sys32shmctl                       ID = 396
	sys32shmat                        ID = 397
	sys32shmdt                        ID = 398
	sys32msgget                       ID = 399
	sys32msgsnd                       ID = 400
	sys32msgrcv                       ID = 401
	sys32msgctl                       ID = 402
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

func SyscallsToCheck() []ID {
	return []ID{
		Read,
		Write,
		Open,
		Close,
		Ioctl,
		Socket,
		Sendto,
		Recvfrom,
		Sendmsg,
		Recvmsg,
		Execve,
		Kill,
		Getdents,
		Ptrace,
		Getdents64,
		Openat,
		Bpf,
		Execveat,
	}
}
