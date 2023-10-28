//go:build amd64
// +build amd64

package events

// x86 64bit syscall numbers (used as event IDs for the Syscall Events)
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
	Sys32vm86old                      ID = 113
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
	Sys32getpmsg                      ID = 188
	Sys32putpmsg                      ID = 189
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
	Sys32set_thread_area              ID = 243
	Sys32get_thread_area              ID = 244
	Sys32io_setup                     ID = 245
	Sys32io_destroy                   ID = 246
	Sys32io_getevents                 ID = 247
	Sys32io_submit                    ID = 248
	Sys32io_cancel                    ID = 249
	Sys32fadvise64                    ID = 250
	Sys32exit_group                   ID = 252
	Sys32lookup_dcookie               ID = 253
	Sys32epoll_create                 ID = 254
	Sys32epoll_ctl                    ID = 255
	Sys32epoll_wait                   ID = 256
	Sys32remap_file_pages             ID = 257
	Sys32set_tid_address              ID = 258
	Sys32timer_create                 ID = 259
	Sys32timer_settime                ID = 260
	Sys32timer_gettime                ID = 261
	Sys32timer_getoverrun             ID = 262
	Sys32timer_delete                 ID = 263
	Sys32clock_settime                ID = 264
	Sys32clock_gettime                ID = 265
	Sys32clock_getres                 ID = 266
	Sys32clock_nanosleep              ID = 267
	Sys32statfs64                     ID = 268
	Sys32fstatfs64                    ID = 269
	Sys32tgkill                       ID = 270
	Sys32utimes                       ID = 271
	Sys32fadvise64_64                 ID = 272
	Sys32vserver                      ID = 273
	Sys32mbind                        ID = 274
	Sys32get_mempolicy                ID = 275
	Sys32set_mempolicy                ID = 276
	Sys32mq_open                      ID = 277
	Sys32mq_unlink                    ID = 278
	Sys32mq_timedsend                 ID = 279
	Sys32mq_timedreceive              ID = 280
	Sys32mq_notify                    ID = 281
	Sys32mq_getsetattr                ID = 282
	Sys32kexec_load                   ID = 283
	Sys32waitid                       ID = 284
	Sys32add_key                      ID = 286
	Sys32request_key                  ID = 287
	Sys32keyctl                       ID = 288
	Sys32ioprio_set                   ID = 289
	Sys32ioprio_get                   ID = 290
	Sys32inotify_init                 ID = 291
	Sys32inotify_add_watch            ID = 292
	Sys32inotify_rm_watch             ID = 293
	Sys32migrate_pages                ID = 294
	Sys32openat                       ID = 295
	Sys32mkdirat                      ID = 296
	Sys32mknodat                      ID = 297
	Sys32fchownat                     ID = 298
	Sys32futimesat                    ID = 299
	Sys32fstatat64                    ID = 300
	Sys32unlinkat                     ID = 301
	Sys32renameat                     ID = 302
	Sys32linkat                       ID = 303
	Sys32symlinkat                    ID = 304
	Sys32readlinkat                   ID = 305
	Sys32fchmodat                     ID = 306
	Sys32faccessat                    ID = 307
	Sys32pselect6                     ID = 308
	Sys32ppoll                        ID = 309
	Sys32unshare                      ID = 310
	Sys32set_robust_list              ID = 311
	Sys32get_robust_list              ID = 312
	Sys32splice                       ID = 313
	Sys32sync_file_range              ID = 314
	Sys32tee                          ID = 315
	Sys32vmsplice                     ID = 316
	Sys32move_pages                   ID = 317
	Sys32getcpu                       ID = 318
	Sys32epoll_pwait                  ID = 319
	Sys32utimensat                    ID = 320
	Sys32signalfd                     ID = 321
	Sys32timerfd_create               ID = 322
	Sys32eventfd                      ID = 323
	Sys32fallocate                    ID = 324
	Sys32timerfd_settime              ID = 325
	Sys32timerfd_gettime              ID = 326
	Sys32signalfd4                    ID = 327
	Sys32eventfd2                     ID = 328
	Sys32epoll_create1                ID = 329
	Sys32dup3                         ID = 330
	Sys32pipe2                        ID = 331
	Sys32inotify_init1                ID = 332
	Sys32preadv                       ID = 333
	Sys32pwritev                      ID = 334
	Sys32rt_tgsigqueueinfo            ID = 335
	Sys32perf_event_open              ID = 336
	Sys32recvmmsg                     ID = 337
	Sys32fanotify_init                ID = 338
	Sys32fanotify_mark                ID = 339
	Sys32prlimit64                    ID = 340
	Sys32name_to_handle_at            ID = 341
	Sys32open_by_handle_at            ID = 342
	Sys32clock_adjtime                ID = 343
	Sys32syncfs                       ID = 344
	Sys32sendmmsg                     ID = 345
	Sys32setns                        ID = 346
	Sys32process_vm_readv             ID = 347
	Sys32process_vm_writev            ID = 348
	Sys32kcmp                         ID = 349
	Sys32finit_module                 ID = 350
	Sys32sched_setattr                ID = 351
	Sys32sched_getattr                ID = 352
	Sys32renameat2                    ID = 353
	Sys32seccomp                      ID = 354
	Sys32getrandom                    ID = 355
	Sys32memfd_create                 ID = 356
	Sys32bpf                          ID = 357
	Sys32execveat                     ID = 358
	Sys32socket                       ID = 359
	Sys32socketpair                   ID = 360
	Sys32bind                         ID = 361
	Sys32connect                      ID = 362
	Sys32listen                       ID = 363
	Sys32accept4                      ID = 364
	Sys32getsockopt                   ID = 365
	Sys32setsockopt                   ID = 366
	Sys32getsockname                  ID = 367
	Sys32getpeername                  ID = 368
	Sys32sendto                       ID = 369
	Sys32sendmsg                      ID = 370
	Sys32recvfrom                     ID = 371
	Sys32recvmsg                      ID = 372
	Sys32shutdown                     ID = 373
	Sys32userfaultfd                  ID = 374
	Sys32membarrier                   ID = 375
	Sys32mlock2                       ID = 376
	Sys32copy_file_range              ID = 377
	Sys32preadv2                      ID = 378
	Sys32pwritev2                     ID = 379
	Sys32pkey_mprotect                ID = 380
	Sys32pkey_alloc                   ID = 381
	Sys32pkey_free                    ID = 382
	Sys32statx                        ID = 383
	Sys32arch_prctl                   ID = 384
	Sys32io_pgetevents                ID = 385
	Sys32rseq                         ID = 386
	Sys32semget                       ID = 393
	Sys32semctl                       ID = 394
	Sys32shmget                       ID = 395
	Sys32shmctl                       ID = 396
	Sys32shmat                        ID = 397
	Sys32shmdt                        ID = 398
	Sys32msgget                       ID = 399
	Sys32msgsnd                       ID = 400
	Sys32msgrcv                       ID = 401
	Sys32msgctl                       ID = 402
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
var SyscallSymbolNames = map[ID][]KernelRestrictions{
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
