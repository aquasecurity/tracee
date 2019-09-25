#!/usr/bin/python

# Authors:
#       Yaniv Agman <yaniv@aquasec.com>


# todo: add syscalls: "getdirents", "uname"
# todo: add full sockaddr struct to: "connect", "accept", "bind", "getsockname"
# todo: move python helpers (e.g. flags) to different file
# todo: write code in c/c++ with libbpf for performance reasons (avoid missed samples when we have many events)

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
import bcc.utils as utils
import argparse
import re
import time
import os
import sys
import json
import logging
import ctypes
import array
from collections import defaultdict

log = logging.getLogger()
log.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
#formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
#handler.setFormatter(formatter)
log.addHandler(handler)

BPF_PROGRAM = "container_event_monitor_ebpf.c"
MAX_ARGS = 20

# capabilities to names, generated from (and will need updating):
# awk '/^#define.CAP_.*[0-9]$/ { print "    " $3 ": \"" $2 "\"," }' \
#     include/uapi/linux/capability.h
capabilities = {
    0: "CAP_CHOWN",
    1: "CAP_DAC_OVERRIDE",
    2: "CAP_DAC_READ_SEARCH",
    3: "CAP_FOWNER",
    4: "CAP_FSETID",
    5: "CAP_KILL",
    6: "CAP_SETGID",
    7: "CAP_SETUID",
    8: "CAP_SETPCAP",
    9: "CAP_LINUX_IMMUTABLE",
    10: "CAP_NET_BIND_SERVICE",
    11: "CAP_NET_BROADCAST",
    12: "CAP_NET_ADMIN",
    13: "CAP_NET_RAW",
    14: "CAP_IPC_LOCK",
    15: "CAP_IPC_OWNER",
    16: "CAP_SYS_MODULE",
    17: "CAP_SYS_RAWIO",
    18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE",
    20: "CAP_SYS_PACCT",
    21: "CAP_SYS_ADMIN",
    22: "CAP_SYS_BOOT",
    23: "CAP_SYS_NICE",
    24: "CAP_SYS_RESOURCE",
    25: "CAP_SYS_TIME",
    26: "CAP_SYS_TTY_CONFIG",
    27: "CAP_MKNOD",
    28: "CAP_LEASE",
    29: "CAP_AUDIT_WRITE",
    30: "CAP_AUDIT_CONTROL",
    31: "CAP_SETFCAP",
    32: "CAP_MAC_OVERRIDE",
    33: "CAP_MAC_ADMIN",
    34: "CAP_SYSLOG",
    35: "CAP_WAKE_ALARM",
    36: "CAP_BLOCK_SUSPEND",
    37: "CAP_AUDIT_READ",
}

sock_domain = {
    0: "AF_UNSPEC",
    1: "AF_UNIX",
    2: "AF_INET",
    3: "AF_AX25",
    4: "AF_IPX",
    5: "AF_APPLETALK",
    6: "AF_NETROM",
    7: "AF_BRIDGE",
    8: "AF_ATMPVC",
    9: "AF_X25",
    10: "AF_INET6",
    11: "AF_ROSE",
    12: "AF_DECnet",
    13: "AF_NETBEUI",
    14: "AF_SECURITY",
    15: "AF_KEY",
    16: "AF_NETLINK",
    17: "AF_PACKET",
    18: "AF_ASH",
    19: "AF_ECONET",
    20: "AF_ATMSVC",
    21: "AF_RDS",
    22: "AF_SNA",
    23: "AF_IRDA",
    24: "AF_PPPOX",
    25: "AF_WANPIPE",
    26: "AF_LLC",
    27: "AF_IB",
    28: "AF_MPLS",
    29: "AF_CAN",
    30: "AF_TIPC",
    31: "AF_BLUETOOTH",
    32: "AF_IUCV",
    33: "AF_RXRPC",
    34: "AF_ISDN",
    35: "AF_PHONET",
    36: "AF_IEEE802154",
    37: "AF_CAIF",
    38: "AF_ALG",
    39: "AF_NFC",
    40: "AF_VSOCK",
    41: "AF_KCM",
    42: "AF_QIPCRTR",
    43: "AF_SMC",
    44: "AF_XDP",
}

sock_type = {
    1: "SOCK_STREAM",
    2: "SOCK_DGRAM",
    3: "SOCK_RAW",
    4: "SOCK_RDM",
    5: "SOCK_SEQPACKET",
    6: "SOCK_DCCP",
    10: "SOCK_PACKET",
}

syscalls = ["execve", "execveat", "mmap", "mprotect", "clone", "fork", "vfork", "newstat",
            "newfstat", "newlstat", "mknod", "mknodat", "dup", "dup2", "dup3",
            "memfd_create", "socket", "close", "ioctl", "access", "faccessat", "kill", "listen",
            "connect", "accept", "accept4", "bind", "getsockname", "prctl", "ptrace",
            "process_vm_writev", "process_vm_readv", "init_module", "finit_module", "delete_module",
            "symlink", "symlinkat", "getdents", "getdents64"]

class EventType(object):
    EVENT_ARG = 0
    EVENT_RET = 1

# This enum fields and order should match event_id enum in ebpf file code
class EventId(object):
    SYS_READ                    = 0
    SYS_WRITE                   = 1
    SYS_OPEN                    = 2
    SYS_CLOSE                   = 3
    SYS_STAT                    = 4
    SYS_FSTAT                   = 5
    SYS_LSTAT                   = 6
    SYS_POLL                    = 7
    SYS_LSEEK                   = 8
    SYS_MMAP                    = 9
    SYS_MPROTECT                = 10
    SYS_MUNMAP                  = 11
    SYS_BRK                     = 12
    SYS_RT_SIGACTION            = 13
    SYS_RT_SIGPROCMASK          = 14
    SYS_RT_SIGRETURN            = 15
    SYS_IOCTL                   = 16
    SYS_PREAD64                 = 17
    SYS_PWRITE64                = 18
    SYS_READV                   = 19
    SYS_WRITEV                  = 20
    SYS_ACCESS                  = 21
    SYS_PIPE                    = 22
    SYS_SELECT                  = 23
    SYS_SCHED_YIELD             = 24
    SYS_MREMAP                  = 25
    SYS_MSYNC                   = 26
    SYS_MINCORE                 = 27
    SYS_MADVISE                 = 28
    SYS_SHMGET                  = 29
    SYS_SHMAT                   = 30
    SYS_SHMCTL                  = 31
    SYS_DUP                     = 32
    SYS_DUP2                    = 33
    SYS_PAUSE                   = 34
    SYS_NANOSLEEP               = 35
    SYS_GETITIMER               = 36
    SYS_ALARM                   = 37
    SYS_SETITIMER               = 38
    SYS_GETPID                  = 39
    SYS_SENDFILE                = 40
    SYS_SOCKET                  = 41
    SYS_CONNECT                 = 42
    SYS_ACCEPT                  = 43
    SYS_SENDTO                  = 44
    SYS_RECVFROM                = 45
    SYS_SENDMSG                 = 46
    SYS_RECVMSG                 = 47
    SYS_SHUTDOWN                = 48
    SYS_BIND                    = 49
    SYS_LISTEN                  = 50
    SYS_GETSOCKNAME             = 51
    SYS_GETPEERNAME             = 52
    SYS_SOCKETPAIR              = 53
    SYS_SETSOCKOPT              = 54
    SYS_GETSOCKOPT              = 55
    SYS_CLONE                   = 56
    SYS_FORK                    = 57
    SYS_VFORK                   = 58
    SYS_EXECVE                  = 59
    SYS_EXIT                    = 60
    SYS_WAIT4                   = 61
    SYS_KILL                    = 62
    SYS_UNAME                   = 63
    SYS_SEMGET                  = 64
    SYS_SEMOP                   = 65
    SYS_SEMCTL                  = 66
    SYS_SHMDT                   = 67
    SYS_MSGGET                  = 68
    SYS_MSGSND                  = 69
    SYS_MSGRCV                  = 70
    SYS_MSGCTL                  = 71
    SYS_FCNTL                   = 72
    SYS_FLOCK                   = 73
    SYS_FSYNC                   = 74
    SYS_FDATASYNC               = 75
    SYS_TRUNCATE                = 76
    SYS_FTRUNCATE               = 77
    SYS_GETDENTS                = 78
    SYS_GETCWD                  = 79
    SYS_CHDIR                   = 80
    SYS_FCHDIR                  = 81
    SYS_RENAME                  = 82
    SYS_MKDIR                   = 83
    SYS_RMDIR                   = 84
    SYS_CREAT                   = 85
    SYS_LINK                    = 86
    SYS_UNLINK                  = 87
    SYS_SYMLINK                 = 88
    SYS_READLINK                = 89
    SYS_CHMOD                   = 90
    SYS_FCHMOD                  = 91
    SYS_CHOWN                   = 92
    SYS_FCHOWN                  = 93
    SYS_LCHOWN                  = 94
    SYS_UMASK                   = 95
    SYS_GETTIMEOFDAY            = 96
    SYS_GETRLIMIT               = 97
    SYS_GETRUSAGE               = 98
    SYS_SYSINFO                 = 99
    SYS_TIMES                   = 100
    SYS_PTRACE                  = 101
    SYS_GETUID                  = 102
    SYS_SYSLOG                  = 103
    SYS_GETGID                  = 104
    SYS_SETUID                  = 105
    SYS_SETGID                  = 106
    SYS_GETEUID                 = 107
    SYS_GETEGID                 = 108
    SYS_SETPGID                 = 109
    SYS_GETPPID                 = 110
    SYS_GETPGRP                 = 111
    SYS_SETSID                  = 112
    SYS_SETREUID                = 113
    SYS_SETREGID                = 114
    SYS_GETGROUPS               = 115
    SYS_SETGROUPS               = 116
    SYS_SETRESUID               = 117
    SYS_GETRESUID               = 118
    SYS_SETRESGID               = 119
    SYS_GETRESGID               = 120
    SYS_GETPGID                 = 121
    SYS_SETFSUID                = 122
    SYS_SETFSGID                = 123
    SYS_GETSID                  = 124
    SYS_CAPGET                  = 125
    SYS_CAPSET                  = 126
    SYS_RT_SIGPENDING           = 127
    SYS_RT_SIGTIMEDWAIT         = 128
    SYS_RT_SIGQUEUEINFO         = 129
    SYS_RT_SIGSUSPEND           = 130
    SYS_SIGALTSTACK             = 131
    SYS_UTIME                   = 132
    SYS_MKNOD                   = 133
    SYS_USELIB                  = 134
    SYS_PERSONALITY             = 135
    SYS_USTAT                   = 136
    SYS_STATFS                  = 137
    SYS_FSTATFS                 = 138
    SYS_SYSFS                   = 139
    SYS_GETPRIORITY             = 140
    SYS_SETPRIORITY             = 141
    SYS_SCHED_SETPARAM          = 142
    SYS_SCHED_GETPARAM          = 143
    SYS_SCHED_SETSCHEDULER      = 144
    SYS_SCHED_GETSCHEDULER      = 145
    SYS_SCHED_GET_PRIORITY_MAX  = 146
    SYS_SCHED_GET_PRIORITY_MIN  = 147
    SYS_SCHED_RR_GET_INTERVAL   = 148
    SYS_MLOCK                   = 149
    SYS_MUNLOCK                 = 150
    SYS_MLOCKALL                = 151
    SYS_MUNLOCKALL              = 152
    SYS_VHANGUP                 = 153
    SYS_MODIFY_LDT              = 154
    SYS_PIVOT_ROOT              = 155
    SYS_SYSCTL                  = 156
    SYS_PRCTL                   = 157
    SYS_ARCH_PRCTL              = 158
    SYS_ADJTIMEX                = 159
    SYS_SETRLIMIT               = 160
    SYS_CHROOT                  = 161
    SYS_SYNC                    = 162
    SYS_ACCT                    = 163
    SYS_SETTIMEOFDAY            = 164
    SYS_MOUNT                   = 165
    SYS_UMOUNT                  = 166
    SYS_SWAPON                  = 167
    SYS_SWAPOFF                 = 168
    SYS_REBOOT                  = 169
    SYS_SETHOSTNAME             = 170
    SYS_SETDOMAINNAME           = 171
    SYS_IOPL                    = 172
    SYS_IOPERM                  = 173
    SYS_CREATE_MODULE           = 174
    SYS_INIT_MODULE             = 175
    SYS_DELETE_MODULE           = 176
    SYS_GET_KERNEL_SYMS         = 177
    SYS_QUERY_MODULE            = 178
    SYS_QUOTACTL                = 179
    SYS_NFSSERVCTL              = 180
    SYS_GETPMSG                 = 181
    SYS_PUTPMSG                 = 182
    SYS_AFS                     = 183
    SYS_TUXCALL                 = 184
    SYS_SECURITY                = 185
    SYS_GETTID                  = 186
    SYS_READAHEAD               = 187
    SYS_SETXATTR                = 188
    SYS_LSETXATTR               = 189
    SYS_FSETXATTR               = 190
    SYS_GETXATTR                = 191
    SYS_LGETXATTR               = 192
    SYS_FGETXATTR               = 193
    SYS_LISTXATTR               = 194
    SYS_LLISTXATTR              = 195
    SYS_FLISTXATTR              = 196
    SYS_REMOVEXATTR             = 197
    SYS_LREMOVEXATTR            = 198
    SYS_FREMOVEXATTR            = 199
    SYS_TKILL                   = 200
    SYS_TIME                    = 201
    SYS_FUTEX                   = 202
    SYS_SCHED_SETAFFINITY       = 203
    SYS_SCHED_GETAFFINITY       = 204
    SYS_SET_THREAD_AREA         = 205
    SYS_IO_SETUP                = 206
    SYS_IO_DESTROY              = 207
    SYS_IO_GETEVENTS            = 208
    SYS_IO_SUBMIT               = 209
    SYS_IO_CANCEL               = 210
    SYS_GET_THREAD_AREA         = 211
    SYS_LOOOKUP_DCOOKIE         = 212
    SYS_EPOLL_CREATE            = 213
    SYS_EPOLL_CTL_OLD           = 214
    SYS_EPOLL_WAIT_OLD          = 215
    SYS_REMAP_FILE_PAGES        = 216
    SYS_GETDENTS64              = 217
    SYS_SET_TID_ADDRESS         = 218
    SYS_RESTART_SYSCALL         = 219
    SYS_SEMTIMEDOP              = 220
    SYS_FADVISE64               = 221
    SYS_TIMER_CREATE            = 222
    SYS_TIMER_SETTIME           = 223
    SYS_TIMER_GETTIME           = 224
    SYS_TIMER_GETOVERRUN        = 225
    SYS_TIMER_DELETE            = 226
    SYS_CLOCK_SETTIME           = 227
    SYS_CLOCK_GETTIME           = 228
    SYS_CLOCK_GETRES            = 229
    SYS_CLOCK_NANOSLEEP         = 230
    SYS_EXIT_GROUP              = 231
    SYS_EPOLL_WAIT              = 232
    SYS_EPOLL_CTL               = 233
    SYS_TGKILL                  = 234
    SYS_UTIMES                  = 235
    SYS_VSERVER                 = 236
    SYS_MBIND                   = 237
    SYS_SET_MEMPOLICY           = 238
    SYS_GET_MEMPOLICY           = 239
    SYS_MQ_OPEN                 = 240
    SYS_MQ_UNLINK               = 241
    SYS_MQ_TIMEDSEND            = 242
    SYS_MQ_TIMEDRECEIVE         = 243
    SYS_MQ_NOTIFY               = 244
    SYS_MQ_GETSETATTR           = 245
    SYS_KEXEC_LOAD              = 246
    SYS_WAITID                  = 247
    SYS_ADD_KEY                 = 248
    SYS_REQUEST_KEY             = 249
    SYS_KEYCTL                  = 250
    SYS_IOPRIO_SET              = 251
    SYS_IOPRIO_GET              = 252
    SYS_INOTIFY_INIT            = 253
    SYS_INOTIFY_ADD_WATCH       = 254
    SYS_INOTIFY_RM_WATCH        = 255
    SYS_MIGRATE_PAGES           = 256
    SYS_OPENAT                  = 257
    SYS_MKDIRAT                 = 258
    SYS_MKNODAT                 = 259
    SYS_FCHOWNAT                = 260
    SYS_FUTIMESAT               = 261
    SYS_NEWFSTATAT              = 262
    SYS_UNLINKAT                = 263
    SYS_RENAMEAT                = 264
    SYS_LINKAT                  = 265
    SYS_SYMLINKAT               = 266
    SYS_READLINKAT              = 267
    SYS_FCHMODAT                = 268
    SYS_FACCESSAT               = 269
    SYS_PSELECT6                = 270
    SYS_PPOLL                   = 271
    SYS_UNSHARE                 = 272
    SYS_SET_ROBUST_LIST         = 273
    SYS_GET_ROBUST_LIST         = 274
    SYS_SPLICE                  = 275
    SYS_TEE                     = 276
    SYS_SYNC_FILE_RANGE         = 277
    SYS_VMSPLICE                = 278
    SYS_MOVE_PAGES              = 279
    SYS_UTIMENSAT               = 280
    SYS_EPOLL_PWAIT             = 281
    SYS_SIGNALFD                = 282
    SYS_TIMERFD_CREATE          = 283
    SYS_EVENTFD                 = 284
    SYS_FALLOCATE               = 285
    SYS_TIMERFD_SETTIME         = 286
    SYS_TIMERFD_GETTIME         = 287
    SYS_ACCEPT4                 = 288
    SYS_SIGNALFD4               = 289
    SYS_EVENTFD2                = 290
    SYS_EPOLL_CREATE1           = 291
    SYS_DUP3                    = 292
    SYS_PIPE2                   = 293
    SYS_IONOTIFY_INIT1          = 294
    SYS_PREADV                  = 295
    SYS_PWRITEV                 = 296
    SYS_RT_TGSIGQUEUEINFO       = 297
    SYS_PERF_EVENT_OPEN         = 298
    SYS_RECVMMSG                = 299
    SYS_FANOTIFY_INIT           = 300
    SYS_FANOTIFY_MARK           = 301
    SYS_PRLIMIT64               = 302
    SYS_NAME_TO_HANDLE_AT       = 303
    SYS_OPEN_BY_HANDLE_AT       = 304
    SYS_CLOCK_ADJTIME           = 305
    SYS_SYNCFS                  = 306
    SYS_SENDMMSG                = 307
    SYS_SETNS                   = 308
    SYS_GETCPU                  = 309
    SYS_PROCESS_VM_READV        = 310
    SYS_PROCESS_VM_WRITEV       = 311
    SYS_KCMP                    = 312
    SYS_FINIT_MODULE            = 313
    SYS_SCHED_SETATTR           = 314
    SYS_SCHED_GETATTR           = 315
    SYS_RENAMEAT2               = 316
    SYS_SECCOMP                 = 317
    SYS_GETRANDOM               = 318
    SYS_MEMFD_CREATE            = 319
    SYS_KEXEC_FILE_LOAD         = 320
    SYS_BPF                     = 321
    SYS_EXECVEAT                = 322
    SYS_USERFAULTFD             = 323
    SYS_MEMBARRIER              = 324
    SYS_MLOCK2                  = 325
    SYS_COPY_FILE_RANGE         = 326
    SYS_PREADV2                 = 327
    SYS_PWRITEV2                = 328
    SYS_PKEY_MPROTECT           = 329
    SYS_PKEY_ALLOC              = 330
    SYS_PKRY_FREE               = 331
    SYS_STATX                   = 332
    SYS_IO_PGETEVENTS           = 333
    SYS_RSEQ                    = 334
    # Non syscall events start here
    DO_EXIT                     = 335
    CAP_CAPABLE                 = 336

class context_t(ctypes.Structure): # match layout of eBPF C's context_t struct
    _fields_ = [("ts", ctypes.c_uint64),
                ("pid", ctypes.c_uint32),
                ("tid", ctypes.c_uint32),
                ("ppid", ctypes.c_uint32),
                ("uid", ctypes.c_uint32),
                ("mnt_id", ctypes.c_uint32),
                ("pid_id", ctypes.c_uint32),
                ("comm", ctypes.c_char*16),
                ("eventid", ctypes.c_uint),
                ("retval", ctypes.c_int64),]

class execve_info_t(ctypes.Structure):
    _fields_ = [("context", context_t),
                ("type", ctypes.c_uint),
                ("argv_loc", ctypes.c_uint*(MAX_ARGS+1)),]

class execveat_info_t(ctypes.Structure):
    _fields_ = [("context", context_t),
                ("type", ctypes.c_uint),
                ("argv_loc", ctypes.c_uint*(MAX_ARGS+1)),
                ("dirfd", ctypes.c_int),
                ("flags", ctypes.c_int),]

class open_info_t(ctypes.Structure):
    _pack_ = 1 # for all events passed with buffer (in eBPF code), we use packed structs
    _fields_ = [("context", context_t),
                ("dirfd", ctypes.c_int),
                ("filename_loc", ctypes.c_uint),
                ("flags", ctypes.c_int),]

class memfd_create_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("name_loc", ctypes.c_uint),
                ("flags", ctypes.c_uint),]

class mknod_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("pathname_loc", ctypes.c_uint),
                ("mode", ctypes.c_uint),
                ("dev", ctypes.c_uint),]

class mknodat_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("dirfd", ctypes.c_int),
                ("pathname_loc", ctypes.c_uint),
                ("mode", ctypes.c_uint),
                ("dev", ctypes.c_uint),]

class dup_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("oldfd", ctypes.c_int),
                ("newfd", ctypes.c_int),
                ("flags", ctypes.c_int),]

class close_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("fd", ctypes.c_uint),]

class ioctl_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("fd", ctypes.c_uint),
                ("request", ctypes.c_ulong),]

class access_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("pathname_loc", ctypes.c_uint),
                ("mode", ctypes.c_int),]

class faccessat_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("dirfd", ctypes.c_int),
                ("pathname_loc", ctypes.c_uint),
                ("mode", ctypes.c_int),
                ("flags", ctypes.c_int),]

class kill_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("pid", ctypes.c_int),
                ("sig", ctypes.c_int),]

class listen_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("sockfd", ctypes.c_int),
                ("backlog", ctypes.c_int),]

class connect_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("sockfd", ctypes.c_int),
                ("sockaddr", ctypes.c_short),]

class accept_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("sockfd", ctypes.c_int),
                ("sockaddr", ctypes.c_short),]

class accept4_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("sockfd", ctypes.c_int),
                ("sockaddr", ctypes.c_short),]

class bind_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("sockfd", ctypes.c_int),
                ("sockaddr", ctypes.c_short),]

class getsockname_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("sockfd", ctypes.c_int),
                ("sockaddr", ctypes.c_short),]

class socket_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("domain", ctypes.c_int),
                ("type", ctypes.c_int),
                ("protocol", ctypes.c_int),]

class mmap_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("addr", ctypes.c_void_p),
                ("length", ctypes.c_ulong),
                ("prot", ctypes.c_int),
                ("flags", ctypes.c_int),
                ("fd", ctypes.c_int),
                ("offset", ctypes.c_ulong),]

class stat_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("path_loc", ctypes.c_uint),]

class fstat_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("fd", ctypes.c_uint),]

class prctl_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("option", ctypes.c_uint),
                ("arg2", ctypes.c_ulong),
                ("arg3", ctypes.c_ulong),
                ("arg4", ctypes.c_ulong),
                ("arg5", ctypes.c_ulong),]

class ptrace_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("request", ctypes.c_uint),
                ("pid", ctypes.c_int),
                ("addr", ctypes.c_void_p),
                ("data", ctypes.c_void_p),]

class process_vm_writev_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("pid", ctypes.c_int),
                ("local_iov", ctypes.c_void_p),
                ("liovcnt", ctypes.c_ulong),
                ("remote_iov", ctypes.c_void_p),
                ("riovcnt", ctypes.c_ulong),
                ("flags", ctypes.c_ulong),]

class process_vm_readv_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("pid", ctypes.c_int),
                ("local_iov", ctypes.c_void_p),
                ("liovcnt", ctypes.c_ulong),
                ("remote_iov", ctypes.c_void_p),
                ("riovcnt", ctypes.c_ulong),
                ("flags", ctypes.c_ulong),]

class init_module_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("module_image", ctypes.c_void_p),
                ("len", ctypes.c_ulong),
                ("param_values_loc", ctypes.c_uint),]

class finit_module_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("fd", ctypes.c_int),
                ("param_values_loc", ctypes.c_uint),
                ("flags", ctypes.c_int),]

class delete_module_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("name_loc", ctypes.c_uint),
                ("flags", ctypes.c_int),]

class symlink_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("target_loc", ctypes.c_uint),
                ("linkpath_loc", ctypes.c_uint),]

class symlinkat_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("target_loc", ctypes.c_uint),
                ("newdirfd", ctypes.c_int),
                ("linkpath_loc", ctypes.c_uint),]

class getdents_info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("context", context_t),
                ("fd", ctypes.c_uint),]

class cap_info_t(ctypes.Structure):
    _fields_ = [("context", context_t),
                ("capability", ctypes.c_int),]

class EventMonitor():

    def __init__(self, args):
        self.events = list()
        self.do_trace = True
        self.bpf = None
        self.argv = defaultdict(list)
        self.verbose = args.verbose
        self.ebpf = args.ebpf
        self.max_buf_size = 8191   # this size should be the same as the ebpf c code. todo: pass config in map


    def init_bpf(self):
        bpf_text = self.load_bpf_program().replace("MAXARG", str(MAX_ARGS))

        if self.ebpf:
            log.debug(bpf_text)
            exit()

        # initialize BPF
        self.bpf = BPF(text=bpf_text)

        # attaching kprobes
        for syscall in syscalls:
            syscall_fnname = self.bpf.get_syscall_fnname(syscall)
            self.bpf.attach_kprobe(event=syscall_fnname, fn_name="trace_sys_" + syscall)
            self.bpf.attach_kretprobe(event=syscall_fnname, fn_name="trace_ret_sys_" + syscall)

        self.bpf.attach_kprobe(event="do_sys_open", fn_name="trace_open")
        self.bpf.attach_kretprobe(event="do_sys_open", fn_name="trace_ret_open")
        self.bpf.attach_kprobe(event="do_exit", fn_name="trace_do_exit")
        #self.bpf.attach_kprobe(event="cap_capable", fn_name="trace_cap_capable")

        if self.verbose:
            log.info("%-14s %-12s %-12s %-6s %-16s %-16s %-6s %-6s %-6s %-16s %s" % ("TIME(s)", "MNT_NS", "PID_NS", "UID", "EVENT", "COMM", "PID", "TID", "PPID", "RET", "ARGS"))

    # define BPF program
    def load_bpf_program(self):
        bpf = None
        with open(BPF_PROGRAM, "r") as f:
            bpf = f.read()
        return bpf

    # This is best-effort PPID matching. Short-lived processes may exit
    # before we get a chance to read the PPID.
    # This is a fallback for when fetching the PPID from task->real_parent->tgid
    # returns 0, which happens in some kernel versions (e.g. Ubuntu 4.13.0-generic).
    def get_ppid(self, pid):
        try:
            with open("/proc/%d/status" % pid) as status:
                for line in status:
                    if line.startswith("PPid:"):
                        return int(line.split()[1])
        except IOError:
            pass
        return 0


    def get_ns_pid(self, pid):
        try:
            with open("/proc/%s/status" % pid) as status:
                for line in status:
                    if line.startswith("NSpid:"):
                        return int(line.split()[2])
        except IOError:
            pass
        return 0


    def prot_to_str(self, prot):
        p_str = ""
        has_prot = False

        if not prot|0x0:
            return "PROT_NONE"

        if prot&0x1:
            p_str += "PROT_READ"
            has_prot = True

        if prot&0x2:
            if has_prot:
                p_str += "|PROT_WRITE"
            else:
                p_str += "PROT_WRITE"
                has_prot = True

        if prot&0x4:
            if has_prot:
                p_str += "|PROT_EXEC"
            else:
                p_str += "PROT_EXEC"
                has_prot = True

        return p_str

    def mknod_mode_to_str(self, flags):
        f_str = ""

        if flags&0o140000:
            f_str += "S_IFSOCK"
        elif flags&0o100000:
            f_str += "S_IFREG"
        elif flags&0o060000:
            f_str += "S_IFBLK"
        elif flags&0o020000:
            f_str += "S_IFCHR"
        elif flags&0o010000:
            f_str += "S_IFIFO"
        else:
            return "invalid"

        if flags&0o0700 == 0o0700:
            f_str += "|S_IRWXU"
        else:
            if flags&0o0400:
                f_str += "|S_IRUSR"

            if flags&0o0200:
                f_str += "|S_IWUSR"

            if flags&0o0100:
                f_str += "|S_IXUSR"


        if flags&0o0070 == 0o0070:
            f_str += "|S_IRWXG"
        else:
            if flags&0o0040:
                f_str += "|S_IRGRP"

            if flags&0o0020:
                f_str += "|S_IWGRP"

            if flags&0o0010:
                f_str += "|S_IXGRP"


        if flags&0o0007 == 0o0007:
            f_str += "|S_IRWXO"
        else:
            if flags&0o0004:
                f_str += "|S_IROTH"

            if flags&0o0002:
                f_str += "|S_IWOTH"

            if flags&0o0001:
                f_str += "|S_IXOTH"

        return f_str

    def execveat_flags_to_str(self, flags):
        f_str = ""

        if flags&0x1000:
            f_str += "AT_EMPTY_PATH"

        if flags&0x100:
            if f_str == "":
                f_str += "AT_SYMLINK_NOFOLLOW"
            else:
                f_str += "|AT_SYMLINK_NOFOLLOW"

        return f_str

    def access_mode_to_str(self, flags):
        f_str = ""

        if not flags|0x0:
            return "F_OK"

        if flags&0x04:
            f_str += "R_OK"

        if flags&0x02:
            if f_str == "":
                f_str += "W_OK"
            else:
                f_str += "|W_OK"

        if flags&0x01:
            if f_str == "":
                f_str += "X_OK"
            else:
                f_str += "|X_OK"

        return f_str

    def open_flags_to_str(self, flags):
        f_str = ""

        if flags&0x1:
            f_str += "O_WRONLY"
        elif flags&0x2:
            f_str += "O_RDWR"
        else:
            f_str += "O_RDONLY"


        if flags&0x100:
            f_str += "|O_CREAT"

        if flags&0x200:
            f_str += "|O_EXCL"

        if flags&0x400:
            f_str += "|O_NOCTTY"

        if flags&0x1000:
            f_str += "|O_TRUNC"

        if flags&0x2000:
            f_str += "|O_APPEND"

        if flags&0x4000:
            f_str += "|O_NONBLOCK"

        if flags&0x4010000:
            f_str += "|O_SYNC"

        if flags&0x20000:
            f_str += "|O_ASYNC"

        if flags&0x100000:
            f_str += "|O_LARGEFILE"

        if flags&0x200000:
            f_str += "|O_DIRECTORY"

        if flags&0x400000:
            f_str += "|O_NOFOLLOW"

        if flags&0x2000000:
            f_str += "|O_CLOEXEC"

        if flags&0x40000:
            f_str += "|O_DIRECT"

        if flags&0x1000000:
            f_str += "|O_NOATIME"

        if flags&0x10000000:
            f_str += "|O_PATH"

        if flags&0x20000000:
            f_str += "|O_TMPFILE"

        return f_str

    def get_string_from_buf(self, cpu, str_loc):
        str_size = str_loc & 0xffff
        str_off = (str_loc & 0xffff0000) >> 16
        str_buf = self.bpf["str_buf"][cpu].buf[str_off:str_off + str_size]
        return str(array.array('B', str_buf).tostring().decode("utf-8"))

    # process event
    def print_event(self, cpu, data, size):
        #event = self.bpf["events"].event(data)
        context = ctypes.cast(data, ctypes.POINTER(context_t)).contents

        #ppid = context.ppid if context.ppid > 0 else get_ppid(context.pid)
        #ppid = b"%d" % ppid if ppid > 0 else b"?"
        pid = context.pid
        tid = context.tid
        ppid = context.ppid
        #pid = get_ns_pid(str(context.pid))
        #ppid = get_ns_pid(str(context.ppid))
        #ppid = 0

        args = list()

        if context.eventid == EventId.SYS_EXECVE:
            eventname = "execve"
            event = ctypes.cast(data, ctypes.POINTER(execve_info_t)).contents
            if event.type == EventType.EVENT_ARG:
                for i in range(MAX_ARGS+1):
                    argv_loc = int(event.argv_loc[i])
                    if argv_loc == 0:
                        break
                    self.argv[pid].append(self.get_string_from_buf(cpu, argv_loc))
                return
            elif event.type == EventType.EVENT_RET:
                args = self.argv[pid]
                try:
                    del(self.argv[pid])
                except Exception:
                    pass
        elif context.eventid == EventId.SYS_EXECVEAT:
            eventname = "execveat"
            event = ctypes.cast(data, ctypes.POINTER(execveat_info_t)).contents
            if event.type == EventType.EVENT_ARG:
                for i in range(MAX_ARGS+1):
                    argv_loc = int(event.argv_loc[i])
                    if argv_loc == 0:
                        break
                    self.argv[pid].append(self.get_string_from_buf(cpu, argv_loc))
                return
            elif event.type == EventType.EVENT_RET:
                args.append(str(event.dirfd))
                args = args + self.argv[pid]
                args.append(self.execveat_flags_to_str(event.flags))
                try:
                    del(self.argv[pid])
                except Exception:
                    pass
        elif context.eventid == EventId.SYS_OPEN:
            eventname = "open"
            event = ctypes.cast(data, ctypes.POINTER(open_info_t)).contents
            args.append(self.get_string_from_buf(cpu, int(event.filename_loc)))
            args.append(self.open_flags_to_str(event.flags))
        elif context.eventid == EventId.SYS_MEMFD_CREATE:
            eventname = "memfd_create"
            event = ctypes.cast(data, ctypes.POINTER(memfd_create_info_t)).contents
            args.append(self.get_string_from_buf(cpu, int(event.name_loc)))
            args.append(str(event.flags))
        elif context.eventid == EventId.CAP_CAPABLE:
            eventname = "cap_capable"
            event = ctypes.cast(data, ctypes.POINTER(cap_info_t)).contents
            if event.capability in capabilities:
                args.append(capabilities[event.capability])
            else:
                args.append(str(event.capability))
        elif context.eventid == EventId.SYS_MMAP:
            eventname = "mmap"
            event = ctypes.cast(data, ctypes.POINTER(mmap_info_t)).contents
            args.append(str(hex(0 if event.addr is None else event.addr)))
            args.append(str(event.length))
            args.append(self.prot_to_str(event.prot))
            args.append(str(event.flags))
            args.append(str(event.fd))
            args.append(str(event.offset))
        elif context.eventid == EventId.SYS_MKNOD:
            eventname = "mknod"
            event = ctypes.cast(data, ctypes.POINTER(mknod_info_t)).contents
            args.append(self.get_string_from_buf(cpu, int(event.pathname_loc)))
            args.append(self.mknod_mode_to_str(event.mode))
            args.append(str(event.dev))
        elif context.eventid == EventId.SYS_MKNOD:
            eventname = "mknodat"
            event = ctypes.cast(data, ctypes.POINTER(mknodat_info_t)).contents
            args.append(str(event.dirfd))
            args.append(self.get_string_from_buf(cpu, int(event.pathname_loc)))
            args.append(self.mknod_mode_to_str(event.mode))
            args.append(str(event.dev))
        elif context.eventid == EventId.SYS_DUP:
            eventname = "dup"
            event = ctypes.cast(data, ctypes.POINTER(dup_info_t)).contents
            args.append(str(event.oldfd))
        elif context.eventid == EventId.SYS_DUP2:
            eventname = "dup2"
            event = ctypes.cast(data, ctypes.POINTER(dup_info_t)).contents
            args.append(str(event.oldfd))
            args.append(str(event.newfd))
        elif context.eventid == EventId.SYS_DUP3:
            eventname = "dup3"
            event = ctypes.cast(data, ctypes.POINTER(dup_info_t)).contents
            args.append(str(event.oldfd))
            args.append(str(event.newfd))
            args.append(str(event.flags))
        elif context.eventid == EventId.SYS_CLOSE:
            eventname = "close"
            event = ctypes.cast(data, ctypes.POINTER(close_info_t)).contents
            args.append(str(event.fd))
        elif context.eventid == EventId.SYS_IOCTL:
            eventname = "ioctl"
            event = ctypes.cast(data, ctypes.POINTER(ioctl_info_t)).contents
            args.append(str(event.fd))
            args.append(str(event.request))
        elif context.eventid == EventId.SYS_KILL:
            eventname = "kill"
            event = ctypes.cast(data, ctypes.POINTER(kill_info_t)).contents
            args.append(str(event.pid))
            args.append(str(event.sig))
        elif context.eventid == EventId.SYS_LISTEN:
            eventname = "listen"
            event = ctypes.cast(data, ctypes.POINTER(listen_info_t)).contents
            args.append(str(event.sockfd))
            args.append(str(event.backlog))
        elif context.eventid == EventId.SYS_CONNECT:
            eventname = "connect"
            event = ctypes.cast(data, ctypes.POINTER(connect_info_t)).contents
            args.append(str(event.sockfd))
            if event.sockaddr in sock_domain:
                args.append(sock_domain[event.sockaddr])
            else:
                args.append(str(event.sockaddr))
        elif context.eventid == EventId.SYS_ACCEPT:
            eventname = "accept"
            event = ctypes.cast(data, ctypes.POINTER(accept_info_t)).contents
            args.append(str(event.sockfd))
            if event.sockaddr in sock_domain:
                args.append(sock_domain[event.sockaddr])
            else:
                args.append(str(event.sockaddr))
        elif context.eventid == EventId.SYS_ACCEPT4:
            eventname = "accept4"
            event = ctypes.cast(data, ctypes.POINTER(accept4_info_t)).contents
            args.append(str(event.sockfd))
            if event.sockaddr in sock_domain:
                args.append(sock_domain[event.sockaddr])
            else:
                args.append(str(event.sockaddr))
        elif context.eventid == EventId.SYS_BIND:
            eventname = "bind"
            event = ctypes.cast(data, ctypes.POINTER(bind_info_t)).contents
            args.append(str(event.sockfd))
            if event.sockaddr in sock_domain:
                args.append(sock_domain[event.sockaddr])
            else:
                args.append(str(event.sockaddr))
        elif context.eventid == EventId.SYS_GETSOCKNAME:
            eventname = "getsockname"
            event = ctypes.cast(data, ctypes.POINTER(getsockname_info_t)).contents
            args.append(str(event.sockfd))
            if event.sockaddr in sock_domain:
                args.append(sock_domain[event.sockaddr])
            else:
                args.append(str(event.sockaddr))
        elif context.eventid == EventId.SYS_ACCESS:
            eventname = "access"
            event = ctypes.cast(data, ctypes.POINTER(access_info_t)).contents
            args.append(self.get_string_from_buf(cpu, int(event.pathname_loc)))
            args.append(self.access_mode_to_str(event.mode))
        elif context.eventid == EventId.SYS_FACCESSAT:
            eventname = "faccessat"
            event = ctypes.cast(data, ctypes.POINTER(faccessat_info_t)).contents
            args.append(str(event.dirfd))
            args.append(self.get_string_from_buf(cpu, int(event.pathname_loc)))
            args.append(self.access_mode_to_str(event.mode))
            args.append(str(event.flags))
        elif context.eventid == EventId.SYS_SOCKET:
            eventname = "socket"
            event = ctypes.cast(data, ctypes.POINTER(socket_info_t)).contents
            if event.domain in sock_domain:
                args.append(sock_domain[event.domain])
            else:
                args.append(str(event.domain))
            type_str = ""
            s_type = event.type&0x111
            if s_type in sock_type:
                type_str = sock_type[s_type]
            else:
                type_str = str(s_type)
            if event.type&0o00004000:
                type_str += "|SOCK_NONBLOCK"
            if event.type&0o02000000:
                type_str += "|SOCK_CLOEXEC"
            args.append(type_str)
            args.append(str(event.protocol))
        elif context.eventid == EventId.SYS_MPROTECT:
            eventname = "mprotect"
            event = ctypes.cast(data, ctypes.POINTER(mmap_info_t)).contents
            args.append(str(hex(0 if event.addr is None else event.addr)))
            args.append(str(event.length))
            args.append(self.prot_to_str(event.prot))
        elif context.eventid == EventId.SYS_STAT:
            eventname = "stat"
            event = ctypes.cast(data, ctypes.POINTER(stat_info_t)).contents
            args.append(self.get_string_from_buf(cpu, int(event.path_loc)))
        elif context.eventid == EventId.SYS_FSTAT:
            eventname = "fstat"
            event = ctypes.cast(data, ctypes.POINTER(fstat_info_t)).contents
            args.append(str(event.fd))
        elif context.eventid == EventId.SYS_LSTAT:
            eventname = "lstat"
            event = ctypes.cast(data, ctypes.POINTER(stat_info_t)).contents
            args.append(self.get_string_from_buf(cpu, int(event.path_loc)))
        elif context.eventid == EventId.SYS_PRCTL:
            eventname = "prctl"
            event = ctypes.cast(data, ctypes.POINTER(prctl_info_t)).contents
            args.append(str(event.option))
            args.append(str(event.arg2))
            args.append(str(event.arg3))
            args.append(str(event.arg4))
            args.append(str(event.arg5))
        elif context.eventid == EventId.SYS_PTRACE:
            eventname = "ptrace"
            event = ctypes.cast(data, ctypes.POINTER(ptrace_info_t)).contents
            args.append(str(event.request))
            args.append(str(event.pid))
            args.append(str(hex(0 if event.addr is None else event.addr)))
            args.append(str(hex(0 if event.data is None else event.data)))
        elif context.eventid == EventId.SYS_PROCESS_VM_WRITEV:
            eventname = "process_vm_writev"
            event = ctypes.cast(data, ctypes.POINTER(process_vm_writev_info_t)).contents
            args.append(str(event.pid))
            args.append(str(hex(0 if event.local_iov is None else event.local_iov)))
            args.append(str(event.liovcnt))
            args.append(str(hex(0 if event.remote_iov is None else event.remote_iov)))
            args.append(str(event.riovcnt))
            args.append(str(event.flags))
        elif context.eventid == EventId.SYS_PROCESS_VM_READV:
            eventname = "process_vm_readv"
            event = ctypes.cast(data, ctypes.POINTER(process_vm_readv_info_t)).contents
            args.append(str(event.pid))
            args.append(str(hex(0 if event.local_iov is None else event.local_iov)))
            args.append(str(event.liovcnt))
            args.append(str(hex(0 if event.remote_iov is None else event.remote_iov)))
            args.append(str(event.riovcnt))
            args.append(str(event.flags))
        elif context.eventid == EventId.SYS_INIT_MODULE:
            eventname = "init_module"
            event = ctypes.cast(data, ctypes.POINTER(init_module_info_t)).contents
            args.append(str(hex(0 if event.module_image is None else event.module_image)))
            args.append(str(event.len))
            args.append(self.get_string_from_buf(cpu, int(event.param_values_loc)))
        elif context.eventid == EventId.SYS_FINIT_MODULE:
            eventname = "finit_module"
            event = ctypes.cast(data, ctypes.POINTER(finit_module_info_t)).contents
            args.append(str(event.fd))
            args.append(self.get_string_from_buf(cpu, int(event.param_values_loc)))
            args.append(str(event.flags))
        elif context.eventid == EventId.SYS_DELETE_MODULE:
            eventname = "delete_module"
            event = ctypes.cast(data, ctypes.POINTER(delete_module_info_t)).contents
            args.append(self.get_string_from_buf(cpu, int(event.name_loc)))
            args.append(str(event.flags))
        elif context.eventid == EventId.SYS_SYMLINK:
            eventname = "symlink"
            event = ctypes.cast(data, ctypes.POINTER(symlink_info_t)).contents
            args.append(self.get_string_from_buf(cpu, int(event.target_loc)))
            args.append(self.get_string_from_buf(cpu, int(event.linkpath_loc)))
        elif context.eventid == EventId.SYS_SYMLINKAT:
            eventname = "symlinkat"
            event = ctypes.cast(data, ctypes.POINTER(symlinkat_info_t)).contents
            args.append(self.get_string_from_buf(cpu, int(event.target_loc)))
            args.append(str(event.newdirfd))
            args.append(self.get_string_from_buf(cpu, int(event.linkpath_loc)))
        elif context.eventid == EventId.SYS_GETDENTS:
            eventname = "getdents"
            event = ctypes.cast(data, ctypes.POINTER(getdents_info_t)).contents
            args.append(str(event.fd))
        elif context.eventid == EventId.SYS_GETDENTS64:
            eventname = "getdents64"
            event = ctypes.cast(data, ctypes.POINTER(getdents_info_t)).contents
            args.append(str(event.fd))
        elif context.eventid == EventId.SYS_CLONE:
            eventname = "clone"
        elif context.eventid == EventId.SYS_FORK:
            eventname = "fork"
        elif context.eventid == EventId.SYS_VFORK:
            eventname = "vfork"
        elif context.eventid == EventId.DO_EXIT:
            eventname = "do_exit"
        else:
            return

        if self.verbose:
            log.info("%-14f %-12d %-12d %-6d %-16s %-16s %-6d %-6d %-6d %-16d %s" % (context.ts/1000000.0, context.mnt_id, context.pid_id, context.uid,
                    eventname, context.comm.decode("utf-8"), pid, tid, ppid, context.retval, " ".join(args)))
        else: #prepare data to be consumed by ultrabox
            data = dict()
            data["status"] = [0]
            data["raw"] = ""
            data["type"] = ["apicall"]
            data["time"] = context.ts/1000000.0
            data["mnt_ns"] = context.mnt_id
            data["pid_ns"] = context.pid_id
            data["uid"] = context.uid
            data["api"] = eventname
            data["process_name"] = context.comm.decode("utf-8")
            data["pid"] = pid
            data["tid"] = tid
            data["ppid"] = ppid
            data["return_value"] = context.retval
            dict_args = dict()
            args_len = len(args)
            for i in range(args_len):
                dict_args["p" + str(i)] = args[i].rstrip('\0')
            data["arguments"] = dict_args

            log.info(json.dumps(data))
            self.events.append(data)

        #if eventname == "do_exit" and pid == 1:
            #log.info(json.dumps(events, indent=4))
            #exit()

    def stop_trace(self):
        self.do_trace = False

    def get_events(self):
        return self.events

    def monitor_events(self):
        # loop with callback to print_event
        self.bpf["events"].open_perf_buffer(self.print_event)
        while self.do_trace:
            try:
                self.bpf.perf_buffer_poll(1000)
            except KeyboardInterrupt:
                exit()

