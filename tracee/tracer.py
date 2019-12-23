#!/usr/bin/python

# Authors:
#       Yaniv Agman <yaniv@aquasec.com>

from __future__ import print_function

import array
import ctypes
import json
import logging
import sys

from bcc import BPF

log = logging.getLogger()
log.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
log.addHandler(handler)

BPF_PROGRAM = "tracee/event_monitor_ebpf.c"

# include/uapi/linux/capability.h
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
            "symlink", "symlinkat", "getdents", "getdents64", "creat", "open", "openat",
            "mount", "umount", "unlink", "unlinkat", "setuid", "setgid", "setreuid", "setregid",
            "setresuid", "setresgid", "setfsuid", "setfsgid"]
sysevents = ["cap_capable", "do_exit"]

# We always need kprobes for execve[at] so that we capture the new PID namespace, 
# and do_exit so we clean up  
essential_syscalls = ["execve", "execveat"]
essential_sysevents = ["do_exit"]

# event_id numbers should match event_id enum in ebpf file code
event_id = {
    0: "read",
    1: "write",
    2: "open",
    3: "close",
    4: "stat",
    5: "fstat",
    6: "lstat",
    7: "poll",
    8: "lseek",
    9: "mmap",
    10: "mprotect",
    11: "munmap",
    12: "brk",
    13: "rt_sigaction",
    14: "rt_sigprocmask",
    15: "rt_sigreturn",
    16: "ioctl",
    17: "pread64",
    18: "pwrite64",
    19: "readv",
    20: "writev",
    21: "access",
    22: "pipe",
    23: "select",
    24: "sched_yield",
    25: "mremap",
    26: "msync",
    27: "mincore",
    28: "madvise",
    29: "shmget",
    30: "shmat",
    31: "shmctl",
    32: "dup",
    33: "dup2",
    34: "pause",
    35: "nanosleep",
    36: "getitimer",
    37: "alarm",
    38: "setitimer",
    39: "getpid",
    40: "sendfile",
    41: "socket",
    42: "connect",
    43: "accept",
    44: "sendto",
    45: "recvfrom",
    46: "sendmsg",
    47: "recvmsg",
    48: "shutdown",
    49: "bind",
    50: "listen",
    51: "getsockname",
    52: "getpeername",
    53: "socketpair",
    54: "setsockopt",
    55: "getsockopt",
    56: "clone",
    57: "fork",
    58: "vfork",
    59: "execve",
    60: "exit",
    61: "wait4",
    62: "kill",
    63: "uname",
    64: "semget",
    65: "semop",
    66: "semctl",
    67: "shmdt",
    68: "msgget",
    69: "msgsnd",
    70: "msgrcv",
    71: "msgctl",
    72: "fcntl",
    73: "flock",
    74: "fsync",
    75: "fdatasync",
    76: "truncate",
    77: "ftruncate",
    78: "getdents",
    79: "getcwd",
    80: "chdir",
    81: "fchdir",
    82: "rename",
    83: "mkdir",
    84: "rmdir",
    85: "creat",
    86: "link",
    87: "unlink",
    88: "symlink",
    89: "readlink",
    90: "chmod",
    91: "fchmod",
    92: "chown",
    93: "fchown",
    94: "lchown",
    95: "umask",
    96: "gettimeofday",
    97: "getrlimit",
    98: "getrusage",
    99: "sysinfo",
    100: "times",
    101: "ptrace",
    102: "getuid",
    103: "syslog",
    104: "getgid",
    105: "setuid",
    106: "setgid",
    107: "geteuid",
    108: "getegid",
    109: "setpgid",
    110: "getppid",
    111: "getpgrp",
    112: "setsid",
    113: "setreuid",
    114: "setregid",
    115: "getgroups",
    116: "setgroups",
    117: "setresuid",
    118: "getresuid",
    119: "setresgid",
    120: "getresgid",
    121: "getpgid",
    122: "setfsuid",
    123: "setfsgid",
    124: "getsid",
    125: "capget",
    126: "capset",
    127: "rt_sigpending",
    128: "rt_sigtimedwait",
    129: "rt_sigqueueinfo",
    130: "rt_sigsuspend",
    131: "sigaltstack",
    132: "utime",
    133: "mknod",
    134: "uselib",
    135: "personality",
    136: "ustat",
    137: "statfs",
    138: "fstatfs",
    139: "sysfs",
    140: "getpriority",
    141: "setpriority",
    142: "sched_setparam",
    143: "sched_getparam",
    144: "sched_setscheduler",
    145: "sched_getscheduler",
    146: "sched_get_priority_max",
    147: "sched_get_priority_min",
    148: "sched_rr_get_interval",
    149: "mlock",
    150: "munlock",
    151: "mlockall",
    152: "munlockall",
    153: "vhangup",
    154: "modify_ldt",
    155: "pivot_root",
    156: "sysctl",
    157: "prctl",
    158: "arch_prctl",
    159: "adjtimex",
    160: "setrlimit",
    161: "chroot",
    162: "sync",
    163: "acct",
    164: "settimeofday",
    165: "mount",
    166: "umount",
    167: "swapon",
    168: "swapoff",
    169: "reboot",
    170: "sethostname",
    171: "setdomainname",
    172: "iopl",
    173: "ioperm",
    174: "create_module",
    175: "init_module",
    176: "delete_module",
    177: "get_kernel_syms",
    178: "query_module",
    179: "quotactl",
    180: "nfsservctl",
    181: "getpmsg",
    182: "putpmsg",
    183: "afs",
    184: "tuxcall",
    185: "security",
    186: "gettid",
    187: "readahead",
    188: "setxattr",
    189: "lsetxattr",
    190: "fsetxattr",
    191: "getxattr",
    192: "lgetxattr",
    193: "fgetxattr",
    194: "listxattr",
    195: "llistxattr",
    196: "flistxattr",
    197: "removexattr",
    198: "lremovexattr",
    199: "fremovexattr",
    200: "tkill",
    201: "time",
    202: "futex",
    203: "sched_setaffinity",
    204: "sched_getaffinity",
    205: "set_thread_area",
    206: "io_setup",
    207: "io_destroy",
    208: "io_getevents",
    209: "io_submit",
    210: "io_cancel",
    211: "get_thread_area",
    212: "lookup_dcookie",
    213: "epoll_create",
    214: "epoll_ctl_old",
    215: "epoll_wait_old",
    216: "remap_file_pages",
    217: "getdents64",
    218: "set_tid_address",
    219: "restart_syscall",
    220: "semtimedop",
    221: "fadvise64",
    222: "timer_create",
    223: "timer_settime",
    224: "timer_gettime",
    225: "timer_getoverrun",
    226: "timer_delete",
    227: "clock_settime",
    228: "clock_gettime",
    229: "clock_getres",
    230: "clock_nanosleep",
    231: "exit_group",
    232: "epoll_wait",
    233: "epoll_ctl",
    234: "tgkill",
    235: "utimes",
    236: "vserver",
    237: "mbind",
    238: "set_mempolicy",
    239: "get_mempolicy",
    240: "mq_open",
    241: "mq_unlink",
    242: "mq_timedsend",
    243: "mq_timedreceive",
    244: "mq_notify",
    245: "mq_getsetattr",
    246: "kexec_load",
    247: "waitid",
    248: "add_key",
    249: "request_key",
    250: "keyctl",
    251: "ioprio_set",
    252: "ioprio_get",
    253: "inotify_init",
    254: "inotify_add_watch",
    255: "inotify_rm_watch",
    256: "migrate_pages",
    257: "openat",
    258: "mkdirat",
    259: "mknodat",
    260: "fchownat",
    261: "futimesat",
    262: "newfstatat",
    263: "unlinkat",
    264: "renameat",
    265: "linkat",
    266: "symlinkat",
    267: "readlinkat",
    268: "fchmodat",
    269: "faccessat",
    270: "pselect6",
    271: "ppoll",
    272: "unshare",
    273: "set_robust_list",
    274: "get_robust_list",
    275: "splice",
    276: "tee",
    277: "sync_file_range",
    278: "vmsplice",
    279: "move_pages",
    280: "utimensat",
    281: "epoll_pwait",
    282: "signalfd",
    283: "timerfd_create",
    284: "eventfd",
    285: "fallocate",
    286: "timerfd_settime",
    287: "timerfd_gettime",
    288: "accept4",
    289: "signalfd4",
    290: "eventfd2",
    291: "epoll_create1",
    292: "dup3",
    293: "pipe2",
    294: "ionotify_init1",
    295: "preadv",
    296: "pwritev",
    297: "rt_tgsigqueueinfo",
    298: "perf_event_open",
    299: "recvmmsg",
    300: "fanotify_init",
    301: "fanotify_mark",
    302: "prlimit64",
    303: "name_tohandle_at",
    304: "open_by_handle_at",
    305: "clock_adjtime",
    306: "sycnfs",
    307: "sendmmsg",
    308: "setns",
    309: "getcpu",
    310: "process_vm_readv",
    311: "process_vm_writev",
    312: "kcmp",
    313: "finit_module",
    314: "sched_setattr",
    315: "sched_getattr",
    316: "renameat2",
    317: "seccomp",
    318: "getrandom",
    319: "memfd_create",
    320: "kexec_file_load",
    321: "bpf",
    322: "execveat",
    323: "userfaultfd",
    324: "membarrier",
    325: "mlock2",
    326: "copy_file_range",
    327: "preadv2",
    328: "pwritev2",
    329: "pkey_mprotect",
    330: "pkey_alloc",
    331: "pkey_free",
    332: "statx",
    333: "io_pgetevents",
    334: "rseq",
    # Non syscall events start here
    335: "do_exit",
    336: "cap_capable",
}

# argument types should match defined values in ebpf file code
class ArgType(object):
    NONE            = 0
    INT_T           = 1
    UINT_T          = 2
    LONG_T          = 3
    ULONG_T         = 4
    OFF_T_T         = 5
    MODE_T_T        = 6
    DEV_T_T         = 7
    SIZE_T_T        = 8
    POINTER_T       = 9
    STR_T           = 10
    STR_ARR_T       = 11
    SOCKADDR_T      = 12
    OPENFLAGS_T     = 13
    EXEC_FLAG_T     = 14
    SOCK_DOM_T      = 15
    SOCK_TYPE_T     = 16
    CAP_T           = 17
    TYPE_MAX        = 255

class shared_config(object):
    CONFIG_CONT_MODE    = 0

class context_t(ctypes.Structure):  # match layout of eBPF C's context_t struct
    _fields_ = [("ts", ctypes.c_uint64),
                ("pid", ctypes.c_uint32),
                ("tid", ctypes.c_uint32),
                ("ppid", ctypes.c_uint32),
                ("uid", ctypes.c_uint32),
                ("mnt_id", ctypes.c_uint32),
                ("pid_id", ctypes.c_uint32),
                ("comm", ctypes.c_char * 16),
                ("uts_name", ctypes.c_char * 16),
                ("eventid", ctypes.c_uint),
                ("argnum", ctypes.c_uint8),
                ("retval", ctypes.c_int64), ]


def load_bpf_program():
    with open(BPF_PROGRAM, "r") as f:
        bpf = f.read()
    return bpf


def prot_to_str(prot):
    p_str = ""
    has_prot = False

    if not prot | 0x0:
        return "PROT_NONE"

    if prot & 0x1:
        p_str += "PROT_READ"
        has_prot = True

    if prot & 0x2:
        if has_prot:
            p_str += "|PROT_WRITE"
        else:
            p_str += "PROT_WRITE"
            has_prot = True

    if prot & 0x4:
        if has_prot:
            p_str += "|PROT_EXEC"
        else:
            p_str += "PROT_EXEC"
            has_prot = True

    return p_str


def mknod_mode_to_str(flags):
    f_str = ""

    if flags & 0o140000:
        f_str += "S_IFSOCK"
    elif flags & 0o100000:
        f_str += "S_IFREG"
    elif flags & 0o060000:
        f_str += "S_IFBLK"
    elif flags & 0o020000:
        f_str += "S_IFCHR"
    elif flags & 0o010000:
        f_str += "S_IFIFO"
    else:
        return "invalid"

    if flags & 0o0700 == 0o0700:
        f_str += "|S_IRWXU"
    else:
        if flags & 0o0400:
            f_str += "|S_IRUSR"

        if flags & 0o0200:
            f_str += "|S_IWUSR"

        if flags & 0o0100:
            f_str += "|S_IXUSR"

    if flags & 0o0070 == 0o0070:
        f_str += "|S_IRWXG"
    else:
        if flags & 0o0040:
            f_str += "|S_IRGRP"

        if flags & 0o0020:
            f_str += "|S_IWGRP"

        if flags & 0o0010:
            f_str += "|S_IXGRP"

    if flags & 0o0007 == 0o0007:
        f_str += "|S_IRWXO"
    else:
        if flags & 0o0004:
            f_str += "|S_IROTH"

        if flags & 0o0002:
            f_str += "|S_IWOTH"

        if flags & 0o0001:
            f_str += "|S_IXOTH"

    return f_str


def execveat_flags_to_str(flags):
    f_str = "0"

    if flags & 0x1000:
        f_str = "AT_EMPTY_PATH"

    if flags & 0x100:
        if f_str == "0":
            f_str = "AT_SYMLINK_NOFOLLOW"
        else:
            f_str += "|AT_SYMLINK_NOFOLLOW"

    return f_str


def access_mode_to_str(flags):
    f_str = ""

    if not flags | 0x0:
        return "F_OK"

    if flags & 0x04:
        f_str += "R_OK"

    if flags & 0x02:
        if f_str == "":
            f_str += "W_OK"
        else:
            f_str += "|W_OK"

    if flags & 0x01:
        if f_str == "":
            f_str += "X_OK"
        else:
            f_str += "|X_OK"

    return f_str

def sock_type_to_str(sock_type_num):
    type_str = ""
    s_type = sock_type_num & 0xf
    if s_type in sock_type:
        type_str = sock_type[s_type]
    else:
        type_str = str(s_type)
    if sock_type_num & 0o00004000:
        type_str += "|SOCK_NONBLOCK"
    if sock_type_num & 0o02000000:
        type_str += "|SOCK_CLOEXEC"

    return type_str

def open_flags_to_str(flags):
    f_str = ""

    if flags & 0o1:
        f_str += "O_WRONLY"
    elif flags & 0o2:
        f_str += "O_RDWR"
    else:
        f_str += "O_RDONLY"

    if flags & 0o100:
        f_str += "|O_CREAT"

    if flags & 0o200:
        f_str += "|O_EXCL"

    if flags & 0o400:
        f_str += "|O_NOCTTY"

    if flags & 0o1000:
        f_str += "|O_TRUNC"

    if flags & 0o2000:
        f_str += "|O_APPEND"

    if flags & 0o4000:
        f_str += "|O_NONBLOCK"

    if flags & 0o4010000:
        f_str += "|O_SYNC"

    if flags & 0o20000:
        f_str += "|O_ASYNC"

    if flags & 0o100000:
        f_str += "|O_LARGEFILE"

    if flags & 0o200000:
        f_str += "|O_DIRECTORY"

    if flags & 0o400000:
        f_str += "|O_NOFOLLOW"

    if flags & 0o2000000:
        f_str += "|O_CLOEXEC"

    if flags & 0o40000:
        f_str += "|O_DIRECT"

    if flags & 0o1000000:
        f_str += "|O_NOATIME"

    if flags & 0o10000000:
        f_str += "|O_PATH"

    if flags & 0o20000000:
        f_str += "|O_TMPFILE"

    return f_str

# Given the list of event names the user wants to trace, get_kprobes() returns the 
# - syscalls we want kprobes for 
# - events we want kprobes for 
# Includes the essential kprobes needed for Tracee to work
def get_kprobes(events):
    sc = essential_syscalls
    se = essential_sysevents
    for e in events:
        if e in syscalls:
            sc.append(e)
        elif e in sysevents:
            se.append(e)
        # Argument parsing should have already checked that the event names are good
        else:
            raise ValueError("Bad event name {0}".format(e))

    # Dedupe the lists in case the essential syscalls / sysevents were specified
    sc = list(set(sc))
    se = list(set(se))
    return sc, se


class EventMonitor:

    def __init__(self, args):
        self.cur_off = 0
        self.events = list()
        self.do_trace = True
        self.bpf = None
        self.event_bufs = list()
        self.total_lost = 0

        # input arguments
        self.cont_mode = args.container
        self.json = args.json
        self.ebpf = args.ebpf
        self.list_events = args.list
        self.events_to_trace = args.events_to_trace
        self.buf_pages = args.buf_pages

    def init_bpf(self):
        bpf_text = load_bpf_program()

        if self.list_events:
            log.info("Syscalls:")
            for e in syscalls:
                log.info("  %s" % e)
            log.info("\nOther events:")
            for e in sysevents:
                log.info("  %s" % e)
            exit()

        if self.ebpf:
            log.debug(bpf_text)
            exit()

        # initialize BPF
        self.bpf = BPF(text=bpf_text)

        # set shared config
        key = ctypes.c_uint32(shared_config.CONFIG_CONT_MODE)
        self.bpf["config_map"][key] = ctypes.c_uint32(self.cont_mode)

        # attaching kprobes
        sk, se = get_kprobes(self.events_to_trace)

        for syscall in sk:
            syscall_fnname = self.bpf.get_syscall_fnname(syscall)
            self.bpf.attach_kprobe(event=syscall_fnname, fn_name="syscall__" + syscall)
            self.bpf.attach_kretprobe(event=syscall_fnname, fn_name="trace_ret_" + syscall)

        for sysevent in se:
            self.bpf.attach_kprobe(event=sysevent, fn_name="trace_" + sysevent)

        if not self.json:
            log.info("%-14s %-16s %-12s %-12s %-6s %-16s %-16s %-6s %-6s %-6s %-12s %s" % (
                "TIME(s)", "UTS_NAME", "MNT_NS", "PID_NS", "UID", "EVENT", "COMM", "PID", "TID", "PPID", "RET", "ARGS"))

    def get_sockaddr_from_buf(self, buf):
        # todo: parse all fields
        c_val = ctypes.cast(ctypes.byref(buf, self.cur_off), ctypes.POINTER(ctypes.c_short)).contents
        self.cur_off = self.cur_off + 2
        domain = c_val.value
        if domain in sock_domain:
            return sock_domain[domain]
        else:
            return str(domain)

    def get_type_from_buf(self, buf):
        c_val = ctypes.cast(ctypes.byref(buf, self.cur_off), ctypes.POINTER(ctypes.c_byte)).contents
        self.cur_off = self.cur_off + 1
        return c_val.value

    def get_int_from_buf(self, buf):
        c_val = ctypes.cast(ctypes.byref(buf, self.cur_off), ctypes.POINTER(ctypes.c_int)).contents
        self.cur_off = self.cur_off + 4
        return c_val.value

    def get_uint_from_buf(self, buf):
        c_val = ctypes.cast(ctypes.byref(buf, self.cur_off), ctypes.POINTER(ctypes.c_uint)).contents
        self.cur_off = self.cur_off + 4
        return c_val.value

    def get_long_from_buf(self, buf):
        c_val = ctypes.cast(ctypes.byref(buf, self.cur_off), ctypes.POINTER(ctypes.c_long)).contents
        self.cur_off = self.cur_off + 8
        return c_val.value

    def get_ulong_from_buf(self, buf):
        c_val = ctypes.cast(ctypes.byref(buf, self.cur_off), ctypes.POINTER(ctypes.c_ulong)).contents
        self.cur_off = self.cur_off + 8
        return c_val.value

    def get_pointer_from_buf(self, buf):
        c_val = ctypes.cast(ctypes.byref(buf, self.cur_off), ctypes.POINTER(ctypes.c_void_p)).contents
        self.cur_off = self.cur_off + 8
        return hex(0 if c_val.value is None else c_val.value)

    def get_string_from_buf(self, buf):
        str_size = ctypes.cast(ctypes.byref(buf, self.cur_off), ctypes.POINTER(ctypes.c_uint)).contents.value
        str_off = self.cur_off + 4
        str_buf = buf[str_off:str_off + str_size]
        self.cur_off = self.cur_off + str_size + 4
        try:
            ret_str = str(array.array('B', str_buf).tostring().decode("utf-8"))
            return ret_str
        except:
            return ""

    def get_str_arr_from_buf(self, buf, args):
        str_list = list()
        while self.cur_off < ctypes.sizeof(buf):
            argtype = self.get_type_from_buf(buf)
            if argtype == ArgType.STR_T:
                str_list.append(self.get_string_from_buf(buf).rstrip('\x00'))
            else:
                args.append('[%s]' % ', '.join(map(str, str_list)))
                return

    def print_event(self, eventname, context, args):
        # There are some syscalls which doesn't have the same name as their function
        eventfunc = "dummy"
        if context.eventid == 4:
            eventfunc = "newstat"
        elif context.eventid == 5:
            eventfunc = "newfstat"
        elif context.eventid == 6:
            eventfunc = "newlstat"

        try:
            comm = context.comm.decode("utf-8")
            uts_name = context.uts_name.decode("utf-8")
        except:
            return

        if eventname in self.events_to_trace or eventfunc in self.events_to_trace:
            if not self.json:
                log.info("%-14f %-16s %-12d %-12d %-6d %-16s %-16s %-6d %-6d %-6d %-12d %s" % (
                    context.ts / 1000000.0, uts_name, context.mnt_id, context.pid_id, context.uid,
                    eventname, comm, context.pid, context.tid, context.ppid, context.retval, " ".join(args)))
            else:  # prepare data to be consumed by ultrabox
                data = dict()
                data["status"] = [0]
                data["raw"] = ""
                data["type"] = ["apicall"]
                data["time"] = context.ts / 1000000.0
                data["mnt_ns"] = context.mnt_id
                data["pid_ns"] = context.pid_id
                data["uid"] = context.uid
                data["api"] = eventname
                data["uts_name"] = uts_name
                data["process_name"] = comm
                data["pid"] = context.pid
                data["tid"] = context.tid
                data["ppid"] = context.ppid
                data["return_value"] = context.retval
                dict_args = dict()
                args_len = len(args)
                for i in range(args_len):
                    dict_args["p" + str(i)] = args[i].rstrip('\0')
                data["arguments"] = dict_args

                log.info(json.dumps(data))
                self.events.append(data)

    def parse_event(self, event_buf):
        context = ctypes.cast(ctypes.byref(event_buf), ctypes.POINTER(context_t)).contents
        self.cur_off = ctypes.sizeof(context_t)
        args = list()

        if context.eventid in event_id:
            eventname = event_id[context.eventid]
            for i in range(context.argnum):
                argtype = self.get_type_from_buf(event_buf)
                # sanity check - should never happen
                if self.cur_off >= ctypes.sizeof(event_buf):
                    return

                if argtype == ArgType.INT_T:
                    args.append(str(self.get_int_from_buf(event_buf)))
                elif argtype == ArgType.UINT_T:
                    args.append(str(self.get_uint_from_buf(event_buf)))
                elif argtype == ArgType.LONG_T:
                    args.append(str(self.get_long_from_buf(event_buf)))
                elif argtype == ArgType.ULONG_T:
                    args.append(str(self.get_ulong_from_buf(event_buf)))
                elif argtype == ArgType.OFF_T_T:
                    args.append(str(self.get_ulong_from_buf(event_buf)))
                elif argtype == ArgType.MODE_T_T:
                    args.append(str(self.get_uint_from_buf(event_buf)))
                elif argtype == ArgType.DEV_T_T:
                    args.append(str(self.get_uint_from_buf(event_buf)))
                elif argtype == ArgType.SIZE_T_T:
                    args.append(str(self.get_ulong_from_buf(event_buf)))
                elif argtype == ArgType.POINTER_T:
                    args.append(str(self.get_pointer_from_buf(event_buf)))
                elif argtype == ArgType.STR_T:
                    args.append(self.get_string_from_buf(event_buf))
                elif argtype == ArgType.STR_ARR_T:
                    self.get_str_arr_from_buf(event_buf, args)
                elif argtype == ArgType.SOCKADDR_T:
                    # sockaddr (partialy parsed to family)
                    args.append(self.get_sockaddr_from_buf(event_buf))
                elif argtype == ArgType.OPENFLAGS_T:
                    args.append(open_flags_to_str(self.get_int_from_buf(event_buf)))
                elif argtype == ArgType.EXEC_FLAG_T:
                    flags = self.get_int_from_buf(event_buf)
                    args.append(execveat_flags_to_str(flags))
                elif argtype == ArgType.SOCK_DOM_T:
                    domain = self.get_int_from_buf(event_buf)
                    if domain in sock_domain:
                        args.append(sock_domain[domain])
                    else:
                        args.append(str(domain))
                elif argtype == ArgType.SOCK_TYPE_T:
                    sock_type_num = self.get_int_from_buf(event_buf)
                    args.append(sock_type_to_str(sock_type_num))
                elif argtype == ArgType.CAP_T:
                    capability = self.get_int_from_buf(event_buf)
                    if capability in capabilities:
                        args.append(capabilities[capability])
                    else:
                        args.append(str(capability))
        else:
            return

        return self.print_event(eventname, context, args)

    # process event
    def handle_event(self, cpu, data, size):
        buf = ctypes.cast(data, ctypes.POINTER(ctypes.c_char*size)).contents
        event_buf = (ctypes.c_char * size).from_buffer_copy(buf)
        self.event_bufs.append(event_buf)

    def lost_event(self, lost):
        self.total_lost += lost
        log.info("Possibly lost %d events (%d in total), consider using a bigger buffer" % (lost, self.total_lost))

    def stop_trace(self):
        self.do_trace = False

    def get_events(self):
        return self.events

    def monitor_events(self):
        # loop with callback to handle_event
        self.bpf["events"].open_perf_buffer(self.handle_event, page_cnt=self.buf_pages, lost_cb=self.lost_event)
        while self.do_trace:
            try:
                # It would have been better to parse the events in a "consumer" thread
                # As python threading is not efficient - parse here
                for event in self.event_bufs:
                    self.parse_event(event)
                self.event_bufs = list()
                self.bpf.perf_buffer_poll(1000)
            except KeyboardInterrupt:
                exit()
