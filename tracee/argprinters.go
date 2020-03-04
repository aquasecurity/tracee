package tracee

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
)

// PrintInodeMode prints the `mode` bitmask argument of the `mknod` syscall
// http://man7.org/linux/man-pages/man7/inode.7.html
func PrintInodeMode(mode uint32) string {
	var f []string

	// File Type
	switch {
	case mode&0140000 == 0140000:
		f = append(f, "S_IFSOCK")
	case mode&0120000 == 0120000:
		f = append(f, "S_IFLNK")
	case mode&0100000 == 0100000:
		f = append(f, "S_IFREG")
	case mode&060000 == 060000:
		f = append(f, "S_IFBLK")
	case mode&040000 == 040000:
		f = append(f, "S_IFDIR")
	case mode&020000 == 020000:
		f = append(f, "S_IFCHR")
	case mode&010000 == 010000:
		f = append(f, "S_IFIFO")
	default:
		f = append(f, "invalid file type")
	}

	// File Mode
	// Owner
	if mode&00700 == 00700 {
		f = append(f, "S_IRWXU")
	} else {
		if mode&00400 == 00400 {
			f = append(f, "S_IRUSR")
		}
		if mode&00200 == 00200 {
			f = append(f, "S_IWUSR")
		}
		if mode&00100 == 00100 {
			f = append(f, "S_IXUSR")
		}
	}
	// Group
	if mode&00070 == 00070 {
		f = append(f, "S_IRWXG")
	} else {
		if mode&00040 == 00040 {
			f = append(f, "S_IRGRP")
		}
		if mode&00020 == 00020 {
			f = append(f, "S_IWGRP")
		}
		if mode&00010 == 00010 {
			f = append(f, "S_IXGRP")
		}
	}
	// Others
	if mode&00007 == 00007 {
		f = append(f, "S_IRWXO")
	} else {
		if mode&00004 == 00004 {
			f = append(f, "S_IROTH")
		}
		if mode&00002 == 00002 {
			f = append(f, "S_IWOTH")
		}
		if mode&00001 == 00001 {
			f = append(f, "S_IXOTH")
		}
	}

	return strings.Join(f, "|")
}

// PrintMemProt prints the `prot` bitmask argument of the `mmap` syscall
// http://man7.org/linux/man-pages/man2/mmap.2.html
// https://elixir.bootlin.com/linux/v5.5.3/source/include/uapi/asm-generic/mman-common.h#L10
func PrintMemProt(prot uint32) string {
	var f []string
	if prot == 0x0 {
		f = append(f, "PROT_NONE")
	} else {
		if prot&0x01 == 0x01 {
			f = append(f, "PROT_READ")
		}
		if prot&0x02 == 0x02 {
			f = append(f, "PROT_WRITE")
		}
		if prot&0x04 == 0x04 {
			f = append(f, "PROT_EXEC")
		}
	}
	return strings.Join(f, "|")
}

// PrintOpenFlags prints the `flags` bitmask argument of the `open` syscall
// http://man7.org/linux/man-pages/man2/open.2.html
// https://elixir.bootlin.com/linux/v5.5.3/source/include/uapi/asm-generic/fcntl.h
func PrintOpenFlags(flags uint32) string {
	var f []string

	//access mode
	switch {
	case flags&00 == 00:
		f = append(f, "O_RDONLY")
	case flags&01 == 01:
		f = append(f, "O_WRONLY")
	case flags&02 == 0x02:
		f = append(f, "O_RDWR")
	}

	// file creation and status flags
	if flags&0100 == 0100 {
		f = append(f, "O_CREAT")
	}
	if flags&0200 == 0200 {
		f = append(f, "O_EXCL")
	}
	if flags&0400 == 0400 {
		f = append(f, "O_NOCTTY")
	}
	if flags&01000 == 01000 {
		f = append(f, "O_TRUNC")
	}
	if flags&02000 == 02000 {
		f = append(f, "O_APPEND")
	}
	if flags&04000 == 04000 {
		f = append(f, "O_NONBLOCK")
	}
	if flags&04010000 == 04010000 {
		f = append(f, "O_SYNC")
	}
	if flags&020000 == 020000 {
		f = append(f, "O_ASYNC")
	}
	if flags&0100000 == 0100000 {
		f = append(f, "O_LARGEFILE")
	}
	if flags&0200000 == 0200000 {
		f = append(f, "O_DIRECTORY")
	}
	if flags&0400000 == 0400000 {
		f = append(f, "O_NOFOLLOW")
	}
	if flags&02000000 == 02000000 {
		f = append(f, "O_CLOEXEC")
	}
	if flags&040000 == 040000 {
		f = append(f, "O_DIRECT")
	}
	if flags&01000000 == 01000000 {
		f = append(f, "O_NOATIME")
	}
	if flags&010000000 == 010000000 {
		f = append(f, "O_PATH")
	}
	if flags&020000000 == 020000000 {
		f = append(f, "O_TMPFILE")
	}

	return strings.Join(f, "|")
}

// http://man7.org/linux/man-pages/man2/access.2.html
// https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/unistd.h.html#tag_13_77_03_04
func PrintAccessMode(mode uint32) string {
	var f []string
	if mode == 0x0 {
		f = append(f, "F_OK")
	} else {
		if mode&0x04 == 0x04 {
			f = append(f, "R_OK")
		}
		if mode&0x02 == 0x02 {
			f = append(f, "W_OK")
		}
		if mode&0x01 == 0x01 {
			f = append(f, "X_OK")
		}
	}
	return strings.Join(f, "|")
}

// PrintExecFlags prints the `flags` bitmask argument of the `execve` syscall
// http://man7.org/linux/man-pages/man2/axecveat.2.html
// https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/fcntl.h#L94
func PrintExecFlags(flags uint32) string {
	var f []string
	if flags&0x100 == 0x100 {
		f = append(f, "AT_EMPTY_PATH")
	}
	if flags&0x1000 == 0x1000 {
		f = append(f, "AT_SYMLINK_NOFOLLOW")
	}
	if len(f) == 0 {
		f = append(f, "0")
	}
	return strings.Join(f, "|")
}

// PrintSocketType prints the `type` bitmask argument of the `socket` syscall
// http://man7.org/linux/man-pages/man2/socket.2.html
func PrintSocketType(st uint32) string {
	var socketTypes = map[uint32]string{
		1:  "SOCK_STREAM",
		2:  "SOCK_DGRAM",
		3:  "SOCK_RAW",
		4:  "SOCK_RDM",
		5:  "SOCK_SEQPACKET",
		6:  "SOCK_DCCP",
		10: "SOCK_PACKET",
	}
	var f []string
	if stName, ok := socketTypes[st]; ok {
		f = append(f, stName)
	} else {
		f = append(f, strconv.Itoa(int(st)))
	}
	if st&000004000 == 000004000 {
		f = append(f, "SOCK_NONBLOCK")
	}
	if st&002000000 == 002000000 {
		f = append(f, "SOCK_CLOEXEC")
	}
	return strings.Join(f, "|")
}

// PrintSocketDomain prints the `domain` bitmask argument of the `socket` syscall
// http://man7.org/linux/man-pages/man2/socket.2.html
func PrintSocketDomain(sd uint32) string {
	var socketDomains = map[uint32]string{
		0:  "AF_UNSPEC",
		1:  "AF_UNIX",
		2:  "AF_INET",
		3:  "AF_AX25",
		4:  "AF_IPX",
		5:  "AF_APPLETALK",
		6:  "AF_NETROM",
		7:  "AF_BRIDGE",
		8:  "AF_ATMPVC",
		9:  "AF_X25",
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
	var res string
	if sdName, ok := socketDomains[sd]; ok {
		res = sdName
	} else {
		res = strconv.Itoa(int(sd))
	}
	return res
}

// PrintUint32IP prints the IP address encoded as a uint32
func PrintUint32IP(in uint32) string {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, in)
	return ip.String()
}

// Print16BytesSliceIP prints the IP address encoded as 16 bytes long PrintBytesSliceIP
// It would be more correct to accept a [16]byte instead of variable lenth slice, but that would case unnecessary memory copying and type conversions
func Print16BytesSliceIP(in []byte) string {
	ip := net.IP(in)
	return ip.String()
}

// PrintCapability prints the `capability` bitmask argument of the `cap_capable` function
// include/uapi/linux/capability.h
func PrintCapability(cap int32) string {
	var capabilities = map[int32]string{
		0:  "CAP_CHOWN",
		1:  "CAP_DAC_OVERRIDE",
		2:  "CAP_DAC_READ_SEARCH",
		3:  "CAP_FOWNER",
		4:  "CAP_FSETID",
		5:  "CAP_KILL",
		6:  "CAP_SETGID",
		7:  "CAP_SETUID",
		8:  "CAP_SETPCAP",
		9:  "CAP_LINUX_IMMUTABLE",
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
	var res string
	if capName, ok := capabilities[cap]; ok {
		res = capName
	} else {
		res = strconv.Itoa(int(cap))
	}
	return res
}

// PrintSyscall prints the `syscall` argument that encodes a syscall in the Tracee eBPF program
func PrintSyscall(sc int32) string {
	var syscalls = map[int32]string{
		0:   "read",
		1:   "write",
		2:   "open",
		3:   "close",
		4:   "newstat",
		5:   "fstat",
		6:   "newlstat",
		7:   "poll",
		8:   "lseek",
		9:   "mmap",
		10:  "mprotect",
		11:  "munmap",
		12:  "brk",
		13:  "rt_sigaction",
		14:  "rt_sigprocmask",
		15:  "rt_sigreturn",
		16:  "ioctl",
		17:  "pread64",
		18:  "pwrite64",
		19:  "readv",
		20:  "writev",
		21:  "access",
		22:  "pipe",
		23:  "select",
		24:  "sched_yield",
		25:  "mremap",
		26:  "msync",
		27:  "mincore",
		28:  "madvise",
		29:  "shmget",
		30:  "shmat",
		31:  "shmctl",
		32:  "dup",
		33:  "dup2",
		34:  "pause",
		35:  "nanosleep",
		36:  "getitimer",
		37:  "alarm",
		38:  "setitimer",
		39:  "getpid",
		40:  "sendfile",
		41:  "socket",
		42:  "connect",
		43:  "accept",
		44:  "sendto",
		45:  "recvfrom",
		46:  "sendmsg",
		47:  "recvmsg",
		48:  "shutdown",
		49:  "bind",
		50:  "listen",
		51:  "getsockname",
		52:  "getpeername",
		53:  "socketpair",
		54:  "setsockopt",
		55:  "getsockopt",
		56:  "clone",
		57:  "fork",
		58:  "vfork",
		59:  "execve",
		60:  "exit",
		61:  "wait4",
		62:  "kill",
		63:  "uname",
		64:  "semget",
		65:  "semop",
		66:  "semctl",
		67:  "shmdt",
		68:  "msgget",
		69:  "msgsnd",
		70:  "msgrcv",
		71:  "msgctl",
		72:  "fcntl",
		73:  "flock",
		74:  "fsync",
		75:  "fdatasync",
		76:  "truncate",
		77:  "ftruncate",
		78:  "getdents",
		79:  "getcwd",
		80:  "chdir",
		81:  "fchdir",
		82:  "rename",
		83:  "mkdir",
		84:  "rmdir",
		85:  "creat",
		86:  "link",
		87:  "unlink",
		88:  "symlink",
		89:  "readlink",
		90:  "chmod",
		91:  "fchmod",
		92:  "chown",
		93:  "fchown",
		94:  "lchown",
		95:  "umask",
		96:  "gettimeofday",
		97:  "getrlimit",
		98:  "getrusage",
		99:  "sysinfo",
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
	}
	var res string
	if scName, ok := syscalls[sc]; ok {
		res = scName
	} else {
		res = strconv.Itoa(int(sc))
	}
	return res
}
