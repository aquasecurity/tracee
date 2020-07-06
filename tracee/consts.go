package tracee

// ArgType is an enum that encodes the argument types that the BPF program may write to the shared buffer
type ArgType uint8

// argument types should match defined values in ebpf code
const (
	NONE          ArgType = 0
	INT_T         ArgType = 1
	UINT_T        ArgType = 2
	LONG_T        ArgType = 3
	ULONG_T       ArgType = 4
	OFF_T_T       ArgType = 5
	MODE_T_T      ArgType = 6
	DEV_T_T       ArgType = 7
	SIZE_T_T      ArgType = 8
	POINTER_T     ArgType = 9
	STR_T         ArgType = 10
	STR_ARR_T     ArgType = 11
	SOCKADDR_T    ArgType = 12
	OPEN_FLAGS_T  ArgType = 13
	EXEC_FLAGS_T  ArgType = 14
	SOCK_DOM_T    ArgType = 15
	SOCK_TYPE_T   ArgType = 16
	CAP_T         ArgType = 17
	SYSCALL_T     ArgType = 18
	PROT_FLAGS_T  ArgType = 19
	ACCESS_MODE_T ArgType = 20
	PTRACE_REQ_T  ArgType = 21
	PRCTL_OPT_T   ArgType = 22
	TYPE_MAX      ArgType = 255
)

// ProbeType is an enum that describes the mechanism used to attach the event
type ProbeType uint8

// Syscall tracepoints are explained here: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#8-system-call-tracepoints
// Kprobes are explained here: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#1-kprobes
// Tracepoints are explained here: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#3-tracepoints
const (
	SYSCALL          ProbeType = 0
	KPROBE           ProbeType = 1
	KRETPROBE        ProbeType = 2
	KPROBE_KRETPROBE ProbeType = 3
	TRACEPOINT       ProbeType = 4
)

// EventConfig is a struct describing an event configuration
type EventConfig struct {
	ID               int32
	Name             string
	AttachMechanism  ProbeType
	EnabledByDefault bool
	EssentialEvent   bool
	ProbeName        string
}

// EventsIDToEvent is list of supported events, indexed by their ID
var EventsIDToEvent = map[int32]EventConfig{
	//		0:   EventConfig{ID: 0, Name: "read", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "read"},
	//		1:   EventConfig{ID: 1, Name: "write", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "write"},
	2: EventConfig{ID: 2, Name: "open", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "open"},
	3: EventConfig{ID: 3, Name: "close", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "close"},
	4: EventConfig{ID: 4, Name: "newstat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "newstat"},
	//		5:   EventConfig{ID: 5, Name: "fstat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "fstat"},
	6: EventConfig{ID: 6, Name: "newlstat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "newlstat"},
	//		7:   EventConfig{ID: 7, Name: "poll", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "poll"},
	//		8:   EventConfig{ID: 8, Name: "lseek", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "lseek"},
	9:  EventConfig{ID: 9, Name: "mmap", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "mmap"},
	10: EventConfig{ID: 10, Name: "mprotect", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "mprotect"},
	//		11:  EventConfig{ID: 11, Name: "munmap", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "munmap"},
	//		12:  EventConfig{ID: 12, Name: "brk", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "brk"},
	//		13:  EventConfig{ID: 13, Name: "rt_sigaction", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "rt_sigaction"},
	//		14:  EventConfig{ID: 14, Name: "rt_sigprocmask", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "rt_sigprocmask"},
	//		15:  EventConfig{ID: 15, Name: "rt_sigreturn", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "rt_sigreturn"},
	16: EventConfig{ID: 16, Name: "ioctl", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "ioctl"},
	//		17:  EventConfig{ID: 17, Name: "pread64", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "pread64"},
	//		18:  EventConfig{ID: 18, Name: "pwrite64", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "pwrite64"},
	//		19:  EventConfig{ID: 19, Name: "readv", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "readv"},
	//		20:  EventConfig{ID: 20, Name: "writev", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "writev"},
	21: EventConfig{ID: 21, Name: "access", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "access"},
	//		22:  EventConfig{ID: 22, Name: "pipe", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "pipe"},
	//		23:  EventConfig{ID: 23, Name: "select", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "select"},
	//		24:  EventConfig{ID: 24, Name: "sched_yield", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "sched_yield"},
	//		25:  EventConfig{ID: 25, Name: "mremap", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "mremap"},
	//		26:  EventConfig{ID: 26, Name: "msync", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "msync"},
	//		27:  EventConfig{ID: 27, Name: "mincore", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "mincore"},
	//		28:  EventConfig{ID: 28, Name: "madvise", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "madvise"},
	//		29:  EventConfig{ID: 29, Name: "shmget", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "shmget"},
	//		30:  EventConfig{ID: 30, Name: "shmat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "shmat"},
	//		31:  EventConfig{ID: 31, Name: "shmctl", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "shmctl"},
	32: EventConfig{ID: 32, Name: "dup", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "dup"},
	33: EventConfig{ID: 33, Name: "dup2", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "dup2"},
	//		34:  EventConfig{ID: 34, Name: "pause", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "pause"},
	//		35:  EventConfig{ID: 35, Name: "nanosleep", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "nanosleep"},
	//		36:  EventConfig{ID: 36, Name: "getitimer", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getitimer"},
	//		37:  EventConfig{ID: 37, Name: "alarm", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "alarm"},
	//		38:  EventConfig{ID: 38, Name: "setitimer", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "setitimer"},
	//		39:  EventConfig{ID: 39, Name: "getpid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getpid"},
	//		40:  EventConfig{ID: 40, Name: "sendfile", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "sendfile"},
	41: EventConfig{ID: 41, Name: "socket", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "socket"},
	42: EventConfig{ID: 42, Name: "connect", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "connect"},
	43: EventConfig{ID: 43, Name: "accept", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "accept"},
	//		44:  EventConfig{ID: 44, Name: "sendto", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "sendto"},
	//		45:  EventConfig{ID: 45, Name: "recvfrom", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "recvfrom"},
	//		46:  EventConfig{ID: 46, Name: "sendmsg", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "sendmsg"},
	//		47:  EventConfig{ID: 47, Name: "recvmsg", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "recvmsg"},
	//		48:  EventConfig{ID: 48, Name: "shutdown", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "shutdown"},
	49: EventConfig{ID: 49, Name: "bind", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "bind"},
	50: EventConfig{ID: 50, Name: "listen", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "listen"},
	51: EventConfig{ID: 51, Name: "getsockname", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getsockname"},
	//		52:  EventConfig{ID: 52, Name: "getpeername", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getpeername"},
	//		53:  EventConfig{ID: 53, Name: "socketpair", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "socketpair"},
	//		54:  EventConfig{ID: 54, Name: "setsockopt", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "setsockopt"},
	//		55:  EventConfig{ID: 55, Name: "getsockopt", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getsockopt"},
	56: EventConfig{ID: 56, Name: "clone", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: true, ProbeName: "clone"},
	57: EventConfig{ID: 57, Name: "fork", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: true, ProbeName: "fork"},
	58: EventConfig{ID: 58, Name: "vfork", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: true, ProbeName: "vfork"},
	59: EventConfig{ID: 59, Name: "execve", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: true, ProbeName: "execve"},
	//		60:  EventConfig{ID: 60, Name: "exit", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "exit"},
	//		61:  EventConfig{ID: 61, Name: "wait4", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "wait4"},
	62: EventConfig{ID: 62, Name: "kill", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "kill"},
	//		63:  EventConfig{ID: 63, Name: "uname", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "uname"},
	//		64:  EventConfig{ID: 64, Name: "semget", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "semget"},
	//		65:  EventConfig{ID: 65, Name: "semop", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "semop"},
	//		66:  EventConfig{ID: 66, Name: "semctl", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "semctl"},
	//		67:  EventConfig{ID: 67, Name: "shmdt", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "shmdt"},
	//		68:  EventConfig{ID: 68, Name: "msgget", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "msgget"},
	//		69:  EventConfig{ID: 69, Name: "msgsnd", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "msgsnd"},
	//		70:  EventConfig{ID: 70, Name: "msgrcv", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "msgrcv"},
	//		71:  EventConfig{ID: 71, Name: "msgctl", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "msgctl"},
	//		72:  EventConfig{ID: 72, Name: "fcntl", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "fcntl"},
	//		73:  EventConfig{ID: 73, Name: "flock", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "flock"},
	//		74:  EventConfig{ID: 74, Name: "fsync", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "fsync"},
	//		75:  EventConfig{ID: 75, Name: "fdatasync", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "fdatasync"},
	//		76:  EventConfig{ID: 76, Name: "truncate", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "truncate"},
	//		77:  EventConfig{ID: 77, Name: "ftruncate", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "ftruncate"},
	78: EventConfig{ID: 78, Name: "getdents", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getdents"},
	//		79:  EventConfig{ID: 79, Name: "getcwd", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getcwd"},
	//		80:  EventConfig{ID: 80, Name: "chdir", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "chdir"},
	//		81:  EventConfig{ID: 81, Name: "fchdir", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "fchdir"},
	//		82:  EventConfig{ID: 82, Name: "rename", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "rename"},
	//		83:  EventConfig{ID: 83, Name: "mkdir", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "mkdir"},
	//		84:  EventConfig{ID: 84, Name: "rmdir", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "rmdir"},
	85: EventConfig{ID: 85, Name: "creat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "creat"},
	//		86:  EventConfig{ID: 86, Name: "link", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "link"},
	87: EventConfig{ID: 87, Name: "unlink", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "unlink"},
	88: EventConfig{ID: 88, Name: "symlink", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "symlink"},
	//		89:  EventConfig{ID: 89, Name: "readlink", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "readlink"},
	90: EventConfig{ID: 90, Name: "chmod", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "chmod"},
	91: EventConfig{ID: 91, Name: "fchmod", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "fchmod"},
	92: EventConfig{ID: 92, Name: "chown", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "chown"},
	93: EventConfig{ID: 93, Name: "fchown", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "fchown"},
	94: EventConfig{ID: 94, Name: "lchown", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "lchown"},
	//		95:  EventConfig{ID: 95, Name: "umask", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "umask"},
	//		96:  EventConfig{ID: 96, Name: "gettimeofday", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "gettimeofday"},
	//		97:  EventConfig{ID: 97, Name: "getrlimit", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getrlimit"},
	//		98:  EventConfig{ID: 98, Name: "getrusage", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getrusage"},
	//		99:  EventConfig{ID: 99, Name: "sysinfo", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "sysinfo"},
	//		100: EventConfig{ID: 100, Name: "times", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "times"},
	101: EventConfig{ID: 101, Name: "ptrace", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "ptrace"},
	//		102: EventConfig{ID: 102, Name: "getuid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getuid"},
	//		103: EventConfig{ID: 103, Name: "syslog", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "syslog"},
	//		104: EventConfig{ID: 104, Name: "getgid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getgid"},
	105: EventConfig{ID: 105, Name: "setuid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "setuid"},
	106: EventConfig{ID: 106, Name: "setgid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "setgid"},
	//		107: EventConfig{ID: 107, Name: "geteuid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "geteuid"},
	//		108: EventConfig{ID: 108, Name: "getegid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getegid"},
	//		109: EventConfig{ID: 109, Name: "setpgid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "setpgid"},
	//		110: EventConfig{ID: 110, Name: "getppid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getppid"},
	//		111: EventConfig{ID: 111, Name: "getpgrp", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getpgrp"},
	//		112: EventConfig{ID: 112, Name: "setsid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "setsid"},
	113: EventConfig{ID: 113, Name: "setreuid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "setreuid"},
	114: EventConfig{ID: 114, Name: "setregid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "setregid"},
	//		115: EventConfig{ID: 115, Name: "getgroups", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getgroups"},
	//		116: EventConfig{ID: 116, Name: "setgroups", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "setgroups"},
	//		117: EventConfig{ID: 117, Name: "setresuid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "setresuid"},
	//		118: EventConfig{ID: 118, Name: "getresuid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getresuid"},
	//		119: EventConfig{ID: 119, Name: "setresgid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "setresgid"},
	//		120: EventConfig{ID: 120, Name: "getresgid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getresgid"},
	//		121: EventConfig{ID: 121, Name: "getpgid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getpgid"},
	122: EventConfig{ID: 122, Name: "setfsuid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "setfsuid"},
	123: EventConfig{ID: 123, Name: "setfsgid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "setfsgid"},
	//		124: EventConfig{ID: 124, Name: "getsid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getsid"},
	//		125: EventConfig{ID: 125, Name: "capget", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "capget"},
	//		126: EventConfig{ID: 126, Name: "capset", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "capset"},
	//		127: EventConfig{ID: 127, Name: "rt_sigpending", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "rt_sigpending"},
	//		128: EventConfig{ID: 128, Name: "rt_sigtimedwait", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "rt_sigtimedwait"},
	//		129: EventConfig{ID: 129, Name: "rt_sigqueueinfo", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "rt_sigqueueinfo"},
	//		130: EventConfig{ID: 130, Name: "rt_sigsuspend", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "rt_sigsuspend"},
	//		131: EventConfig{ID: 131, Name: "sigaltstack", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "sigaltstack"},
	//		132: EventConfig{ID: 132, Name: "utime", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "utime"},
	133: EventConfig{ID: 133, Name: "mknod", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "mknod"},
	//		134: EventConfig{ID: 134, Name: "uselib", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "uselib"},
	//		135: EventConfig{ID: 135, Name: "personality", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "personality"},
	//		136: EventConfig{ID: 136, Name: "ustat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "ustat"},
	//		137: EventConfig{ID: 137, Name: "statfs", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "statfs"},
	//		138: EventConfig{ID: 138, Name: "fstatfs", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "fstatfs"},
	//		139: EventConfig{ID: 139, Name: "sysfs", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "sysfs"},
	//		140: EventConfig{ID: 140, Name: "getpriority", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getpriority"},
	//		141: EventConfig{ID: 141, Name: "setpriority", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "setpriority"},
	//		142: EventConfig{ID: 142, Name: "sched_setparam", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "sched_setparam"},
	//		143: EventConfig{ID: 143, Name: "sched_getparam", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "sched_getparam"},
	//		144: EventConfig{ID: 144, Name: "sched_setscheduler", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "sched_setscheduler"},
	//		145: EventConfig{ID: 145, Name: "sched_getscheduler", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "sched_getscheduler"},
	//		146: EventConfig{ID: 146, Name: "sched_get_priority_max", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "sched_get_priority_max"},
	//		147: EventConfig{ID: 147, Name: "sched_get_priority_min", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "sched_get_priority_min"},
	//		148: EventConfig{ID: 148, Name: "sched_rr_get_interval", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "sched_rr_get_interval"},
	//		149: EventConfig{ID: 149, Name: "mlock", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "mlock"},
	//		150: EventConfig{ID: 150, Name: "munlock", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "munlock"},
	//		151: EventConfig{ID: 151, Name: "mlockall", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "mlockall"},
	//		152: EventConfig{ID: 152, Name: "munlockall", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "munlockall"},
	//		153: EventConfig{ID: 153, Name: "vhangup", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "vhangup"},
	//		154: EventConfig{ID: 154, Name: "modify_ldt", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "modify_ldt"},
	//		155: EventConfig{ID: 155, Name: "pivot_root", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "pivot_root"},
	//		156: EventConfig{ID: 156, Name: "sysctl", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "sysctl"},
	157: EventConfig{ID: 157, Name: "prctl", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "prctl"},
	//		158: EventConfig{ID: 158, Name: "arch_prctl", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "arch_prctl"},
	//		159: EventConfig{ID: 159, Name: "adjtimex", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "adjtimex"},
	//		160: EventConfig{ID: 160, Name: "setrlimit", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "setrlimit"},
	//		161: EventConfig{ID: 161, Name: "chroot", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "chroot"},
	//		162: EventConfig{ID: 162, Name: "sync", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "sync"},
	//		163: EventConfig{ID: 163, Name: "acct", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "acct"},
	//		164: EventConfig{ID: 164, Name: "settimeofday", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "settimeofday"},
	165: EventConfig{ID: 165, Name: "mount", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "mount"},
	166: EventConfig{ID: 166, Name: "umount", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "umount"},
	//		167: EventConfig{ID: 167, Name: "swapon", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "swapon"},
	//		168: EventConfig{ID: 168, Name: "swapoff", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "swapoff"},
	//		169: EventConfig{ID: 169, Name: "reboot", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "reboot"},
	//		170: EventConfig{ID: 170, Name: "sethostname", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "sethostname"},
	//		171: EventConfig{ID: 171, Name: "setdomainname", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "setdomainname"},
	//		172: EventConfig{ID: 172, Name: "iopl", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "iopl"},
	//		173: EventConfig{ID: 173, Name: "ioperm", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "ioperm"},
	//		174: EventConfig{ID: 174, Name: "create_module", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "create_module"},
	175: EventConfig{ID: 175, Name: "init_module", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "init_module"},
	176: EventConfig{ID: 176, Name: "delete_module", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "delete_module"},
	//		177: EventConfig{ID: 177, Name: "get_kernel_syms", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "get_kernel_syms"},
	//		178: EventConfig{ID: 178, Name: "query_module", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "query_module"},
	//		179: EventConfig{ID: 179, Name: "quotactl", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "quotactl"},
	//		180: EventConfig{ID: 180, Name: "nfsservctl", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "nfsservctl"},
	//		181: EventConfig{ID: 181, Name: "getpmsg", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getpmsg"},
	//		182: EventConfig{ID: 182, Name: "putpmsg", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "putpmsg"},
	//		183: EventConfig{ID: 183, Name: "afs", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "afs"},
	//		184: EventConfig{ID: 184, Name: "tuxcall", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "tuxcall"},
	//		185: EventConfig{ID: 185, Name: "security", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "security"},
	//		186: EventConfig{ID: 186, Name: "gettid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "gettid"},
	//		187: EventConfig{ID: 187, Name: "readahead", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "readahead"},
	//		188: EventConfig{ID: 188, Name: "setxattr", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "setxattr"},
	//		189: EventConfig{ID: 189, Name: "lsetxattr", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "lsetxattr"},
	//		190: EventConfig{ID: 190, Name: "fsetxattr", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "fsetxattr"},
	//		191: EventConfig{ID: 191, Name: "getxattr", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getxattr"},
	//		192: EventConfig{ID: 192, Name: "lgetxattr", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "lgetxattr"},
	//		193: EventConfig{ID: 193, Name: "fgetxattr", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "fgetxattr"},
	//		194: EventConfig{ID: 194, Name: "listxattr", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "listxattr"},
	//		195: EventConfig{ID: 195, Name: "llistxattr", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "llistxattr"},
	//		196: EventConfig{ID: 196, Name: "flistxattr", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "flistxattr"},
	//		197: EventConfig{ID: 197, Name: "removexattr", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "removexattr"},
	//		198: EventConfig{ID: 198, Name: "lremovexattr", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "lremovexattr"},
	//		199: EventConfig{ID: 199, Name: "fremovexattr", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "fremovexattr"},
	//		200: EventConfig{ID: 200, Name: "tkill", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "tkill"},
	//		201: EventConfig{ID: 201, Name: "time", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "time"},
	//		202: EventConfig{ID: 202, Name: "futex", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "futex"},
	//		203: EventConfig{ID: 203, Name: "sched_setaffinity", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "sched_setaffinity"},
	//		204: EventConfig{ID: 204, Name: "sched_getaffinity", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "sched_getaffinity"},
	//		205: EventConfig{ID: 205, Name: "set_thread_area", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "set_thread_area"},
	//		206: EventConfig{ID: 206, Name: "io_setup", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "io_setup"},
	//		207: EventConfig{ID: 207, Name: "io_destroy", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "io_destroy"},
	//		208: EventConfig{ID: 208, Name: "io_getevents", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "io_getevents"},
	//		209: EventConfig{ID: 209, Name: "io_submit", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "io_submit"},
	//		210: EventConfig{ID: 210, Name: "io_cancel", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "io_cancel"},
	//		211: EventConfig{ID: 211, Name: "get_thread_area", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "get_thread_area"},
	//		212: EventConfig{ID: 212, Name: "lookup_dcookie", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "lookup_dcookie"},
	//		213: EventConfig{ID: 213, Name: "epoll_create", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "epoll_create"},
	//		214: EventConfig{ID: 214, Name: "epoll_ctl_old", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "epoll_ctl_old"},
	//		215: EventConfig{ID: 215, Name: "epoll_wait_old", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "epoll_wait_old"},
	//		216: EventConfig{ID: 216, Name: "remap_file_pages", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "remap_file_pages"},
	217: EventConfig{ID: 217, Name: "getdents64", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getdents64"},
	//		218: EventConfig{ID: 218, Name: "set_tid_address", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "set_tid_address"},
	//		219: EventConfig{ID: 219, Name: "restart_syscall", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "restart_syscall"},
	//		220: EventConfig{ID: 220, Name: "semtimedop", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "semtimedop"},
	//		221: EventConfig{ID: 221, Name: "fadvise64", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "fadvise64"},
	//		222: EventConfig{ID: 222, Name: "timer_create", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "timer_create"},
	//		223: EventConfig{ID: 223, Name: "timer_settime", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "timer_settime"},
	//		224: EventConfig{ID: 224, Name: "timer_gettime", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "timer_gettime"},
	//		225: EventConfig{ID: 225, Name: "timer_getoverrun", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "timer_getoverrun"},
	//		226: EventConfig{ID: 226, Name: "timer_delete", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "timer_delete"},
	//		227: EventConfig{ID: 227, Name: "clock_settime", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "clock_settime"},
	//		228: EventConfig{ID: 228, Name: "clock_gettime", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "clock_gettime"},
	//		229: EventConfig{ID: 229, Name: "clock_getres", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "clock_getres"},
	//		230: EventConfig{ID: 230, Name: "clock_nanosleep", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "clock_nanosleep"},
	//		231: EventConfig{ID: 231, Name: "exit_group", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "exit_group"},
	//		232: EventConfig{ID: 232, Name: "epoll_wait", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "epoll_wait"},
	//		233: EventConfig{ID: 233, Name: "epoll_ctl", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "epoll_ctl"},
	//		234: EventConfig{ID: 234, Name: "tgkill", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "tgkill"},
	//		235: EventConfig{ID: 235, Name: "utimes", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "utimes"},
	//		236: EventConfig{ID: 236, Name: "vserver", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "vserver"},
	//		237: EventConfig{ID: 237, Name: "mbind", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "mbind"},
	//		238: EventConfig{ID: 238, Name: "set_mempolicy", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "set_mempolicy"},
	//		239: EventConfig{ID: 239, Name: "get_mempolicy", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "get_mempolicy"},
	//		240: EventConfig{ID: 240, Name: "mq_open", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "mq_open"},
	//		241: EventConfig{ID: 241, Name: "mq_unlink", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "mq_unlink"},
	//		242: EventConfig{ID: 242, Name: "mq_timedsend", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "mq_timedsend"},
	//		243: EventConfig{ID: 243, Name: "mq_timedreceive", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "mq_timedreceive"},
	//		244: EventConfig{ID: 244, Name: "mq_notify", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "mq_notify"},
	//		245: EventConfig{ID: 245, Name: "mq_getsetattr", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "mq_getsetattr"},
	//		246: EventConfig{ID: 246, Name: "kexec_load", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "kexec_load"},
	//		247: EventConfig{ID: 247, Name: "waitid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "waitid"},
	//		248: EventConfig{ID: 248, Name: "add_key", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "add_key"},
	//		249: EventConfig{ID: 249, Name: "request_key", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "request_key"},
	//		250: EventConfig{ID: 250, Name: "keyctl", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "keyctl"},
	//		251: EventConfig{ID: 251, Name: "ioprio_set", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "ioprio_set"},
	//		252: EventConfig{ID: 252, Name: "ioprio_get", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "ioprio_get"},
	//		253: EventConfig{ID: 253, Name: "inotify_init", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "inotify_init"},
	//		254: EventConfig{ID: 254, Name: "inotify_add_watch", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "inotify_add_watch"},
	//		255: EventConfig{ID: 255, Name: "inotify_rm_watch", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "inotify_rm_watch"},
	//		256: EventConfig{ID: 256, Name: "migrate_pages", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "migrate_pages"},
	257: EventConfig{ID: 257, Name: "openat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "openat"},
	//		258: EventConfig{ID: 258, Name: "mkdirat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "mkdirat"},
	259: EventConfig{ID: 259, Name: "mknodat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "mknodat"},
	260: EventConfig{ID: 260, Name: "fchownat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "fchownat"},
	//		261: EventConfig{ID: 261, Name: "futimesat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "futimesat"},
	//		262: EventConfig{ID: 262, Name: "newfstatat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "newfstatat"},
	263: EventConfig{ID: 263, Name: "unlinkat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "unlinkat"},
	//		264: EventConfig{ID: 264, Name: "renameat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "renameat"},
	//		265: EventConfig{ID: 265, Name: "linkat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "linkat"},
	266: EventConfig{ID: 266, Name: "symlinkat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "symlinkat"},
	//		267: EventConfig{ID: 267, Name: "readlinkat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "readlinkat"},
	268: EventConfig{ID: 268, Name: "fchmodat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "fchmodat"},
	269: EventConfig{ID: 269, Name: "faccessat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "faccessat"},
	//		270: EventConfig{ID: 270, Name: "pselect6", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "pselect6"},
	//		271: EventConfig{ID: 271, Name: "ppoll", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "ppoll"},
	//		272: EventConfig{ID: 272, Name: "unshare", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "unshare"},
	//		273: EventConfig{ID: 273, Name: "set_robust_list", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "set_robust_list"},
	//		274: EventConfig{ID: 274, Name: "get_robust_list", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "get_robust_list"},
	//		275: EventConfig{ID: 275, Name: "splice", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "splice"},
	//		276: EventConfig{ID: 276, Name: "tee", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "tee"},
	//		277: EventConfig{ID: 277, Name: "sync_file_range", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "sync_file_range"},
	//		278: EventConfig{ID: 278, Name: "vmsplice", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "vmsplice"},
	//		279: EventConfig{ID: 279, Name: "move_pages", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "move_pages"},
	//		280: EventConfig{ID: 280, Name: "utimensat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "utimensat"},
	//		281: EventConfig{ID: 281, Name: "epoll_pwait", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "epoll_pwait"},
	//		282: EventConfig{ID: 282, Name: "signalfd", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "signalfd"},
	//		283: EventConfig{ID: 283, Name: "timerfd_create", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "timerfd_create"},
	//		284: EventConfig{ID: 284, Name: "eventfd", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "eventfd"},
	//		285: EventConfig{ID: 285, Name: "fallocate", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "fallocate"},
	//		286: EventConfig{ID: 286, Name: "timerfd_settime", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "timerfd_settime"},
	//		287: EventConfig{ID: 287, Name: "timerfd_gettime", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "timerfd_gettime"},
	288: EventConfig{ID: 288, Name: "accept4", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "accept4"},
	//		289: EventConfig{ID: 289, Name: "signalfd4", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "signalfd4"},
	//		290: EventConfig{ID: 290, Name: "eventfd2", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "eventfd2"},
	//		291: EventConfig{ID: 291, Name: "epoll_create1", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "epoll_create1"},
	292: EventConfig{ID: 292, Name: "dup3", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "dup3"},
	//		293: EventConfig{ID: 293, Name: "pipe2", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "pipe2"},
	//		294: EventConfig{ID: 294, Name: "ionotify_init1", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "ionotify_init1"},
	//		295: EventConfig{ID: 295, Name: "preadv", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "preadv"},
	//		296: EventConfig{ID: 296, Name: "pwritev", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "pwritev"},
	//		297: EventConfig{ID: 297, Name: "rt_tgsigqueueinfo", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "rt_tgsigqueueinfo"},
	//		298: EventConfig{ID: 298, Name: "perf_event_open", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "perf_event_open"},
	//		299: EventConfig{ID: 299, Name: "recvmmsg", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "recvmmsg"},
	//		300: EventConfig{ID: 300, Name: "fanotify_init", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "fanotify_init"},
	//		301: EventConfig{ID: 301, Name: "fanotify_mark", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "fanotify_mark"},
	//		302: EventConfig{ID: 302, Name: "prlimit64", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "prlimit64"},
	//		303: EventConfig{ID: 303, Name: "name_tohandle_at", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "name_tohandle_at"},
	//		304: EventConfig{ID: 304, Name: "open_by_handle_at", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "open_by_handle_at"},
	//		305: EventConfig{ID: 305, Name: "clock_adjtime", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "clock_adjtime"},
	//		306: EventConfig{ID: 306, Name: "sycnfs", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "sycnfs"},
	//		307: EventConfig{ID: 307, Name: "sendmmsg", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "sendmmsg"},
	//		308: EventConfig{ID: 308, Name: "setns", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "setns"},
	//		309: EventConfig{ID: 309, Name: "getcpu", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getcpu"},
	310: EventConfig{ID: 310, Name: "process_vm_readv", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "process_vm_readv"},
	311: EventConfig{ID: 311, Name: "process_vm_writev", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "process_vm_writev"},
	//		312: EventConfig{ID: 312, Name: "kcmp", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "kcmp"},
	313: EventConfig{ID: 313, Name: "finit_module", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "finit_module"},
	//		314: EventConfig{ID: 314, Name: "sched_setattr", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "sched_setattr"},
	//		315: EventConfig{ID: 315, Name: "sched_getattr", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "sched_getattr"},
	//		316: EventConfig{ID: 316, Name: "renameat2", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "renameat2"},
	//		317: EventConfig{ID: 317, Name: "seccomp", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "seccomp"},
	//		318: EventConfig{ID: 318, Name: "getrandom", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getrandom"},
	319: EventConfig{ID: 319, Name: "memfd_create", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "memfd_create"},
	//		320: EventConfig{ID: 320, Name: "kexec_file_load", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "kexec_file_load"},
	//		321: EventConfig{ID: 321, Name: "bpf", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "bpf"},
	322: EventConfig{ID: 322, Name: "execveat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: true, ProbeName: "execveat"},
	//		323: EventConfig{ID: 323, Name: "userfaultfd", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "userfaultfd"},
	//		324: EventConfig{ID: 324, Name: "membarrier", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "membarrier"},
	//		325: EventConfig{ID: 325, Name: "mlock2", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "mlock2"},
	//		326: EventConfig{ID: 326, Name: "copy_file_range", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "copy_file_range"},
	//		327: EventConfig{ID: 327, Name: "preadv2", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "preadv2"},
	//		328: EventConfig{ID: 328, Name: "pwritev2", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "pwritev2"},
	329: EventConfig{ID: 329, Name: "pkey_mprotect", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "pkey_mprotect"},
	//		330: EventConfig{ID: 330, Name: "pkey_alloc", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "pkey_alloc"},
	//		331: EventConfig{ID: 331, Name: "pkey_free", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "pkey_free"},
	//		332: EventConfig{ID: 332, Name: "statx", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "statx"},
	//		333: EventConfig{ID: 333, Name: "io_pgetevents", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "io_pgetevents"},
	//		334: EventConfig{ID: 334, Name: "rseq", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "rseq"},
	//		335: EventConfig{ID: 335, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "reserved"},
	//		336: EventConfig{ID: 336, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "reserved"},
	//		337: EventConfig{ID: 337, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "reserved"},
	//		338: EventConfig{ID: 338, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "reserved"},
	//		339: EventConfig{ID: 339, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "reserved"},
	//		340: EventConfig{ID: 340, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "reserved"},
	//		341: EventConfig{ID: 341, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "reserved"},
	//		342: EventConfig{ID: 342, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "reserved"},
	//		343: EventConfig{ID: 343, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "reserved"},
	//		344: EventConfig{ID: 344, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "reserved"},
	//		345: EventConfig{ID: 345, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "reserved"},
	//		346: EventConfig{ID: 346, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "reserved"},
	//		347: EventConfig{ID: 347, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "reserved"},
	//		348: EventConfig{ID: 348, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "reserved"},
	//		349: EventConfig{ID: 349, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "reserved"},
	350: EventConfig{ID: 350, Name: "raw_syscalls", AttachMechanism: TRACEPOINT, EnabledByDefault: false, EssentialEvent: false, ProbeName: "sys_enter"},
	351: EventConfig{ID: 351, Name: "do_exit", AttachMechanism: KPROBE, EnabledByDefault: true, EssentialEvent: true, ProbeName: "do_exit"},
	352: EventConfig{ID: 352, Name: "cap_capable", AttachMechanism: KPROBE, EnabledByDefault: true, EssentialEvent: false, ProbeName: "cap_capable"},
	353: EventConfig{ID: 353, Name: "security_bprm_check", AttachMechanism: KPROBE, EnabledByDefault: true, EssentialEvent: false, ProbeName: "security_bprm_check"},
	354: EventConfig{ID: 354, Name: "security_file_open", AttachMechanism: KPROBE, EnabledByDefault: true, EssentialEvent: false, ProbeName: "security_file_open"},
	355: EventConfig{ID: 355, Name: "vfs_write", AttachMechanism: KPROBE_KRETPROBE, EnabledByDefault: true, EssentialEvent: false, ProbeName: "vfs_write"},
}

// EventsIDToName holds all the events that tracee can trace, indexed by their ID
var EventsIDToName map[int32]string

// EventsNameToID holds all the events that tracee can trace, indexed by their Name
var EventsNameToID map[string]int32

func init() {
	len := len(EventsIDToEvent)
	EventsIDToName = make(map[int32]string, len)
	EventsNameToID = make(map[string]int32, len)
	for id, event := range EventsIDToEvent {
		EventsIDToName[id] = event.Name
		EventsNameToID[event.Name] = event.ID
	}
}

// essentialEvents is a list of event ids (in EventsIDToName map) that are essential to the operation of tracee and therefore must be traced
// the boolean value is used to indicate if the event were also requested to be traced by the user
var essentialEvents = map[int32]bool{
	335: false, // do_exit
	56:  false, // clone
	57:  false, // fork
	58:  false, // vfork
	59:  false, // execve
	322: false, // execveat
}

type bpfConfig uint32

const (
	CONFIG_CONT_MODE           bpfConfig = 0
	CONFIG_DETECT_ORIG_SYSCALL bpfConfig = 1
	CONFIG_EXEC_ENV            bpfConfig = 2
	CONFIG_CAPTURE_FILES       bpfConfig = 3
)

const (
	TAIL_VFS_WRITE uint32 = 0
	TAIL_SEND_BIN  uint32 = 1
)
