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

// bpfConfig is an enum that include various configurations that can be passed to bpf code
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
	0:   EventConfig{ID: 0, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "read"},
	1:   EventConfig{ID: 1, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "write"},
	2:   EventConfig{ID: 2, Name: "open", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "open"},
	3:   EventConfig{ID: 3, Name: "close", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "close"},
	4:   EventConfig{ID: 4, Name: "newstat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "newstat"},
	5:   EventConfig{ID: 5, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "fstat"},
	6:   EventConfig{ID: 6, Name: "newlstat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "newlstat"},
	7:   EventConfig{ID: 7, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "poll"},
	8:   EventConfig{ID: 8, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "lseek"},
	9:   EventConfig{ID: 9, Name: "mmap", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "mmap"},
	10:  EventConfig{ID: 10, Name: "mprotect", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "mprotect"},
	11:  EventConfig{ID: 11, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "munmap"},
	12:  EventConfig{ID: 12, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "brk"},
	13:  EventConfig{ID: 13, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "rt_sigaction"},
	14:  EventConfig{ID: 14, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "rt_sigprocmask"},
	15:  EventConfig{ID: 15, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "rt_sigreturn"},
	16:  EventConfig{ID: 16, Name: "ioctl", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "ioctl"},
	17:  EventConfig{ID: 17, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "pread64"},
	18:  EventConfig{ID: 18, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "pwrite64"},
	19:  EventConfig{ID: 19, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "readv"},
	20:  EventConfig{ID: 20, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "writev"},
	21:  EventConfig{ID: 21, Name: "access", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "access"},
	22:  EventConfig{ID: 22, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "pipe"},
	23:  EventConfig{ID: 23, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "select"},
	24:  EventConfig{ID: 24, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "sched_yield"},
	25:  EventConfig{ID: 25, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "mremap"},
	26:  EventConfig{ID: 26, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "msync"},
	27:  EventConfig{ID: 27, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "mincore"},
	28:  EventConfig{ID: 28, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "madvise"},
	29:  EventConfig{ID: 29, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "shmget"},
	30:  EventConfig{ID: 30, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "shmat"},
	31:  EventConfig{ID: 31, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "shmctl"},
	32:  EventConfig{ID: 32, Name: "dup", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "dup"},
	33:  EventConfig{ID: 33, Name: "dup2", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "dup2"},
	34:  EventConfig{ID: 34, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "pause"},
	35:  EventConfig{ID: 35, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "nanosleep"},
	36:  EventConfig{ID: 36, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "getitimer"},
	37:  EventConfig{ID: 37, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "alarm"},
	38:  EventConfig{ID: 38, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "setitimer"},
	39:  EventConfig{ID: 39, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "getpid"},
	40:  EventConfig{ID: 40, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "sendfile"},
	41:  EventConfig{ID: 41, Name: "socket", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "socket"},
	42:  EventConfig{ID: 42, Name: "connect", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "connect"},
	43:  EventConfig{ID: 43, Name: "accept", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "accept"},
	44:  EventConfig{ID: 44, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "sendto"},
	45:  EventConfig{ID: 45, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "recvfrom"},
	46:  EventConfig{ID: 46, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "sendmsg"},
	47:  EventConfig{ID: 47, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "recvmsg"},
	48:  EventConfig{ID: 48, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "shutdown"},
	49:  EventConfig{ID: 49, Name: "bind", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "bind"},
	50:  EventConfig{ID: 50, Name: "listen", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "listen"},
	51:  EventConfig{ID: 51, Name: "getsockname", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getsockname"},
	52:  EventConfig{ID: 52, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "getpeername"},
	53:  EventConfig{ID: 53, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "socketpair"},
	54:  EventConfig{ID: 54, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "setsockopt"},
	55:  EventConfig{ID: 55, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "getsockopt"},
	56:  EventConfig{ID: 56, Name: "clone", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: true, ProbeName: "clone"},
	57:  EventConfig{ID: 57, Name: "fork", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: true, ProbeName: "fork"},
	58:  EventConfig{ID: 58, Name: "vfork", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: true, ProbeName: "vfork"},
	59:  EventConfig{ID: 59, Name: "execve", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: true, ProbeName: "execve"},
	60:  EventConfig{ID: 60, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "exit"},
	61:  EventConfig{ID: 61, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "wait4"},
	62:  EventConfig{ID: 62, Name: "kill", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "kill"},
	63:  EventConfig{ID: 63, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "uname"},
	64:  EventConfig{ID: 64, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "semget"},
	65:  EventConfig{ID: 65, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "semop"},
	66:  EventConfig{ID: 66, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "semctl"},
	67:  EventConfig{ID: 67, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "shmdt"},
	68:  EventConfig{ID: 68, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "msgget"},
	69:  EventConfig{ID: 69, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "msgsnd"},
	70:  EventConfig{ID: 70, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "msgrcv"},
	71:  EventConfig{ID: 71, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "msgctl"},
	72:  EventConfig{ID: 72, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "fcntl"},
	73:  EventConfig{ID: 73, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "flock"},
	74:  EventConfig{ID: 74, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "fsync"},
	75:  EventConfig{ID: 75, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "fdatasync"},
	76:  EventConfig{ID: 76, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "truncate"},
	77:  EventConfig{ID: 77, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "ftruncate"},
	78:  EventConfig{ID: 78, Name: "getdents", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getdents"},
	79:  EventConfig{ID: 79, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "getcwd"},
	80:  EventConfig{ID: 80, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "chdir"},
	81:  EventConfig{ID: 81, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "fchdir"},
	82:  EventConfig{ID: 82, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "rename"},
	83:  EventConfig{ID: 83, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "mkdir"},
	84:  EventConfig{ID: 84, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "rmdir"},
	85:  EventConfig{ID: 85, Name: "creat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "creat"},
	86:  EventConfig{ID: 86, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "link"},
	87:  EventConfig{ID: 87, Name: "unlink", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "unlink"},
	88:  EventConfig{ID: 88, Name: "symlink", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "symlink"},
	89:  EventConfig{ID: 89, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "readlink"},
	90:  EventConfig{ID: 90, Name: "chmod", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "chmod"},
	91:  EventConfig{ID: 91, Name: "fchmod", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "fchmod"},
	92:  EventConfig{ID: 92, Name: "chown", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "chown"},
	93:  EventConfig{ID: 93, Name: "fchown", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "fchown"},
	94:  EventConfig{ID: 94, Name: "lchown", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "lchown"},
	95:  EventConfig{ID: 95, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "umask"},
	96:  EventConfig{ID: 96, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "gettimeofday"},
	97:  EventConfig{ID: 97, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "getrlimit"},
	98:  EventConfig{ID: 98, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "getrusage"},
	99:  EventConfig{ID: 99, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "sysinfo"},
	100: EventConfig{ID: 100, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "times"},
	101: EventConfig{ID: 101, Name: "ptrace", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "ptrace"},
	102: EventConfig{ID: 102, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "getuid"},
	103: EventConfig{ID: 103, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "syslog"},
	104: EventConfig{ID: 104, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "getgid"},
	105: EventConfig{ID: 105, Name: "setuid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "setuid"},
	106: EventConfig{ID: 106, Name: "setgid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "setgid"},
	107: EventConfig{ID: 107, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "geteuid"},
	108: EventConfig{ID: 108, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "getegid"},
	109: EventConfig{ID: 109, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "setpgid"},
	110: EventConfig{ID: 110, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "getppid"},
	111: EventConfig{ID: 111, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "getpgrp"},
	112: EventConfig{ID: 112, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "setsid"},
	113: EventConfig{ID: 113, Name: "setreuid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "setreuid"},
	114: EventConfig{ID: 114, Name: "setregid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "setregid"},
	115: EventConfig{ID: 115, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "getgroups"},
	116: EventConfig{ID: 116, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "setgroups"},
	117: EventConfig{ID: 117, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "setresuid"},
	118: EventConfig{ID: 118, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "getresuid"},
	119: EventConfig{ID: 119, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "setresgid"},
	120: EventConfig{ID: 120, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "getresgid"},
	121: EventConfig{ID: 121, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "getpgid"},
	122: EventConfig{ID: 122, Name: "setfsuid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "setfsuid"},
	123: EventConfig{ID: 123, Name: "setfsgid", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "setfsgid"},
	124: EventConfig{ID: 124, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "getsid"},
	125: EventConfig{ID: 125, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "capget"},
	126: EventConfig{ID: 126, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "capset"},
	127: EventConfig{ID: 127, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "rt_sigpending"},
	128: EventConfig{ID: 128, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "rt_sigtimedwait"},
	129: EventConfig{ID: 129, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "rt_sigqueueinfo"},
	130: EventConfig{ID: 130, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "rt_sigsuspend"},
	131: EventConfig{ID: 131, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "sigaltstack"},
	132: EventConfig{ID: 132, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "utime"},
	133: EventConfig{ID: 133, Name: "mknod", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "mknod"},
	134: EventConfig{ID: 134, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "uselib"},
	135: EventConfig{ID: 135, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "personality"},
	136: EventConfig{ID: 136, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "ustat"},
	137: EventConfig{ID: 137, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "statfs"},
	138: EventConfig{ID: 138, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "fstatfs"},
	139: EventConfig{ID: 139, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "sysfs"},
	140: EventConfig{ID: 140, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "getpriority"},
	141: EventConfig{ID: 141, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "setpriority"},
	142: EventConfig{ID: 142, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "sched_setparam"},
	143: EventConfig{ID: 143, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "sched_getparam"},
	144: EventConfig{ID: 144, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "sched_setscheduler"},
	145: EventConfig{ID: 145, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "sched_getscheduler"},
	146: EventConfig{ID: 146, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "sched_get_priority_max"},
	147: EventConfig{ID: 147, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "sched_get_priority_min"},
	148: EventConfig{ID: 148, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "sched_rr_get_interval"},
	149: EventConfig{ID: 149, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "mlock"},
	150: EventConfig{ID: 150, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "munlock"},
	151: EventConfig{ID: 151, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "mlockall"},
	152: EventConfig{ID: 152, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "munlockall"},
	153: EventConfig{ID: 153, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "vhangup"},
	154: EventConfig{ID: 154, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "modify_ldt"},
	155: EventConfig{ID: 155, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "pivot_root"},
	156: EventConfig{ID: 156, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "sysctl"},
	157: EventConfig{ID: 157, Name: "prctl", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "prctl"},
	158: EventConfig{ID: 158, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "arch_prctl"},
	159: EventConfig{ID: 159, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "adjtimex"},
	160: EventConfig{ID: 160, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "setrlimit"},
	161: EventConfig{ID: 161, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "chroot"},
	162: EventConfig{ID: 162, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "sync"},
	163: EventConfig{ID: 163, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "acct"},
	164: EventConfig{ID: 164, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "settimeofday"},
	165: EventConfig{ID: 165, Name: "mount", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "mount"},
	166: EventConfig{ID: 166, Name: "umount", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "umount"},
	167: EventConfig{ID: 167, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "swapon"},
	168: EventConfig{ID: 168, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "swapoff"},
	169: EventConfig{ID: 169, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "reboot"},
	170: EventConfig{ID: 170, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "sethostname"},
	171: EventConfig{ID: 171, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "setdomainname"},
	172: EventConfig{ID: 172, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "iopl"},
	173: EventConfig{ID: 173, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "ioperm"},
	174: EventConfig{ID: 174, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "create_module"},
	175: EventConfig{ID: 175, Name: "init_module", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "init_module"},
	176: EventConfig{ID: 176, Name: "delete_module", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "delete_module"},
	177: EventConfig{ID: 177, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "get_kernel_syms"},
	178: EventConfig{ID: 178, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "query_module"},
	179: EventConfig{ID: 179, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "quotactl"},
	180: EventConfig{ID: 180, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "nfsservctl"},
	181: EventConfig{ID: 181, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "getpmsg"},
	182: EventConfig{ID: 182, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "putpmsg"},
	183: EventConfig{ID: 183, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "afs"},
	184: EventConfig{ID: 184, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "tuxcall"},
	185: EventConfig{ID: 185, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "security"},
	186: EventConfig{ID: 186, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "gettid"},
	187: EventConfig{ID: 187, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "readahead"},
	188: EventConfig{ID: 188, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "setxattr"},
	189: EventConfig{ID: 189, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "lsetxattr"},
	190: EventConfig{ID: 190, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "fsetxattr"},
	191: EventConfig{ID: 191, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "getxattr"},
	192: EventConfig{ID: 192, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "lgetxattr"},
	193: EventConfig{ID: 193, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "fgetxattr"},
	194: EventConfig{ID: 194, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "listxattr"},
	195: EventConfig{ID: 195, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "llistxattr"},
	196: EventConfig{ID: 196, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "flistxattr"},
	197: EventConfig{ID: 197, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "removexattr"},
	198: EventConfig{ID: 198, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "lremovexattr"},
	199: EventConfig{ID: 199, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "fremovexattr"},
	200: EventConfig{ID: 200, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "tkill"},
	201: EventConfig{ID: 201, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "time"},
	202: EventConfig{ID: 202, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "futex"},
	203: EventConfig{ID: 203, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "sched_setaffinity"},
	204: EventConfig{ID: 204, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "sched_getaffinity"},
	205: EventConfig{ID: 205, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "set_thread_area"},
	206: EventConfig{ID: 206, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "io_setup"},
	207: EventConfig{ID: 207, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "io_destroy"},
	208: EventConfig{ID: 208, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "io_getevents"},
	209: EventConfig{ID: 209, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "io_submit"},
	210: EventConfig{ID: 210, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "io_cancel"},
	211: EventConfig{ID: 211, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "get_thread_area"},
	212: EventConfig{ID: 212, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "lookup_dcookie"},
	213: EventConfig{ID: 213, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "epoll_create"},
	214: EventConfig{ID: 214, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "epoll_ctl_old"},
	215: EventConfig{ID: 215, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "epoll_wait_old"},
	216: EventConfig{ID: 216, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "remap_file_pages"},
	217: EventConfig{ID: 217, Name: "getdents64", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "getdents64"},
	218: EventConfig{ID: 218, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "set_tid_address"},
	219: EventConfig{ID: 219, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "restart_syscall"},
	220: EventConfig{ID: 220, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "semtimedop"},
	221: EventConfig{ID: 221, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "fadvise64"},
	222: EventConfig{ID: 222, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "timer_create"},
	223: EventConfig{ID: 223, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "timer_settime"},
	224: EventConfig{ID: 224, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "timer_gettime"},
	225: EventConfig{ID: 225, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "timer_getoverrun"},
	226: EventConfig{ID: 226, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "timer_delete"},
	227: EventConfig{ID: 227, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "clock_settime"},
	228: EventConfig{ID: 228, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "clock_gettime"},
	229: EventConfig{ID: 229, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "clock_getres"},
	230: EventConfig{ID: 230, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "clock_nanosleep"},
	231: EventConfig{ID: 231, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "exit_group"},
	232: EventConfig{ID: 232, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "epoll_wait"},
	233: EventConfig{ID: 233, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "epoll_ctl"},
	234: EventConfig{ID: 234, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "tgkill"},
	235: EventConfig{ID: 235, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "utimes"},
	236: EventConfig{ID: 236, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "vserver"},
	237: EventConfig{ID: 237, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "mbind"},
	238: EventConfig{ID: 238, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "set_mempolicy"},
	239: EventConfig{ID: 239, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "get_mempolicy"},
	240: EventConfig{ID: 240, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "mq_open"},
	241: EventConfig{ID: 241, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "mq_unlink"},
	242: EventConfig{ID: 242, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "mq_timedsend"},
	243: EventConfig{ID: 243, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "mq_timedreceive"},
	244: EventConfig{ID: 244, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "mq_notify"},
	245: EventConfig{ID: 245, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "mq_getsetattr"},
	246: EventConfig{ID: 246, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "kexec_load"},
	247: EventConfig{ID: 247, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "waitid"},
	248: EventConfig{ID: 248, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "add_key"},
	249: EventConfig{ID: 249, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "request_key"},
	250: EventConfig{ID: 250, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "keyctl"},
	251: EventConfig{ID: 251, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "ioprio_set"},
	252: EventConfig{ID: 252, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "ioprio_get"},
	253: EventConfig{ID: 253, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "inotify_init"},
	254: EventConfig{ID: 254, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "inotify_add_watch"},
	255: EventConfig{ID: 255, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "inotify_rm_watch"},
	256: EventConfig{ID: 256, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "migrate_pages"},
	257: EventConfig{ID: 257, Name: "openat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "openat"},
	258: EventConfig{ID: 258, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "mkdirat"},
	259: EventConfig{ID: 259, Name: "mknodat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "mknodat"},
	260: EventConfig{ID: 260, Name: "fchownat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "fchownat"},
	261: EventConfig{ID: 261, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "futimesat"},
	262: EventConfig{ID: 262, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "newfstatat"},
	263: EventConfig{ID: 263, Name: "unlinkat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "unlinkat"},
	264: EventConfig{ID: 264, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "renameat"},
	265: EventConfig{ID: 265, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "linkat"},
	266: EventConfig{ID: 266, Name: "symlinkat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "symlinkat"},
	267: EventConfig{ID: 267, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "readlinkat"},
	268: EventConfig{ID: 268, Name: "fchmodat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "fchmodat"},
	269: EventConfig{ID: 269, Name: "faccessat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "faccessat"},
	270: EventConfig{ID: 270, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "pselect6"},
	271: EventConfig{ID: 271, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "ppoll"},
	272: EventConfig{ID: 272, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "unshare"},
	273: EventConfig{ID: 273, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "set_robust_list"},
	274: EventConfig{ID: 274, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "get_robust_list"},
	275: EventConfig{ID: 275, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "splice"},
	276: EventConfig{ID: 276, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "tee"},
	277: EventConfig{ID: 277, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "sync_file_range"},
	278: EventConfig{ID: 278, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "vmsplice"},
	279: EventConfig{ID: 279, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "move_pages"},
	280: EventConfig{ID: 280, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "utimensat"},
	281: EventConfig{ID: 281, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "epoll_pwait"},
	282: EventConfig{ID: 282, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "signalfd"},
	283: EventConfig{ID: 283, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "timerfd_create"},
	284: EventConfig{ID: 284, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "eventfd"},
	285: EventConfig{ID: 285, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "fallocate"},
	286: EventConfig{ID: 286, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "timerfd_settime"},
	287: EventConfig{ID: 287, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "timerfd_gettime"},
	288: EventConfig{ID: 288, Name: "accept4", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "accept4"},
	289: EventConfig{ID: 289, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "signalfd4"},
	290: EventConfig{ID: 290, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "eventfd2"},
	291: EventConfig{ID: 291, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "epoll_create1"},
	292: EventConfig{ID: 292, Name: "dup3", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "dup3"},
	293: EventConfig{ID: 293, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "pipe2"},
	294: EventConfig{ID: 294, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "ionotify_init1"},
	295: EventConfig{ID: 295, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "preadv"},
	296: EventConfig{ID: 296, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "pwritev"},
	297: EventConfig{ID: 297, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "rt_tgsigqueueinfo"},
	298: EventConfig{ID: 298, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "perf_event_open"},
	299: EventConfig{ID: 299, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "recvmmsg"},
	300: EventConfig{ID: 300, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "fanotify_init"},
	301: EventConfig{ID: 301, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "fanotify_mark"},
	302: EventConfig{ID: 302, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "prlimit64"},
	303: EventConfig{ID: 303, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "name_tohandle_at"},
	304: EventConfig{ID: 304, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "open_by_handle_at"},
	305: EventConfig{ID: 305, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "clock_adjtime"},
	306: EventConfig{ID: 306, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "sycnfs"},
	307: EventConfig{ID: 307, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "sendmmsg"},
	308: EventConfig{ID: 308, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "setns"},
	309: EventConfig{ID: 309, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "getcpu"},
	310: EventConfig{ID: 310, Name: "process_vm_readv", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "process_vm_readv"},
	311: EventConfig{ID: 311, Name: "process_vm_writev", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "process_vm_writev"},
	312: EventConfig{ID: 312, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "kcmp"},
	313: EventConfig{ID: 313, Name: "finit_module", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "finit_module"},
	314: EventConfig{ID: 314, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "sched_setattr"},
	315: EventConfig{ID: 315, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "sched_getattr"},
	316: EventConfig{ID: 316, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "renameat2"},
	317: EventConfig{ID: 317, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "seccomp"},
	318: EventConfig{ID: 318, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "getrandom"},
	319: EventConfig{ID: 319, Name: "memfd_create", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "memfd_create"},
	320: EventConfig{ID: 320, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "kexec_file_load"},
	321: EventConfig{ID: 321, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "bpf"},
	322: EventConfig{ID: 322, Name: "execveat", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: true, ProbeName: "execveat"},
	323: EventConfig{ID: 323, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "userfaultfd"},
	324: EventConfig{ID: 324, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "membarrier"},
	325: EventConfig{ID: 325, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "mlock2"},
	326: EventConfig{ID: 326, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "copy_file_range"},
	327: EventConfig{ID: 327, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "preadv2"},
	328: EventConfig{ID: 328, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "pwritev2"},
	329: EventConfig{ID: 329, Name: "pkey_mprotect", AttachMechanism: SYSCALL, EnabledByDefault: true, EssentialEvent: false, ProbeName: "pkey_mprotect"},
	330: EventConfig{ID: 330, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "pkey_alloc"},
	331: EventConfig{ID: 331, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "pkey_free"},
	332: EventConfig{ID: 332, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "statx"},
	333: EventConfig{ID: 333, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "io_pgetevents"},
	334: EventConfig{ID: 334, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "rseq"},
	335: EventConfig{ID: 335, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "reserved"},
	336: EventConfig{ID: 336, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "reserved"},
	337: EventConfig{ID: 337, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "reserved"},
	338: EventConfig{ID: 338, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "reserved"},
	339: EventConfig{ID: 339, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "reserved"},
	340: EventConfig{ID: 340, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "reserved"},
	341: EventConfig{ID: 341, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "reserved"},
	342: EventConfig{ID: 342, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "reserved"},
	343: EventConfig{ID: 343, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "reserved"},
	344: EventConfig{ID: 344, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "reserved"},
	345: EventConfig{ID: 345, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "reserved"},
	346: EventConfig{ID: 346, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "reserved"},
	347: EventConfig{ID: 347, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "reserved"},
	348: EventConfig{ID: 348, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "reserved"},
	349: EventConfig{ID: 349, Name: "reserved", AttachMechanism: SYSCALL, EnabledByDefault: false, EssentialEvent: false, ProbeName: "reserved"},
	350: EventConfig{ID: 350, Name: "raw_syscalls", AttachMechanism: TRACEPOINT, EnabledByDefault: false, EssentialEvent: false, ProbeName: "sys_enter"},
	351: EventConfig{ID: 351, Name: "do_exit", AttachMechanism: KPROBE, EnabledByDefault: true, EssentialEvent: true, ProbeName: "do_exit"},
	352: EventConfig{ID: 352, Name: "cap_capable", AttachMechanism: KPROBE, EnabledByDefault: true, EssentialEvent: false, ProbeName: "cap_capable"},
	353: EventConfig{ID: 353, Name: "security_bprm_check", AttachMechanism: KPROBE, EnabledByDefault: true, EssentialEvent: false, ProbeName: "security_bprm_check"},
	354: EventConfig{ID: 354, Name: "security_file_open", AttachMechanism: KPROBE, EnabledByDefault: true, EssentialEvent: false, ProbeName: "security_file_open"},
	355: EventConfig{ID: 355, Name: "vfs_write", AttachMechanism: KPROBE_KRETPROBE, EnabledByDefault: true, EssentialEvent: false, ProbeName: "vfs_write"},
}

// EventsNameToID holds all the events that tracee can trace, indexed by their Name
var EventsNameToID map[string]int32

// essentialEvents is a list of event ids (in EventsIDToEvent map) that are essential to the operation of tracee and therefore must be traced
// the boolean value is used to indicate if the event were also requested to be traced by the user
var essentialEvents map[int32]bool

func init() {
	len := len(EventsIDToEvent)
	EventsNameToID = make(map[string]int32, len)
	essentialEvents = make(map[int32]bool, len)
	for id, event := range EventsIDToEvent {
		EventsNameToID[event.Name] = event.ID
		if event.EssentialEvent {
			essentialEvents[id] = false
		}
	}
}
