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
	ALERT_T       ArgType = 23
	TYPE_MAX      ArgType = 255
)

// bpfConfig is an enum that include various configurations that can be passed to bpf code
type bpfConfig uint32

const (
	CONFIG_CONT_MODE           bpfConfig = 0
	CONFIG_DETECT_ORIG_SYSCALL bpfConfig = 1
	CONFIG_EXEC_ENV            bpfConfig = 2
	CONFIG_CAPTURE_FILES       bpfConfig = 3
	CONFIG_EXTRACT_DYN_CODE    bpfConfig = 4
)

const (
	TAIL_VFS_WRITE uint32 = 0
	TAIL_SEND_BIN  uint32 = 1
)

const (
	SEND_VFS_WRITE uint8 = 1
	SEND_MPROTECT  uint8 = 2
)

// ProbeType is an enum that describes the mechanism used to attach the event
type probeType uint8

// Syscall tracepoints are explained here: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#8-system-call-tracepoints
// Kprobes are explained here: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#1-kprobes
// Tracepoints are explained here: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#3-tracepoints
const (
	SYSCALL          probeType = 0
	KPROBE           probeType = 1
	KRETPROBE        probeType = 2
	TRACEPOINT       probeType = 3
)

type probe struct {
	Event  string
	Attach probeType
	Fn     string
}

// EventConfig is a struct describing an event configuration
type EventConfig struct {
	ID               int32
	Name             string
	Probes           []probe
	EnabledByDefault bool
	EssentialEvent   bool
}

// EventsIDToEvent is list of supported events, indexed by their ID
var EventsIDToEvent = map[int32]EventConfig{
	0:   EventConfig{ID: 0, Name: "reserved", Probes: []probe{probe{Event: "read", Attach: SYSCALL, Fn: "read"}}, EnabledByDefault: false, EssentialEvent: false},
	1:   EventConfig{ID: 1, Name: "reserved", Probes: []probe{probe{Event: "write", Attach: SYSCALL, Fn: "write"}} , EnabledByDefault: false, EssentialEvent: false},
	2:   EventConfig{ID: 2, Name: "open", Probes: []probe{probe{Event: "open", Attach: SYSCALL, Fn: "open"}} , EnabledByDefault: true, EssentialEvent: false},
	3:   EventConfig{ID: 3, Name: "close", Probes: []probe{probe{Event: "close", Attach: SYSCALL, Fn: "close"}} , EnabledByDefault: true, EssentialEvent: false},
	4:   EventConfig{ID: 4, Name: "newstat", Probes: []probe{probe{Event: "newstat", Attach: SYSCALL, Fn: "newstat"}} , EnabledByDefault: true, EssentialEvent: false},
	5:   EventConfig{ID: 5, Name: "reserved", Probes: []probe{probe{Event: "fstat", Attach: SYSCALL, Fn: "fstat"}} , EnabledByDefault: false, EssentialEvent: false},
	6:   EventConfig{ID: 6, Name: "newlstat", Probes: []probe{probe{Event: "newlstat", Attach: SYSCALL, Fn: "newlstat"}} , EnabledByDefault: true, EssentialEvent: false},
	7:   EventConfig{ID: 7, Name: "reserved", Probes: []probe{probe{Event: "poll", Attach: SYSCALL, Fn: "poll"}} , EnabledByDefault: false, EssentialEvent: false},
	8:   EventConfig{ID: 8, Name: "reserved", Probes: []probe{probe{Event: "lseek", Attach: SYSCALL, Fn: "lseek"}} , EnabledByDefault: false, EssentialEvent: false},
	9:   EventConfig{ID: 9, Name: "mmap", Probes: []probe{probe{Event: "mmap", Attach: SYSCALL, Fn: "mmap"}} , EnabledByDefault: true, EssentialEvent: false},
	10:  EventConfig{ID: 10, Name: "mprotect", Probes: []probe{probe{Event: "mprotect", Attach: SYSCALL, Fn: "mprotect"}} , EnabledByDefault: true, EssentialEvent: false},
	11:  EventConfig{ID: 11, Name: "reserved", Probes: []probe{probe{Event: "munmap", Attach: SYSCALL, Fn: "munmap"}} , EnabledByDefault: false, EssentialEvent: false},
	12:  EventConfig{ID: 12, Name: "reserved", Probes: []probe{probe{Event: "brk", Attach: SYSCALL, Fn: "brk"}} , EnabledByDefault: false, EssentialEvent: false},
	13:  EventConfig{ID: 13, Name: "reserved", Probes: []probe{probe{Event: "rt_sigaction", Attach: SYSCALL, Fn: "rt_sigaction"}} , EnabledByDefault: false, EssentialEvent: false},
	14:  EventConfig{ID: 14, Name: "reserved", Probes: []probe{probe{Event: "rt_sigprocmask", Attach: SYSCALL, Fn: "rt_sigprocmask"}} , EnabledByDefault: false, EssentialEvent: false},
	15:  EventConfig{ID: 15, Name: "reserved", Probes: []probe{probe{Event: "rt_sigreturn", Attach: SYSCALL, Fn: "rt_sigreturn"}} , EnabledByDefault: false, EssentialEvent: false},
	16:  EventConfig{ID: 16, Name: "ioctl", Probes: []probe{probe{Event: "ioctl", Attach: SYSCALL, Fn: "ioctl"}} , EnabledByDefault: true, EssentialEvent: false},
	17:  EventConfig{ID: 17, Name: "reserved", Probes: []probe{probe{Event: "pread64", Attach: SYSCALL, Fn: "pread64"}} , EnabledByDefault: false, EssentialEvent: false},
	18:  EventConfig{ID: 18, Name: "reserved", Probes: []probe{probe{Event: "pwrite64", Attach: SYSCALL, Fn: "pwrite64"}} , EnabledByDefault: false, EssentialEvent: false},
	19:  EventConfig{ID: 19, Name: "reserved", Probes: []probe{probe{Event: "readv", Attach: SYSCALL, Fn: "readv"}} , EnabledByDefault: false, EssentialEvent: false},
	20:  EventConfig{ID: 20, Name: "reserved", Probes: []probe{probe{Event: "writev", Attach: SYSCALL, Fn: "writev"}} , EnabledByDefault: false, EssentialEvent: false},
	21:  EventConfig{ID: 21, Name: "access", Probes: []probe{probe{Event: "access", Attach: SYSCALL, Fn: "access"}} , EnabledByDefault: true, EssentialEvent: false},
	22:  EventConfig{ID: 22, Name: "reserved", Probes: []probe{probe{Event: "pipe", Attach: SYSCALL, Fn: "pipe"}} , EnabledByDefault: false, EssentialEvent: false},
	23:  EventConfig{ID: 23, Name: "reserved", Probes: []probe{probe{Event: "select", Attach: SYSCALL, Fn: "select"}} , EnabledByDefault: false, EssentialEvent: false},
	24:  EventConfig{ID: 24, Name: "reserved", Probes: []probe{probe{Event: "sched_yield", Attach: SYSCALL, Fn: "sched_yield"}} , EnabledByDefault: false, EssentialEvent: false},
	25:  EventConfig{ID: 25, Name: "reserved", Probes: []probe{probe{Event: "mremap", Attach: SYSCALL, Fn: "mremap"}} , EnabledByDefault: false, EssentialEvent: false},
	26:  EventConfig{ID: 26, Name: "reserved", Probes: []probe{probe{Event: "msync", Attach: SYSCALL, Fn: "msync"}} , EnabledByDefault: false, EssentialEvent: false},
	27:  EventConfig{ID: 27, Name: "reserved", Probes: []probe{probe{Event: "mincore", Attach: SYSCALL, Fn: "mincore"}} , EnabledByDefault: false, EssentialEvent: false},
	28:  EventConfig{ID: 28, Name: "reserved", Probes: []probe{probe{Event: "madvise", Attach: SYSCALL, Fn: "madvise"}} , EnabledByDefault: false, EssentialEvent: false},
	29:  EventConfig{ID: 29, Name: "reserved", Probes: []probe{probe{Event: "shmget", Attach: SYSCALL, Fn: "shmget"}} , EnabledByDefault: false, EssentialEvent: false},
	30:  EventConfig{ID: 30, Name: "reserved", Probes: []probe{probe{Event: "shmat", Attach: SYSCALL, Fn: "shmat"}} , EnabledByDefault: false, EssentialEvent: false},
	31:  EventConfig{ID: 31, Name: "reserved", Probes: []probe{probe{Event: "shmctl", Attach: SYSCALL, Fn: "shmctl"}} , EnabledByDefault: false, EssentialEvent: false},
	32:  EventConfig{ID: 32, Name: "dup", Probes: []probe{probe{Event: "dup", Attach: SYSCALL, Fn: "dup"}} , EnabledByDefault: true, EssentialEvent: false},
	33:  EventConfig{ID: 33, Name: "dup2", Probes: []probe{probe{Event: "dup2", Attach: SYSCALL, Fn: "dup2"}} , EnabledByDefault: true, EssentialEvent: false},
	34:  EventConfig{ID: 34, Name: "reserved", Probes: []probe{probe{Event: "pause", Attach: SYSCALL, Fn: "pause"}} , EnabledByDefault: false, EssentialEvent: false},
	35:  EventConfig{ID: 35, Name: "reserved", Probes: []probe{probe{Event: "nanosleep", Attach: SYSCALL, Fn: "nanosleep"}} , EnabledByDefault: false, EssentialEvent: false},
	36:  EventConfig{ID: 36, Name: "reserved", Probes: []probe{probe{Event: "getitimer", Attach: SYSCALL, Fn: "getitimer"}} , EnabledByDefault: false, EssentialEvent: false},
	37:  EventConfig{ID: 37, Name: "reserved", Probes: []probe{probe{Event: "alarm", Attach: SYSCALL, Fn: "alarm"}} , EnabledByDefault: false, EssentialEvent: false},
	38:  EventConfig{ID: 38, Name: "reserved", Probes: []probe{probe{Event: "setitimer", Attach: SYSCALL, Fn: "setitimer"}} , EnabledByDefault: false, EssentialEvent: false},
	39:  EventConfig{ID: 39, Name: "reserved", Probes: []probe{probe{Event: "getpid", Attach: SYSCALL, Fn: "getpid"}} , EnabledByDefault: false, EssentialEvent: false},
	40:  EventConfig{ID: 40, Name: "reserved", Probes: []probe{probe{Event: "sendfile", Attach: SYSCALL, Fn: "sendfile"}} , EnabledByDefault: false, EssentialEvent: false},
	41:  EventConfig{ID: 41, Name: "socket", Probes: []probe{probe{Event: "socket", Attach: SYSCALL, Fn: "socket"}} , EnabledByDefault: true, EssentialEvent: false},
	42:  EventConfig{ID: 42, Name: "connect", Probes: []probe{probe{Event: "connect", Attach: SYSCALL, Fn: "connect"}} , EnabledByDefault: true, EssentialEvent: false},
	43:  EventConfig{ID: 43, Name: "accept", Probes: []probe{probe{Event: "accept", Attach: SYSCALL, Fn: "accept"}} , EnabledByDefault: true, EssentialEvent: false},
	44:  EventConfig{ID: 44, Name: "reserved", Probes: []probe{probe{Event: "sendto", Attach: SYSCALL, Fn: "sendto"}} , EnabledByDefault: false, EssentialEvent: false},
	45:  EventConfig{ID: 45, Name: "reserved", Probes: []probe{probe{Event: "recvfrom", Attach: SYSCALL, Fn: "recvfrom"}} , EnabledByDefault: false, EssentialEvent: false},
	46:  EventConfig{ID: 46, Name: "reserved", Probes: []probe{probe{Event: "sendmsg", Attach: SYSCALL, Fn: "sendmsg"}} , EnabledByDefault: false, EssentialEvent: false},
	47:  EventConfig{ID: 47, Name: "reserved", Probes: []probe{probe{Event: "recvmsg", Attach: SYSCALL, Fn: "recvmsg"}} , EnabledByDefault: false, EssentialEvent: false},
	48:  EventConfig{ID: 48, Name: "reserved", Probes: []probe{probe{Event: "shutdown", Attach: SYSCALL, Fn: "shutdown"}} , EnabledByDefault: false, EssentialEvent: false},
	49:  EventConfig{ID: 49, Name: "bind", Probes: []probe{probe{Event: "bind", Attach: SYSCALL, Fn: "bind"}} , EnabledByDefault: true, EssentialEvent: false},
	50:  EventConfig{ID: 50, Name: "listen", Probes: []probe{probe{Event: "listen", Attach: SYSCALL, Fn: "listen"}} , EnabledByDefault: true, EssentialEvent: false},
	51:  EventConfig{ID: 51, Name: "getsockname", Probes: []probe{probe{Event: "getsockname", Attach: SYSCALL, Fn: "getsockname"}} , EnabledByDefault: true, EssentialEvent: false},
	52:  EventConfig{ID: 52, Name: "reserved", Probes: []probe{probe{Event: "getpeername", Attach: SYSCALL, Fn: "getpeername"}} , EnabledByDefault: false, EssentialEvent: false},
	53:  EventConfig{ID: 53, Name: "reserved", Probes: []probe{probe{Event: "socketpair", Attach: SYSCALL, Fn: "socketpair"}} , EnabledByDefault: false, EssentialEvent: false},
	54:  EventConfig{ID: 54, Name: "reserved", Probes: []probe{probe{Event: "setsockopt", Attach: SYSCALL, Fn: "setsockopt"}} , EnabledByDefault: false, EssentialEvent: false},
	55:  EventConfig{ID: 55, Name: "reserved", Probes: []probe{probe{Event: "getsockopt", Attach: SYSCALL, Fn: "getsockopt"}} , EnabledByDefault: false, EssentialEvent: false},
	56:  EventConfig{ID: 56, Name: "clone", Probes: []probe{probe{Event: "clone", Attach: SYSCALL, Fn: "clone"}} , EnabledByDefault: true, EssentialEvent: true},
	57:  EventConfig{ID: 57, Name: "fork", Probes: []probe{probe{Event: "fork", Attach: SYSCALL, Fn: "fork"}} , EnabledByDefault: true, EssentialEvent: true},
	58:  EventConfig{ID: 58, Name: "vfork", Probes: []probe{probe{Event: "vfork", Attach: SYSCALL, Fn: "vfork"}} , EnabledByDefault: true, EssentialEvent: true},
	59:  EventConfig{ID: 59, Name: "execve", Probes: []probe{probe{Event: "execve", Attach: SYSCALL, Fn: "execve"}} , EnabledByDefault: true, EssentialEvent: true},
	60:  EventConfig{ID: 60, Name: "reserved", Probes: []probe{probe{Event: "exit", Attach: SYSCALL, Fn: "exit"}} , EnabledByDefault: false, EssentialEvent: false},
	61:  EventConfig{ID: 61, Name: "reserved", Probes: []probe{probe{Event: "wait4", Attach: SYSCALL, Fn: "wait4"}} , EnabledByDefault: false, EssentialEvent: false},
	62:  EventConfig{ID: 62, Name: "kill", Probes: []probe{probe{Event: "kill", Attach: SYSCALL, Fn: "kill"}} , EnabledByDefault: true, EssentialEvent: false},
	63:  EventConfig{ID: 63, Name: "reserved", Probes: []probe{probe{Event: "uname", Attach: SYSCALL, Fn: "uname"}} , EnabledByDefault: false, EssentialEvent: false},
	64:  EventConfig{ID: 64, Name: "reserved", Probes: []probe{probe{Event: "semget", Attach: SYSCALL, Fn: "semget"}} , EnabledByDefault: false, EssentialEvent: false},
	65:  EventConfig{ID: 65, Name: "reserved", Probes: []probe{probe{Event: "semop", Attach: SYSCALL, Fn: "semop"}} , EnabledByDefault: false, EssentialEvent: false},
	66:  EventConfig{ID: 66, Name: "reserved", Probes: []probe{probe{Event: "semctl", Attach: SYSCALL, Fn: "semctl"}} , EnabledByDefault: false, EssentialEvent: false},
	67:  EventConfig{ID: 67, Name: "reserved", Probes: []probe{probe{Event: "shmdt", Attach: SYSCALL, Fn: "shmdt"}} , EnabledByDefault: false, EssentialEvent: false},
	68:  EventConfig{ID: 68, Name: "reserved", Probes: []probe{probe{Event: "msgget", Attach: SYSCALL, Fn: "msgget"}} , EnabledByDefault: false, EssentialEvent: false},
	69:  EventConfig{ID: 69, Name: "reserved", Probes: []probe{probe{Event: "msgsnd", Attach: SYSCALL, Fn: "msgsnd"}} , EnabledByDefault: false, EssentialEvent: false},
	70:  EventConfig{ID: 70, Name: "reserved", Probes: []probe{probe{Event: "msgrcv", Attach: SYSCALL, Fn: "msgrcv"}} , EnabledByDefault: false, EssentialEvent: false},
	71:  EventConfig{ID: 71, Name: "reserved", Probes: []probe{probe{Event: "msgctl", Attach: SYSCALL, Fn: "msgctl"}} , EnabledByDefault: false, EssentialEvent: false},
	72:  EventConfig{ID: 72, Name: "reserved", Probes: []probe{probe{Event: "fcntl", Attach: SYSCALL, Fn: "fcntl"}} , EnabledByDefault: false, EssentialEvent: false},
	73:  EventConfig{ID: 73, Name: "reserved", Probes: []probe{probe{Event: "flock", Attach: SYSCALL, Fn: "flock"}} , EnabledByDefault: false, EssentialEvent: false},
	74:  EventConfig{ID: 74, Name: "reserved", Probes: []probe{probe{Event: "fsync", Attach: SYSCALL, Fn: "fsync"}} , EnabledByDefault: false, EssentialEvent: false},
	75:  EventConfig{ID: 75, Name: "reserved", Probes: []probe{probe{Event: "fdatasync", Attach: SYSCALL, Fn: "fdatasync"}} , EnabledByDefault: false, EssentialEvent: false},
	76:  EventConfig{ID: 76, Name: "reserved", Probes: []probe{probe{Event: "truncate", Attach: SYSCALL, Fn: "truncate"}} , EnabledByDefault: false, EssentialEvent: false},
	77:  EventConfig{ID: 77, Name: "reserved", Probes: []probe{probe{Event: "ftruncate", Attach: SYSCALL, Fn: "ftruncate"}} , EnabledByDefault: false, EssentialEvent: false},
	78:  EventConfig{ID: 78, Name: "getdents", Probes: []probe{probe{Event: "getdents", Attach: SYSCALL, Fn: "getdents"}} , EnabledByDefault: true, EssentialEvent: false},
	79:  EventConfig{ID: 79, Name: "reserved", Probes: []probe{probe{Event: "getcwd", Attach: SYSCALL, Fn: "getcwd"}} , EnabledByDefault: false, EssentialEvent: false},
	80:  EventConfig{ID: 80, Name: "reserved", Probes: []probe{probe{Event: "chdir", Attach: SYSCALL, Fn: "chdir"}} , EnabledByDefault: false, EssentialEvent: false},
	81:  EventConfig{ID: 81, Name: "reserved", Probes: []probe{probe{Event: "fchdir", Attach: SYSCALL, Fn: "fchdir"}} , EnabledByDefault: false, EssentialEvent: false},
	82:  EventConfig{ID: 82, Name: "reserved", Probes: []probe{probe{Event: "rename", Attach: SYSCALL, Fn: "rename"}} , EnabledByDefault: false, EssentialEvent: false},
	83:  EventConfig{ID: 83, Name: "reserved", Probes: []probe{probe{Event: "mkdir", Attach: SYSCALL, Fn: "mkdir"}} , EnabledByDefault: false, EssentialEvent: false},
	84:  EventConfig{ID: 84, Name: "reserved", Probes: []probe{probe{Event: "rmdir", Attach: SYSCALL, Fn: "rmdir"}} , EnabledByDefault: false, EssentialEvent: false},
	85:  EventConfig{ID: 85, Name: "creat", Probes: []probe{probe{Event: "creat", Attach: SYSCALL, Fn: "creat"}} , EnabledByDefault: true, EssentialEvent: false},
	86:  EventConfig{ID: 86, Name: "reserved", Probes: []probe{probe{Event: "link", Attach: SYSCALL, Fn: "link"}} , EnabledByDefault: false, EssentialEvent: false},
	87:  EventConfig{ID: 87, Name: "unlink", Probes: []probe{probe{Event: "unlink", Attach: SYSCALL, Fn: "unlink"}} , EnabledByDefault: true, EssentialEvent: false},
	88:  EventConfig{ID: 88, Name: "symlink", Probes: []probe{probe{Event: "symlink", Attach: SYSCALL, Fn: "symlink"}} , EnabledByDefault: true, EssentialEvent: false},
	89:  EventConfig{ID: 89, Name: "reserved", Probes: []probe{probe{Event: "readlink", Attach: SYSCALL, Fn: "readlink"}} , EnabledByDefault: false, EssentialEvent: false},
	90:  EventConfig{ID: 90, Name: "chmod", Probes: []probe{probe{Event: "chmod", Attach: SYSCALL, Fn: "chmod"}} , EnabledByDefault: true, EssentialEvent: false},
	91:  EventConfig{ID: 91, Name: "fchmod", Probes: []probe{probe{Event: "fchmod", Attach: SYSCALL, Fn: "fchmod"}} , EnabledByDefault: true, EssentialEvent: false},
	92:  EventConfig{ID: 92, Name: "chown", Probes: []probe{probe{Event: "chown", Attach: SYSCALL, Fn: "chown"}} , EnabledByDefault: true, EssentialEvent: false},
	93:  EventConfig{ID: 93, Name: "fchown", Probes: []probe{probe{Event: "fchown", Attach: SYSCALL, Fn: "fchown"}} , EnabledByDefault: true, EssentialEvent: false},
	94:  EventConfig{ID: 94, Name: "lchown", Probes: []probe{probe{Event: "lchown", Attach: SYSCALL, Fn: "lchown"}} , EnabledByDefault: true, EssentialEvent: false},
	95:  EventConfig{ID: 95, Name: "reserved", Probes: []probe{probe{Event: "umask", Attach: SYSCALL, Fn: "umask"}} , EnabledByDefault: false, EssentialEvent: false},
	96:  EventConfig{ID: 96, Name: "reserved", Probes: []probe{probe{Event: "gettimeofday", Attach: SYSCALL, Fn: "gettimeofday"}} , EnabledByDefault: false, EssentialEvent: false},
	97:  EventConfig{ID: 97, Name: "reserved", Probes: []probe{probe{Event: "getrlimit", Attach: SYSCALL, Fn: "getrlimit"}} , EnabledByDefault: false, EssentialEvent: false},
	98:  EventConfig{ID: 98, Name: "reserved", Probes: []probe{probe{Event: "getrusage", Attach: SYSCALL, Fn: "getrusage"}} , EnabledByDefault: false, EssentialEvent: false},
	99:  EventConfig{ID: 99, Name: "reserved", Probes: []probe{probe{Event: "sysinfo", Attach: SYSCALL, Fn: "sysinfo"}} , EnabledByDefault: false, EssentialEvent: false},
	100: EventConfig{ID: 100, Name: "reserved", Probes: []probe{probe{Event: "times", Attach: SYSCALL, Fn: "times"}} , EnabledByDefault: false, EssentialEvent: false},
	101: EventConfig{ID: 101, Name: "ptrace", Probes: []probe{probe{Event: "ptrace", Attach: SYSCALL, Fn: "ptrace"}} , EnabledByDefault: true, EssentialEvent: false},
	102: EventConfig{ID: 102, Name: "reserved", Probes: []probe{probe{Event: "getuid", Attach: SYSCALL, Fn: "getuid"}} , EnabledByDefault: false, EssentialEvent: false},
	103: EventConfig{ID: 103, Name: "reserved", Probes: []probe{probe{Event: "syslog", Attach: SYSCALL, Fn: "syslog"}} , EnabledByDefault: false, EssentialEvent: false},
	104: EventConfig{ID: 104, Name: "reserved", Probes: []probe{probe{Event: "getgid", Attach: SYSCALL, Fn: "getgid"}} , EnabledByDefault: false, EssentialEvent: false},
	105: EventConfig{ID: 105, Name: "setuid", Probes: []probe{probe{Event: "setuid", Attach: SYSCALL, Fn: "setuid"}} , EnabledByDefault: true, EssentialEvent: false},
	106: EventConfig{ID: 106, Name: "setgid", Probes: []probe{probe{Event: "setgid", Attach: SYSCALL, Fn: "setgid"}} , EnabledByDefault: true, EssentialEvent: false},
	107: EventConfig{ID: 107, Name: "reserved", Probes: []probe{probe{Event: "geteuid", Attach: SYSCALL, Fn: "geteuid"}} , EnabledByDefault: false, EssentialEvent: false},
	108: EventConfig{ID: 108, Name: "reserved", Probes: []probe{probe{Event: "getegid", Attach: SYSCALL, Fn: "getegid"}} , EnabledByDefault: false, EssentialEvent: false},
	109: EventConfig{ID: 109, Name: "reserved", Probes: []probe{probe{Event: "setpgid", Attach: SYSCALL, Fn: "setpgid"}} , EnabledByDefault: false, EssentialEvent: false},
	110: EventConfig{ID: 110, Name: "reserved", Probes: []probe{probe{Event: "getppid", Attach: SYSCALL, Fn: "getppid"}} , EnabledByDefault: false, EssentialEvent: false},
	111: EventConfig{ID: 111, Name: "reserved", Probes: []probe{probe{Event: "getpgrp", Attach: SYSCALL, Fn: "getpgrp"}} , EnabledByDefault: false, EssentialEvent: false},
	112: EventConfig{ID: 112, Name: "reserved", Probes: []probe{probe{Event: "setsid", Attach: SYSCALL, Fn: "setsid"}} , EnabledByDefault: false, EssentialEvent: false},
	113: EventConfig{ID: 113, Name: "setreuid", Probes: []probe{probe{Event: "setreuid", Attach: SYSCALL, Fn: "setreuid"}} , EnabledByDefault: true, EssentialEvent: false},
	114: EventConfig{ID: 114, Name: "setregid", Probes: []probe{probe{Event: "setregid", Attach: SYSCALL, Fn: "setregid"}} , EnabledByDefault: true, EssentialEvent: false},
	115: EventConfig{ID: 115, Name: "reserved", Probes: []probe{probe{Event: "getgroups", Attach: SYSCALL, Fn: "getgroups"}} , EnabledByDefault: false, EssentialEvent: false},
	116: EventConfig{ID: 116, Name: "reserved", Probes: []probe{probe{Event: "setgroups", Attach: SYSCALL, Fn: "setgroups"}} , EnabledByDefault: false, EssentialEvent: false},
	117: EventConfig{ID: 117, Name: "reserved", Probes: []probe{probe{Event: "setresuid", Attach: SYSCALL, Fn: "setresuid"}} , EnabledByDefault: false, EssentialEvent: false},
	118: EventConfig{ID: 118, Name: "reserved", Probes: []probe{probe{Event: "getresuid", Attach: SYSCALL, Fn: "getresuid"}} , EnabledByDefault: false, EssentialEvent: false},
	119: EventConfig{ID: 119, Name: "reserved", Probes: []probe{probe{Event: "setresgid", Attach: SYSCALL, Fn: "setresgid"}} , EnabledByDefault: false, EssentialEvent: false},
	120: EventConfig{ID: 120, Name: "reserved", Probes: []probe{probe{Event: "getresgid", Attach: SYSCALL, Fn: "getresgid"}} , EnabledByDefault: false, EssentialEvent: false},
	121: EventConfig{ID: 121, Name: "reserved", Probes: []probe{probe{Event: "getpgid", Attach: SYSCALL, Fn: "getpgid"}} , EnabledByDefault: false, EssentialEvent: false},
	122: EventConfig{ID: 122, Name: "setfsuid", Probes: []probe{probe{Event: "setfsuid", Attach: SYSCALL, Fn: "setfsuid"}} , EnabledByDefault: true, EssentialEvent: false},
	123: EventConfig{ID: 123, Name: "setfsgid", Probes: []probe{probe{Event: "setfsgid", Attach: SYSCALL, Fn: "setfsgid"}} , EnabledByDefault: true, EssentialEvent: false},
	124: EventConfig{ID: 124, Name: "reserved", Probes: []probe{probe{Event: "getsid", Attach: SYSCALL, Fn: "getsid"}} , EnabledByDefault: false, EssentialEvent: false},
	125: EventConfig{ID: 125, Name: "reserved", Probes: []probe{probe{Event: "capget", Attach: SYSCALL, Fn: "capget"}} , EnabledByDefault: false, EssentialEvent: false},
	126: EventConfig{ID: 126, Name: "reserved", Probes: []probe{probe{Event: "capset", Attach: SYSCALL, Fn: "capset"}} , EnabledByDefault: false, EssentialEvent: false},
	127: EventConfig{ID: 127, Name: "reserved", Probes: []probe{probe{Event: "rt_sigpending", Attach: SYSCALL, Fn: "rt_sigpending"}} , EnabledByDefault: false, EssentialEvent: false},
	128: EventConfig{ID: 128, Name: "reserved", Probes: []probe{probe{Event: "rt_sigtimedwait", Attach: SYSCALL, Fn: "rt_sigtimedwait"}} , EnabledByDefault: false, EssentialEvent: false},
	129: EventConfig{ID: 129, Name: "reserved", Probes: []probe{probe{Event: "rt_sigqueueinfo", Attach: SYSCALL, Fn: "rt_sigqueueinfo"}} , EnabledByDefault: false, EssentialEvent: false},
	130: EventConfig{ID: 130, Name: "reserved", Probes: []probe{probe{Event: "rt_sigsuspend", Attach: SYSCALL, Fn: "rt_sigsuspend"}} , EnabledByDefault: false, EssentialEvent: false},
	131: EventConfig{ID: 131, Name: "reserved", Probes: []probe{probe{Event: "sigaltstack", Attach: SYSCALL, Fn: "sigaltstack"}} , EnabledByDefault: false, EssentialEvent: false},
	132: EventConfig{ID: 132, Name: "reserved", Probes: []probe{probe{Event: "utime", Attach: SYSCALL, Fn: "utime"}} , EnabledByDefault: false, EssentialEvent: false},
	133: EventConfig{ID: 133, Name: "mknod", Probes: []probe{probe{Event: "mknod", Attach: SYSCALL, Fn: "mknod"}} , EnabledByDefault: true, EssentialEvent: false},
	134: EventConfig{ID: 134, Name: "reserved", Probes: []probe{probe{Event: "uselib", Attach: SYSCALL, Fn: "uselib"}} , EnabledByDefault: false, EssentialEvent: false},
	135: EventConfig{ID: 135, Name: "reserved", Probes: []probe{probe{Event: "personality", Attach: SYSCALL, Fn: "personality"}} , EnabledByDefault: false, EssentialEvent: false},
	136: EventConfig{ID: 136, Name: "reserved", Probes: []probe{probe{Event: "ustat", Attach: SYSCALL, Fn: "ustat"}} , EnabledByDefault: false, EssentialEvent: false},
	137: EventConfig{ID: 137, Name: "reserved", Probes: []probe{probe{Event: "statfs", Attach: SYSCALL, Fn: "statfs"}} , EnabledByDefault: false, EssentialEvent: false},
	138: EventConfig{ID: 138, Name: "reserved", Probes: []probe{probe{Event: "fstatfs", Attach: SYSCALL, Fn: "fstatfs"}} , EnabledByDefault: false, EssentialEvent: false},
	139: EventConfig{ID: 139, Name: "reserved", Probes: []probe{probe{Event: "sysfs", Attach: SYSCALL, Fn: "sysfs"}} , EnabledByDefault: false, EssentialEvent: false},
	140: EventConfig{ID: 140, Name: "reserved", Probes: []probe{probe{Event: "getpriority", Attach: SYSCALL, Fn: "getpriority"}} , EnabledByDefault: false, EssentialEvent: false},
	141: EventConfig{ID: 141, Name: "reserved", Probes: []probe{probe{Event: "setpriority", Attach: SYSCALL, Fn: "setpriority"}} , EnabledByDefault: false, EssentialEvent: false},
	142: EventConfig{ID: 142, Name: "reserved", Probes: []probe{probe{Event: "sched_setparam", Attach: SYSCALL, Fn: "sched_setparam"}} , EnabledByDefault: false, EssentialEvent: false},
	143: EventConfig{ID: 143, Name: "reserved", Probes: []probe{probe{Event: "sched_getparam", Attach: SYSCALL, Fn: "sched_getparam"}} , EnabledByDefault: false, EssentialEvent: false},
	144: EventConfig{ID: 144, Name: "reserved", Probes: []probe{probe{Event: "sched_setscheduler", Attach: SYSCALL, Fn: "sched_setscheduler"}} , EnabledByDefault: false, EssentialEvent: false},
	145: EventConfig{ID: 145, Name: "reserved", Probes: []probe{probe{Event: "sched_getscheduler", Attach: SYSCALL, Fn: "sched_getscheduler"}} , EnabledByDefault: false, EssentialEvent: false},
	146: EventConfig{ID: 146, Name: "reserved", Probes: []probe{probe{Event: "sched_get_priority_max", Attach: SYSCALL, Fn: "sched_get_priority_max"}} , EnabledByDefault: false, EssentialEvent: false},
	147: EventConfig{ID: 147, Name: "reserved", Probes: []probe{probe{Event: "sched_get_priority_min", Attach: SYSCALL, Fn: "sched_get_priority_min"}} , EnabledByDefault: false, EssentialEvent: false},
	148: EventConfig{ID: 148, Name: "reserved", Probes: []probe{probe{Event: "sched_rr_get_interval", Attach: SYSCALL, Fn: "sched_rr_get_interval"}} , EnabledByDefault: false, EssentialEvent: false},
	149: EventConfig{ID: 149, Name: "reserved", Probes: []probe{probe{Event: "mlock", Attach: SYSCALL, Fn: "mlock"}} , EnabledByDefault: false, EssentialEvent: false},
	150: EventConfig{ID: 150, Name: "reserved", Probes: []probe{probe{Event: "munlock", Attach: SYSCALL, Fn: "munlock"}} , EnabledByDefault: false, EssentialEvent: false},
	151: EventConfig{ID: 151, Name: "reserved", Probes: []probe{probe{Event: "mlockall", Attach: SYSCALL, Fn: "mlockall"}} , EnabledByDefault: false, EssentialEvent: false},
	152: EventConfig{ID: 152, Name: "reserved", Probes: []probe{probe{Event: "munlockall", Attach: SYSCALL, Fn: "munlockall"}} , EnabledByDefault: false, EssentialEvent: false},
	153: EventConfig{ID: 153, Name: "reserved", Probes: []probe{probe{Event: "vhangup", Attach: SYSCALL, Fn: "vhangup"}} , EnabledByDefault: false, EssentialEvent: false},
	154: EventConfig{ID: 154, Name: "reserved", Probes: []probe{probe{Event: "modify_ldt", Attach: SYSCALL, Fn: "modify_ldt"}} , EnabledByDefault: false, EssentialEvent: false},
	155: EventConfig{ID: 155, Name: "reserved", Probes: []probe{probe{Event: "pivot_root", Attach: SYSCALL, Fn: "pivot_root"}} , EnabledByDefault: false, EssentialEvent: false},
	156: EventConfig{ID: 156, Name: "reserved", Probes: []probe{probe{Event: "sysctl", Attach: SYSCALL, Fn: "sysctl"}} , EnabledByDefault: false, EssentialEvent: false},
	157: EventConfig{ID: 157, Name: "prctl", Probes: []probe{probe{Event: "prctl", Attach: SYSCALL, Fn: "prctl"}} , EnabledByDefault: true, EssentialEvent: false},
	158: EventConfig{ID: 158, Name: "reserved", Probes: []probe{probe{Event: "arch_prctl", Attach: SYSCALL, Fn: "arch_prctl"}} , EnabledByDefault: false, EssentialEvent: false},
	159: EventConfig{ID: 159, Name: "reserved", Probes: []probe{probe{Event: "adjtimex", Attach: SYSCALL, Fn: "adjtimex"}} , EnabledByDefault: false, EssentialEvent: false},
	160: EventConfig{ID: 160, Name: "reserved", Probes: []probe{probe{Event: "setrlimit", Attach: SYSCALL, Fn: "setrlimit"}} , EnabledByDefault: false, EssentialEvent: false},
	161: EventConfig{ID: 161, Name: "reserved", Probes: []probe{probe{Event: "chroot", Attach: SYSCALL, Fn: "chroot"}} , EnabledByDefault: false, EssentialEvent: false},
	162: EventConfig{ID: 162, Name: "reserved", Probes: []probe{probe{Event: "sync", Attach: SYSCALL, Fn: "sync"}} , EnabledByDefault: false, EssentialEvent: false},
	163: EventConfig{ID: 163, Name: "reserved", Probes: []probe{probe{Event: "acct", Attach: SYSCALL, Fn: "acct"}} , EnabledByDefault: false, EssentialEvent: false},
	164: EventConfig{ID: 164, Name: "reserved", Probes: []probe{probe{Event: "settimeofday", Attach: SYSCALL, Fn: "settimeofday"}} , EnabledByDefault: false, EssentialEvent: false},
	165: EventConfig{ID: 165, Name: "mount", Probes: []probe{probe{Event: "mount", Attach: SYSCALL, Fn: "mount"}} , EnabledByDefault: true, EssentialEvent: false},
	166: EventConfig{ID: 166, Name: "umount", Probes: []probe{probe{Event: "umount", Attach: SYSCALL, Fn: "umount"}} , EnabledByDefault: true, EssentialEvent: false},
	167: EventConfig{ID: 167, Name: "reserved", Probes: []probe{probe{Event: "swapon", Attach: SYSCALL, Fn: "swapon"}} , EnabledByDefault: false, EssentialEvent: false},
	168: EventConfig{ID: 168, Name: "reserved", Probes: []probe{probe{Event: "swapoff", Attach: SYSCALL, Fn: "swapoff"}} , EnabledByDefault: false, EssentialEvent: false},
	169: EventConfig{ID: 169, Name: "reserved", Probes: []probe{probe{Event: "reboot", Attach: SYSCALL, Fn: "reboot"}} , EnabledByDefault: false, EssentialEvent: false},
	170: EventConfig{ID: 170, Name: "reserved", Probes: []probe{probe{Event: "sethostname", Attach: SYSCALL, Fn: "sethostname"}} , EnabledByDefault: false, EssentialEvent: false},
	171: EventConfig{ID: 171, Name: "reserved", Probes: []probe{probe{Event: "setdomainname", Attach: SYSCALL, Fn: "setdomainname"}} , EnabledByDefault: false, EssentialEvent: false},
	172: EventConfig{ID: 172, Name: "reserved", Probes: []probe{probe{Event: "iopl", Attach: SYSCALL, Fn: "iopl"}} , EnabledByDefault: false, EssentialEvent: false},
	173: EventConfig{ID: 173, Name: "reserved", Probes: []probe{probe{Event: "ioperm", Attach: SYSCALL, Fn: "ioperm"}} , EnabledByDefault: false, EssentialEvent: false},
	174: EventConfig{ID: 174, Name: "reserved", Probes: []probe{probe{Event: "create_module", Attach: SYSCALL, Fn: "create_module"}} , EnabledByDefault: false, EssentialEvent: false},
	175: EventConfig{ID: 175, Name: "init_module", Probes: []probe{probe{Event: "init_module", Attach: SYSCALL, Fn: "init_module"}} , EnabledByDefault: true, EssentialEvent: false},
	176: EventConfig{ID: 176, Name: "delete_module", Probes: []probe{probe{Event: "delete_module", Attach: SYSCALL, Fn: "delete_module"}} , EnabledByDefault: true, EssentialEvent: false},
	177: EventConfig{ID: 177, Name: "reserved", Probes: []probe{probe{Event: "get_kernel_syms", Attach: SYSCALL, Fn: "get_kernel_syms"}} , EnabledByDefault: false, EssentialEvent: false},
	178: EventConfig{ID: 178, Name: "reserved", Probes: []probe{probe{Event: "query_module", Attach: SYSCALL, Fn: "query_module"}} , EnabledByDefault: false, EssentialEvent: false},
	179: EventConfig{ID: 179, Name: "reserved", Probes: []probe{probe{Event: "quotactl", Attach: SYSCALL, Fn: "quotactl"}} , EnabledByDefault: false, EssentialEvent: false},
	180: EventConfig{ID: 180, Name: "reserved", Probes: []probe{probe{Event: "nfsservctl", Attach: SYSCALL, Fn: "nfsservctl"}} , EnabledByDefault: false, EssentialEvent: false},
	181: EventConfig{ID: 181, Name: "reserved", Probes: []probe{probe{Event: "getpmsg", Attach: SYSCALL, Fn: "getpmsg"}} , EnabledByDefault: false, EssentialEvent: false},
	182: EventConfig{ID: 182, Name: "reserved", Probes: []probe{probe{Event: "putpmsg", Attach: SYSCALL, Fn: "putpmsg"}} , EnabledByDefault: false, EssentialEvent: false},
	183: EventConfig{ID: 183, Name: "reserved", Probes: []probe{probe{Event: "afs", Attach: SYSCALL, Fn: "afs"}} , EnabledByDefault: false, EssentialEvent: false},
	184: EventConfig{ID: 184, Name: "reserved", Probes: []probe{probe{Event: "tuxcall", Attach: SYSCALL, Fn: "tuxcall"}} , EnabledByDefault: false, EssentialEvent: false},
	185: EventConfig{ID: 185, Name: "reserved", Probes: []probe{probe{Event: "security", Attach: SYSCALL, Fn: "security"}} , EnabledByDefault: false, EssentialEvent: false},
	186: EventConfig{ID: 186, Name: "reserved", Probes: []probe{probe{Event: "gettid", Attach: SYSCALL, Fn: "gettid"}} , EnabledByDefault: false, EssentialEvent: false},
	187: EventConfig{ID: 187, Name: "reserved", Probes: []probe{probe{Event: "readahead", Attach: SYSCALL, Fn: "readahead"}} , EnabledByDefault: false, EssentialEvent: false},
	188: EventConfig{ID: 188, Name: "reserved", Probes: []probe{probe{Event: "setxattr", Attach: SYSCALL, Fn: "setxattr"}} , EnabledByDefault: false, EssentialEvent: false},
	189: EventConfig{ID: 189, Name: "reserved", Probes: []probe{probe{Event: "lsetxattr", Attach: SYSCALL, Fn: "lsetxattr"}} , EnabledByDefault: false, EssentialEvent: false},
	190: EventConfig{ID: 190, Name: "reserved", Probes: []probe{probe{Event: "fsetxattr", Attach: SYSCALL, Fn: "fsetxattr"}} , EnabledByDefault: false, EssentialEvent: false},
	191: EventConfig{ID: 191, Name: "reserved", Probes: []probe{probe{Event: "getxattr", Attach: SYSCALL, Fn: "getxattr"}} , EnabledByDefault: false, EssentialEvent: false},
	192: EventConfig{ID: 192, Name: "reserved", Probes: []probe{probe{Event: "lgetxattr", Attach: SYSCALL, Fn: "lgetxattr"}} , EnabledByDefault: false, EssentialEvent: false},
	193: EventConfig{ID: 193, Name: "reserved", Probes: []probe{probe{Event: "fgetxattr", Attach: SYSCALL, Fn: "fgetxattr"}} , EnabledByDefault: false, EssentialEvent: false},
	194: EventConfig{ID: 194, Name: "reserved", Probes: []probe{probe{Event: "listxattr", Attach: SYSCALL, Fn: "listxattr"}} , EnabledByDefault: false, EssentialEvent: false},
	195: EventConfig{ID: 195, Name: "reserved", Probes: []probe{probe{Event: "llistxattr", Attach: SYSCALL, Fn: "llistxattr"}} , EnabledByDefault: false, EssentialEvent: false},
	196: EventConfig{ID: 196, Name: "reserved", Probes: []probe{probe{Event: "flistxattr", Attach: SYSCALL, Fn: "flistxattr"}} , EnabledByDefault: false, EssentialEvent: false},
	197: EventConfig{ID: 197, Name: "reserved", Probes: []probe{probe{Event: "removexattr", Attach: SYSCALL, Fn: "removexattr"}} , EnabledByDefault: false, EssentialEvent: false},
	198: EventConfig{ID: 198, Name: "reserved", Probes: []probe{probe{Event: "lremovexattr", Attach: SYSCALL, Fn: "lremovexattr"}} , EnabledByDefault: false, EssentialEvent: false},
	199: EventConfig{ID: 199, Name: "reserved", Probes: []probe{probe{Event: "fremovexattr", Attach: SYSCALL, Fn: "fremovexattr"}} , EnabledByDefault: false, EssentialEvent: false},
	200: EventConfig{ID: 200, Name: "reserved", Probes: []probe{probe{Event: "tkill", Attach: SYSCALL, Fn: "tkill"}} , EnabledByDefault: false, EssentialEvent: false},
	201: EventConfig{ID: 201, Name: "reserved", Probes: []probe{probe{Event: "time", Attach: SYSCALL, Fn: "time"}} , EnabledByDefault: false, EssentialEvent: false},
	202: EventConfig{ID: 202, Name: "reserved", Probes: []probe{probe{Event: "futex", Attach: SYSCALL, Fn: "futex"}} , EnabledByDefault: false, EssentialEvent: false},
	203: EventConfig{ID: 203, Name: "reserved", Probes: []probe{probe{Event: "sched_setaffinity", Attach: SYSCALL, Fn: "sched_setaffinity"}} , EnabledByDefault: false, EssentialEvent: false},
	204: EventConfig{ID: 204, Name: "reserved", Probes: []probe{probe{Event: "sched_getaffinity", Attach: SYSCALL, Fn: "sched_getaffinity"}} , EnabledByDefault: false, EssentialEvent: false},
	205: EventConfig{ID: 205, Name: "reserved", Probes: []probe{probe{Event: "set_thread_area", Attach: SYSCALL, Fn: "set_thread_area"}} , EnabledByDefault: false, EssentialEvent: false},
	206: EventConfig{ID: 206, Name: "reserved", Probes: []probe{probe{Event: "io_setup", Attach: SYSCALL, Fn: "io_setup"}} , EnabledByDefault: false, EssentialEvent: false},
	207: EventConfig{ID: 207, Name: "reserved", Probes: []probe{probe{Event: "io_destroy", Attach: SYSCALL, Fn: "io_destroy"}} , EnabledByDefault: false, EssentialEvent: false},
	208: EventConfig{ID: 208, Name: "reserved", Probes: []probe{probe{Event: "io_getevents", Attach: SYSCALL, Fn: "io_getevents"}} , EnabledByDefault: false, EssentialEvent: false},
	209: EventConfig{ID: 209, Name: "reserved", Probes: []probe{probe{Event: "io_submit", Attach: SYSCALL, Fn: "io_submit"}} , EnabledByDefault: false, EssentialEvent: false},
	210: EventConfig{ID: 210, Name: "reserved", Probes: []probe{probe{Event: "io_cancel", Attach: SYSCALL, Fn: "io_cancel"}} , EnabledByDefault: false, EssentialEvent: false},
	211: EventConfig{ID: 211, Name: "reserved", Probes: []probe{probe{Event: "get_thread_area", Attach: SYSCALL, Fn: "get_thread_area"}} , EnabledByDefault: false, EssentialEvent: false},
	212: EventConfig{ID: 212, Name: "reserved", Probes: []probe{probe{Event: "lookup_dcookie", Attach: SYSCALL, Fn: "lookup_dcookie"}} , EnabledByDefault: false, EssentialEvent: false},
	213: EventConfig{ID: 213, Name: "reserved", Probes: []probe{probe{Event: "epoll_create", Attach: SYSCALL, Fn: "epoll_create"}} , EnabledByDefault: false, EssentialEvent: false},
	214: EventConfig{ID: 214, Name: "reserved", Probes: []probe{probe{Event: "epoll_ctl_old", Attach: SYSCALL, Fn: "epoll_ctl_old"}} , EnabledByDefault: false, EssentialEvent: false},
	215: EventConfig{ID: 215, Name: "reserved", Probes: []probe{probe{Event: "epoll_wait_old", Attach: SYSCALL, Fn: "epoll_wait_old"}} , EnabledByDefault: false, EssentialEvent: false},
	216: EventConfig{ID: 216, Name: "reserved", Probes: []probe{probe{Event: "remap_file_pages", Attach: SYSCALL, Fn: "remap_file_pages"}} , EnabledByDefault: false, EssentialEvent: false},
	217: EventConfig{ID: 217, Name: "getdents64", Probes: []probe{probe{Event: "getdents64", Attach: SYSCALL, Fn: "getdents64"}} , EnabledByDefault: true, EssentialEvent: false},
	218: EventConfig{ID: 218, Name: "reserved", Probes: []probe{probe{Event: "set_tid_address", Attach: SYSCALL, Fn: "set_tid_address"}} , EnabledByDefault: false, EssentialEvent: false},
	219: EventConfig{ID: 219, Name: "reserved", Probes: []probe{probe{Event: "restart_syscall", Attach: SYSCALL, Fn: "restart_syscall"}} , EnabledByDefault: false, EssentialEvent: false},
	220: EventConfig{ID: 220, Name: "reserved", Probes: []probe{probe{Event: "semtimedop", Attach: SYSCALL, Fn: "semtimedop"}} , EnabledByDefault: false, EssentialEvent: false},
	221: EventConfig{ID: 221, Name: "reserved", Probes: []probe{probe{Event: "fadvise64", Attach: SYSCALL, Fn: "fadvise64"}} , EnabledByDefault: false, EssentialEvent: false},
	222: EventConfig{ID: 222, Name: "reserved", Probes: []probe{probe{Event: "timer_create", Attach: SYSCALL, Fn: "timer_create"}} , EnabledByDefault: false, EssentialEvent: false},
	223: EventConfig{ID: 223, Name: "reserved", Probes: []probe{probe{Event: "timer_settime", Attach: SYSCALL, Fn: "timer_settime"}} , EnabledByDefault: false, EssentialEvent: false},
	224: EventConfig{ID: 224, Name: "reserved", Probes: []probe{probe{Event: "timer_gettime", Attach: SYSCALL, Fn: "timer_gettime"}} , EnabledByDefault: false, EssentialEvent: false},
	225: EventConfig{ID: 225, Name: "reserved", Probes: []probe{probe{Event: "timer_getoverrun", Attach: SYSCALL, Fn: "timer_getoverrun"}} , EnabledByDefault: false, EssentialEvent: false},
	226: EventConfig{ID: 226, Name: "reserved", Probes: []probe{probe{Event: "timer_delete", Attach: SYSCALL, Fn: "timer_delete"}} , EnabledByDefault: false, EssentialEvent: false},
	227: EventConfig{ID: 227, Name: "reserved", Probes: []probe{probe{Event: "clock_settime", Attach: SYSCALL, Fn: "clock_settime"}} , EnabledByDefault: false, EssentialEvent: false},
	228: EventConfig{ID: 228, Name: "reserved", Probes: []probe{probe{Event: "clock_gettime", Attach: SYSCALL, Fn: "clock_gettime"}} , EnabledByDefault: false, EssentialEvent: false},
	229: EventConfig{ID: 229, Name: "reserved", Probes: []probe{probe{Event: "clock_getres", Attach: SYSCALL, Fn: "clock_getres"}} , EnabledByDefault: false, EssentialEvent: false},
	230: EventConfig{ID: 230, Name: "reserved", Probes: []probe{probe{Event: "clock_nanosleep", Attach: SYSCALL, Fn: "clock_nanosleep"}} , EnabledByDefault: false, EssentialEvent: false},
	231: EventConfig{ID: 231, Name: "reserved", Probes: []probe{probe{Event: "exit_group", Attach: SYSCALL, Fn: "exit_group"}} , EnabledByDefault: false, EssentialEvent: false},
	232: EventConfig{ID: 232, Name: "reserved", Probes: []probe{probe{Event: "epoll_wait", Attach: SYSCALL, Fn: "epoll_wait"}} , EnabledByDefault: false, EssentialEvent: false},
	233: EventConfig{ID: 233, Name: "reserved", Probes: []probe{probe{Event: "epoll_ctl", Attach: SYSCALL, Fn: "epoll_ctl"}} , EnabledByDefault: false, EssentialEvent: false},
	234: EventConfig{ID: 234, Name: "reserved", Probes: []probe{probe{Event: "tgkill", Attach: SYSCALL, Fn: "tgkill"}} , EnabledByDefault: false, EssentialEvent: false},
	235: EventConfig{ID: 235, Name: "reserved", Probes: []probe{probe{Event: "utimes", Attach: SYSCALL, Fn: "utimes"}} , EnabledByDefault: false, EssentialEvent: false},
	236: EventConfig{ID: 236, Name: "reserved", Probes: []probe{probe{Event: "vserver", Attach: SYSCALL, Fn: "vserver"}} , EnabledByDefault: false, EssentialEvent: false},
	237: EventConfig{ID: 237, Name: "reserved", Probes: []probe{probe{Event: "mbind", Attach: SYSCALL, Fn: "mbind"}} , EnabledByDefault: false, EssentialEvent: false},
	238: EventConfig{ID: 238, Name: "reserved", Probes: []probe{probe{Event: "set_mempolicy", Attach: SYSCALL, Fn: "set_mempolicy"}} , EnabledByDefault: false, EssentialEvent: false},
	239: EventConfig{ID: 239, Name: "reserved", Probes: []probe{probe{Event: "get_mempolicy", Attach: SYSCALL, Fn: "get_mempolicy"}} , EnabledByDefault: false, EssentialEvent: false},
	240: EventConfig{ID: 240, Name: "reserved", Probes: []probe{probe{Event: "mq_open", Attach: SYSCALL, Fn: "mq_open"}} , EnabledByDefault: false, EssentialEvent: false},
	241: EventConfig{ID: 241, Name: "reserved", Probes: []probe{probe{Event: "mq_unlink", Attach: SYSCALL, Fn: "mq_unlink"}} , EnabledByDefault: false, EssentialEvent: false},
	242: EventConfig{ID: 242, Name: "reserved", Probes: []probe{probe{Event: "mq_timedsend", Attach: SYSCALL, Fn: "mq_timedsend"}} , EnabledByDefault: false, EssentialEvent: false},
	243: EventConfig{ID: 243, Name: "reserved", Probes: []probe{probe{Event: "mq_timedreceive", Attach: SYSCALL, Fn: "mq_timedreceive"}} , EnabledByDefault: false, EssentialEvent: false},
	244: EventConfig{ID: 244, Name: "reserved", Probes: []probe{probe{Event: "mq_notify", Attach: SYSCALL, Fn: "mq_notify"}} , EnabledByDefault: false, EssentialEvent: false},
	245: EventConfig{ID: 245, Name: "reserved", Probes: []probe{probe{Event: "mq_getsetattr", Attach: SYSCALL, Fn: "mq_getsetattr"}} , EnabledByDefault: false, EssentialEvent: false},
	246: EventConfig{ID: 246, Name: "reserved", Probes: []probe{probe{Event: "kexec_load", Attach: SYSCALL, Fn: "kexec_load"}} , EnabledByDefault: false, EssentialEvent: false},
	247: EventConfig{ID: 247, Name: "reserved", Probes: []probe{probe{Event: "waitid", Attach: SYSCALL, Fn: "waitid"}} , EnabledByDefault: false, EssentialEvent: false},
	248: EventConfig{ID: 248, Name: "reserved", Probes: []probe{probe{Event: "add_key", Attach: SYSCALL, Fn: "add_key"}} , EnabledByDefault: false, EssentialEvent: false},
	249: EventConfig{ID: 249, Name: "reserved", Probes: []probe{probe{Event: "request_key", Attach: SYSCALL, Fn: "request_key"}} , EnabledByDefault: false, EssentialEvent: false},
	250: EventConfig{ID: 250, Name: "reserved", Probes: []probe{probe{Event: "keyctl", Attach: SYSCALL, Fn: "keyctl"}} , EnabledByDefault: false, EssentialEvent: false},
	251: EventConfig{ID: 251, Name: "reserved", Probes: []probe{probe{Event: "ioprio_set", Attach: SYSCALL, Fn: "ioprio_set"}} , EnabledByDefault: false, EssentialEvent: false},
	252: EventConfig{ID: 252, Name: "reserved", Probes: []probe{probe{Event: "ioprio_get", Attach: SYSCALL, Fn: "ioprio_get"}} , EnabledByDefault: false, EssentialEvent: false},
	253: EventConfig{ID: 253, Name: "reserved", Probes: []probe{probe{Event: "inotify_init", Attach: SYSCALL, Fn: "inotify_init"}} , EnabledByDefault: false, EssentialEvent: false},
	254: EventConfig{ID: 254, Name: "reserved", Probes: []probe{probe{Event: "inotify_add_watch", Attach: SYSCALL, Fn: "inotify_add_watch"}} , EnabledByDefault: false, EssentialEvent: false},
	255: EventConfig{ID: 255, Name: "reserved", Probes: []probe{probe{Event: "inotify_rm_watch", Attach: SYSCALL, Fn: "inotify_rm_watch"}} , EnabledByDefault: false, EssentialEvent: false},
	256: EventConfig{ID: 256, Name: "reserved", Probes: []probe{probe{Event: "migrate_pages", Attach: SYSCALL, Fn: "migrate_pages"}} , EnabledByDefault: false, EssentialEvent: false},
	257: EventConfig{ID: 257, Name: "openat", Probes: []probe{probe{Event: "openat", Attach: SYSCALL, Fn: "openat"}} , EnabledByDefault: true, EssentialEvent: false},
	258: EventConfig{ID: 258, Name: "reserved", Probes: []probe{probe{Event: "mkdirat", Attach: SYSCALL, Fn: "mkdirat"}} , EnabledByDefault: false, EssentialEvent: false},
	259: EventConfig{ID: 259, Name: "mknodat", Probes: []probe{probe{Event: "mknodat", Attach: SYSCALL, Fn: "mknodat"}} , EnabledByDefault: true, EssentialEvent: false},
	260: EventConfig{ID: 260, Name: "fchownat", Probes: []probe{probe{Event: "fchownat", Attach: SYSCALL, Fn: "fchownat"}} , EnabledByDefault: true, EssentialEvent: false},
	261: EventConfig{ID: 261, Name: "reserved", Probes: []probe{probe{Event: "futimesat", Attach: SYSCALL, Fn: "futimesat"}} , EnabledByDefault: false, EssentialEvent: false},
	262: EventConfig{ID: 262, Name: "reserved", Probes: []probe{probe{Event: "newfstatat", Attach: SYSCALL, Fn: "newfstatat"}} , EnabledByDefault: false, EssentialEvent: false},
	263: EventConfig{ID: 263, Name: "unlinkat", Probes: []probe{probe{Event: "unlinkat", Attach: SYSCALL, Fn: "unlinkat"}} , EnabledByDefault: true, EssentialEvent: false},
	264: EventConfig{ID: 264, Name: "reserved", Probes: []probe{probe{Event: "renameat", Attach: SYSCALL, Fn: "renameat"}} , EnabledByDefault: false, EssentialEvent: false},
	265: EventConfig{ID: 265, Name: "reserved", Probes: []probe{probe{Event: "linkat", Attach: SYSCALL, Fn: "linkat"}} , EnabledByDefault: false, EssentialEvent: false},
	266: EventConfig{ID: 266, Name: "symlinkat", Probes: []probe{probe{Event: "symlinkat", Attach: SYSCALL, Fn: "symlinkat"}} , EnabledByDefault: true, EssentialEvent: false},
	267: EventConfig{ID: 267, Name: "reserved", Probes: []probe{probe{Event: "readlinkat", Attach: SYSCALL, Fn: "readlinkat"}} , EnabledByDefault: false, EssentialEvent: false},
	268: EventConfig{ID: 268, Name: "fchmodat", Probes: []probe{probe{Event: "fchmodat", Attach: SYSCALL, Fn: "fchmodat"}} , EnabledByDefault: true, EssentialEvent: false},
	269: EventConfig{ID: 269, Name: "faccessat", Probes: []probe{probe{Event: "faccessat", Attach: SYSCALL, Fn: "faccessat"}} , EnabledByDefault: true, EssentialEvent: false},
	270: EventConfig{ID: 270, Name: "reserved", Probes: []probe{probe{Event: "pselect6", Attach: SYSCALL, Fn: "pselect6"}} , EnabledByDefault: false, EssentialEvent: false},
	271: EventConfig{ID: 271, Name: "reserved", Probes: []probe{probe{Event: "ppoll", Attach: SYSCALL, Fn: "ppoll"}} , EnabledByDefault: false, EssentialEvent: false},
	272: EventConfig{ID: 272, Name: "reserved", Probes: []probe{probe{Event: "unshare", Attach: SYSCALL, Fn: "unshare"}} , EnabledByDefault: false, EssentialEvent: false},
	273: EventConfig{ID: 273, Name: "reserved", Probes: []probe{probe{Event: "set_robust_list", Attach: SYSCALL, Fn: "set_robust_list"}} , EnabledByDefault: false, EssentialEvent: false},
	274: EventConfig{ID: 274, Name: "reserved", Probes: []probe{probe{Event: "get_robust_list", Attach: SYSCALL, Fn: "get_robust_list"}} , EnabledByDefault: false, EssentialEvent: false},
	275: EventConfig{ID: 275, Name: "reserved", Probes: []probe{probe{Event: "splice", Attach: SYSCALL, Fn: "splice"}} , EnabledByDefault: false, EssentialEvent: false},
	276: EventConfig{ID: 276, Name: "reserved", Probes: []probe{probe{Event: "tee", Attach: SYSCALL, Fn: "tee"}} , EnabledByDefault: false, EssentialEvent: false},
	277: EventConfig{ID: 277, Name: "reserved", Probes: []probe{probe{Event: "sync_file_range", Attach: SYSCALL, Fn: "sync_file_range"}} , EnabledByDefault: false, EssentialEvent: false},
	278: EventConfig{ID: 278, Name: "reserved", Probes: []probe{probe{Event: "vmsplice", Attach: SYSCALL, Fn: "vmsplice"}} , EnabledByDefault: false, EssentialEvent: false},
	279: EventConfig{ID: 279, Name: "reserved", Probes: []probe{probe{Event: "move_pages", Attach: SYSCALL, Fn: "move_pages"}} , EnabledByDefault: false, EssentialEvent: false},
	280: EventConfig{ID: 280, Name: "reserved", Probes: []probe{probe{Event: "utimensat", Attach: SYSCALL, Fn: "utimensat"}} , EnabledByDefault: false, EssentialEvent: false},
	281: EventConfig{ID: 281, Name: "reserved", Probes: []probe{probe{Event: "epoll_pwait", Attach: SYSCALL, Fn: "epoll_pwait"}} , EnabledByDefault: false, EssentialEvent: false},
	282: EventConfig{ID: 282, Name: "reserved", Probes: []probe{probe{Event: "signalfd", Attach: SYSCALL, Fn: "signalfd"}} , EnabledByDefault: false, EssentialEvent: false},
	283: EventConfig{ID: 283, Name: "reserved", Probes: []probe{probe{Event: "timerfd_create", Attach: SYSCALL, Fn: "timerfd_create"}} , EnabledByDefault: false, EssentialEvent: false},
	284: EventConfig{ID: 284, Name: "reserved", Probes: []probe{probe{Event: "eventfd", Attach: SYSCALL, Fn: "eventfd"}} , EnabledByDefault: false, EssentialEvent: false},
	285: EventConfig{ID: 285, Name: "reserved", Probes: []probe{probe{Event: "fallocate", Attach: SYSCALL, Fn: "fallocate"}} , EnabledByDefault: false, EssentialEvent: false},
	286: EventConfig{ID: 286, Name: "reserved", Probes: []probe{probe{Event: "timerfd_settime", Attach: SYSCALL, Fn: "timerfd_settime"}} , EnabledByDefault: false, EssentialEvent: false},
	287: EventConfig{ID: 287, Name: "reserved", Probes: []probe{probe{Event: "timerfd_gettime", Attach: SYSCALL, Fn: "timerfd_gettime"}} , EnabledByDefault: false, EssentialEvent: false},
	288: EventConfig{ID: 288, Name: "accept4", Probes: []probe{probe{Event: "accept4", Attach: SYSCALL, Fn: "accept4"}} , EnabledByDefault: true, EssentialEvent: false},
	289: EventConfig{ID: 289, Name: "reserved", Probes: []probe{probe{Event: "signalfd4", Attach: SYSCALL, Fn: "signalfd4"}} , EnabledByDefault: false, EssentialEvent: false},
	290: EventConfig{ID: 290, Name: "reserved", Probes: []probe{probe{Event: "eventfd2", Attach: SYSCALL, Fn: "eventfd2"}} , EnabledByDefault: false, EssentialEvent: false},
	291: EventConfig{ID: 291, Name: "reserved", Probes: []probe{probe{Event: "epoll_create1", Attach: SYSCALL, Fn: "epoll_create1"}} , EnabledByDefault: false, EssentialEvent: false},
	292: EventConfig{ID: 292, Name: "dup3", Probes: []probe{probe{Event: "dup3", Attach: SYSCALL, Fn: "dup3"}} , EnabledByDefault: true, EssentialEvent: false},
	293: EventConfig{ID: 293, Name: "reserved", Probes: []probe{probe{Event: "pipe2", Attach: SYSCALL, Fn: "pipe2"}} , EnabledByDefault: false, EssentialEvent: false},
	294: EventConfig{ID: 294, Name: "reserved", Probes: []probe{probe{Event: "ionotify_init1", Attach: SYSCALL, Fn: "ionotify_init1"}} , EnabledByDefault: false, EssentialEvent: false},
	295: EventConfig{ID: 295, Name: "reserved", Probes: []probe{probe{Event: "preadv", Attach: SYSCALL, Fn: "preadv"}} , EnabledByDefault: false, EssentialEvent: false},
	296: EventConfig{ID: 296, Name: "reserved", Probes: []probe{probe{Event: "pwritev", Attach: SYSCALL, Fn: "pwritev"}} , EnabledByDefault: false, EssentialEvent: false},
	297: EventConfig{ID: 297, Name: "reserved", Probes: []probe{probe{Event: "rt_tgsigqueueinfo", Attach: SYSCALL, Fn: "rt_tgsigqueueinfo"}} , EnabledByDefault: false, EssentialEvent: false},
	298: EventConfig{ID: 298, Name: "reserved", Probes: []probe{probe{Event: "perf_event_open", Attach: SYSCALL, Fn: "perf_event_open"}} , EnabledByDefault: false, EssentialEvent: false},
	299: EventConfig{ID: 299, Name: "reserved", Probes: []probe{probe{Event: "recvmmsg", Attach: SYSCALL, Fn: "recvmmsg"}} , EnabledByDefault: false, EssentialEvent: false},
	300: EventConfig{ID: 300, Name: "reserved", Probes: []probe{probe{Event: "fanotify_init", Attach: SYSCALL, Fn: "fanotify_init"}} , EnabledByDefault: false, EssentialEvent: false},
	301: EventConfig{ID: 301, Name: "reserved", Probes: []probe{probe{Event: "fanotify_mark", Attach: SYSCALL, Fn: "fanotify_mark"}} , EnabledByDefault: false, EssentialEvent: false},
	302: EventConfig{ID: 302, Name: "reserved", Probes: []probe{probe{Event: "prlimit64", Attach: SYSCALL, Fn: "prlimit64"}} , EnabledByDefault: false, EssentialEvent: false},
	303: EventConfig{ID: 303, Name: "reserved", Probes: []probe{probe{Event: "name_tohandle_at", Attach: SYSCALL, Fn: "name_tohandle_at"}} , EnabledByDefault: false, EssentialEvent: false},
	304: EventConfig{ID: 304, Name: "reserved", Probes: []probe{probe{Event: "open_by_handle_at", Attach: SYSCALL, Fn: "open_by_handle_at"}} , EnabledByDefault: false, EssentialEvent: false},
	305: EventConfig{ID: 305, Name: "reserved", Probes: []probe{probe{Event: "clock_adjtime", Attach: SYSCALL, Fn: "clock_adjtime"}} , EnabledByDefault: false, EssentialEvent: false},
	306: EventConfig{ID: 306, Name: "reserved", Probes: []probe{probe{Event: "sycnfs", Attach: SYSCALL, Fn: "sycnfs"}} , EnabledByDefault: false, EssentialEvent: false},
	307: EventConfig{ID: 307, Name: "reserved", Probes: []probe{probe{Event: "sendmmsg", Attach: SYSCALL, Fn: "sendmmsg"}} , EnabledByDefault: false, EssentialEvent: false},
	308: EventConfig{ID: 308, Name: "reserved", Probes: []probe{probe{Event: "setns", Attach: SYSCALL, Fn: "setns"}} , EnabledByDefault: false, EssentialEvent: false},
	309: EventConfig{ID: 309, Name: "reserved", Probes: []probe{probe{Event: "getcpu", Attach: SYSCALL, Fn: "getcpu"}} , EnabledByDefault: false, EssentialEvent: false},
	310: EventConfig{ID: 310, Name: "process_vm_readv", Probes: []probe{probe{Event: "process_vm_readv", Attach: SYSCALL, Fn: "process_vm_readv"}} , EnabledByDefault: true, EssentialEvent: false},
	311: EventConfig{ID: 311, Name: "process_vm_writev", Probes: []probe{probe{Event: "process_vm_writev", Attach: SYSCALL, Fn: "process_vm_writev"}} , EnabledByDefault: true, EssentialEvent: false},
	312: EventConfig{ID: 312, Name: "reserved", Probes: []probe{probe{Event: "kcmp", Attach: SYSCALL, Fn: "kcmp"}} , EnabledByDefault: false, EssentialEvent: false},
	313: EventConfig{ID: 313, Name: "finit_module", Probes: []probe{probe{Event: "finit_module", Attach: SYSCALL, Fn: "finit_module"}} , EnabledByDefault: true, EssentialEvent: false},
	314: EventConfig{ID: 314, Name: "reserved", Probes: []probe{probe{Event: "sched_setattr", Attach: SYSCALL, Fn: "sched_setattr"}} , EnabledByDefault: false, EssentialEvent: false},
	315: EventConfig{ID: 315, Name: "reserved", Probes: []probe{probe{Event: "sched_getattr", Attach: SYSCALL, Fn: "sched_getattr"}} , EnabledByDefault: false, EssentialEvent: false},
	316: EventConfig{ID: 316, Name: "reserved", Probes: []probe{probe{Event: "renameat2", Attach: SYSCALL, Fn: "renameat2"}} , EnabledByDefault: false, EssentialEvent: false},
	317: EventConfig{ID: 317, Name: "reserved", Probes: []probe{probe{Event: "seccomp", Attach: SYSCALL, Fn: "seccomp"}} , EnabledByDefault: false, EssentialEvent: false},
	318: EventConfig{ID: 318, Name: "reserved", Probes: []probe{probe{Event: "getrandom", Attach: SYSCALL, Fn: "getrandom"}} , EnabledByDefault: false, EssentialEvent: false},
	319: EventConfig{ID: 319, Name: "memfd_create", Probes: []probe{probe{Event: "memfd_create", Attach: SYSCALL, Fn: "memfd_create"}} , EnabledByDefault: true, EssentialEvent: false},
	320: EventConfig{ID: 320, Name: "reserved", Probes: []probe{probe{Event: "kexec_file_load", Attach: SYSCALL, Fn: "kexec_file_load"}} , EnabledByDefault: false, EssentialEvent: false},
	321: EventConfig{ID: 321, Name: "reserved", Probes: []probe{probe{Event: "bpf", Attach: SYSCALL, Fn: "bpf"}} , EnabledByDefault: false, EssentialEvent: false},
	322: EventConfig{ID: 322, Name: "execveat", Probes: []probe{probe{Event: "execveat", Attach: SYSCALL, Fn: "execveat"}} , EnabledByDefault: true, EssentialEvent: true},
	323: EventConfig{ID: 323, Name: "reserved", Probes: []probe{probe{Event: "userfaultfd", Attach: SYSCALL, Fn: "userfaultfd"}} , EnabledByDefault: false, EssentialEvent: false},
	324: EventConfig{ID: 324, Name: "reserved", Probes: []probe{probe{Event: "membarrier", Attach: SYSCALL, Fn: "membarrier"}} , EnabledByDefault: false, EssentialEvent: false},
	325: EventConfig{ID: 325, Name: "reserved", Probes: []probe{probe{Event: "mlock2", Attach: SYSCALL, Fn: "mlock2"}} , EnabledByDefault: false, EssentialEvent: false},
	326: EventConfig{ID: 326, Name: "reserved", Probes: []probe{probe{Event: "copy_file_range", Attach: SYSCALL, Fn: "copy_file_range"}} , EnabledByDefault: false, EssentialEvent: false},
	327: EventConfig{ID: 327, Name: "reserved", Probes: []probe{probe{Event: "preadv2", Attach: SYSCALL, Fn: "preadv2"}} , EnabledByDefault: false, EssentialEvent: false},
	328: EventConfig{ID: 328, Name: "reserved", Probes: []probe{probe{Event: "pwritev2", Attach: SYSCALL, Fn: "pwritev2"}} , EnabledByDefault: false, EssentialEvent: false},
	329: EventConfig{ID: 329, Name: "pkey_mprotect", Probes: []probe{probe{Event: "pkey_mprotect", Attach: SYSCALL, Fn: "pkey_mprotect"}} , EnabledByDefault: true, EssentialEvent: false},
	330: EventConfig{ID: 330, Name: "reserved", Probes: []probe{probe{Event: "pkey_alloc", Attach: SYSCALL, Fn: "pkey_alloc"}} , EnabledByDefault: false, EssentialEvent: false},
	331: EventConfig{ID: 331, Name: "reserved", Probes: []probe{probe{Event: "pkey_free", Attach: SYSCALL, Fn: "pkey_free"}} , EnabledByDefault: false, EssentialEvent: false},
	332: EventConfig{ID: 332, Name: "reserved", Probes: []probe{probe{Event: "statx", Attach: SYSCALL, Fn: "statx"}} , EnabledByDefault: false, EssentialEvent: false},
	333: EventConfig{ID: 333, Name: "reserved", Probes: []probe{probe{Event: "io_pgetevents", Attach: SYSCALL, Fn: "io_pgetevents"}} , EnabledByDefault: false, EssentialEvent: false},
	334: EventConfig{ID: 334, Name: "reserved", Probes: []probe{probe{Event: "rseq", Attach: SYSCALL, Fn: "rseq"}} , EnabledByDefault: false, EssentialEvent: false},
	335: EventConfig{ID: 335, Name: "reserved", Probes: []probe{probe{Event: "reserved", Attach: SYSCALL, Fn: "reserved"}} , EnabledByDefault: false, EssentialEvent: false},
	336: EventConfig{ID: 336, Name: "reserved", Probes: []probe{probe{Event: "reserved", Attach: SYSCALL, Fn: "reserved"}} , EnabledByDefault: false, EssentialEvent: false},
	337: EventConfig{ID: 337, Name: "reserved", Probes: []probe{probe{Event: "reserved", Attach: SYSCALL, Fn: "reserved"}} , EnabledByDefault: false, EssentialEvent: false},
	338: EventConfig{ID: 338, Name: "reserved", Probes: []probe{probe{Event: "reserved", Attach: SYSCALL, Fn: "reserved"}} , EnabledByDefault: false, EssentialEvent: false},
	339: EventConfig{ID: 339, Name: "reserved", Probes: []probe{probe{Event: "reserved", Attach: SYSCALL, Fn: "reserved"}} , EnabledByDefault: false, EssentialEvent: false},
	340: EventConfig{ID: 340, Name: "reserved", Probes: []probe{probe{Event: "reserved", Attach: SYSCALL, Fn: "reserved"}} , EnabledByDefault: false, EssentialEvent: false},
	341: EventConfig{ID: 341, Name: "reserved", Probes: []probe{probe{Event: "reserved", Attach: SYSCALL, Fn: "reserved"}} , EnabledByDefault: false, EssentialEvent: false},
	342: EventConfig{ID: 342, Name: "reserved", Probes: []probe{probe{Event: "reserved", Attach: SYSCALL, Fn: "reserved"}} , EnabledByDefault: false, EssentialEvent: false},
	343: EventConfig{ID: 343, Name: "reserved", Probes: []probe{probe{Event: "reserved", Attach: SYSCALL, Fn: "reserved"}} , EnabledByDefault: false, EssentialEvent: false},
	344: EventConfig{ID: 344, Name: "reserved", Probes: []probe{probe{Event: "reserved", Attach: SYSCALL, Fn: "reserved"}} , EnabledByDefault: false, EssentialEvent: false},
	345: EventConfig{ID: 345, Name: "reserved", Probes: []probe{probe{Event: "reserved", Attach: SYSCALL, Fn: "reserved"}} , EnabledByDefault: false, EssentialEvent: false},
	346: EventConfig{ID: 346, Name: "reserved", Probes: []probe{probe{Event: "reserved", Attach: SYSCALL, Fn: "reserved"}} , EnabledByDefault: false, EssentialEvent: false},
	347: EventConfig{ID: 347, Name: "reserved", Probes: []probe{probe{Event: "reserved", Attach: SYSCALL, Fn: "reserved"}} , EnabledByDefault: false, EssentialEvent: false},
	348: EventConfig{ID: 348, Name: "reserved", Probes: []probe{probe{Event: "reserved", Attach: SYSCALL, Fn: "reserved"}} , EnabledByDefault: false, EssentialEvent: false},
	349: EventConfig{ID: 349, Name: "reserved", Probes: []probe{probe{Event: "reserved", Attach: SYSCALL, Fn: "reserved"}} , EnabledByDefault: false, EssentialEvent: false},
	350: EventConfig{ID: 350, Name: "raw_syscalls", Probes: []probe{probe{Event: "raw_syscalls:sys_enter", Attach: TRACEPOINT, Fn: "tracepoint__raw_syscalls__sys_enter"}} , EnabledByDefault: false, EssentialEvent: false},
	351: EventConfig{ID: 351, Name: "do_exit", Probes: []probe{probe{Event: "do_exit", Attach: KPROBE, Fn: "trace_do_exit"}} , EnabledByDefault: true, EssentialEvent: true},
	352: EventConfig{ID: 352, Name: "cap_capable", Probes: []probe{probe{Event: "cap_capable", Attach: KPROBE, Fn: "trace_cap_capable"}} , EnabledByDefault: true, EssentialEvent: false},
	353: EventConfig{ID: 353, Name: "security_bprm_check", Probes: []probe{probe{Event: "security_bprm_check", Attach: KPROBE, Fn: "trace_security_bprm_check"}} , EnabledByDefault: true, EssentialEvent: false},
	354: EventConfig{ID: 354, Name: "security_file_open", Probes: []probe{probe{Event: "security_file_open", Attach: KPROBE, Fn: "trace_security_file_open"}} , EnabledByDefault: true, EssentialEvent: false},
	355: EventConfig{ID: 355, Name: "vfs_write", Probes: []probe{probe{Event: "vfs_write", Attach: KPROBE, Fn: "trace_vfs_write"}, probe{Event: "vfs_write", Attach: KRETPROBE, Fn: "trace_ret_vfs_write"}} , EnabledByDefault: true, EssentialEvent: false},
	356: EventConfig{ID: 356, Name: "mem_prot_alert", Probes: []probe{probe{Event: "security_mmap_addr", Attach: KPROBE, Fn: "trace_mmap_alert"}, probe{Event: "security_file_mprotect", Attach: KPROBE, Fn: "trace_mprotect_alert"}} , EnabledByDefault: false, EssentialEvent: false},
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
