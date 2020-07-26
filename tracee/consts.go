package tracee

// argType is an enum that encodes the argument types that the BPF program may write to the shared buffer
type argType uint8

// argument types should match defined values in ebpf code
const (
	noneT       argType = 0
	intT        argType = 1
	uintT       argType = 2
	longT       argType = 3
	ulongT      argType = 4
	offT        argType = 5
	modeT       argType = 6
	devT        argType = 7
	sizeT       argType = 8
	pointerT    argType = 9
	strT        argType = 10
	strArrT     argType = 11
	sockAddrT   argType = 12
	openFlagsT  argType = 13
	execFlagsT  argType = 14
	sockDomT    argType = 15
	sockTypeT   argType = 16
	capT        argType = 17
	syscallT    argType = 18
	protFlagsT  argType = 19
	accessModeT argType = 20
	ptraceReqT  argType = 21
	prctlOptT   argType = 22
	alertT      argType = 23
	typeMax     argType = 255
)

// bpfConfig is an enum that include various configurations that can be passed to bpf code
type bpfConfig uint32

const (
	configContMode          bpfConfig = 0
	configDetectOrigSyscall bpfConfig = 1
	configExecEnv           bpfConfig = 2
	configCaptureFiles      bpfConfig = 3
	configExtractDynCode    bpfConfig = 4
)

const (
	tailVfsWrite uint32 = 0
	tailSendBin  uint32 = 1
)

const (
	sendVfsWrite uint8 = 1
	sendMprotect uint8 = 2
)

// Arg tags should match defined values in ebpf code
const (
	TagNone uint8 = iota
	TagFd
	TagFilename
	TagPathname
	TagArgv
	TagEnvp
	TagDev
	TagInode
	TagDirfd
	TagFlags
	TagCap
	TagSyscall
	TagCount
	TagPos
	TagAlert
	TagMode
	TagAddr
	TagLength
	TagProt
	TagOffset
	TagPkey
	TagName
	TagOldfd
	TagNewfd
	TagDomain
	TagType
	TagProtocol
	TagRequest
	TagPid
	TagSig
	TagSockfd
	TagBacklog
	TagOption
	TagArg2
	TagArg3
	TagArg4
	TagArg5
	TagData
	TagLocalIov
	TagLiovcnt
	TagRemoteIov
	TagRiovcnt
	TagModuleImage
	TagLen
	TagParamValues
	TagTarget
	TagNewdirfd
	TagLinkpath
	TagSource
	TagFilesystemtype
	TagMountflags
	TagUid
	TagGid
	TagFsuid
	TagFsgid
	TagRuid
	TagEuid
	TagRgid
	TagEgid
	TagSuid
	TagSgid
	TagOwner
	TagGroup
)

var argNames = map[uint8]string{
	TagNone:           "",
	TagFd:             "fd",
	TagFilename:       "filename",
	TagPathname:       "pathname",
	TagArgv:           "argv",
	TagEnvp:           "envp",
	TagDev:            "dev",
	TagInode:          "inode",
	TagDirfd:          "dirfd",
	TagFlags:          "flags",
	TagCap:            "cap",
	TagSyscall:        "syscall",
	TagCount:          "count",
	TagPos:            "pos",
	TagAlert:          "alert",
	TagMode:           "mode",
	TagAddr:           "addr",
	TagLength:         "length",
	TagProt:           "prot",
	TagOffset:         "offset",
	TagPkey:           "pkey",
	TagName:           "name",
	TagOldfd:          "oldfd",
	TagNewfd:          "newfd",
	TagDomain:         "domain",
	TagType:           "type",
	TagProtocol:       "protocol",
	TagRequest:        "request",
	TagPid:            "pid",
	TagSig:            "sig",
	TagSockfd:         "sockfd",
	TagBacklog:        "backlog",
	TagOption:         "option",
	TagArg2:           "arg2",
	TagArg3:           "arg3",
	TagArg4:           "arg4",
	TagArg5:           "arg5",
	TagData:           "data",
	TagLocalIov:       "local_iov",
	TagLiovcnt:        "liovcnt",
	TagRemoteIov:      "remote_iov",
	TagRiovcnt:        "riovcnt",
	TagModuleImage:    "module_image",
	TagLen:            "len",
	TagParamValues:    "param_values",
	TagTarget:         "target",
	TagNewdirfd:       "newdirfd",
	TagLinkpath:       "linkpath",
	TagSource:         "source",
	TagFilesystemtype: "filesystemtype",
	TagMountflags:     "mountflags",
	TagUid:            "uid",
	TagGid:            "gid",
	TagFsuid:          "fsuid",
	TagFsgid:          "fsgid",
	TagRuid:           "ruid",
	TagEuid:           "euid",
	TagRgid:           "rgid",
	TagEgid:           "egid",
	TagSuid:           "suid",
	TagSgid:           "sgid",
	TagOwner:          "owner",
	TagGroup:          "group",
}

// ProbeType is an enum that describes the mechanism used to attach the event
type probeType uint8

// Syscall tracepoints are explained here: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#8-system-call-tracepoints
// Kprobes are explained here: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#1-kprobes
// Tracepoints are explained here: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#3-tracepoints
const (
	sysCall    probeType = 0
	kprobe     probeType = 1
	kretprobe  probeType = 2
	tracepoint probeType = 3
)

type probe struct {
	event  string
	attach probeType
	fn     string
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
	0:   EventConfig{ID: 0, Name: "reserved", Probes: []probe{probe{event: "read", attach: sysCall, fn: "read"}}, EnabledByDefault: false, EssentialEvent: false},
	1:   EventConfig{ID: 1, Name: "reserved", Probes: []probe{probe{event: "write", attach: sysCall, fn: "write"}}, EnabledByDefault: false, EssentialEvent: false},
	2:   EventConfig{ID: 2, Name: "open", Probes: []probe{probe{event: "open", attach: sysCall, fn: "open"}}, EnabledByDefault: true, EssentialEvent: false},
	3:   EventConfig{ID: 3, Name: "close", Probes: []probe{probe{event: "close", attach: sysCall, fn: "close"}}, EnabledByDefault: true, EssentialEvent: false},
	4:   EventConfig{ID: 4, Name: "newstat", Probes: []probe{probe{event: "newstat", attach: sysCall, fn: "newstat"}}, EnabledByDefault: true, EssentialEvent: false},
	5:   EventConfig{ID: 5, Name: "reserved", Probes: []probe{probe{event: "fstat", attach: sysCall, fn: "fstat"}}, EnabledByDefault: false, EssentialEvent: false},
	6:   EventConfig{ID: 6, Name: "newlstat", Probes: []probe{probe{event: "newlstat", attach: sysCall, fn: "newlstat"}}, EnabledByDefault: true, EssentialEvent: false},
	7:   EventConfig{ID: 7, Name: "reserved", Probes: []probe{probe{event: "poll", attach: sysCall, fn: "poll"}}, EnabledByDefault: false, EssentialEvent: false},
	8:   EventConfig{ID: 8, Name: "reserved", Probes: []probe{probe{event: "lseek", attach: sysCall, fn: "lseek"}}, EnabledByDefault: false, EssentialEvent: false},
	9:   EventConfig{ID: 9, Name: "mmap", Probes: []probe{probe{event: "mmap", attach: sysCall, fn: "mmap"}}, EnabledByDefault: true, EssentialEvent: false},
	10:  EventConfig{ID: 10, Name: "mprotect", Probes: []probe{probe{event: "mprotect", attach: sysCall, fn: "mprotect"}}, EnabledByDefault: true, EssentialEvent: false},
	11:  EventConfig{ID: 11, Name: "reserved", Probes: []probe{probe{event: "munmap", attach: sysCall, fn: "munmap"}}, EnabledByDefault: false, EssentialEvent: false},
	12:  EventConfig{ID: 12, Name: "reserved", Probes: []probe{probe{event: "brk", attach: sysCall, fn: "brk"}}, EnabledByDefault: false, EssentialEvent: false},
	13:  EventConfig{ID: 13, Name: "reserved", Probes: []probe{probe{event: "rt_sigaction", attach: sysCall, fn: "rt_sigaction"}}, EnabledByDefault: false, EssentialEvent: false},
	14:  EventConfig{ID: 14, Name: "reserved", Probes: []probe{probe{event: "rt_sigprocmask", attach: sysCall, fn: "rt_sigprocmask"}}, EnabledByDefault: false, EssentialEvent: false},
	15:  EventConfig{ID: 15, Name: "reserved", Probes: []probe{probe{event: "rt_sigreturn", attach: sysCall, fn: "rt_sigreturn"}}, EnabledByDefault: false, EssentialEvent: false},
	16:  EventConfig{ID: 16, Name: "ioctl", Probes: []probe{probe{event: "ioctl", attach: sysCall, fn: "ioctl"}}, EnabledByDefault: true, EssentialEvent: false},
	17:  EventConfig{ID: 17, Name: "reserved", Probes: []probe{probe{event: "pread64", attach: sysCall, fn: "pread64"}}, EnabledByDefault: false, EssentialEvent: false},
	18:  EventConfig{ID: 18, Name: "reserved", Probes: []probe{probe{event: "pwrite64", attach: sysCall, fn: "pwrite64"}}, EnabledByDefault: false, EssentialEvent: false},
	19:  EventConfig{ID: 19, Name: "reserved", Probes: []probe{probe{event: "readv", attach: sysCall, fn: "readv"}}, EnabledByDefault: false, EssentialEvent: false},
	20:  EventConfig{ID: 20, Name: "reserved", Probes: []probe{probe{event: "writev", attach: sysCall, fn: "writev"}}, EnabledByDefault: false, EssentialEvent: false},
	21:  EventConfig{ID: 21, Name: "access", Probes: []probe{probe{event: "access", attach: sysCall, fn: "access"}}, EnabledByDefault: true, EssentialEvent: false},
	22:  EventConfig{ID: 22, Name: "reserved", Probes: []probe{probe{event: "pipe", attach: sysCall, fn: "pipe"}}, EnabledByDefault: false, EssentialEvent: false},
	23:  EventConfig{ID: 23, Name: "reserved", Probes: []probe{probe{event: "select", attach: sysCall, fn: "select"}}, EnabledByDefault: false, EssentialEvent: false},
	24:  EventConfig{ID: 24, Name: "reserved", Probes: []probe{probe{event: "sched_yield", attach: sysCall, fn: "sched_yield"}}, EnabledByDefault: false, EssentialEvent: false},
	25:  EventConfig{ID: 25, Name: "reserved", Probes: []probe{probe{event: "mremap", attach: sysCall, fn: "mremap"}}, EnabledByDefault: false, EssentialEvent: false},
	26:  EventConfig{ID: 26, Name: "reserved", Probes: []probe{probe{event: "msync", attach: sysCall, fn: "msync"}}, EnabledByDefault: false, EssentialEvent: false},
	27:  EventConfig{ID: 27, Name: "reserved", Probes: []probe{probe{event: "mincore", attach: sysCall, fn: "mincore"}}, EnabledByDefault: false, EssentialEvent: false},
	28:  EventConfig{ID: 28, Name: "reserved", Probes: []probe{probe{event: "madvise", attach: sysCall, fn: "madvise"}}, EnabledByDefault: false, EssentialEvent: false},
	29:  EventConfig{ID: 29, Name: "reserved", Probes: []probe{probe{event: "shmget", attach: sysCall, fn: "shmget"}}, EnabledByDefault: false, EssentialEvent: false},
	30:  EventConfig{ID: 30, Name: "reserved", Probes: []probe{probe{event: "shmat", attach: sysCall, fn: "shmat"}}, EnabledByDefault: false, EssentialEvent: false},
	31:  EventConfig{ID: 31, Name: "reserved", Probes: []probe{probe{event: "shmctl", attach: sysCall, fn: "shmctl"}}, EnabledByDefault: false, EssentialEvent: false},
	32:  EventConfig{ID: 32, Name: "dup", Probes: []probe{probe{event: "dup", attach: sysCall, fn: "dup"}}, EnabledByDefault: true, EssentialEvent: false},
	33:  EventConfig{ID: 33, Name: "dup2", Probes: []probe{probe{event: "dup2", attach: sysCall, fn: "dup2"}}, EnabledByDefault: true, EssentialEvent: false},
	34:  EventConfig{ID: 34, Name: "reserved", Probes: []probe{probe{event: "pause", attach: sysCall, fn: "pause"}}, EnabledByDefault: false, EssentialEvent: false},
	35:  EventConfig{ID: 35, Name: "reserved", Probes: []probe{probe{event: "nanosleep", attach: sysCall, fn: "nanosleep"}}, EnabledByDefault: false, EssentialEvent: false},
	36:  EventConfig{ID: 36, Name: "reserved", Probes: []probe{probe{event: "getitimer", attach: sysCall, fn: "getitimer"}}, EnabledByDefault: false, EssentialEvent: false},
	37:  EventConfig{ID: 37, Name: "reserved", Probes: []probe{probe{event: "alarm", attach: sysCall, fn: "alarm"}}, EnabledByDefault: false, EssentialEvent: false},
	38:  EventConfig{ID: 38, Name: "reserved", Probes: []probe{probe{event: "setitimer", attach: sysCall, fn: "setitimer"}}, EnabledByDefault: false, EssentialEvent: false},
	39:  EventConfig{ID: 39, Name: "reserved", Probes: []probe{probe{event: "getpid", attach: sysCall, fn: "getpid"}}, EnabledByDefault: false, EssentialEvent: false},
	40:  EventConfig{ID: 40, Name: "reserved", Probes: []probe{probe{event: "sendfile", attach: sysCall, fn: "sendfile"}}, EnabledByDefault: false, EssentialEvent: false},
	41:  EventConfig{ID: 41, Name: "socket", Probes: []probe{probe{event: "socket", attach: sysCall, fn: "socket"}}, EnabledByDefault: true, EssentialEvent: false},
	42:  EventConfig{ID: 42, Name: "connect", Probes: []probe{probe{event: "connect", attach: sysCall, fn: "connect"}}, EnabledByDefault: true, EssentialEvent: false},
	43:  EventConfig{ID: 43, Name: "accept", Probes: []probe{probe{event: "accept", attach: sysCall, fn: "accept"}}, EnabledByDefault: true, EssentialEvent: false},
	44:  EventConfig{ID: 44, Name: "reserved", Probes: []probe{probe{event: "sendto", attach: sysCall, fn: "sendto"}}, EnabledByDefault: false, EssentialEvent: false},
	45:  EventConfig{ID: 45, Name: "reserved", Probes: []probe{probe{event: "recvfrom", attach: sysCall, fn: "recvfrom"}}, EnabledByDefault: false, EssentialEvent: false},
	46:  EventConfig{ID: 46, Name: "reserved", Probes: []probe{probe{event: "sendmsg", attach: sysCall, fn: "sendmsg"}}, EnabledByDefault: false, EssentialEvent: false},
	47:  EventConfig{ID: 47, Name: "reserved", Probes: []probe{probe{event: "recvmsg", attach: sysCall, fn: "recvmsg"}}, EnabledByDefault: false, EssentialEvent: false},
	48:  EventConfig{ID: 48, Name: "reserved", Probes: []probe{probe{event: "shutdown", attach: sysCall, fn: "shutdown"}}, EnabledByDefault: false, EssentialEvent: false},
	49:  EventConfig{ID: 49, Name: "bind", Probes: []probe{probe{event: "bind", attach: sysCall, fn: "bind"}}, EnabledByDefault: true, EssentialEvent: false},
	50:  EventConfig{ID: 50, Name: "listen", Probes: []probe{probe{event: "listen", attach: sysCall, fn: "listen"}}, EnabledByDefault: true, EssentialEvent: false},
	51:  EventConfig{ID: 51, Name: "getsockname", Probes: []probe{probe{event: "getsockname", attach: sysCall, fn: "getsockname"}}, EnabledByDefault: true, EssentialEvent: false},
	52:  EventConfig{ID: 52, Name: "reserved", Probes: []probe{probe{event: "getpeername", attach: sysCall, fn: "getpeername"}}, EnabledByDefault: false, EssentialEvent: false},
	53:  EventConfig{ID: 53, Name: "reserved", Probes: []probe{probe{event: "socketpair", attach: sysCall, fn: "socketpair"}}, EnabledByDefault: false, EssentialEvent: false},
	54:  EventConfig{ID: 54, Name: "reserved", Probes: []probe{probe{event: "setsockopt", attach: sysCall, fn: "setsockopt"}}, EnabledByDefault: false, EssentialEvent: false},
	55:  EventConfig{ID: 55, Name: "reserved", Probes: []probe{probe{event: "getsockopt", attach: sysCall, fn: "getsockopt"}}, EnabledByDefault: false, EssentialEvent: false},
	56:  EventConfig{ID: 56, Name: "clone", Probes: []probe{probe{event: "clone", attach: sysCall, fn: "clone"}}, EnabledByDefault: true, EssentialEvent: true},
	57:  EventConfig{ID: 57, Name: "fork", Probes: []probe{probe{event: "fork", attach: sysCall, fn: "fork"}}, EnabledByDefault: true, EssentialEvent: true},
	58:  EventConfig{ID: 58, Name: "vfork", Probes: []probe{probe{event: "vfork", attach: sysCall, fn: "vfork"}}, EnabledByDefault: true, EssentialEvent: true},
	59:  EventConfig{ID: 59, Name: "execve", Probes: []probe{probe{event: "execve", attach: sysCall, fn: "execve"}}, EnabledByDefault: true, EssentialEvent: true},
	60:  EventConfig{ID: 60, Name: "reserved", Probes: []probe{probe{event: "exit", attach: sysCall, fn: "exit"}}, EnabledByDefault: false, EssentialEvent: false},
	61:  EventConfig{ID: 61, Name: "reserved", Probes: []probe{probe{event: "wait4", attach: sysCall, fn: "wait4"}}, EnabledByDefault: false, EssentialEvent: false},
	62:  EventConfig{ID: 62, Name: "kill", Probes: []probe{probe{event: "kill", attach: sysCall, fn: "kill"}}, EnabledByDefault: true, EssentialEvent: false},
	63:  EventConfig{ID: 63, Name: "reserved", Probes: []probe{probe{event: "uname", attach: sysCall, fn: "uname"}}, EnabledByDefault: false, EssentialEvent: false},
	64:  EventConfig{ID: 64, Name: "reserved", Probes: []probe{probe{event: "semget", attach: sysCall, fn: "semget"}}, EnabledByDefault: false, EssentialEvent: false},
	65:  EventConfig{ID: 65, Name: "reserved", Probes: []probe{probe{event: "semop", attach: sysCall, fn: "semop"}}, EnabledByDefault: false, EssentialEvent: false},
	66:  EventConfig{ID: 66, Name: "reserved", Probes: []probe{probe{event: "semctl", attach: sysCall, fn: "semctl"}}, EnabledByDefault: false, EssentialEvent: false},
	67:  EventConfig{ID: 67, Name: "reserved", Probes: []probe{probe{event: "shmdt", attach: sysCall, fn: "shmdt"}}, EnabledByDefault: false, EssentialEvent: false},
	68:  EventConfig{ID: 68, Name: "reserved", Probes: []probe{probe{event: "msgget", attach: sysCall, fn: "msgget"}}, EnabledByDefault: false, EssentialEvent: false},
	69:  EventConfig{ID: 69, Name: "reserved", Probes: []probe{probe{event: "msgsnd", attach: sysCall, fn: "msgsnd"}}, EnabledByDefault: false, EssentialEvent: false},
	70:  EventConfig{ID: 70, Name: "reserved", Probes: []probe{probe{event: "msgrcv", attach: sysCall, fn: "msgrcv"}}, EnabledByDefault: false, EssentialEvent: false},
	71:  EventConfig{ID: 71, Name: "reserved", Probes: []probe{probe{event: "msgctl", attach: sysCall, fn: "msgctl"}}, EnabledByDefault: false, EssentialEvent: false},
	72:  EventConfig{ID: 72, Name: "reserved", Probes: []probe{probe{event: "fcntl", attach: sysCall, fn: "fcntl"}}, EnabledByDefault: false, EssentialEvent: false},
	73:  EventConfig{ID: 73, Name: "reserved", Probes: []probe{probe{event: "flock", attach: sysCall, fn: "flock"}}, EnabledByDefault: false, EssentialEvent: false},
	74:  EventConfig{ID: 74, Name: "reserved", Probes: []probe{probe{event: "fsync", attach: sysCall, fn: "fsync"}}, EnabledByDefault: false, EssentialEvent: false},
	75:  EventConfig{ID: 75, Name: "reserved", Probes: []probe{probe{event: "fdatasync", attach: sysCall, fn: "fdatasync"}}, EnabledByDefault: false, EssentialEvent: false},
	76:  EventConfig{ID: 76, Name: "reserved", Probes: []probe{probe{event: "truncate", attach: sysCall, fn: "truncate"}}, EnabledByDefault: false, EssentialEvent: false},
	77:  EventConfig{ID: 77, Name: "reserved", Probes: []probe{probe{event: "ftruncate", attach: sysCall, fn: "ftruncate"}}, EnabledByDefault: false, EssentialEvent: false},
	78:  EventConfig{ID: 78, Name: "getdents", Probes: []probe{probe{event: "getdents", attach: sysCall, fn: "getdents"}}, EnabledByDefault: true, EssentialEvent: false},
	79:  EventConfig{ID: 79, Name: "reserved", Probes: []probe{probe{event: "getcwd", attach: sysCall, fn: "getcwd"}}, EnabledByDefault: false, EssentialEvent: false},
	80:  EventConfig{ID: 80, Name: "reserved", Probes: []probe{probe{event: "chdir", attach: sysCall, fn: "chdir"}}, EnabledByDefault: false, EssentialEvent: false},
	81:  EventConfig{ID: 81, Name: "reserved", Probes: []probe{probe{event: "fchdir", attach: sysCall, fn: "fchdir"}}, EnabledByDefault: false, EssentialEvent: false},
	82:  EventConfig{ID: 82, Name: "reserved", Probes: []probe{probe{event: "rename", attach: sysCall, fn: "rename"}}, EnabledByDefault: false, EssentialEvent: false},
	83:  EventConfig{ID: 83, Name: "reserved", Probes: []probe{probe{event: "mkdir", attach: sysCall, fn: "mkdir"}}, EnabledByDefault: false, EssentialEvent: false},
	84:  EventConfig{ID: 84, Name: "reserved", Probes: []probe{probe{event: "rmdir", attach: sysCall, fn: "rmdir"}}, EnabledByDefault: false, EssentialEvent: false},
	85:  EventConfig{ID: 85, Name: "creat", Probes: []probe{probe{event: "creat", attach: sysCall, fn: "creat"}}, EnabledByDefault: true, EssentialEvent: false},
	86:  EventConfig{ID: 86, Name: "reserved", Probes: []probe{probe{event: "link", attach: sysCall, fn: "link"}}, EnabledByDefault: false, EssentialEvent: false},
	87:  EventConfig{ID: 87, Name: "unlink", Probes: []probe{probe{event: "unlink", attach: sysCall, fn: "unlink"}}, EnabledByDefault: true, EssentialEvent: false},
	88:  EventConfig{ID: 88, Name: "symlink", Probes: []probe{probe{event: "symlink", attach: sysCall, fn: "symlink"}}, EnabledByDefault: true, EssentialEvent: false},
	89:  EventConfig{ID: 89, Name: "reserved", Probes: []probe{probe{event: "readlink", attach: sysCall, fn: "readlink"}}, EnabledByDefault: false, EssentialEvent: false},
	90:  EventConfig{ID: 90, Name: "chmod", Probes: []probe{probe{event: "chmod", attach: sysCall, fn: "chmod"}}, EnabledByDefault: true, EssentialEvent: false},
	91:  EventConfig{ID: 91, Name: "fchmod", Probes: []probe{probe{event: "fchmod", attach: sysCall, fn: "fchmod"}}, EnabledByDefault: true, EssentialEvent: false},
	92:  EventConfig{ID: 92, Name: "chown", Probes: []probe{probe{event: "chown", attach: sysCall, fn: "chown"}}, EnabledByDefault: true, EssentialEvent: false},
	93:  EventConfig{ID: 93, Name: "fchown", Probes: []probe{probe{event: "fchown", attach: sysCall, fn: "fchown"}}, EnabledByDefault: true, EssentialEvent: false},
	94:  EventConfig{ID: 94, Name: "lchown", Probes: []probe{probe{event: "lchown", attach: sysCall, fn: "lchown"}}, EnabledByDefault: true, EssentialEvent: false},
	95:  EventConfig{ID: 95, Name: "reserved", Probes: []probe{probe{event: "umask", attach: sysCall, fn: "umask"}}, EnabledByDefault: false, EssentialEvent: false},
	96:  EventConfig{ID: 96, Name: "reserved", Probes: []probe{probe{event: "gettimeofday", attach: sysCall, fn: "gettimeofday"}}, EnabledByDefault: false, EssentialEvent: false},
	97:  EventConfig{ID: 97, Name: "reserved", Probes: []probe{probe{event: "getrlimit", attach: sysCall, fn: "getrlimit"}}, EnabledByDefault: false, EssentialEvent: false},
	98:  EventConfig{ID: 98, Name: "reserved", Probes: []probe{probe{event: "getrusage", attach: sysCall, fn: "getrusage"}}, EnabledByDefault: false, EssentialEvent: false},
	99:  EventConfig{ID: 99, Name: "reserved", Probes: []probe{probe{event: "sysinfo", attach: sysCall, fn: "sysinfo"}}, EnabledByDefault: false, EssentialEvent: false},
	100: EventConfig{ID: 100, Name: "reserved", Probes: []probe{probe{event: "times", attach: sysCall, fn: "times"}}, EnabledByDefault: false, EssentialEvent: false},
	101: EventConfig{ID: 101, Name: "ptrace", Probes: []probe{probe{event: "ptrace", attach: sysCall, fn: "ptrace"}}, EnabledByDefault: true, EssentialEvent: false},
	102: EventConfig{ID: 102, Name: "reserved", Probes: []probe{probe{event: "getuid", attach: sysCall, fn: "getuid"}}, EnabledByDefault: false, EssentialEvent: false},
	103: EventConfig{ID: 103, Name: "reserved", Probes: []probe{probe{event: "syslog", attach: sysCall, fn: "syslog"}}, EnabledByDefault: false, EssentialEvent: false},
	104: EventConfig{ID: 104, Name: "reserved", Probes: []probe{probe{event: "getgid", attach: sysCall, fn: "getgid"}}, EnabledByDefault: false, EssentialEvent: false},
	105: EventConfig{ID: 105, Name: "setuid", Probes: []probe{probe{event: "setuid", attach: sysCall, fn: "setuid"}}, EnabledByDefault: true, EssentialEvent: false},
	106: EventConfig{ID: 106, Name: "setgid", Probes: []probe{probe{event: "setgid", attach: sysCall, fn: "setgid"}}, EnabledByDefault: true, EssentialEvent: false},
	107: EventConfig{ID: 107, Name: "reserved", Probes: []probe{probe{event: "geteuid", attach: sysCall, fn: "geteuid"}}, EnabledByDefault: false, EssentialEvent: false},
	108: EventConfig{ID: 108, Name: "reserved", Probes: []probe{probe{event: "getegid", attach: sysCall, fn: "getegid"}}, EnabledByDefault: false, EssentialEvent: false},
	109: EventConfig{ID: 109, Name: "reserved", Probes: []probe{probe{event: "setpgid", attach: sysCall, fn: "setpgid"}}, EnabledByDefault: false, EssentialEvent: false},
	110: EventConfig{ID: 110, Name: "reserved", Probes: []probe{probe{event: "getppid", attach: sysCall, fn: "getppid"}}, EnabledByDefault: false, EssentialEvent: false},
	111: EventConfig{ID: 111, Name: "reserved", Probes: []probe{probe{event: "getpgrp", attach: sysCall, fn: "getpgrp"}}, EnabledByDefault: false, EssentialEvent: false},
	112: EventConfig{ID: 112, Name: "reserved", Probes: []probe{probe{event: "setsid", attach: sysCall, fn: "setsid"}}, EnabledByDefault: false, EssentialEvent: false},
	113: EventConfig{ID: 113, Name: "setreuid", Probes: []probe{probe{event: "setreuid", attach: sysCall, fn: "setreuid"}}, EnabledByDefault: true, EssentialEvent: false},
	114: EventConfig{ID: 114, Name: "setregid", Probes: []probe{probe{event: "setregid", attach: sysCall, fn: "setregid"}}, EnabledByDefault: true, EssentialEvent: false},
	115: EventConfig{ID: 115, Name: "reserved", Probes: []probe{probe{event: "getgroups", attach: sysCall, fn: "getgroups"}}, EnabledByDefault: false, EssentialEvent: false},
	116: EventConfig{ID: 116, Name: "reserved", Probes: []probe{probe{event: "setgroups", attach: sysCall, fn: "setgroups"}}, EnabledByDefault: false, EssentialEvent: false},
	117: EventConfig{ID: 117, Name: "reserved", Probes: []probe{probe{event: "setresuid", attach: sysCall, fn: "setresuid"}}, EnabledByDefault: false, EssentialEvent: false},
	118: EventConfig{ID: 118, Name: "reserved", Probes: []probe{probe{event: "getresuid", attach: sysCall, fn: "getresuid"}}, EnabledByDefault: false, EssentialEvent: false},
	119: EventConfig{ID: 119, Name: "reserved", Probes: []probe{probe{event: "setresgid", attach: sysCall, fn: "setresgid"}}, EnabledByDefault: false, EssentialEvent: false},
	120: EventConfig{ID: 120, Name: "reserved", Probes: []probe{probe{event: "getresgid", attach: sysCall, fn: "getresgid"}}, EnabledByDefault: false, EssentialEvent: false},
	121: EventConfig{ID: 121, Name: "reserved", Probes: []probe{probe{event: "getpgid", attach: sysCall, fn: "getpgid"}}, EnabledByDefault: false, EssentialEvent: false},
	122: EventConfig{ID: 122, Name: "setfsuid", Probes: []probe{probe{event: "setfsuid", attach: sysCall, fn: "setfsuid"}}, EnabledByDefault: true, EssentialEvent: false},
	123: EventConfig{ID: 123, Name: "setfsgid", Probes: []probe{probe{event: "setfsgid", attach: sysCall, fn: "setfsgid"}}, EnabledByDefault: true, EssentialEvent: false},
	124: EventConfig{ID: 124, Name: "reserved", Probes: []probe{probe{event: "getsid", attach: sysCall, fn: "getsid"}}, EnabledByDefault: false, EssentialEvent: false},
	125: EventConfig{ID: 125, Name: "reserved", Probes: []probe{probe{event: "capget", attach: sysCall, fn: "capget"}}, EnabledByDefault: false, EssentialEvent: false},
	126: EventConfig{ID: 126, Name: "reserved", Probes: []probe{probe{event: "capset", attach: sysCall, fn: "capset"}}, EnabledByDefault: false, EssentialEvent: false},
	127: EventConfig{ID: 127, Name: "reserved", Probes: []probe{probe{event: "rt_sigpending", attach: sysCall, fn: "rt_sigpending"}}, EnabledByDefault: false, EssentialEvent: false},
	128: EventConfig{ID: 128, Name: "reserved", Probes: []probe{probe{event: "rt_sigtimedwait", attach: sysCall, fn: "rt_sigtimedwait"}}, EnabledByDefault: false, EssentialEvent: false},
	129: EventConfig{ID: 129, Name: "reserved", Probes: []probe{probe{event: "rt_sigqueueinfo", attach: sysCall, fn: "rt_sigqueueinfo"}}, EnabledByDefault: false, EssentialEvent: false},
	130: EventConfig{ID: 130, Name: "reserved", Probes: []probe{probe{event: "rt_sigsuspend", attach: sysCall, fn: "rt_sigsuspend"}}, EnabledByDefault: false, EssentialEvent: false},
	131: EventConfig{ID: 131, Name: "reserved", Probes: []probe{probe{event: "sigaltstack", attach: sysCall, fn: "sigaltstack"}}, EnabledByDefault: false, EssentialEvent: false},
	132: EventConfig{ID: 132, Name: "reserved", Probes: []probe{probe{event: "utime", attach: sysCall, fn: "utime"}}, EnabledByDefault: false, EssentialEvent: false},
	133: EventConfig{ID: 133, Name: "mknod", Probes: []probe{probe{event: "mknod", attach: sysCall, fn: "mknod"}}, EnabledByDefault: true, EssentialEvent: false},
	134: EventConfig{ID: 134, Name: "reserved", Probes: []probe{probe{event: "uselib", attach: sysCall, fn: "uselib"}}, EnabledByDefault: false, EssentialEvent: false},
	135: EventConfig{ID: 135, Name: "reserved", Probes: []probe{probe{event: "personality", attach: sysCall, fn: "personality"}}, EnabledByDefault: false, EssentialEvent: false},
	136: EventConfig{ID: 136, Name: "reserved", Probes: []probe{probe{event: "ustat", attach: sysCall, fn: "ustat"}}, EnabledByDefault: false, EssentialEvent: false},
	137: EventConfig{ID: 137, Name: "reserved", Probes: []probe{probe{event: "statfs", attach: sysCall, fn: "statfs"}}, EnabledByDefault: false, EssentialEvent: false},
	138: EventConfig{ID: 138, Name: "reserved", Probes: []probe{probe{event: "fstatfs", attach: sysCall, fn: "fstatfs"}}, EnabledByDefault: false, EssentialEvent: false},
	139: EventConfig{ID: 139, Name: "reserved", Probes: []probe{probe{event: "sysfs", attach: sysCall, fn: "sysfs"}}, EnabledByDefault: false, EssentialEvent: false},
	140: EventConfig{ID: 140, Name: "reserved", Probes: []probe{probe{event: "getpriority", attach: sysCall, fn: "getpriority"}}, EnabledByDefault: false, EssentialEvent: false},
	141: EventConfig{ID: 141, Name: "reserved", Probes: []probe{probe{event: "setpriority", attach: sysCall, fn: "setpriority"}}, EnabledByDefault: false, EssentialEvent: false},
	142: EventConfig{ID: 142, Name: "reserved", Probes: []probe{probe{event: "sched_setparam", attach: sysCall, fn: "sched_setparam"}}, EnabledByDefault: false, EssentialEvent: false},
	143: EventConfig{ID: 143, Name: "reserved", Probes: []probe{probe{event: "sched_getparam", attach: sysCall, fn: "sched_getparam"}}, EnabledByDefault: false, EssentialEvent: false},
	144: EventConfig{ID: 144, Name: "reserved", Probes: []probe{probe{event: "sched_setscheduler", attach: sysCall, fn: "sched_setscheduler"}}, EnabledByDefault: false, EssentialEvent: false},
	145: EventConfig{ID: 145, Name: "reserved", Probes: []probe{probe{event: "sched_getscheduler", attach: sysCall, fn: "sched_getscheduler"}}, EnabledByDefault: false, EssentialEvent: false},
	146: EventConfig{ID: 146, Name: "reserved", Probes: []probe{probe{event: "sched_get_priority_max", attach: sysCall, fn: "sched_get_priority_max"}}, EnabledByDefault: false, EssentialEvent: false},
	147: EventConfig{ID: 147, Name: "reserved", Probes: []probe{probe{event: "sched_get_priority_min", attach: sysCall, fn: "sched_get_priority_min"}}, EnabledByDefault: false, EssentialEvent: false},
	148: EventConfig{ID: 148, Name: "reserved", Probes: []probe{probe{event: "sched_rr_get_interval", attach: sysCall, fn: "sched_rr_get_interval"}}, EnabledByDefault: false, EssentialEvent: false},
	149: EventConfig{ID: 149, Name: "reserved", Probes: []probe{probe{event: "mlock", attach: sysCall, fn: "mlock"}}, EnabledByDefault: false, EssentialEvent: false},
	150: EventConfig{ID: 150, Name: "reserved", Probes: []probe{probe{event: "munlock", attach: sysCall, fn: "munlock"}}, EnabledByDefault: false, EssentialEvent: false},
	151: EventConfig{ID: 151, Name: "reserved", Probes: []probe{probe{event: "mlockall", attach: sysCall, fn: "mlockall"}}, EnabledByDefault: false, EssentialEvent: false},
	152: EventConfig{ID: 152, Name: "reserved", Probes: []probe{probe{event: "munlockall", attach: sysCall, fn: "munlockall"}}, EnabledByDefault: false, EssentialEvent: false},
	153: EventConfig{ID: 153, Name: "reserved", Probes: []probe{probe{event: "vhangup", attach: sysCall, fn: "vhangup"}}, EnabledByDefault: false, EssentialEvent: false},
	154: EventConfig{ID: 154, Name: "reserved", Probes: []probe{probe{event: "modify_ldt", attach: sysCall, fn: "modify_ldt"}}, EnabledByDefault: false, EssentialEvent: false},
	155: EventConfig{ID: 155, Name: "reserved", Probes: []probe{probe{event: "pivot_root", attach: sysCall, fn: "pivot_root"}}, EnabledByDefault: false, EssentialEvent: false},
	156: EventConfig{ID: 156, Name: "reserved", Probes: []probe{probe{event: "sysctl", attach: sysCall, fn: "sysctl"}}, EnabledByDefault: false, EssentialEvent: false},
	157: EventConfig{ID: 157, Name: "prctl", Probes: []probe{probe{event: "prctl", attach: sysCall, fn: "prctl"}}, EnabledByDefault: true, EssentialEvent: false},
	158: EventConfig{ID: 158, Name: "reserved", Probes: []probe{probe{event: "arch_prctl", attach: sysCall, fn: "arch_prctl"}}, EnabledByDefault: false, EssentialEvent: false},
	159: EventConfig{ID: 159, Name: "reserved", Probes: []probe{probe{event: "adjtimex", attach: sysCall, fn: "adjtimex"}}, EnabledByDefault: false, EssentialEvent: false},
	160: EventConfig{ID: 160, Name: "reserved", Probes: []probe{probe{event: "setrlimit", attach: sysCall, fn: "setrlimit"}}, EnabledByDefault: false, EssentialEvent: false},
	161: EventConfig{ID: 161, Name: "reserved", Probes: []probe{probe{event: "chroot", attach: sysCall, fn: "chroot"}}, EnabledByDefault: false, EssentialEvent: false},
	162: EventConfig{ID: 162, Name: "reserved", Probes: []probe{probe{event: "sync", attach: sysCall, fn: "sync"}}, EnabledByDefault: false, EssentialEvent: false},
	163: EventConfig{ID: 163, Name: "reserved", Probes: []probe{probe{event: "acct", attach: sysCall, fn: "acct"}}, EnabledByDefault: false, EssentialEvent: false},
	164: EventConfig{ID: 164, Name: "reserved", Probes: []probe{probe{event: "settimeofday", attach: sysCall, fn: "settimeofday"}}, EnabledByDefault: false, EssentialEvent: false},
	165: EventConfig{ID: 165, Name: "mount", Probes: []probe{probe{event: "mount", attach: sysCall, fn: "mount"}}, EnabledByDefault: true, EssentialEvent: false},
	166: EventConfig{ID: 166, Name: "umount", Probes: []probe{probe{event: "umount", attach: sysCall, fn: "umount"}}, EnabledByDefault: true, EssentialEvent: false},
	167: EventConfig{ID: 167, Name: "reserved", Probes: []probe{probe{event: "swapon", attach: sysCall, fn: "swapon"}}, EnabledByDefault: false, EssentialEvent: false},
	168: EventConfig{ID: 168, Name: "reserved", Probes: []probe{probe{event: "swapoff", attach: sysCall, fn: "swapoff"}}, EnabledByDefault: false, EssentialEvent: false},
	169: EventConfig{ID: 169, Name: "reserved", Probes: []probe{probe{event: "reboot", attach: sysCall, fn: "reboot"}}, EnabledByDefault: false, EssentialEvent: false},
	170: EventConfig{ID: 170, Name: "reserved", Probes: []probe{probe{event: "sethostname", attach: sysCall, fn: "sethostname"}}, EnabledByDefault: false, EssentialEvent: false},
	171: EventConfig{ID: 171, Name: "reserved", Probes: []probe{probe{event: "setdomainname", attach: sysCall, fn: "setdomainname"}}, EnabledByDefault: false, EssentialEvent: false},
	172: EventConfig{ID: 172, Name: "reserved", Probes: []probe{probe{event: "iopl", attach: sysCall, fn: "iopl"}}, EnabledByDefault: false, EssentialEvent: false},
	173: EventConfig{ID: 173, Name: "reserved", Probes: []probe{probe{event: "ioperm", attach: sysCall, fn: "ioperm"}}, EnabledByDefault: false, EssentialEvent: false},
	174: EventConfig{ID: 174, Name: "reserved", Probes: []probe{probe{event: "create_module", attach: sysCall, fn: "create_module"}}, EnabledByDefault: false, EssentialEvent: false},
	175: EventConfig{ID: 175, Name: "init_module", Probes: []probe{probe{event: "init_module", attach: sysCall, fn: "init_module"}}, EnabledByDefault: true, EssentialEvent: false},
	176: EventConfig{ID: 176, Name: "delete_module", Probes: []probe{probe{event: "delete_module", attach: sysCall, fn: "delete_module"}}, EnabledByDefault: true, EssentialEvent: false},
	177: EventConfig{ID: 177, Name: "reserved", Probes: []probe{probe{event: "get_kernel_syms", attach: sysCall, fn: "get_kernel_syms"}}, EnabledByDefault: false, EssentialEvent: false},
	178: EventConfig{ID: 178, Name: "reserved", Probes: []probe{probe{event: "query_module", attach: sysCall, fn: "query_module"}}, EnabledByDefault: false, EssentialEvent: false},
	179: EventConfig{ID: 179, Name: "reserved", Probes: []probe{probe{event: "quotactl", attach: sysCall, fn: "quotactl"}}, EnabledByDefault: false, EssentialEvent: false},
	180: EventConfig{ID: 180, Name: "reserved", Probes: []probe{probe{event: "nfsservctl", attach: sysCall, fn: "nfsservctl"}}, EnabledByDefault: false, EssentialEvent: false},
	181: EventConfig{ID: 181, Name: "reserved", Probes: []probe{probe{event: "getpmsg", attach: sysCall, fn: "getpmsg"}}, EnabledByDefault: false, EssentialEvent: false},
	182: EventConfig{ID: 182, Name: "reserved", Probes: []probe{probe{event: "putpmsg", attach: sysCall, fn: "putpmsg"}}, EnabledByDefault: false, EssentialEvent: false},
	183: EventConfig{ID: 183, Name: "reserved", Probes: []probe{probe{event: "afs", attach: sysCall, fn: "afs"}}, EnabledByDefault: false, EssentialEvent: false},
	184: EventConfig{ID: 184, Name: "reserved", Probes: []probe{probe{event: "tuxcall", attach: sysCall, fn: "tuxcall"}}, EnabledByDefault: false, EssentialEvent: false},
	185: EventConfig{ID: 185, Name: "reserved", Probes: []probe{probe{event: "security", attach: sysCall, fn: "security"}}, EnabledByDefault: false, EssentialEvent: false},
	186: EventConfig{ID: 186, Name: "reserved", Probes: []probe{probe{event: "gettid", attach: sysCall, fn: "gettid"}}, EnabledByDefault: false, EssentialEvent: false},
	187: EventConfig{ID: 187, Name: "reserved", Probes: []probe{probe{event: "readahead", attach: sysCall, fn: "readahead"}}, EnabledByDefault: false, EssentialEvent: false},
	188: EventConfig{ID: 188, Name: "reserved", Probes: []probe{probe{event: "setxattr", attach: sysCall, fn: "setxattr"}}, EnabledByDefault: false, EssentialEvent: false},
	189: EventConfig{ID: 189, Name: "reserved", Probes: []probe{probe{event: "lsetxattr", attach: sysCall, fn: "lsetxattr"}}, EnabledByDefault: false, EssentialEvent: false},
	190: EventConfig{ID: 190, Name: "reserved", Probes: []probe{probe{event: "fsetxattr", attach: sysCall, fn: "fsetxattr"}}, EnabledByDefault: false, EssentialEvent: false},
	191: EventConfig{ID: 191, Name: "reserved", Probes: []probe{probe{event: "getxattr", attach: sysCall, fn: "getxattr"}}, EnabledByDefault: false, EssentialEvent: false},
	192: EventConfig{ID: 192, Name: "reserved", Probes: []probe{probe{event: "lgetxattr", attach: sysCall, fn: "lgetxattr"}}, EnabledByDefault: false, EssentialEvent: false},
	193: EventConfig{ID: 193, Name: "reserved", Probes: []probe{probe{event: "fgetxattr", attach: sysCall, fn: "fgetxattr"}}, EnabledByDefault: false, EssentialEvent: false},
	194: EventConfig{ID: 194, Name: "reserved", Probes: []probe{probe{event: "listxattr", attach: sysCall, fn: "listxattr"}}, EnabledByDefault: false, EssentialEvent: false},
	195: EventConfig{ID: 195, Name: "reserved", Probes: []probe{probe{event: "llistxattr", attach: sysCall, fn: "llistxattr"}}, EnabledByDefault: false, EssentialEvent: false},
	196: EventConfig{ID: 196, Name: "reserved", Probes: []probe{probe{event: "flistxattr", attach: sysCall, fn: "flistxattr"}}, EnabledByDefault: false, EssentialEvent: false},
	197: EventConfig{ID: 197, Name: "reserved", Probes: []probe{probe{event: "removexattr", attach: sysCall, fn: "removexattr"}}, EnabledByDefault: false, EssentialEvent: false},
	198: EventConfig{ID: 198, Name: "reserved", Probes: []probe{probe{event: "lremovexattr", attach: sysCall, fn: "lremovexattr"}}, EnabledByDefault: false, EssentialEvent: false},
	199: EventConfig{ID: 199, Name: "reserved", Probes: []probe{probe{event: "fremovexattr", attach: sysCall, fn: "fremovexattr"}}, EnabledByDefault: false, EssentialEvent: false},
	200: EventConfig{ID: 200, Name: "reserved", Probes: []probe{probe{event: "tkill", attach: sysCall, fn: "tkill"}}, EnabledByDefault: false, EssentialEvent: false},
	201: EventConfig{ID: 201, Name: "reserved", Probes: []probe{probe{event: "time", attach: sysCall, fn: "time"}}, EnabledByDefault: false, EssentialEvent: false},
	202: EventConfig{ID: 202, Name: "reserved", Probes: []probe{probe{event: "futex", attach: sysCall, fn: "futex"}}, EnabledByDefault: false, EssentialEvent: false},
	203: EventConfig{ID: 203, Name: "reserved", Probes: []probe{probe{event: "sched_setaffinity", attach: sysCall, fn: "sched_setaffinity"}}, EnabledByDefault: false, EssentialEvent: false},
	204: EventConfig{ID: 204, Name: "reserved", Probes: []probe{probe{event: "sched_getaffinity", attach: sysCall, fn: "sched_getaffinity"}}, EnabledByDefault: false, EssentialEvent: false},
	205: EventConfig{ID: 205, Name: "reserved", Probes: []probe{probe{event: "set_thread_area", attach: sysCall, fn: "set_thread_area"}}, EnabledByDefault: false, EssentialEvent: false},
	206: EventConfig{ID: 206, Name: "reserved", Probes: []probe{probe{event: "io_setup", attach: sysCall, fn: "io_setup"}}, EnabledByDefault: false, EssentialEvent: false},
	207: EventConfig{ID: 207, Name: "reserved", Probes: []probe{probe{event: "io_destroy", attach: sysCall, fn: "io_destroy"}}, EnabledByDefault: false, EssentialEvent: false},
	208: EventConfig{ID: 208, Name: "reserved", Probes: []probe{probe{event: "io_getevents", attach: sysCall, fn: "io_getevents"}}, EnabledByDefault: false, EssentialEvent: false},
	209: EventConfig{ID: 209, Name: "reserved", Probes: []probe{probe{event: "io_submit", attach: sysCall, fn: "io_submit"}}, EnabledByDefault: false, EssentialEvent: false},
	210: EventConfig{ID: 210, Name: "reserved", Probes: []probe{probe{event: "io_cancel", attach: sysCall, fn: "io_cancel"}}, EnabledByDefault: false, EssentialEvent: false},
	211: EventConfig{ID: 211, Name: "reserved", Probes: []probe{probe{event: "get_thread_area", attach: sysCall, fn: "get_thread_area"}}, EnabledByDefault: false, EssentialEvent: false},
	212: EventConfig{ID: 212, Name: "reserved", Probes: []probe{probe{event: "lookup_dcookie", attach: sysCall, fn: "lookup_dcookie"}}, EnabledByDefault: false, EssentialEvent: false},
	213: EventConfig{ID: 213, Name: "reserved", Probes: []probe{probe{event: "epoll_create", attach: sysCall, fn: "epoll_create"}}, EnabledByDefault: false, EssentialEvent: false},
	214: EventConfig{ID: 214, Name: "reserved", Probes: []probe{probe{event: "epoll_ctl_old", attach: sysCall, fn: "epoll_ctl_old"}}, EnabledByDefault: false, EssentialEvent: false},
	215: EventConfig{ID: 215, Name: "reserved", Probes: []probe{probe{event: "epoll_wait_old", attach: sysCall, fn: "epoll_wait_old"}}, EnabledByDefault: false, EssentialEvent: false},
	216: EventConfig{ID: 216, Name: "reserved", Probes: []probe{probe{event: "remap_file_pages", attach: sysCall, fn: "remap_file_pages"}}, EnabledByDefault: false, EssentialEvent: false},
	217: EventConfig{ID: 217, Name: "getdents64", Probes: []probe{probe{event: "getdents64", attach: sysCall, fn: "getdents64"}}, EnabledByDefault: true, EssentialEvent: false},
	218: EventConfig{ID: 218, Name: "reserved", Probes: []probe{probe{event: "set_tid_address", attach: sysCall, fn: "set_tid_address"}}, EnabledByDefault: false, EssentialEvent: false},
	219: EventConfig{ID: 219, Name: "reserved", Probes: []probe{probe{event: "restart_sysCall", attach: sysCall, fn: "restart_sysCall"}}, EnabledByDefault: false, EssentialEvent: false},
	220: EventConfig{ID: 220, Name: "reserved", Probes: []probe{probe{event: "semtimedop", attach: sysCall, fn: "semtimedop"}}, EnabledByDefault: false, EssentialEvent: false},
	221: EventConfig{ID: 221, Name: "reserved", Probes: []probe{probe{event: "fadvise64", attach: sysCall, fn: "fadvise64"}}, EnabledByDefault: false, EssentialEvent: false},
	222: EventConfig{ID: 222, Name: "reserved", Probes: []probe{probe{event: "timer_create", attach: sysCall, fn: "timer_create"}}, EnabledByDefault: false, EssentialEvent: false},
	223: EventConfig{ID: 223, Name: "reserved", Probes: []probe{probe{event: "timer_settime", attach: sysCall, fn: "timer_settime"}}, EnabledByDefault: false, EssentialEvent: false},
	224: EventConfig{ID: 224, Name: "reserved", Probes: []probe{probe{event: "timer_gettime", attach: sysCall, fn: "timer_gettime"}}, EnabledByDefault: false, EssentialEvent: false},
	225: EventConfig{ID: 225, Name: "reserved", Probes: []probe{probe{event: "timer_getoverrun", attach: sysCall, fn: "timer_getoverrun"}}, EnabledByDefault: false, EssentialEvent: false},
	226: EventConfig{ID: 226, Name: "reserved", Probes: []probe{probe{event: "timer_delete", attach: sysCall, fn: "timer_delete"}}, EnabledByDefault: false, EssentialEvent: false},
	227: EventConfig{ID: 227, Name: "reserved", Probes: []probe{probe{event: "clock_settime", attach: sysCall, fn: "clock_settime"}}, EnabledByDefault: false, EssentialEvent: false},
	228: EventConfig{ID: 228, Name: "reserved", Probes: []probe{probe{event: "clock_gettime", attach: sysCall, fn: "clock_gettime"}}, EnabledByDefault: false, EssentialEvent: false},
	229: EventConfig{ID: 229, Name: "reserved", Probes: []probe{probe{event: "clock_getres", attach: sysCall, fn: "clock_getres"}}, EnabledByDefault: false, EssentialEvent: false},
	230: EventConfig{ID: 230, Name: "reserved", Probes: []probe{probe{event: "clock_nanosleep", attach: sysCall, fn: "clock_nanosleep"}}, EnabledByDefault: false, EssentialEvent: false},
	231: EventConfig{ID: 231, Name: "reserved", Probes: []probe{probe{event: "exit_group", attach: sysCall, fn: "exit_group"}}, EnabledByDefault: false, EssentialEvent: false},
	232: EventConfig{ID: 232, Name: "reserved", Probes: []probe{probe{event: "epoll_wait", attach: sysCall, fn: "epoll_wait"}}, EnabledByDefault: false, EssentialEvent: false},
	233: EventConfig{ID: 233, Name: "reserved", Probes: []probe{probe{event: "epoll_ctl", attach: sysCall, fn: "epoll_ctl"}}, EnabledByDefault: false, EssentialEvent: false},
	234: EventConfig{ID: 234, Name: "reserved", Probes: []probe{probe{event: "tgkill", attach: sysCall, fn: "tgkill"}}, EnabledByDefault: false, EssentialEvent: false},
	235: EventConfig{ID: 235, Name: "reserved", Probes: []probe{probe{event: "utimes", attach: sysCall, fn: "utimes"}}, EnabledByDefault: false, EssentialEvent: false},
	236: EventConfig{ID: 236, Name: "reserved", Probes: []probe{probe{event: "vserver", attach: sysCall, fn: "vserver"}}, EnabledByDefault: false, EssentialEvent: false},
	237: EventConfig{ID: 237, Name: "reserved", Probes: []probe{probe{event: "mbind", attach: sysCall, fn: "mbind"}}, EnabledByDefault: false, EssentialEvent: false},
	238: EventConfig{ID: 238, Name: "reserved", Probes: []probe{probe{event: "set_mempolicy", attach: sysCall, fn: "set_mempolicy"}}, EnabledByDefault: false, EssentialEvent: false},
	239: EventConfig{ID: 239, Name: "reserved", Probes: []probe{probe{event: "get_mempolicy", attach: sysCall, fn: "get_mempolicy"}}, EnabledByDefault: false, EssentialEvent: false},
	240: EventConfig{ID: 240, Name: "reserved", Probes: []probe{probe{event: "mq_open", attach: sysCall, fn: "mq_open"}}, EnabledByDefault: false, EssentialEvent: false},
	241: EventConfig{ID: 241, Name: "reserved", Probes: []probe{probe{event: "mq_unlink", attach: sysCall, fn: "mq_unlink"}}, EnabledByDefault: false, EssentialEvent: false},
	242: EventConfig{ID: 242, Name: "reserved", Probes: []probe{probe{event: "mq_timedsend", attach: sysCall, fn: "mq_timedsend"}}, EnabledByDefault: false, EssentialEvent: false},
	243: EventConfig{ID: 243, Name: "reserved", Probes: []probe{probe{event: "mq_timedreceive", attach: sysCall, fn: "mq_timedreceive"}}, EnabledByDefault: false, EssentialEvent: false},
	244: EventConfig{ID: 244, Name: "reserved", Probes: []probe{probe{event: "mq_notify", attach: sysCall, fn: "mq_notify"}}, EnabledByDefault: false, EssentialEvent: false},
	245: EventConfig{ID: 245, Name: "reserved", Probes: []probe{probe{event: "mq_getsetattr", attach: sysCall, fn: "mq_getsetattr"}}, EnabledByDefault: false, EssentialEvent: false},
	246: EventConfig{ID: 246, Name: "reserved", Probes: []probe{probe{event: "kexec_load", attach: sysCall, fn: "kexec_load"}}, EnabledByDefault: false, EssentialEvent: false},
	247: EventConfig{ID: 247, Name: "reserved", Probes: []probe{probe{event: "waitid", attach: sysCall, fn: "waitid"}}, EnabledByDefault: false, EssentialEvent: false},
	248: EventConfig{ID: 248, Name: "reserved", Probes: []probe{probe{event: "add_key", attach: sysCall, fn: "add_key"}}, EnabledByDefault: false, EssentialEvent: false},
	249: EventConfig{ID: 249, Name: "reserved", Probes: []probe{probe{event: "request_key", attach: sysCall, fn: "request_key"}}, EnabledByDefault: false, EssentialEvent: false},
	250: EventConfig{ID: 250, Name: "reserved", Probes: []probe{probe{event: "keyctl", attach: sysCall, fn: "keyctl"}}, EnabledByDefault: false, EssentialEvent: false},
	251: EventConfig{ID: 251, Name: "reserved", Probes: []probe{probe{event: "ioprio_set", attach: sysCall, fn: "ioprio_set"}}, EnabledByDefault: false, EssentialEvent: false},
	252: EventConfig{ID: 252, Name: "reserved", Probes: []probe{probe{event: "ioprio_get", attach: sysCall, fn: "ioprio_get"}}, EnabledByDefault: false, EssentialEvent: false},
	253: EventConfig{ID: 253, Name: "reserved", Probes: []probe{probe{event: "inotify_init", attach: sysCall, fn: "inotify_init"}}, EnabledByDefault: false, EssentialEvent: false},
	254: EventConfig{ID: 254, Name: "reserved", Probes: []probe{probe{event: "inotify_add_watch", attach: sysCall, fn: "inotify_add_watch"}}, EnabledByDefault: false, EssentialEvent: false},
	255: EventConfig{ID: 255, Name: "reserved", Probes: []probe{probe{event: "inotify_rm_watch", attach: sysCall, fn: "inotify_rm_watch"}}, EnabledByDefault: false, EssentialEvent: false},
	256: EventConfig{ID: 256, Name: "reserved", Probes: []probe{probe{event: "migrate_pages", attach: sysCall, fn: "migrate_pages"}}, EnabledByDefault: false, EssentialEvent: false},
	257: EventConfig{ID: 257, Name: "openat", Probes: []probe{probe{event: "openat", attach: sysCall, fn: "openat"}}, EnabledByDefault: true, EssentialEvent: false},
	258: EventConfig{ID: 258, Name: "reserved", Probes: []probe{probe{event: "mkdirat", attach: sysCall, fn: "mkdirat"}}, EnabledByDefault: false, EssentialEvent: false},
	259: EventConfig{ID: 259, Name: "mknodat", Probes: []probe{probe{event: "mknodat", attach: sysCall, fn: "mknodat"}}, EnabledByDefault: true, EssentialEvent: false},
	260: EventConfig{ID: 260, Name: "fchownat", Probes: []probe{probe{event: "fchownat", attach: sysCall, fn: "fchownat"}}, EnabledByDefault: true, EssentialEvent: false},
	261: EventConfig{ID: 261, Name: "reserved", Probes: []probe{probe{event: "futimesat", attach: sysCall, fn: "futimesat"}}, EnabledByDefault: false, EssentialEvent: false},
	262: EventConfig{ID: 262, Name: "reserved", Probes: []probe{probe{event: "newfstatat", attach: sysCall, fn: "newfstatat"}}, EnabledByDefault: false, EssentialEvent: false},
	263: EventConfig{ID: 263, Name: "unlinkat", Probes: []probe{probe{event: "unlinkat", attach: sysCall, fn: "unlinkat"}}, EnabledByDefault: true, EssentialEvent: false},
	264: EventConfig{ID: 264, Name: "reserved", Probes: []probe{probe{event: "renameat", attach: sysCall, fn: "renameat"}}, EnabledByDefault: false, EssentialEvent: false},
	265: EventConfig{ID: 265, Name: "reserved", Probes: []probe{probe{event: "linkat", attach: sysCall, fn: "linkat"}}, EnabledByDefault: false, EssentialEvent: false},
	266: EventConfig{ID: 266, Name: "symlinkat", Probes: []probe{probe{event: "symlinkat", attach: sysCall, fn: "symlinkat"}}, EnabledByDefault: true, EssentialEvent: false},
	267: EventConfig{ID: 267, Name: "reserved", Probes: []probe{probe{event: "readlinkat", attach: sysCall, fn: "readlinkat"}}, EnabledByDefault: false, EssentialEvent: false},
	268: EventConfig{ID: 268, Name: "fchmodat", Probes: []probe{probe{event: "fchmodat", attach: sysCall, fn: "fchmodat"}}, EnabledByDefault: true, EssentialEvent: false},
	269: EventConfig{ID: 269, Name: "faccessat", Probes: []probe{probe{event: "faccessat", attach: sysCall, fn: "faccessat"}}, EnabledByDefault: true, EssentialEvent: false},
	270: EventConfig{ID: 270, Name: "reserved", Probes: []probe{probe{event: "pselect6", attach: sysCall, fn: "pselect6"}}, EnabledByDefault: false, EssentialEvent: false},
	271: EventConfig{ID: 271, Name: "reserved", Probes: []probe{probe{event: "ppoll", attach: sysCall, fn: "ppoll"}}, EnabledByDefault: false, EssentialEvent: false},
	272: EventConfig{ID: 272, Name: "reserved", Probes: []probe{probe{event: "unshare", attach: sysCall, fn: "unshare"}}, EnabledByDefault: false, EssentialEvent: false},
	273: EventConfig{ID: 273, Name: "reserved", Probes: []probe{probe{event: "set_robust_list", attach: sysCall, fn: "set_robust_list"}}, EnabledByDefault: false, EssentialEvent: false},
	274: EventConfig{ID: 274, Name: "reserved", Probes: []probe{probe{event: "get_robust_list", attach: sysCall, fn: "get_robust_list"}}, EnabledByDefault: false, EssentialEvent: false},
	275: EventConfig{ID: 275, Name: "reserved", Probes: []probe{probe{event: "splice", attach: sysCall, fn: "splice"}}, EnabledByDefault: false, EssentialEvent: false},
	276: EventConfig{ID: 276, Name: "reserved", Probes: []probe{probe{event: "tee", attach: sysCall, fn: "tee"}}, EnabledByDefault: false, EssentialEvent: false},
	277: EventConfig{ID: 277, Name: "reserved", Probes: []probe{probe{event: "sync_file_range", attach: sysCall, fn: "sync_file_range"}}, EnabledByDefault: false, EssentialEvent: false},
	278: EventConfig{ID: 278, Name: "reserved", Probes: []probe{probe{event: "vmsplice", attach: sysCall, fn: "vmsplice"}}, EnabledByDefault: false, EssentialEvent: false},
	279: EventConfig{ID: 279, Name: "reserved", Probes: []probe{probe{event: "move_pages", attach: sysCall, fn: "move_pages"}}, EnabledByDefault: false, EssentialEvent: false},
	280: EventConfig{ID: 280, Name: "reserved", Probes: []probe{probe{event: "utimensat", attach: sysCall, fn: "utimensat"}}, EnabledByDefault: false, EssentialEvent: false},
	281: EventConfig{ID: 281, Name: "reserved", Probes: []probe{probe{event: "epoll_pwait", attach: sysCall, fn: "epoll_pwait"}}, EnabledByDefault: false, EssentialEvent: false},
	282: EventConfig{ID: 282, Name: "reserved", Probes: []probe{probe{event: "signalfd", attach: sysCall, fn: "signalfd"}}, EnabledByDefault: false, EssentialEvent: false},
	283: EventConfig{ID: 283, Name: "reserved", Probes: []probe{probe{event: "timerfd_create", attach: sysCall, fn: "timerfd_create"}}, EnabledByDefault: false, EssentialEvent: false},
	284: EventConfig{ID: 284, Name: "reserved", Probes: []probe{probe{event: "eventfd", attach: sysCall, fn: "eventfd"}}, EnabledByDefault: false, EssentialEvent: false},
	285: EventConfig{ID: 285, Name: "reserved", Probes: []probe{probe{event: "fallocate", attach: sysCall, fn: "fallocate"}}, EnabledByDefault: false, EssentialEvent: false},
	286: EventConfig{ID: 286, Name: "reserved", Probes: []probe{probe{event: "timerfd_settime", attach: sysCall, fn: "timerfd_settime"}}, EnabledByDefault: false, EssentialEvent: false},
	287: EventConfig{ID: 287, Name: "reserved", Probes: []probe{probe{event: "timerfd_gettime", attach: sysCall, fn: "timerfd_gettime"}}, EnabledByDefault: false, EssentialEvent: false},
	288: EventConfig{ID: 288, Name: "accept4", Probes: []probe{probe{event: "accept4", attach: sysCall, fn: "accept4"}}, EnabledByDefault: true, EssentialEvent: false},
	289: EventConfig{ID: 289, Name: "reserved", Probes: []probe{probe{event: "signalfd4", attach: sysCall, fn: "signalfd4"}}, EnabledByDefault: false, EssentialEvent: false},
	290: EventConfig{ID: 290, Name: "reserved", Probes: []probe{probe{event: "eventfd2", attach: sysCall, fn: "eventfd2"}}, EnabledByDefault: false, EssentialEvent: false},
	291: EventConfig{ID: 291, Name: "reserved", Probes: []probe{probe{event: "epoll_create1", attach: sysCall, fn: "epoll_create1"}}, EnabledByDefault: false, EssentialEvent: false},
	292: EventConfig{ID: 292, Name: "dup3", Probes: []probe{probe{event: "dup3", attach: sysCall, fn: "dup3"}}, EnabledByDefault: true, EssentialEvent: false},
	293: EventConfig{ID: 293, Name: "reserved", Probes: []probe{probe{event: "pipe2", attach: sysCall, fn: "pipe2"}}, EnabledByDefault: false, EssentialEvent: false},
	294: EventConfig{ID: 294, Name: "reserved", Probes: []probe{probe{event: "ionotify_init1", attach: sysCall, fn: "ionotify_init1"}}, EnabledByDefault: false, EssentialEvent: false},
	295: EventConfig{ID: 295, Name: "reserved", Probes: []probe{probe{event: "preadv", attach: sysCall, fn: "preadv"}}, EnabledByDefault: false, EssentialEvent: false},
	296: EventConfig{ID: 296, Name: "reserved", Probes: []probe{probe{event: "pwritev", attach: sysCall, fn: "pwritev"}}, EnabledByDefault: false, EssentialEvent: false},
	297: EventConfig{ID: 297, Name: "reserved", Probes: []probe{probe{event: "rt_tgsigqueueinfo", attach: sysCall, fn: "rt_tgsigqueueinfo"}}, EnabledByDefault: false, EssentialEvent: false},
	298: EventConfig{ID: 298, Name: "reserved", Probes: []probe{probe{event: "perf_event_open", attach: sysCall, fn: "perf_event_open"}}, EnabledByDefault: false, EssentialEvent: false},
	299: EventConfig{ID: 299, Name: "reserved", Probes: []probe{probe{event: "recvmmsg", attach: sysCall, fn: "recvmmsg"}}, EnabledByDefault: false, EssentialEvent: false},
	300: EventConfig{ID: 300, Name: "reserved", Probes: []probe{probe{event: "fanotify_init", attach: sysCall, fn: "fanotify_init"}}, EnabledByDefault: false, EssentialEvent: false},
	301: EventConfig{ID: 301, Name: "reserved", Probes: []probe{probe{event: "fanotify_mark", attach: sysCall, fn: "fanotify_mark"}}, EnabledByDefault: false, EssentialEvent: false},
	302: EventConfig{ID: 302, Name: "reserved", Probes: []probe{probe{event: "prlimit64", attach: sysCall, fn: "prlimit64"}}, EnabledByDefault: false, EssentialEvent: false},
	303: EventConfig{ID: 303, Name: "reserved", Probes: []probe{probe{event: "name_tohandle_at", attach: sysCall, fn: "name_tohandle_at"}}, EnabledByDefault: false, EssentialEvent: false},
	304: EventConfig{ID: 304, Name: "reserved", Probes: []probe{probe{event: "open_by_handle_at", attach: sysCall, fn: "open_by_handle_at"}}, EnabledByDefault: false, EssentialEvent: false},
	305: EventConfig{ID: 305, Name: "reserved", Probes: []probe{probe{event: "clock_adjtime", attach: sysCall, fn: "clock_adjtime"}}, EnabledByDefault: false, EssentialEvent: false},
	306: EventConfig{ID: 306, Name: "reserved", Probes: []probe{probe{event: "sycnfs", attach: sysCall, fn: "sycnfs"}}, EnabledByDefault: false, EssentialEvent: false},
	307: EventConfig{ID: 307, Name: "reserved", Probes: []probe{probe{event: "sendmmsg", attach: sysCall, fn: "sendmmsg"}}, EnabledByDefault: false, EssentialEvent: false},
	308: EventConfig{ID: 308, Name: "reserved", Probes: []probe{probe{event: "setns", attach: sysCall, fn: "setns"}}, EnabledByDefault: false, EssentialEvent: false},
	309: EventConfig{ID: 309, Name: "reserved", Probes: []probe{probe{event: "getcpu", attach: sysCall, fn: "getcpu"}}, EnabledByDefault: false, EssentialEvent: false},
	310: EventConfig{ID: 310, Name: "process_vm_readv", Probes: []probe{probe{event: "process_vm_readv", attach: sysCall, fn: "process_vm_readv"}}, EnabledByDefault: true, EssentialEvent: false},
	311: EventConfig{ID: 311, Name: "process_vm_writev", Probes: []probe{probe{event: "process_vm_writev", attach: sysCall, fn: "process_vm_writev"}}, EnabledByDefault: true, EssentialEvent: false},
	312: EventConfig{ID: 312, Name: "reserved", Probes: []probe{probe{event: "kcmp", attach: sysCall, fn: "kcmp"}}, EnabledByDefault: false, EssentialEvent: false},
	313: EventConfig{ID: 313, Name: "finit_module", Probes: []probe{probe{event: "finit_module", attach: sysCall, fn: "finit_module"}}, EnabledByDefault: true, EssentialEvent: false},
	314: EventConfig{ID: 314, Name: "reserved", Probes: []probe{probe{event: "sched_setattr", attach: sysCall, fn: "sched_setattr"}}, EnabledByDefault: false, EssentialEvent: false},
	315: EventConfig{ID: 315, Name: "reserved", Probes: []probe{probe{event: "sched_getattr", attach: sysCall, fn: "sched_getattr"}}, EnabledByDefault: false, EssentialEvent: false},
	316: EventConfig{ID: 316, Name: "reserved", Probes: []probe{probe{event: "renameat2", attach: sysCall, fn: "renameat2"}}, EnabledByDefault: false, EssentialEvent: false},
	317: EventConfig{ID: 317, Name: "reserved", Probes: []probe{probe{event: "seccomp", attach: sysCall, fn: "seccomp"}}, EnabledByDefault: false, EssentialEvent: false},
	318: EventConfig{ID: 318, Name: "reserved", Probes: []probe{probe{event: "getrandom", attach: sysCall, fn: "getrandom"}}, EnabledByDefault: false, EssentialEvent: false},
	319: EventConfig{ID: 319, Name: "memfd_create", Probes: []probe{probe{event: "memfd_create", attach: sysCall, fn: "memfd_create"}}, EnabledByDefault: true, EssentialEvent: false},
	320: EventConfig{ID: 320, Name: "reserved", Probes: []probe{probe{event: "kexec_file_load", attach: sysCall, fn: "kexec_file_load"}}, EnabledByDefault: false, EssentialEvent: false},
	321: EventConfig{ID: 321, Name: "reserved", Probes: []probe{probe{event: "bpf", attach: sysCall, fn: "bpf"}}, EnabledByDefault: false, EssentialEvent: false},
	322: EventConfig{ID: 322, Name: "execveat", Probes: []probe{probe{event: "execveat", attach: sysCall, fn: "execveat"}}, EnabledByDefault: true, EssentialEvent: true},
	323: EventConfig{ID: 323, Name: "reserved", Probes: []probe{probe{event: "userfaultfd", attach: sysCall, fn: "userfaultfd"}}, EnabledByDefault: false, EssentialEvent: false},
	324: EventConfig{ID: 324, Name: "reserved", Probes: []probe{probe{event: "membarrier", attach: sysCall, fn: "membarrier"}}, EnabledByDefault: false, EssentialEvent: false},
	325: EventConfig{ID: 325, Name: "reserved", Probes: []probe{probe{event: "mlock2", attach: sysCall, fn: "mlock2"}}, EnabledByDefault: false, EssentialEvent: false},
	326: EventConfig{ID: 326, Name: "reserved", Probes: []probe{probe{event: "copy_file_range", attach: sysCall, fn: "copy_file_range"}}, EnabledByDefault: false, EssentialEvent: false},
	327: EventConfig{ID: 327, Name: "reserved", Probes: []probe{probe{event: "preadv2", attach: sysCall, fn: "preadv2"}}, EnabledByDefault: false, EssentialEvent: false},
	328: EventConfig{ID: 328, Name: "reserved", Probes: []probe{probe{event: "pwritev2", attach: sysCall, fn: "pwritev2"}}, EnabledByDefault: false, EssentialEvent: false},
	329: EventConfig{ID: 329, Name: "pkey_mprotect", Probes: []probe{probe{event: "pkey_mprotect", attach: sysCall, fn: "pkey_mprotect"}}, EnabledByDefault: true, EssentialEvent: false},
	330: EventConfig{ID: 330, Name: "reserved", Probes: []probe{probe{event: "pkey_alloc", attach: sysCall, fn: "pkey_alloc"}}, EnabledByDefault: false, EssentialEvent: false},
	331: EventConfig{ID: 331, Name: "reserved", Probes: []probe{probe{event: "pkey_free", attach: sysCall, fn: "pkey_free"}}, EnabledByDefault: false, EssentialEvent: false},
	332: EventConfig{ID: 332, Name: "reserved", Probes: []probe{probe{event: "statx", attach: sysCall, fn: "statx"}}, EnabledByDefault: false, EssentialEvent: false},
	333: EventConfig{ID: 333, Name: "reserved", Probes: []probe{probe{event: "io_pgetevents", attach: sysCall, fn: "io_pgetevents"}}, EnabledByDefault: false, EssentialEvent: false},
	334: EventConfig{ID: 334, Name: "reserved", Probes: []probe{probe{event: "rseq", attach: sysCall, fn: "rseq"}}, EnabledByDefault: false, EssentialEvent: false},
	335: EventConfig{ID: 335, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	336: EventConfig{ID: 336, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	337: EventConfig{ID: 337, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	338: EventConfig{ID: 338, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	339: EventConfig{ID: 339, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	340: EventConfig{ID: 340, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	341: EventConfig{ID: 341, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	342: EventConfig{ID: 342, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	343: EventConfig{ID: 343, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	344: EventConfig{ID: 344, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	345: EventConfig{ID: 345, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	346: EventConfig{ID: 346, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	347: EventConfig{ID: 347, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	348: EventConfig{ID: 348, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	349: EventConfig{ID: 349, Name: "reserved", Probes: []probe{probe{event: "reserved", attach: sysCall, fn: "reserved"}}, EnabledByDefault: false, EssentialEvent: false},
	350: EventConfig{ID: 350, Name: "raw_syscalls", Probes: []probe{probe{event: "raw_syscalls:sys_enter", attach: tracepoint, fn: "tracepoint__raw_syscalls__sys_enter"}}, EnabledByDefault: false, EssentialEvent: false},
	351: EventConfig{ID: 351, Name: "do_exit", Probes: []probe{probe{event: "do_exit", attach: kprobe, fn: "trace_do_exit"}}, EnabledByDefault: true, EssentialEvent: true},
	352: EventConfig{ID: 352, Name: "cap_capable", Probes: []probe{probe{event: "cap_capable", attach: kprobe, fn: "trace_cap_capable"}}, EnabledByDefault: true, EssentialEvent: false},
	353: EventConfig{ID: 353, Name: "security_bprm_check", Probes: []probe{probe{event: "security_bprm_check", attach: kprobe, fn: "trace_security_bprm_check"}}, EnabledByDefault: true, EssentialEvent: false},
	354: EventConfig{ID: 354, Name: "security_file_open", Probes: []probe{probe{event: "security_file_open", attach: kprobe, fn: "trace_security_file_open"}}, EnabledByDefault: true, EssentialEvent: false},
	355: EventConfig{ID: 355, Name: "vfs_write", Probes: []probe{probe{event: "vfs_write", attach: kprobe, fn: "trace_vfs_write"}, probe{event: "vfs_write", attach: kretprobe, fn: "trace_ret_vfs_write"}}, EnabledByDefault: true, EssentialEvent: false},
	356: EventConfig{ID: 356, Name: "mem_prot_alert", Probes: []probe{probe{event: "security_mmap_addr", attach: kprobe, fn: "trace_mmap_alert"}, probe{event: "security_file_mprotect", attach: kprobe, fn: "trace_mprotect_alert"}}, EnabledByDefault: false, EssentialEvent: false},
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
