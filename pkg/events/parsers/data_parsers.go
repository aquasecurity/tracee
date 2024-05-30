package parsers

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"

	"github.com/aquasecurity/tracee/pkg/utils/environment"
)

type SystemFunctionArgument interface {
	fmt.Stringer
	Value() uint64
}

// OptionAreContainedInArgument checks whether the argument (rawArgument)
// contains all of the 'options' such as with flags passed to the clone flag.
// This function takes an arbitrary number of SystemCallArguments.It will
// only return true if each and every option is present in rawArgument.
// Typically linux syscalls have multiple options specified in a single
// argument via bitmasks = which this function checks for.
func OptionAreContainedInArgument(rawArgument uint64, options ...SystemFunctionArgument) bool {
	var isPresent = true
	for _, option := range options {
		isPresent = isPresent && (option.Value()&rawArgument == option.Value())
	}
	return isPresent
}

type CloneFlagArgument struct {
	rawValue    uint64
	stringValue string
}

// revive:disable

var (
	// These values are copied from uapi/linux/sched.h
	CLONE_VM             CloneFlagArgument = CloneFlagArgument{rawValue: 0x00000100, stringValue: "CLONE_VM"}
	CLONE_FS             CloneFlagArgument = CloneFlagArgument{rawValue: 0x00000200, stringValue: "CLONE_FS"}
	CLONE_FILES          CloneFlagArgument = CloneFlagArgument{rawValue: 0x00000400, stringValue: "CLONE_FILES"}
	CLONE_SIGHAND        CloneFlagArgument = CloneFlagArgument{rawValue: 0x00000800, stringValue: "CLONE_SIGHAND"}
	CLONE_PIDFD          CloneFlagArgument = CloneFlagArgument{rawValue: 0x00001000, stringValue: "CLONE_PIDFD"}
	CLONE_PTRACE         CloneFlagArgument = CloneFlagArgument{rawValue: 0x00002000, stringValue: "CLONE_PTRACE"}
	CLONE_VFORK          CloneFlagArgument = CloneFlagArgument{rawValue: 0x00004000, stringValue: "CLONE_VFORK"}
	CLONE_PARENT         CloneFlagArgument = CloneFlagArgument{rawValue: 0x00008000, stringValue: "CLONE_PARENT"}
	CLONE_THREAD         CloneFlagArgument = CloneFlagArgument{rawValue: 0x00010000, stringValue: "CLONE_THREAD"}
	CLONE_NEWNS          CloneFlagArgument = CloneFlagArgument{rawValue: 0x00020000, stringValue: "CLONE_NEWNS"}
	CLONE_SYSVSEM        CloneFlagArgument = CloneFlagArgument{rawValue: 0x00040000, stringValue: "CLONE_SYSVSEM"}
	CLONE_SETTLS         CloneFlagArgument = CloneFlagArgument{rawValue: 0x00080000, stringValue: "CLONE_SETTLS"}
	CLONE_PARENT_SETTID  CloneFlagArgument = CloneFlagArgument{rawValue: 0x00100000, stringValue: "CLONE_PARENT_SETTID"}
	CLONE_CHILD_CLEARTID CloneFlagArgument = CloneFlagArgument{rawValue: 0x00200000, stringValue: "CLONE_CHILD_CLEARTID"}
	CLONE_DETACHED       CloneFlagArgument = CloneFlagArgument{rawValue: 0x00400000, stringValue: "CLONE_DETACHED"}
	CLONE_UNTRACED       CloneFlagArgument = CloneFlagArgument{rawValue: 0x00800000, stringValue: "CLONE_UNTRACED"}
	CLONE_CHILD_SETTID   CloneFlagArgument = CloneFlagArgument{rawValue: 0x01000000, stringValue: "CLONE_CHILD_SETTID"}
	CLONE_NEWCGROUP      CloneFlagArgument = CloneFlagArgument{rawValue: 0x02000000, stringValue: "CLONE_NEWCGROUP"}
	CLONE_NEWUTS         CloneFlagArgument = CloneFlagArgument{rawValue: 0x04000000, stringValue: "CLONE_NEWUTS"}
	CLONE_NEWIPC         CloneFlagArgument = CloneFlagArgument{rawValue: 0x08000000, stringValue: "CLONE_NEWIPC"}
	CLONE_NEWUSER        CloneFlagArgument = CloneFlagArgument{rawValue: 0x10000000, stringValue: "CLONE_NEWUSER"}
	CLONE_NEWPID         CloneFlagArgument = CloneFlagArgument{rawValue: 0x20000000, stringValue: "CLONE_NEWPID"}
	CLONE_NEWNET         CloneFlagArgument = CloneFlagArgument{rawValue: 0x40000000, stringValue: "CLONE_NEWNET"}
	CLONE_IO             CloneFlagArgument = CloneFlagArgument{rawValue: 0x80000000, stringValue: "CLONE_IO"}
)

// revive:enable

func (c CloneFlagArgument) Value() uint64  { return c.rawValue }
func (c CloneFlagArgument) String() string { return c.stringValue }

func ParseCloneFlags(rawValue uint64) (CloneFlagArgument, error) {
	if rawValue == 0 {
		return CloneFlagArgument{}, nil
	}

	var f []string
	if OptionAreContainedInArgument(rawValue, CLONE_VM) {
		f = append(f, CLONE_VM.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_FS) {
		f = append(f, CLONE_FS.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_FILES) {
		f = append(f, CLONE_FILES.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_SIGHAND) {
		f = append(f, CLONE_SIGHAND.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_PIDFD) {
		f = append(f, CLONE_PIDFD.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_PTRACE) {
		f = append(f, CLONE_PTRACE.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_VFORK) {
		f = append(f, CLONE_VFORK.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_PARENT) {
		f = append(f, CLONE_PARENT.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_THREAD) {
		f = append(f, CLONE_THREAD.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_NEWNS) {
		f = append(f, CLONE_NEWNS.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_SYSVSEM) {
		f = append(f, CLONE_SYSVSEM.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_SETTLS) {
		f = append(f, CLONE_SETTLS.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_PARENT_SETTID) {
		f = append(f, CLONE_PARENT_SETTID.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_CHILD_CLEARTID) {
		f = append(f, CLONE_CHILD_CLEARTID.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_DETACHED) {
		f = append(f, CLONE_DETACHED.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_UNTRACED) {
		f = append(f, CLONE_UNTRACED.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_CHILD_SETTID) {
		f = append(f, CLONE_CHILD_SETTID.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_NEWCGROUP) {
		f = append(f, CLONE_NEWCGROUP.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_NEWUTS) {
		f = append(f, CLONE_NEWUTS.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_NEWIPC) {
		f = append(f, CLONE_NEWIPC.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_NEWUSER) {
		f = append(f, CLONE_NEWUSER.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_NEWPID) {
		f = append(f, CLONE_NEWPID.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_NEWNET) {
		f = append(f, CLONE_NEWNET.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_IO) {
		f = append(f, CLONE_IO.String())
	}
	if len(f) == 0 {
		return CloneFlagArgument{}, fmt.Errorf("no valid clone flag values present in raw value: 0x%x", rawValue)
	}

	return CloneFlagArgument{stringValue: strings.Join(f, "|"), rawValue: rawValue}, nil
}

type OpenFlagArgument struct {
	rawValue    uint64
	stringValue string
}

// revive:disable

var (
	// These values are copied from uapi/asm-generic/fcntl.h
	O_ACCMODE   OpenFlagArgument = OpenFlagArgument{rawValue: 00000003, stringValue: "O_ACCMODE"}
	O_RDONLY    OpenFlagArgument = OpenFlagArgument{rawValue: 00000000, stringValue: "O_RDONLY"}
	O_WRONLY    OpenFlagArgument = OpenFlagArgument{rawValue: 00000001, stringValue: "O_WRONLY"}
	O_RDWR      OpenFlagArgument = OpenFlagArgument{rawValue: 00000002, stringValue: "O_RDWR"}
	O_CREAT     OpenFlagArgument = OpenFlagArgument{rawValue: 00000100, stringValue: "O_CREAT"}
	O_EXCL      OpenFlagArgument = OpenFlagArgument{rawValue: 00000200, stringValue: "O_EXCL"}
	O_NOCTTY    OpenFlagArgument = OpenFlagArgument{rawValue: 00000400, stringValue: "O_NOCTTY"}
	O_TRUNC     OpenFlagArgument = OpenFlagArgument{rawValue: 00001000, stringValue: "O_TRUNC"}
	O_APPEND    OpenFlagArgument = OpenFlagArgument{rawValue: 00002000, stringValue: "O_APPEND"}
	O_NONBLOCK  OpenFlagArgument = OpenFlagArgument{rawValue: 00004000, stringValue: "O_NONBLOCK"}
	O_DSYNC     OpenFlagArgument = OpenFlagArgument{rawValue: 00010000, stringValue: "O_DSYNC"}
	O_SYNC      OpenFlagArgument = OpenFlagArgument{rawValue: 04010000, stringValue: "O_SYNC"}
	FASYNC      OpenFlagArgument = OpenFlagArgument{rawValue: 00020000, stringValue: "FASYNC"}
	O_DIRECT    OpenFlagArgument = OpenFlagArgument{rawValue: 00040000, stringValue: "O_DIRECT"}
	O_LARGEFILE OpenFlagArgument = OpenFlagArgument{rawValue: 00100000, stringValue: "O_LARGEFILE"}
	O_DIRECTORY OpenFlagArgument = OpenFlagArgument{rawValue: 00200000, stringValue: "O_DIRECTORY"}
	O_NOFOLLOW  OpenFlagArgument = OpenFlagArgument{rawValue: 00400000, stringValue: "O_NOFOLLOW"}
	O_NOATIME   OpenFlagArgument = OpenFlagArgument{rawValue: 01000000, stringValue: "O_NOATIME"}
	O_CLOEXEC   OpenFlagArgument = OpenFlagArgument{rawValue: 02000000, stringValue: "O_CLOEXEC"}
	O_PATH      OpenFlagArgument = OpenFlagArgument{rawValue: 040000000, stringValue: "O_PATH"}
	O_TMPFILE   OpenFlagArgument = OpenFlagArgument{rawValue: 020000000, stringValue: "O_TMPFILE"}
)

// revive:enable

func (o OpenFlagArgument) Value() uint64  { return o.rawValue }
func (o OpenFlagArgument) String() string { return o.stringValue }

// ParseOpenFlagArgument parses the `flags` bitmask argument of the `open` syscall
// http://man7.org/linux/man-pages/man2/open.2.html
// https://elixir.bootlin.com/linux/v5.5.3/source/include/uapi/asm-generic/fcntl.h
func ParseOpenFlagArgument(rawValue uint64) (OpenFlagArgument, error) {
	if rawValue == 0 {
		return OpenFlagArgument{}, nil
	}
	var f []string

	// access mode
	switch {
	case OptionAreContainedInArgument(rawValue, O_WRONLY):
		f = append(f, O_WRONLY.String())
	case OptionAreContainedInArgument(rawValue, O_RDWR):
		f = append(f, O_RDWR.String())
	default:
		f = append(f, O_RDONLY.String())
	}

	// file creation and status flags
	if OptionAreContainedInArgument(rawValue, O_CREAT) {
		f = append(f, O_CREAT.String())
	}
	if OptionAreContainedInArgument(rawValue, O_EXCL) {
		f = append(f, O_EXCL.String())
	}
	if OptionAreContainedInArgument(rawValue, O_NOCTTY) {
		f = append(f, O_NOCTTY.String())
	}
	if OptionAreContainedInArgument(rawValue, O_TRUNC) {
		f = append(f, O_TRUNC.String())
	}
	if OptionAreContainedInArgument(rawValue, O_APPEND) {
		f = append(f, O_APPEND.String())
	}
	if OptionAreContainedInArgument(rawValue, O_NONBLOCK) {
		f = append(f, O_NONBLOCK.String())
	}
	if OptionAreContainedInArgument(rawValue, O_SYNC) {
		f = append(f, O_SYNC.String())
	}
	if OptionAreContainedInArgument(rawValue, FASYNC) {
		f = append(f, FASYNC.String())
	}
	if OptionAreContainedInArgument(rawValue, O_LARGEFILE) {
		f = append(f, O_LARGEFILE.String())
	}
	if OptionAreContainedInArgument(rawValue, O_DIRECTORY) {
		f = append(f, O_DIRECTORY.String())
	}
	if OptionAreContainedInArgument(rawValue, O_NOFOLLOW) {
		f = append(f, O_NOFOLLOW.String())
	}
	if OptionAreContainedInArgument(rawValue, O_CLOEXEC) {
		f = append(f, O_CLOEXEC.String())
	}
	if OptionAreContainedInArgument(rawValue, O_DIRECT) {
		f = append(f, O_DIRECT.String())
	}
	if OptionAreContainedInArgument(rawValue, O_NOATIME) {
		f = append(f, O_NOATIME.String())
	}
	if OptionAreContainedInArgument(rawValue, O_PATH) {
		f = append(f, O_PATH.String())
	}
	if OptionAreContainedInArgument(rawValue, O_TMPFILE) {
		f = append(f, O_TMPFILE.String())
	}

	if len(f) == 0 {
		return OpenFlagArgument{}, fmt.Errorf("no valid open flag values present in raw value: 0x%x", rawValue)
	}

	return OpenFlagArgument{rawValue: rawValue, stringValue: strings.Join(f, "|")}, nil
}

type AccessModeArgument struct {
	rawValue    uint64
	stringValue string
}

// revive:disable

var (
	F_OK AccessModeArgument = AccessModeArgument{rawValue: 0, stringValue: "F_OK"}
	X_OK AccessModeArgument = AccessModeArgument{rawValue: 1, stringValue: "X_OK"}
	W_OK AccessModeArgument = AccessModeArgument{rawValue: 2, stringValue: "W_OK"}
	R_OK AccessModeArgument = AccessModeArgument{rawValue: 4, stringValue: "R_OK"}
)

// revive:enable

func (a AccessModeArgument) Value() uint64 { return a.rawValue }

func (a AccessModeArgument) String() string { return a.stringValue }

// ParseAccessMode parses the mode from the `access` system call
// http://man7.org/linux/man-pages/man2/access.2.html
func ParseAccessMode(rawValue uint64) (AccessModeArgument, error) {
	if rawValue == 0 {
		return AccessModeArgument{}, nil
	}
	var f []string
	if rawValue == 0x0 {
		f = append(f, F_OK.String())
	} else {
		if OptionAreContainedInArgument(rawValue, R_OK) {
			f = append(f, R_OK.String())
		}
		if OptionAreContainedInArgument(rawValue, W_OK) {
			f = append(f, W_OK.String())
		}
		if OptionAreContainedInArgument(rawValue, X_OK) {
			f = append(f, X_OK.String())
		}
	}

	if len(f) == 0 {
		return AccessModeArgument{}, fmt.Errorf("no valid access mode values present in raw value: 0x%x", rawValue)
	}

	return AccessModeArgument{stringValue: strings.Join(f, "|"), rawValue: rawValue}, nil
}

type ExecFlagArgument struct {
	rawValue    uint64
	stringValue string
}

// revive:disable

var (
	AT_SYMLINK_NOFOLLOW   ExecFlagArgument = ExecFlagArgument{stringValue: "AT_SYMLINK_NOFOLLOW", rawValue: 0x100}
	AT_EACCESS            ExecFlagArgument = ExecFlagArgument{stringValue: "AT_EACCESS", rawValue: 0x200}
	AT_REMOVEDIR          ExecFlagArgument = ExecFlagArgument{stringValue: "AT_REMOVEDIR", rawValue: 0x200}
	AT_SYMLINK_FOLLOW     ExecFlagArgument = ExecFlagArgument{stringValue: "AT_SYMLINK_FOLLOW", rawValue: 0x400}
	AT_NO_AUTOMOUNT       ExecFlagArgument = ExecFlagArgument{stringValue: "AT_NO_AUTOMOUNT", rawValue: 0x800}
	AT_EMPTY_PATH         ExecFlagArgument = ExecFlagArgument{stringValue: "AT_EMPTY_PATH", rawValue: 0x1000}
	AT_STATX_SYNC_TYPE    ExecFlagArgument = ExecFlagArgument{stringValue: "AT_STATX_SYNC_TYPE", rawValue: 0x6000}
	AT_STATX_SYNC_AS_STAT ExecFlagArgument = ExecFlagArgument{stringValue: "AT_STATX_SYNC_AS_STAT", rawValue: 0x0000}
	AT_STATX_FORCE_SYNC   ExecFlagArgument = ExecFlagArgument{stringValue: "AT_STATX_FORCE_SYNC", rawValue: 0x2000}
	AT_STATX_DONT_SYNC    ExecFlagArgument = ExecFlagArgument{stringValue: "AT_STATX_DONT_SYNC", rawValue: 0x4000}
	AT_RECURSIVE          ExecFlagArgument = ExecFlagArgument{stringValue: "AT_RECURSIVE", rawValue: 0x8000}
)

// revive:enable

func (e ExecFlagArgument) Value() uint64  { return e.rawValue }
func (e ExecFlagArgument) String() string { return e.stringValue }

func ParseExecFlag(rawValue uint64) (ExecFlagArgument, error) {
	if rawValue == 0 {
		return ExecFlagArgument{}, nil
	}

	var f []string
	if OptionAreContainedInArgument(rawValue, AT_EMPTY_PATH) {
		f = append(f, AT_EMPTY_PATH.String())
	}
	if OptionAreContainedInArgument(rawValue, AT_SYMLINK_NOFOLLOW) {
		f = append(f, AT_SYMLINK_NOFOLLOW.String())
	}
	if OptionAreContainedInArgument(rawValue, AT_EACCESS) {
		f = append(f, AT_EACCESS.String())
	}
	if OptionAreContainedInArgument(rawValue, AT_REMOVEDIR) {
		f = append(f, AT_REMOVEDIR.String())
	}
	if OptionAreContainedInArgument(rawValue, AT_NO_AUTOMOUNT) {
		f = append(f, AT_NO_AUTOMOUNT.String())
	}
	if OptionAreContainedInArgument(rawValue, AT_STATX_SYNC_TYPE) {
		f = append(f, AT_STATX_SYNC_TYPE.String())
	}
	if OptionAreContainedInArgument(rawValue, AT_STATX_FORCE_SYNC) {
		f = append(f, AT_STATX_FORCE_SYNC.String())
	}
	if OptionAreContainedInArgument(rawValue, AT_STATX_DONT_SYNC) {
		f = append(f, AT_STATX_DONT_SYNC.String())
	}
	if OptionAreContainedInArgument(rawValue, AT_RECURSIVE) {
		f = append(f, AT_RECURSIVE.String())
	}
	if len(f) == 0 {
		return ExecFlagArgument{}, fmt.Errorf("no valid exec flag values present in raw value: 0x%x", rawValue)
	}
	return ExecFlagArgument{stringValue: strings.Join(f, "|"), rawValue: rawValue}, nil
}

type CapabilityFlagArgument uint64

const (
	CAP_CHOWN CapabilityFlagArgument = iota
	CAP_DAC_OVERRIDE
	CAP_DAC_READ_SEARCH
	CAP_FOWNER
	CAP_FSETID
	CAP_KILL
	CAP_SETGID
	CAP_SETUID
	CAP_SETPCAP
	CAP_LINUX_IMMUTABLE
	CAP_NET_BIND_SERVICE
	CAP_NET_BROADCAST
	CAP_NET_ADMIN
	CAP_NET_RAW
	CAP_IPC_LOCK
	CAP_IPC_OWNER
	CAP_SYS_MODULE
	CAP_SYS_RAWIO
	CAP_SYS_CHROOT
	CAP_SYS_PTRACE
	CAP_SYS_PACCT
	CAP_SYS_ADMIN
	CAP_SYS_BOOT
	CAP_SYS_NICE
	CAP_SYS_RESOURCE
	CAP_SYS_TIME
	CAP_SYS_TTY_CONFIG
	CAP_MKNOD
	CAP_LEASE
	CAP_AUDIT_WRITE
	CAP_AUDIT_CONTROL
	CAP_SETFCAP
	CAP_MAC_OVERRIDE
	CAP_MAC_ADMIN
	CAP_SYSLOG
	CAP_WAKE_ALARM
	CAP_BLOCK_SUSPEND
	CAP_AUDIT_READ
)

func (c CapabilityFlagArgument) Value() uint64 { return uint64(c) }

var capFlagStringMap = map[CapabilityFlagArgument]string{
	CAP_CHOWN:            "CAP_CHOWN",
	CAP_DAC_OVERRIDE:     "CAP_DAC_OVERRIDE",
	CAP_DAC_READ_SEARCH:  "CAP_DAC_READ_SEARCH",
	CAP_FOWNER:           "CAP_FOWNER",
	CAP_FSETID:           "CAP_FSETID",
	CAP_KILL:             "CAP_KILL",
	CAP_SETGID:           "CAP_SETGID",
	CAP_SETUID:           "CAP_SETUID",
	CAP_SETPCAP:          "CAP_SETPCAP",
	CAP_LINUX_IMMUTABLE:  "CAP_LINUX_IMMUTABLE",
	CAP_NET_BIND_SERVICE: "CAP_NET_BIND_SERVICE",
	CAP_NET_BROADCAST:    "CAP_NET_BROADCAST",
	CAP_NET_ADMIN:        "CAP_NET_ADMIN",
	CAP_NET_RAW:          "CAP_NET_RAW",
	CAP_IPC_LOCK:         "CAP_IPC_LOCK",
	CAP_IPC_OWNER:        "CAP_IPC_OWNER",
	CAP_SYS_MODULE:       "CAP_SYS_MODULE",
	CAP_SYS_RAWIO:        "CAP_SYS_RAWIO",
	CAP_SYS_CHROOT:       "CAP_SYS_CHROOT",
	CAP_SYS_PTRACE:       "CAP_SYS_PTRACE",
	CAP_SYS_PACCT:        "CAP_SYS_PACCT",
	CAP_SYS_ADMIN:        "CAP_SYS_ADMIN",
	CAP_SYS_BOOT:         "CAP_SYS_BOOT",
	CAP_SYS_NICE:         "CAP_SYS_NICE",
	CAP_SYS_RESOURCE:     "CAP_SYS_RESOURCE",
	CAP_SYS_TIME:         "CAP_SYS_TIME",
	CAP_SYS_TTY_CONFIG:   "CAP_SYS_TTY_CONFIG",
	CAP_MKNOD:            "CAP_MKNOD",
	CAP_LEASE:            "CAP_LEASE",
	CAP_AUDIT_WRITE:      "CAP_AUDIT_WRITE",
	CAP_AUDIT_CONTROL:    "CAP_AUDIT_CONTROL",
	CAP_SETFCAP:          "CAP_SETFCAP",
	CAP_MAC_OVERRIDE:     "CAP_MAC_OVERRIDE",
	CAP_MAC_ADMIN:        "CAP_MAC_ADMIN",
	CAP_SYSLOG:           "CAP_SYSLOG",
	CAP_WAKE_ALARM:       "CAP_WAKE_ALARM",
	CAP_BLOCK_SUSPEND:    "CAP_BLOCK_SUSPEND",
	CAP_AUDIT_READ:       "CAP_AUDIT_READ",
}

func (c CapabilityFlagArgument) String() string {
	var res string

	if capName, ok := capFlagStringMap[c]; ok {
		res = capName
	} else {
		res = strconv.Itoa(int(c))
	}
	return res
}

var capabilitiesMap = map[uint64]CapabilityFlagArgument{
	CAP_CHOWN.Value():            CAP_CHOWN,
	CAP_DAC_OVERRIDE.Value():     CAP_DAC_OVERRIDE,
	CAP_DAC_READ_SEARCH.Value():  CAP_DAC_READ_SEARCH,
	CAP_FOWNER.Value():           CAP_FOWNER,
	CAP_FSETID.Value():           CAP_FSETID,
	CAP_KILL.Value():             CAP_KILL,
	CAP_SETGID.Value():           CAP_SETGID,
	CAP_SETUID.Value():           CAP_SETUID,
	CAP_SETPCAP.Value():          CAP_SETPCAP,
	CAP_LINUX_IMMUTABLE.Value():  CAP_LINUX_IMMUTABLE,
	CAP_NET_BIND_SERVICE.Value(): CAP_NET_BIND_SERVICE,
	CAP_NET_BROADCAST.Value():    CAP_NET_BROADCAST,
	CAP_NET_ADMIN.Value():        CAP_NET_ADMIN,
	CAP_NET_RAW.Value():          CAP_NET_RAW,
	CAP_IPC_LOCK.Value():         CAP_IPC_LOCK,
	CAP_IPC_OWNER.Value():        CAP_IPC_OWNER,
	CAP_SYS_MODULE.Value():       CAP_SYS_MODULE,
	CAP_SYS_RAWIO.Value():        CAP_SYS_RAWIO,
	CAP_SYS_CHROOT.Value():       CAP_SYS_CHROOT,
	CAP_SYS_PTRACE.Value():       CAP_SYS_PTRACE,
	CAP_SYS_PACCT.Value():        CAP_SYS_PACCT,
	CAP_SYS_ADMIN.Value():        CAP_SYS_ADMIN,
	CAP_SYS_BOOT.Value():         CAP_SYS_BOOT,
	CAP_SYS_NICE.Value():         CAP_SYS_NICE,
	CAP_SYS_RESOURCE.Value():     CAP_SYS_RESOURCE,
	CAP_SYS_TIME.Value():         CAP_SYS_TIME,
	CAP_SYS_TTY_CONFIG.Value():   CAP_SYS_TTY_CONFIG,
	CAP_MKNOD.Value():            CAP_MKNOD,
	CAP_LEASE.Value():            CAP_LEASE,
	CAP_AUDIT_WRITE.Value():      CAP_AUDIT_WRITE,
	CAP_AUDIT_CONTROL.Value():    CAP_AUDIT_CONTROL,
	CAP_SETFCAP.Value():          CAP_SETFCAP,
	CAP_MAC_OVERRIDE.Value():     CAP_MAC_OVERRIDE,
	CAP_MAC_ADMIN.Value():        CAP_MAC_ADMIN,
	CAP_SYSLOG.Value():           CAP_SYSLOG,
	CAP_WAKE_ALARM.Value():       CAP_WAKE_ALARM,
	CAP_BLOCK_SUSPEND.Value():    CAP_BLOCK_SUSPEND,
	CAP_AUDIT_READ.Value():       CAP_AUDIT_READ,
}

// ParseCapability parses the `capability` bitmask argument of the
// `cap_capable` function
func ParseCapability(rawValue uint64) (CapabilityFlagArgument, error) {
	v, ok := capabilitiesMap[rawValue]
	if !ok {
		return 0, fmt.Errorf("not a valid capability value: %d", rawValue)
	}
	return v, nil
}

type PrctlOptionArgument uint64

const (
	PR_SET_PDEATHSIG PrctlOptionArgument = iota + 1
	PR_GET_PDEATHSIG
	PR_GET_DUMPABLE
	PR_SET_DUMPABLE
	PR_GET_UNALIGN
	PR_SET_UNALIGN
	PR_GET_KEEPCAPS
	PR_SET_KEEPCAPS
	PR_GET_FPEMU
	PR_SET_FPEMU
	PR_GET_FPEXC
	PR_SET_FPEXC
	PR_GET_TIMING
	PR_SET_TIMING
	PR_SET_NAME
	PR_GET_NAME
	PR_GET_ENDIAN
	PR_SET_ENDIAN
	PR_GET_SECCOMP
	PR_SET_SECCOMP
	PR_CAPBSET_READ
	PR_CAPBSET_DROP
	PR_GET_TSC
	PR_SET_TSC
	PR_GET_SECUREBITS
	PR_SET_SECUREBITS
	PR_SET_TIMERSLACK
	PR_GET_TIMERSLACK
	PR_TASK_PERF_EVENTS_DISABLE
	PR_TASK_PERF_EVENTS_ENABLE
	PR_MCE_KILL
	PR_MCE_KILL_GET
	PR_SET_MM
	PR_SET_CHILD_SUBREAPER
	PR_GET_CHILD_SUBREAPER
	PR_SET_NO_NEW_PRIVS
	PR_GET_NO_NEW_PRIVS
	PR_GET_TID_ADDRESS
	PR_SET_THP_DISABLE
	PR_GET_THP_DISABLE
	PR_MPX_ENABLE_MANAGEMENT
	PR_MPX_DISABLE_MANAGEMENT
	PR_SET_FP_MODE
	PR_GET_FP_MODE
	PR_CAP_AMBIENT
	PR_SVE_SET_VL
	PR_SVE_GET_VL
	PR_GET_SPECULATION_CTRL
	PR_SET_SPECULATION_CTRL
	PR_PAC_RESET_KEYS
	PR_SET_TAGGED_ADDR_CTRL
	PR_GET_TAGGED_ADDR_CTRL
)

func (p PrctlOptionArgument) Value() uint64 { return uint64(p) }

var prctlOptionStringMap = map[PrctlOptionArgument]string{
	PR_SET_PDEATHSIG:            "PR_SET_PDEATHSIG",
	PR_GET_PDEATHSIG:            "PR_GET_PDEATHSIG",
	PR_GET_DUMPABLE:             "PR_GET_DUMPABLE",
	PR_SET_DUMPABLE:             "PR_SET_DUMPABLE",
	PR_GET_UNALIGN:              "PR_GET_UNALIGN",
	PR_SET_UNALIGN:              "PR_SET_UNALIGN",
	PR_GET_KEEPCAPS:             "PR_GET_KEEPCAPS",
	PR_SET_KEEPCAPS:             "PR_SET_KEEPCAPS",
	PR_GET_FPEMU:                "PR_GET_FPEMU",
	PR_SET_FPEMU:                "PR_SET_FPEMU",
	PR_GET_FPEXC:                "PR_GET_FPEXC",
	PR_SET_FPEXC:                "PR_SET_FPEXC",
	PR_GET_TIMING:               "PR_GET_TIMING",
	PR_SET_TIMING:               "PR_SET_TIMING",
	PR_SET_NAME:                 "PR_SET_NAME",
	PR_GET_NAME:                 "PR_GET_NAME",
	PR_GET_ENDIAN:               "PR_GET_ENDIAN",
	PR_SET_ENDIAN:               "PR_SET_ENDIAN",
	PR_GET_SECCOMP:              "PR_GET_SECCOMP",
	PR_SET_SECCOMP:              "PR_SET_SECCOMP",
	PR_CAPBSET_READ:             "PR_CAPBSET_READ",
	PR_CAPBSET_DROP:             "PR_CAPBSET_DROP",
	PR_GET_TSC:                  "PR_GET_TSC",
	PR_SET_TSC:                  "PR_SET_TSC",
	PR_GET_SECUREBITS:           "PR_GET_SECUREBITS",
	PR_SET_SECUREBITS:           "PR_SET_SECUREBITS",
	PR_SET_TIMERSLACK:           "PR_SET_TIMERSLACK",
	PR_GET_TIMERSLACK:           "PR_GET_TIMERSLACK",
	PR_TASK_PERF_EVENTS_DISABLE: "PR_TASK_PERF_EVENTS_DISABLE",
	PR_TASK_PERF_EVENTS_ENABLE:  "PR_TASK_PERF_EVENTS_ENABLE",
	PR_MCE_KILL:                 "PR_MCE_KILL",
	PR_MCE_KILL_GET:             "PR_MCE_KILL_GET",
	PR_SET_MM:                   "PR_SET_MM",
	PR_SET_CHILD_SUBREAPER:      "PR_SET_CHILD_SUBREAPER",
	PR_GET_CHILD_SUBREAPER:      "PR_GET_CHILD_SUBREAPER",
	PR_SET_NO_NEW_PRIVS:         "PR_SET_NO_NEW_PRIVS",
	PR_GET_NO_NEW_PRIVS:         "PR_GET_NO_NEW_PRIVS",
	PR_GET_TID_ADDRESS:          "PR_GET_TID_ADDRESS",
	PR_SET_THP_DISABLE:          "PR_SET_THP_DISABLE",
	PR_GET_THP_DISABLE:          "PR_GET_THP_DISABLE",
	PR_MPX_ENABLE_MANAGEMENT:    "PR_MPX_ENABLE_MANAGEMENT",
	PR_MPX_DISABLE_MANAGEMENT:   "PR_MPX_DISABLE_MANAGEMENT",
	PR_SET_FP_MODE:              "PR_SET_FP_MODE",
	PR_GET_FP_MODE:              "PR_GET_FP_MODE",
	PR_CAP_AMBIENT:              "PR_CAP_AMBIENT",
	PR_SVE_SET_VL:               "PR_SVE_SET_VL",
	PR_SVE_GET_VL:               "PR_SVE_GET_VL",
	PR_GET_SPECULATION_CTRL:     "PR_GET_SPECULATION_CTRL",
	PR_SET_SPECULATION_CTRL:     "PR_SET_SPECULATION_CTRL",
	PR_PAC_RESET_KEYS:           "PR_PAC_RESET_KEYS",
	PR_SET_TAGGED_ADDR_CTRL:     "PR_SET_TAGGED_ADDR_CTRL",
	PR_GET_TAGGED_ADDR_CTRL:     "PR_GET_TAGGED_ADDR_CTRL",
}

func (p PrctlOptionArgument) String() string {
	var res string
	if opName, ok := prctlOptionStringMap[p]; ok {
		res = opName
	} else {
		res = strconv.Itoa(int(p))
	}

	return res
}

var prctlOptionsMap = map[uint64]PrctlOptionArgument{
	PR_SET_PDEATHSIG.Value():            PR_SET_PDEATHSIG,
	PR_GET_PDEATHSIG.Value():            PR_GET_PDEATHSIG,
	PR_GET_DUMPABLE.Value():             PR_GET_DUMPABLE,
	PR_SET_DUMPABLE.Value():             PR_SET_DUMPABLE,
	PR_GET_UNALIGN.Value():              PR_GET_UNALIGN,
	PR_SET_UNALIGN.Value():              PR_SET_UNALIGN,
	PR_GET_KEEPCAPS.Value():             PR_GET_KEEPCAPS,
	PR_SET_KEEPCAPS.Value():             PR_SET_KEEPCAPS,
	PR_GET_FPEMU.Value():                PR_GET_FPEMU,
	PR_SET_FPEMU.Value():                PR_SET_FPEMU,
	PR_GET_FPEXC.Value():                PR_GET_FPEXC,
	PR_SET_FPEXC.Value():                PR_SET_FPEXC,
	PR_GET_TIMING.Value():               PR_GET_TIMING,
	PR_SET_TIMING.Value():               PR_SET_TIMING,
	PR_SET_NAME.Value():                 PR_SET_NAME,
	PR_GET_NAME.Value():                 PR_GET_NAME,
	PR_GET_ENDIAN.Value():               PR_GET_ENDIAN,
	PR_SET_ENDIAN.Value():               PR_SET_ENDIAN,
	PR_GET_SECCOMP.Value():              PR_GET_SECCOMP,
	PR_SET_SECCOMP.Value():              PR_SET_SECCOMP,
	PR_CAPBSET_READ.Value():             PR_CAPBSET_READ,
	PR_CAPBSET_DROP.Value():             PR_CAPBSET_DROP,
	PR_GET_TSC.Value():                  PR_GET_TSC,
	PR_SET_TSC.Value():                  PR_SET_TSC,
	PR_GET_SECUREBITS.Value():           PR_GET_SECUREBITS,
	PR_SET_SECUREBITS.Value():           PR_SET_SECUREBITS,
	PR_SET_TIMERSLACK.Value():           PR_SET_TIMERSLACK,
	PR_GET_TIMERSLACK.Value():           PR_GET_TIMERSLACK,
	PR_TASK_PERF_EVENTS_DISABLE.Value(): PR_TASK_PERF_EVENTS_DISABLE,
	PR_TASK_PERF_EVENTS_ENABLE.Value():  PR_TASK_PERF_EVENTS_ENABLE,
	PR_MCE_KILL.Value():                 PR_MCE_KILL,
	PR_MCE_KILL_GET.Value():             PR_MCE_KILL_GET,
	PR_SET_MM.Value():                   PR_SET_MM,
	PR_SET_CHILD_SUBREAPER.Value():      PR_SET_CHILD_SUBREAPER,
	PR_GET_CHILD_SUBREAPER.Value():      PR_GET_CHILD_SUBREAPER,
	PR_SET_NO_NEW_PRIVS.Value():         PR_SET_NO_NEW_PRIVS,
	PR_GET_NO_NEW_PRIVS.Value():         PR_GET_NO_NEW_PRIVS,
	PR_GET_TID_ADDRESS.Value():          PR_GET_TID_ADDRESS,
	PR_SET_THP_DISABLE.Value():          PR_SET_THP_DISABLE,
	PR_GET_THP_DISABLE.Value():          PR_GET_THP_DISABLE,
	PR_MPX_ENABLE_MANAGEMENT.Value():    PR_MPX_ENABLE_MANAGEMENT,
	PR_MPX_DISABLE_MANAGEMENT.Value():   PR_MPX_DISABLE_MANAGEMENT,
	PR_SET_FP_MODE.Value():              PR_SET_FP_MODE,
	PR_GET_FP_MODE.Value():              PR_GET_FP_MODE,
	PR_CAP_AMBIENT.Value():              PR_CAP_AMBIENT,
	PR_SVE_SET_VL.Value():               PR_SVE_SET_VL,
	PR_SVE_GET_VL.Value():               PR_SVE_GET_VL,
	PR_GET_SPECULATION_CTRL.Value():     PR_GET_SPECULATION_CTRL,
	PR_SET_SPECULATION_CTRL.Value():     PR_SET_SPECULATION_CTRL,
	PR_PAC_RESET_KEYS.Value():           PR_PAC_RESET_KEYS,
	PR_SET_TAGGED_ADDR_CTRL.Value():     PR_SET_TAGGED_ADDR_CTRL,
	PR_GET_TAGGED_ADDR_CTRL.Value():     PR_GET_TAGGED_ADDR_CTRL,
}

// ParsePrctlOption parses the `option` argument of the `prctl` syscall
// http://man7.org/linux/man-pages/man2/prctl.2.html
func ParsePrctlOption(rawValue uint64) (PrctlOptionArgument, error) {
	v, ok := prctlOptionsMap[rawValue]
	if !ok {
		return 0, fmt.Errorf("not a valid prctl option value: %d", rawValue)
	}
	return v, nil
}

type BPFCommandArgument uint64

const (
	BPF_MAP_CREATE BPFCommandArgument = iota
	BPF_MAP_LOOKUP_ELEM
	BPF_MAP_UPDATE_ELEM
	BPF_MAP_DELETE_ELEM
	BPF_MAP_GET_NEXT_KEY
	BPF_PROG_LOAD
	BPF_OBJ_PIN
	BPF_OBJ_GET
	BPF_PROG_ATTACH
	BPF_PROG_DETACH
	BPF_PROG_TEST_RUN
	BPF_PROG_GET_NEXT_ID
	BPF_MAP_GET_NEXT_ID
	BPF_PROG_GET_FD_BY_ID
	BPF_MAP_GET_FD_BY_ID
	BPF_OBJ_GET_INFO_BY_FD
	BPF_PROG_QUERY
	BPF_RAW_TRACEPOINT_OPEN
	BPF_BTF_LOAD
	BPF_BTF_GET_FD_BY_ID
	BPF_TASK_FD_QUERY
	BPF_MAP_LOOKUP_AND_DELETE_ELEM
	BPF_MAP_FREEZE
	BPF_BTF_GET_NEXT_ID
	BPF_MAP_LOOKUP_BATCH
	BPF_MAP_LOOKUP_AND_DELETE_BATCH
	BPF_MAP_UPDATE_BATCH
	BPF_MAP_DELETE_BATCH
	BPF_LINK_CREATE
	BPF_LINK_UPDATE
	BPF_LINK_GET_FD_BY_ID
	BPF_LINK_GET_NEXT_ID
	BPF_ENABLE_STATS
	BPF_ITER_CREATE
	BPF_LINK_DETACH
)

func (b BPFCommandArgument) Value() uint64 { return uint64(b) }

var bpfCmdStringMap = map[BPFCommandArgument]string{
	BPF_MAP_CREATE:                  "BPF_MAP_CREATE",
	BPF_MAP_LOOKUP_ELEM:             "BPF_MAP_LOOKUP_ELEM",
	BPF_MAP_UPDATE_ELEM:             "BPF_MAP_UPDATE_ELEM",
	BPF_MAP_DELETE_ELEM:             "BPF_MAP_DELETE_ELEM",
	BPF_MAP_GET_NEXT_KEY:            "BPF_MAP_GET_NEXT_KEY",
	BPF_PROG_LOAD:                   "BPF_PROG_LOAD",
	BPF_OBJ_PIN:                     "BPF_OBJ_PIN",
	BPF_OBJ_GET:                     "BPF_OBJ_GET",
	BPF_PROG_ATTACH:                 "BPF_PROG_ATTACH",
	BPF_PROG_DETACH:                 "BPF_PROG_DETACH",
	BPF_PROG_TEST_RUN:               "BPF_PROG_TEST_RUN",
	BPF_PROG_GET_NEXT_ID:            "BPF_PROG_GET_NEXT_ID",
	BPF_MAP_GET_NEXT_ID:             "BPF_MAP_GET_NEXT_ID",
	BPF_PROG_GET_FD_BY_ID:           "BPF_PROG_GET_FD_BY_ID",
	BPF_MAP_GET_FD_BY_ID:            "BPF_MAP_GET_FD_BY_ID",
	BPF_OBJ_GET_INFO_BY_FD:          "BPF_OBJ_GET_INFO_BY_FD",
	BPF_PROG_QUERY:                  "BPF_PROG_QUERY",
	BPF_RAW_TRACEPOINT_OPEN:         "BPF_RAW_TRACEPOINT_OPEN",
	BPF_BTF_LOAD:                    "BPF_BTF_LOAD",
	BPF_BTF_GET_FD_BY_ID:            "BPF_BTF_GET_FD_BY_ID",
	BPF_TASK_FD_QUERY:               "BPF_TASK_FD_QUERY",
	BPF_MAP_LOOKUP_AND_DELETE_ELEM:  "BPF_MAP_LOOKUP_AND_DELETE_ELEM",
	BPF_MAP_FREEZE:                  "BPF_MAP_FREEZE",
	BPF_BTF_GET_NEXT_ID:             "BPF_BTF_GET_NEXT_ID",
	BPF_MAP_LOOKUP_BATCH:            "BPF_MAP_LOOKUP_BATCH",
	BPF_MAP_LOOKUP_AND_DELETE_BATCH: "BPF_MAP_LOOKUP_AND_DELETE_BATCH",
	BPF_MAP_UPDATE_BATCH:            "BPF_MAP_UPDATE_BATCH",
	BPF_MAP_DELETE_BATCH:            "BPF_MAP_DELETE_BATCH",
	BPF_LINK_CREATE:                 "BPF_LINK_CREATE",
	BPF_LINK_UPDATE:                 "BPF_LINK_UPDATE",
	BPF_LINK_GET_FD_BY_ID:           "BPF_LINK_GET_FD_BY_ID",
	BPF_LINK_GET_NEXT_ID:            "BPF_LINK_GET_NEXT_ID",
	BPF_ENABLE_STATS:                "BPF_ENABLE_STATS",
	BPF_ITER_CREATE:                 "BPF_ITER_CREATE",
	BPF_LINK_DETACH:                 "BPF_LINK_DETACH",
}

// String parses the `cmd` argument of the `bpf` syscall
// https://man7.org/linux/man-pages/man2/bpf.2.html
func (b BPFCommandArgument) String() string {
	var res string
	if cmdName, ok := bpfCmdStringMap[b]; ok {
		res = cmdName
	} else {
		res = strconv.Itoa(int(b))
	}

	return res
}

var bpfCmdMap = map[uint64]BPFCommandArgument{
	BPF_MAP_CREATE.Value():                  BPF_MAP_CREATE,
	BPF_MAP_LOOKUP_ELEM.Value():             BPF_MAP_LOOKUP_ELEM,
	BPF_MAP_UPDATE_ELEM.Value():             BPF_MAP_UPDATE_ELEM,
	BPF_MAP_DELETE_ELEM.Value():             BPF_MAP_DELETE_ELEM,
	BPF_MAP_GET_NEXT_KEY.Value():            BPF_MAP_GET_NEXT_KEY,
	BPF_PROG_LOAD.Value():                   BPF_PROG_LOAD,
	BPF_OBJ_PIN.Value():                     BPF_OBJ_PIN,
	BPF_OBJ_GET.Value():                     BPF_OBJ_GET,
	BPF_PROG_ATTACH.Value():                 BPF_PROG_ATTACH,
	BPF_PROG_DETACH.Value():                 BPF_PROG_DETACH,
	BPF_PROG_TEST_RUN.Value():               BPF_PROG_TEST_RUN,
	BPF_PROG_GET_NEXT_ID.Value():            BPF_PROG_GET_NEXT_ID,
	BPF_MAP_GET_NEXT_ID.Value():             BPF_MAP_GET_NEXT_ID,
	BPF_PROG_GET_FD_BY_ID.Value():           BPF_PROG_GET_FD_BY_ID,
	BPF_MAP_GET_FD_BY_ID.Value():            BPF_MAP_GET_FD_BY_ID,
	BPF_OBJ_GET_INFO_BY_FD.Value():          BPF_OBJ_GET_INFO_BY_FD,
	BPF_PROG_QUERY.Value():                  BPF_PROG_QUERY,
	BPF_RAW_TRACEPOINT_OPEN.Value():         BPF_RAW_TRACEPOINT_OPEN,
	BPF_BTF_LOAD.Value():                    BPF_BTF_LOAD,
	BPF_BTF_GET_FD_BY_ID.Value():            BPF_BTF_GET_FD_BY_ID,
	BPF_TASK_FD_QUERY.Value():               BPF_TASK_FD_QUERY,
	BPF_MAP_LOOKUP_AND_DELETE_ELEM.Value():  BPF_MAP_LOOKUP_AND_DELETE_ELEM,
	BPF_MAP_FREEZE.Value():                  BPF_MAP_FREEZE,
	BPF_BTF_GET_NEXT_ID.Value():             BPF_BTF_GET_NEXT_ID,
	BPF_MAP_LOOKUP_BATCH.Value():            BPF_MAP_LOOKUP_BATCH,
	BPF_MAP_LOOKUP_AND_DELETE_BATCH.Value(): BPF_MAP_LOOKUP_AND_DELETE_BATCH,
	BPF_MAP_UPDATE_BATCH.Value():            BPF_MAP_UPDATE_BATCH,
	BPF_MAP_DELETE_BATCH.Value():            BPF_MAP_DELETE_BATCH,
	BPF_LINK_CREATE.Value():                 BPF_LINK_CREATE,
	BPF_LINK_UPDATE.Value():                 BPF_LINK_UPDATE,
	BPF_LINK_GET_FD_BY_ID.Value():           BPF_LINK_GET_FD_BY_ID,
	BPF_LINK_GET_NEXT_ID.Value():            BPF_LINK_GET_NEXT_ID,
	BPF_ENABLE_STATS.Value():                BPF_ENABLE_STATS,
	BPF_ITER_CREATE.Value():                 BPF_ITER_CREATE,
	BPF_LINK_DETACH.Value():                 BPF_LINK_DETACH,
}

// ParseBPFCmd parses the raw value of the `cmd` argument of the `bpf` syscall
// https://man7.org/linux/man-pages/man2/bpf.2.html
func ParseBPFCmd(cmd uint64) (BPFCommandArgument, error) {
	v, ok := bpfCmdMap[cmd]
	if !ok {
		return 0, fmt.Errorf("not a valid  BPF command argument: %d", cmd)
	}
	return v, nil
}

type PtraceRequestArgument uint64

// revive:disable

var (
	PTRACE_TRACEME              PtraceRequestArgument = 0
	PTRACE_PEEKTEXT             PtraceRequestArgument = 1
	PTRACE_PEEKDATA             PtraceRequestArgument = 2
	PTRACE_PEEKUSER             PtraceRequestArgument = 3
	PTRACE_POKETEXT             PtraceRequestArgument = 4
	PTRACE_POKEDATA             PtraceRequestArgument = 5
	PTRACE_POKEUSER             PtraceRequestArgument = 6
	PTRACE_CONT                 PtraceRequestArgument = 7
	PTRACE_KILL                 PtraceRequestArgument = 8
	PTRACE_SINGLESTEP           PtraceRequestArgument = 9
	PTRACE_GETREGS              PtraceRequestArgument = 12
	PTRACE_SETREGS              PtraceRequestArgument = 13
	PTRACE_GETFPREGS            PtraceRequestArgument = 14
	PTRACE_SETFPREGS            PtraceRequestArgument = 15
	PTRACE_ATTACH               PtraceRequestArgument = 16
	PTRACE_DETACH               PtraceRequestArgument = 17
	PTRACE_GETFPXREGS           PtraceRequestArgument = 18
	PTRACE_SETFPXREGS           PtraceRequestArgument = 19
	PTRACE_SYSCALL              PtraceRequestArgument = 24
	PTRACE_SETOPTIONS           PtraceRequestArgument = 0x4200
	PTRACE_GETEVENTMSG          PtraceRequestArgument = 0x4201
	PTRACE_GETSIGINFO           PtraceRequestArgument = 0x4202
	PTRACE_SETSIGINFO           PtraceRequestArgument = 0x4203
	PTRACE_GETREGSET            PtraceRequestArgument = 0x4204
	PTRACE_SETREGSET            PtraceRequestArgument = 0x4205
	PTRACE_SEIZE                PtraceRequestArgument = 0x4206
	PTRACE_INTERRUPT            PtraceRequestArgument = 0x4207
	PTRACE_LISTEN               PtraceRequestArgument = 0x4208
	PTRACE_PEEKSIGINFO          PtraceRequestArgument = 0x4209
	PTRACE_GETSIGMASK           PtraceRequestArgument = 0x420a
	PTRACE_SETSIGMASK           PtraceRequestArgument = 0x420b
	PTRACE_SECCOMP_GET_FILTER   PtraceRequestArgument = 0x420c
	PTRACE_SECCOMP_GET_METADATA PtraceRequestArgument = 0x420d
	PTRACE_GET_SYSCALL_INFO     PtraceRequestArgument = 0x420e
)

// revive:enable

func (p PtraceRequestArgument) Value() uint64 { return uint64(p) }

var ptraceRequestStringMap = map[PtraceRequestArgument]string{
	PTRACE_TRACEME:              "PTRACE_TRACEME",
	PTRACE_PEEKTEXT:             "PTRACE_PEEKTEXT",
	PTRACE_PEEKDATA:             "PTRACE_PEEKDATA",
	PTRACE_PEEKUSER:             "PTRACE_PEEKUSER",
	PTRACE_POKETEXT:             "PTRACE_POKETEXT",
	PTRACE_POKEDATA:             "PTRACE_POKEDATA",
	PTRACE_POKEUSER:             "PTRACE_POKEUSER",
	PTRACE_CONT:                 "PTRACE_CONT",
	PTRACE_KILL:                 "PTRACE_KILL",
	PTRACE_SINGLESTEP:           "PTRACE_SINGLESTEP",
	PTRACE_GETREGS:              "PTRACE_GETREGS",
	PTRACE_SETREGS:              "PTRACE_SETREGS",
	PTRACE_GETFPREGS:            "PTRACE_GETFPREGS",
	PTRACE_SETFPREGS:            "PTRACE_SETFPREGS",
	PTRACE_ATTACH:               "PTRACE_ATTACH",
	PTRACE_DETACH:               "PTRACE_DETACH",
	PTRACE_GETFPXREGS:           "PTRACE_GETFPXREGS",
	PTRACE_SETFPXREGS:           "PTRACE_SETFPXREGS",
	PTRACE_SYSCALL:              "PTRACE_SYSCALL",
	PTRACE_SETOPTIONS:           "PTRACE_SETOPTIONS",
	PTRACE_GETEVENTMSG:          "PTRACE_GETEVENTMSG",
	PTRACE_GETSIGINFO:           "PTRACE_GETSIGINFO",
	PTRACE_SETSIGINFO:           "PTRACE_SETSIGINFO",
	PTRACE_GETREGSET:            "PTRACE_GETREGSET",
	PTRACE_SETREGSET:            "PTRACE_SETREGSET",
	PTRACE_SEIZE:                "PTRACE_SEIZE",
	PTRACE_INTERRUPT:            "PTRACE_INTERRUPT",
	PTRACE_LISTEN:               "PTRACE_LISTEN",
	PTRACE_PEEKSIGINFO:          "PTRACE_PEEKSIGINFO",
	PTRACE_GETSIGMASK:           "PTRACE_GETSIGMASK",
	PTRACE_SETSIGMASK:           "PTRACE_SETSIGMASK",
	PTRACE_SECCOMP_GET_FILTER:   "PTRACE_SECCOMP_GET_FILTER",
	PTRACE_SECCOMP_GET_METADATA: "PTRACE_SECCOMP_GET_METADATA",
	PTRACE_GET_SYSCALL_INFO:     "PTRACE_GET_SYSCALL_INFO",
}

func (p PtraceRequestArgument) String() string {
	var res string
	if reqName, ok := ptraceRequestStringMap[p]; ok {
		res = reqName
	} else {
		res = strconv.Itoa(int(p))
	}

	return res
}

var ptraceRequestArgMap = map[uint64]PtraceRequestArgument{
	PTRACE_TRACEME.Value():              PTRACE_TRACEME,
	PTRACE_PEEKTEXT.Value():             PTRACE_PEEKTEXT,
	PTRACE_PEEKDATA.Value():             PTRACE_PEEKDATA,
	PTRACE_PEEKUSER.Value():             PTRACE_PEEKUSER,
	PTRACE_POKETEXT.Value():             PTRACE_POKETEXT,
	PTRACE_POKEDATA.Value():             PTRACE_POKEDATA,
	PTRACE_POKEUSER.Value():             PTRACE_POKEUSER,
	PTRACE_CONT.Value():                 PTRACE_CONT,
	PTRACE_KILL.Value():                 PTRACE_KILL,
	PTRACE_SINGLESTEP.Value():           PTRACE_SINGLESTEP,
	PTRACE_GETREGS.Value():              PTRACE_GETREGS,
	PTRACE_SETREGS.Value():              PTRACE_SETREGS,
	PTRACE_GETFPREGS.Value():            PTRACE_GETFPREGS,
	PTRACE_SETFPREGS.Value():            PTRACE_SETFPREGS,
	PTRACE_ATTACH.Value():               PTRACE_ATTACH,
	PTRACE_DETACH.Value():               PTRACE_DETACH,
	PTRACE_GETFPXREGS.Value():           PTRACE_GETFPXREGS,
	PTRACE_SETFPXREGS.Value():           PTRACE_SETFPXREGS,
	PTRACE_SYSCALL.Value():              PTRACE_SYSCALL,
	PTRACE_SETOPTIONS.Value():           PTRACE_SETOPTIONS,
	PTRACE_GETEVENTMSG.Value():          PTRACE_GETEVENTMSG,
	PTRACE_GETSIGINFO.Value():           PTRACE_GETSIGINFO,
	PTRACE_SETSIGINFO.Value():           PTRACE_SETSIGINFO,
	PTRACE_GETREGSET.Value():            PTRACE_GETREGSET,
	PTRACE_SETREGSET.Value():            PTRACE_SETREGSET,
	PTRACE_SEIZE.Value():                PTRACE_SEIZE,
	PTRACE_INTERRUPT.Value():            PTRACE_INTERRUPT,
	PTRACE_LISTEN.Value():               PTRACE_LISTEN,
	PTRACE_PEEKSIGINFO.Value():          PTRACE_PEEKSIGINFO,
	PTRACE_GETSIGMASK.Value():           PTRACE_GETSIGMASK,
	PTRACE_SETSIGMASK.Value():           PTRACE_SETSIGMASK,
	PTRACE_SECCOMP_GET_FILTER.Value():   PTRACE_SECCOMP_GET_FILTER,
	PTRACE_SECCOMP_GET_METADATA.Value(): PTRACE_SECCOMP_GET_METADATA,
	PTRACE_GET_SYSCALL_INFO.Value():     PTRACE_GET_SYSCALL_INFO,
}

func ParsePtraceRequestArgument(rawValue uint64) (PtraceRequestArgument, error) {
	if reqName, ok := ptraceRequestArgMap[rawValue]; ok {
		return reqName, nil
	}
	return 0, fmt.Errorf("not a valid ptrace request value: %d", rawValue)
}

type SocketcallCallArgument uint64

const (
	SYS_SOCKET SocketcallCallArgument = iota + 1
	SYS_BIND
	SYS_CONNECT
	SYS_LISTEN
	SYS_ACCEPT
	SYS_GETSOCKNAME
	SYS_GETPEERNAME
	SYS_SOCKETPAIR
	SYS_SEND
	SYS_RECV
	SYS_SENDTO
	SYS_RECVFROM
	SYS_SHUTDOWN
	SYS_SETSOCKOPT
	SYS_GETSOCKOPT
	SYS_SENDMSG
	SYS_RECVMSG
	SYS_ACCEPT4
	SYS_RECVMMSG
	SYS_SENDMMSG
)

func (s SocketcallCallArgument) Value() uint64 {
	return uint64(s)
}

var socketcallCallStringMap = map[SocketcallCallArgument]string{
	SYS_SOCKET:      "SYS_SOCKET",
	SYS_BIND:        "SYS_BIND",
	SYS_CONNECT:     "SYS_CONNECT",
	SYS_LISTEN:      "SYS_LISTEN",
	SYS_ACCEPT:      "SYS_ACCEPT",
	SYS_GETSOCKNAME: "SYS_GETSOCKNAME",
	SYS_GETPEERNAME: "SYS_GETPEERNAME",
	SYS_SOCKETPAIR:  "SYS_SOCKETPAIR",
	SYS_SEND:        "SYS_SEND",
	SYS_RECV:        "SYS_RECV",
	SYS_SENDTO:      "SYS_SENDTO",
	SYS_RECVFROM:    "SYS_RECVFROM",
	SYS_SHUTDOWN:    "SYS_SHUTDOWN",
	SYS_SETSOCKOPT:  "SYS_SETSOCKOPT",
	SYS_GETSOCKOPT:  "SYS_GETSOCKOPT",
	SYS_SENDMSG:     "SYS_SENDMSG",
	SYS_RECVMSG:     "SYS_RECVMSG",
	SYS_ACCEPT4:     "SYS_ACCEPT4",
	SYS_RECVMMSG:    "SYS_RECVMMSG",
	SYS_SENDMMSG:    "SYS_SENDMMSG",
}

func (s SocketcallCallArgument) String() string {
	var res string

	if sdName, ok := socketcallCallStringMap[s]; ok {
		res = sdName
	} else {
		res = strconv.Itoa(int(s))
	}

	return res
}

var socketcallCallMap = map[uint64]SocketcallCallArgument{
	SYS_SOCKET.Value():      SYS_SOCKET,
	SYS_BIND.Value():        SYS_BIND,
	SYS_CONNECT.Value():     SYS_CONNECT,
	SYS_LISTEN.Value():      SYS_LISTEN,
	SYS_ACCEPT.Value():      SYS_ACCEPT,
	SYS_GETSOCKNAME.Value(): SYS_GETSOCKNAME,
	SYS_GETPEERNAME.Value(): SYS_GETPEERNAME,
	SYS_SOCKETPAIR.Value():  SYS_SOCKETPAIR,
	SYS_SEND.Value():        SYS_SEND,
	SYS_RECV.Value():        SYS_RECV,
	SYS_SENDTO.Value():      SYS_SENDTO,
	SYS_RECVFROM.Value():    SYS_RECVFROM,
	SYS_SHUTDOWN.Value():    SYS_SHUTDOWN,
	SYS_SETSOCKOPT.Value():  SYS_SETSOCKOPT,
	SYS_GETSOCKOPT.Value():  SYS_GETSOCKOPT,
	SYS_SENDMSG.Value():     SYS_SENDMSG,
	SYS_RECVMSG.Value():     SYS_RECVMSG,
	SYS_ACCEPT4.Value():     SYS_ACCEPT4,
	SYS_RECVMMSG.Value():    SYS_RECVMMSG,
	SYS_SENDMMSG.Value():    SYS_SENDMMSG,
}

// ParseSocketcallCall parses the `call` argument of the `socketcall` syscall
// http://man7.org/linux/man-pages/man2/socketcall.2.html
// https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/net.h
func ParseSocketcallCall(rawValue uint64) (SocketcallCallArgument, error) {
	if v, ok := socketcallCallMap[rawValue]; ok {
		return v, nil
	}

	return 0, fmt.Errorf("not a valid socketcall call value: %d", rawValue)
}

type SocketDomainArgument uint64

const (
	AF_UNSPEC SocketDomainArgument = iota
	AF_UNIX
	AF_INET
	AF_AX25
	AF_IPX
	AF_APPLETALK
	AF_NETROM
	AF_BRIDGE
	AF_ATMPVC
	AF_X25
	AF_INET6
	AF_ROSE
	AF_DECnet
	AF_NETBEUI
	AF_SECURITY
	AF_KEY
	AF_NETLINK
	AF_PACKET
	AF_ASH
	AF_ECONET
	AF_ATMSVC
	AF_RDS
	AF_SNA
	AF_IRDA
	AF_PPPOX
	AF_WANPIPE
	AF_LLC
	AF_IB
	AF_MPLS
	AF_CAN
	AF_TIPC
	AF_BLUETOOTH
	AF_IUCV
	AF_RXRPC
	AF_ISDN
	AF_PHONET
	AF_IEEE802154
	AF_CAIF
	AF_ALG
	AF_NFC
	AF_VSOCK
	AF_KCM
	AF_QIPCRTR
	AF_SMC
	AF_XDP
)

func (s SocketDomainArgument) Value() uint64 { return uint64(s) }

var socketDomainStringMap = map[SocketDomainArgument]string{
	AF_UNSPEC:     "AF_UNSPEC",
	AF_UNIX:       "AF_UNIX",
	AF_INET:       "AF_INET",
	AF_AX25:       "AF_AX25",
	AF_IPX:        "AF_IPX",
	AF_APPLETALK:  "AF_APPLETALK",
	AF_NETROM:     "AF_NETROM",
	AF_BRIDGE:     "AF_BRIDGE",
	AF_ATMPVC:     "AF_ATMPVC",
	AF_X25:        "AF_X25",
	AF_INET6:      "AF_INET6",
	AF_ROSE:       "AF_ROSE",
	AF_DECnet:     "AF_DECnet",
	AF_NETBEUI:    "AF_NETBEUI",
	AF_SECURITY:   "AF_SECURITY",
	AF_KEY:        "AF_KEY",
	AF_NETLINK:    "AF_NETLINK",
	AF_PACKET:     "AF_PACKET",
	AF_ASH:        "AF_ASH",
	AF_ECONET:     "AF_ECONET",
	AF_ATMSVC:     "AF_ATMSVC",
	AF_RDS:        "AF_RDS",
	AF_SNA:        "AF_SNA",
	AF_IRDA:       "AF_IRDA",
	AF_PPPOX:      "AF_PPPOX",
	AF_WANPIPE:    "AF_WANPIPE",
	AF_LLC:        "AF_LLC",
	AF_IB:         "AF_IB",
	AF_MPLS:       "AF_MPLS",
	AF_CAN:        "AF_CAN",
	AF_TIPC:       "AF_TIPC",
	AF_BLUETOOTH:  "AF_BLUETOOTH",
	AF_IUCV:       "AF_IUCV",
	AF_RXRPC:      "AF_RXRPC",
	AF_ISDN:       "AF_ISDN",
	AF_PHONET:     "AF_PHONET",
	AF_IEEE802154: "AF_IEEE802154",
	AF_CAIF:       "AF_CAIF",
	AF_ALG:        "AF_ALG",
	AF_NFC:        "AF_NFC",
	AF_VSOCK:      "AF_VSOCK",
	AF_KCM:        "AF_KCM",
	AF_QIPCRTR:    "AF_QIPCRTR",
	AF_SMC:        "AF_SMC",
	AF_XDP:        "AF_XDP",
}

func (s SocketDomainArgument) String() string {
	var res string

	if sdName, ok := socketDomainStringMap[s]; ok {
		res = sdName
	} else {
		res = strconv.Itoa(int(s))
	}

	return res
}

var socketDomainMap = map[uint64]SocketDomainArgument{
	AF_UNSPEC.Value():     AF_UNSPEC,
	AF_UNIX.Value():       AF_UNIX,
	AF_INET.Value():       AF_INET,
	AF_AX25.Value():       AF_AX25,
	AF_IPX.Value():        AF_IPX,
	AF_APPLETALK.Value():  AF_APPLETALK,
	AF_NETROM.Value():     AF_NETROM,
	AF_BRIDGE.Value():     AF_BRIDGE,
	AF_ATMPVC.Value():     AF_ATMPVC,
	AF_X25.Value():        AF_X25,
	AF_INET6.Value():      AF_INET6,
	AF_ROSE.Value():       AF_ROSE,
	AF_DECnet.Value():     AF_DECnet,
	AF_NETBEUI.Value():    AF_NETBEUI,
	AF_SECURITY.Value():   AF_SECURITY,
	AF_KEY.Value():        AF_KEY,
	AF_NETLINK.Value():    AF_NETLINK,
	AF_PACKET.Value():     AF_PACKET,
	AF_ASH.Value():        AF_ASH,
	AF_ECONET.Value():     AF_ECONET,
	AF_ATMSVC.Value():     AF_ATMSVC,
	AF_RDS.Value():        AF_RDS,
	AF_SNA.Value():        AF_SNA,
	AF_IRDA.Value():       AF_IRDA,
	AF_PPPOX.Value():      AF_PPPOX,
	AF_WANPIPE.Value():    AF_WANPIPE,
	AF_LLC.Value():        AF_LLC,
	AF_IB.Value():         AF_IB,
	AF_MPLS.Value():       AF_MPLS,
	AF_CAN.Value():        AF_CAN,
	AF_TIPC.Value():       AF_TIPC,
	AF_BLUETOOTH.Value():  AF_BLUETOOTH,
	AF_IUCV.Value():       AF_IUCV,
	AF_RXRPC.Value():      AF_RXRPC,
	AF_ISDN.Value():       AF_ISDN,
	AF_PHONET.Value():     AF_PHONET,
	AF_IEEE802154.Value(): AF_IEEE802154,
	AF_CAIF.Value():       AF_CAIF,
	AF_ALG.Value():        AF_ALG,
	AF_NFC.Value():        AF_NFC,
	AF_VSOCK.Value():      AF_VSOCK,
	AF_KCM.Value():        AF_KCM,
	AF_QIPCRTR.Value():    AF_QIPCRTR,
	AF_SMC.Value():        AF_SMC,
	AF_XDP.Value():        AF_XDP,
}

// ParseSocketDomainArgument parses the `domain` bitmask argument of the `socket` syscall
// http://man7.org/linux/man-pages/man2/socket.2.html
func ParseSocketDomainArgument(rawValue uint64) (SocketDomainArgument, error) {
	v, ok := socketDomainMap[rawValue]
	if !ok {
		return 0, fmt.Errorf("not a valid argument: %d", rawValue)
	}
	return v, nil
}

type SocketTypeArgument struct {
	rawValue    uint64
	stringValue string
}

// revive:disable

var (
	SOCK_STREAM    SocketTypeArgument = SocketTypeArgument{rawValue: 1, stringValue: "SOCK_STREAM"}
	SOCK_DGRAM     SocketTypeArgument = SocketTypeArgument{rawValue: 2, stringValue: "SOCK_DGRAM"}
	SOCK_RAW       SocketTypeArgument = SocketTypeArgument{rawValue: 3, stringValue: "SOCK_RAW"}
	SOCK_RDM       SocketTypeArgument = SocketTypeArgument{rawValue: 4, stringValue: "SOCK_RDM"}
	SOCK_SEQPACKET SocketTypeArgument = SocketTypeArgument{rawValue: 5, stringValue: "SOCK_SEQPACKET"}
	SOCK_DCCP      SocketTypeArgument = SocketTypeArgument{rawValue: 6, stringValue: "SOCK_DCCP"}
	SOCK_PACKET    SocketTypeArgument = SocketTypeArgument{rawValue: 10, stringValue: "SOCK_PACKET"}
	SOCK_NONBLOCK  SocketTypeArgument = SocketTypeArgument{rawValue: 000004000, stringValue: "SOCK_NONBLOCK"}
	SOCK_CLOEXEC   SocketTypeArgument = SocketTypeArgument{rawValue: 002000000, stringValue: "SOCK_CLOEXEC"}
)

// revive:enable

func (s SocketTypeArgument) Value() uint64  { return s.rawValue }
func (s SocketTypeArgument) String() string { return s.stringValue }

var socketTypeMap = map[uint64]SocketTypeArgument{
	SOCK_STREAM.Value():    SOCK_STREAM,
	SOCK_DGRAM.Value():     SOCK_DGRAM,
	SOCK_RAW.Value():       SOCK_RAW,
	SOCK_RDM.Value():       SOCK_RDM,
	SOCK_SEQPACKET.Value(): SOCK_SEQPACKET,
	SOCK_DCCP.Value():      SOCK_DCCP,
	SOCK_PACKET.Value():    SOCK_PACKET,
}

// ParseSocketType parses the `type` bitmask argument of the `socket` syscall
// http://man7.org/linux/man-pages/man2/socket.2.html
func ParseSocketType(rawValue uint64) (SocketTypeArgument, error) {
	var f []string

	if stName, ok := socketTypeMap[rawValue&0xf]; ok {
		f = append(f, stName.String())
	} else {
		f = append(f, strconv.Itoa(int(rawValue)))
	}

	if OptionAreContainedInArgument(rawValue, SOCK_NONBLOCK) {
		f = append(f, "SOCK_NONBLOCK")
	}
	if OptionAreContainedInArgument(rawValue, SOCK_CLOEXEC) {
		f = append(f, "SOCK_CLOEXEC")
	}

	return SocketTypeArgument{stringValue: strings.Join(f, "|"), rawValue: rawValue}, nil
}

type InodeModeArgument struct {
	rawValue    uint64
	stringValue string
}

// revive:disable

var (
	S_IFSOCK InodeModeArgument = InodeModeArgument{stringValue: "S_IFSOCK", rawValue: 0140000}
	S_IFLNK  InodeModeArgument = InodeModeArgument{stringValue: "S_IFLNK", rawValue: 0120000}
	S_IFREG  InodeModeArgument = InodeModeArgument{stringValue: "S_IFREG", rawValue: 0100000}
	S_IFBLK  InodeModeArgument = InodeModeArgument{stringValue: "S_IFBLK", rawValue: 060000}
	S_IFDIR  InodeModeArgument = InodeModeArgument{stringValue: "S_IFDIR", rawValue: 040000}
	S_IFCHR  InodeModeArgument = InodeModeArgument{stringValue: "S_IFCHR", rawValue: 020000}
	S_IFIFO  InodeModeArgument = InodeModeArgument{stringValue: "S_IFIFO", rawValue: 010000}
	S_IRWXU  InodeModeArgument = InodeModeArgument{stringValue: "S_IRWXU", rawValue: 00700}
	S_IRUSR  InodeModeArgument = InodeModeArgument{stringValue: "S_IRUSR", rawValue: 00400}
	S_IWUSR  InodeModeArgument = InodeModeArgument{stringValue: "S_IWUSR", rawValue: 00200}
	S_IXUSR  InodeModeArgument = InodeModeArgument{stringValue: "S_IXUSR", rawValue: 00100}
	S_IRWXG  InodeModeArgument = InodeModeArgument{stringValue: "S_IRWXG", rawValue: 00070}
	S_IRGRP  InodeModeArgument = InodeModeArgument{stringValue: "S_IRGRP", rawValue: 00040}
	S_IWGRP  InodeModeArgument = InodeModeArgument{stringValue: "S_IWGRP", rawValue: 00020}
	S_IXGRP  InodeModeArgument = InodeModeArgument{stringValue: "S_IXGRP", rawValue: 00010}
	S_IRWXO  InodeModeArgument = InodeModeArgument{stringValue: "S_IRWXO", rawValue: 00007}
	S_IROTH  InodeModeArgument = InodeModeArgument{stringValue: "S_IROTH", rawValue: 00004}
	S_IWOTH  InodeModeArgument = InodeModeArgument{stringValue: "S_IWOTH", rawValue: 00002}
	S_IXOTH  InodeModeArgument = InodeModeArgument{stringValue: "S_IXOTH", rawValue: 00001}
)

// revive:enable

func (mode InodeModeArgument) Value() uint64  { return mode.rawValue }
func (mode InodeModeArgument) String() string { return mode.stringValue }

func ParseInodeMode(rawValue uint64) (InodeModeArgument, error) {
	var f []string

	// File Type
	switch {
	case OptionAreContainedInArgument(rawValue, S_IFSOCK):
		f = append(f, S_IFSOCK.String())
	case OptionAreContainedInArgument(rawValue, S_IFLNK):
		f = append(f, S_IFLNK.String())
	case OptionAreContainedInArgument(rawValue, S_IFREG):
		f = append(f, S_IFREG.String())
	case OptionAreContainedInArgument(rawValue, S_IFBLK):
		f = append(f, S_IFBLK.String())
	case OptionAreContainedInArgument(rawValue, S_IFDIR):
		f = append(f, S_IFDIR.String())
	case OptionAreContainedInArgument(rawValue, S_IFCHR):
		f = append(f, S_IFCHR.String())
	case OptionAreContainedInArgument(rawValue, S_IFIFO):
		f = append(f, S_IFIFO.String())
	}

	// File Mode
	// Owner
	if OptionAreContainedInArgument(rawValue, S_IRWXU) {
		f = append(f, S_IRWXU.String())
	} else {
		if OptionAreContainedInArgument(rawValue, S_IRUSR) {
			f = append(f, S_IRUSR.String())
		}
		if OptionAreContainedInArgument(rawValue, S_IWUSR) {
			f = append(f, S_IWUSR.String())
		}
		if OptionAreContainedInArgument(rawValue, S_IXUSR) {
			f = append(f, S_IXUSR.String())
		}
	}
	// Group
	if OptionAreContainedInArgument(rawValue, S_IRWXG) {
		f = append(f, S_IRWXG.String())
	} else {
		if OptionAreContainedInArgument(rawValue, S_IRGRP) {
			f = append(f, S_IRGRP.String())
		}
		if OptionAreContainedInArgument(rawValue, S_IWGRP) {
			f = append(f, S_IWGRP.String())
		}
		if OptionAreContainedInArgument(rawValue, S_IXGRP) {
			f = append(f, S_IXGRP.String())
		}
	}
	// Others
	if OptionAreContainedInArgument(rawValue, S_IRWXO) {
		f = append(f, S_IRWXO.String())
	} else {
		if OptionAreContainedInArgument(rawValue, S_IROTH) {
			f = append(f, S_IROTH.String())
		}
		if OptionAreContainedInArgument(rawValue, S_IWOTH) {
			f = append(f, S_IWOTH.String())
		}
		if OptionAreContainedInArgument(rawValue, S_IXOTH) {
			f = append(f, S_IXOTH.String())
		}
	}

	return InodeModeArgument{stringValue: strings.Join(f, "|"), rawValue: rawValue}, nil
}

type MmapProtArgument struct {
	rawValue    uint64
	stringValue string
}

// revive:disable

var (
	PROT_READ      MmapProtArgument = MmapProtArgument{stringValue: "PROT_READ", rawValue: 0x1}
	PROT_WRITE     MmapProtArgument = MmapProtArgument{stringValue: "PROT_WRITE", rawValue: 0x2}
	PROT_EXEC      MmapProtArgument = MmapProtArgument{stringValue: "PROT_EXEC", rawValue: 0x4}
	PROT_SEM       MmapProtArgument = MmapProtArgument{stringValue: "PROT_SEM", rawValue: 0x8}
	PROT_NONE      MmapProtArgument = MmapProtArgument{stringValue: "PROT_NONE", rawValue: 0x0}
	PROT_GROWSDOWN MmapProtArgument = MmapProtArgument{stringValue: "PROT_GROWSDOWN", rawValue: 0x01000000}
	PROT_GROWSUP   MmapProtArgument = MmapProtArgument{stringValue: "PROT_GROWSUP", rawValue: 0x02000000}
)

// revive:enable

func (p MmapProtArgument) Value() uint64  { return p.rawValue }
func (p MmapProtArgument) String() string { return p.stringValue }

// ParseMmapProt parses the `prot` bitmask argument of the `mmap` syscall
// http://man7.org/linux/man-pages/man2/mmap.2.html
// https://elixir.bootlin.com/linux/v5.5.3/source/include/uapi/asm-generic/mman-common.h#L10
func ParseMmapProt(rawValue uint64) MmapProtArgument {
	var f []string
	if rawValue == PROT_NONE.Value() {
		f = append(f, PROT_NONE.String())
	} else {
		if OptionAreContainedInArgument(rawValue, PROT_READ) {
			f = append(f, PROT_READ.String())
		}
		if OptionAreContainedInArgument(rawValue, PROT_WRITE) {
			f = append(f, PROT_WRITE.String())
		}
		if OptionAreContainedInArgument(rawValue, PROT_EXEC) {
			f = append(f, PROT_EXEC.String())
		}
		if OptionAreContainedInArgument(rawValue, PROT_SEM) {
			f = append(f, PROT_SEM.String())
		}
		if OptionAreContainedInArgument(rawValue, PROT_GROWSDOWN) {
			f = append(f, PROT_GROWSDOWN.String())
		}
		if OptionAreContainedInArgument(rawValue, PROT_GROWSUP) {
			f = append(f, PROT_GROWSUP.String())
		}
	}

	return MmapProtArgument{stringValue: strings.Join(f, "|"), rawValue: rawValue}
}

// ParseUint32IP parses the IP address encoded as a uint32
func ParseUint32IP(in uint32) string {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, in)

	return ip.String()
}

// Parse16BytesSliceIP parses the IP address encoded as 16 bytes long
// PrintBytesSliceIP. It would be more correct to accept a [16]byte instead of
// variable lenth slice, but that would case unnecessary memory copying and
// type conversions.
func Parse16BytesSliceIP(in []byte) string {
	ip := net.IP(in)

	return ip.String()
}

type SocketLevelArgument uint64

const (
	SOL_SOCKET   SocketLevelArgument = unix.SOL_SOCKET
	SOL_AAL      SocketLevelArgument = unix.SOL_AAL
	SOL_ALG      SocketLevelArgument = unix.SOL_ALG
	SOL_ATM      SocketLevelArgument = unix.SOL_ATM
	SOL_CAIF     SocketLevelArgument = unix.SOL_CAIF
	SOL_CAN_BASE SocketLevelArgument = unix.SOL_CAN_BASE
	SOL_CAN_RAW  SocketLevelArgument = unix.SOL_CAN_RAW
	SOL_DCCP     SocketLevelArgument = unix.SOL_DCCP
	SOL_DECNET   SocketLevelArgument = unix.SOL_DECNET
	SOL_ICMPV6   SocketLevelArgument = unix.SOL_ICMPV6
	SOL_IP       SocketLevelArgument = unix.SOL_IP
	SOL_IPV6     SocketLevelArgument = unix.SOL_IPV6
	SOL_IRDA     SocketLevelArgument = unix.SOL_IRDA
	SOL_IUCV     SocketLevelArgument = unix.SOL_IUCV
	SOL_KCM      SocketLevelArgument = unix.SOL_KCM
	SOL_LLC      SocketLevelArgument = unix.SOL_LLC
	SOL_NETBEUI  SocketLevelArgument = unix.SOL_NETBEUI
	SOL_NETLINK  SocketLevelArgument = unix.SOL_NETLINK
	SOL_NFC      SocketLevelArgument = unix.SOL_NFC
	SOL_PACKET   SocketLevelArgument = unix.SOL_PACKET
	SOL_PNPIPE   SocketLevelArgument = unix.SOL_PNPIPE
	SOL_PPPOL2TP SocketLevelArgument = unix.SOL_PPPOL2TP
	SOL_RAW      SocketLevelArgument = unix.SOL_RAW
	SOL_RDS      SocketLevelArgument = unix.SOL_RDS
	SOL_RXRPC    SocketLevelArgument = unix.SOL_RXRPC
	SOL_TCP      SocketLevelArgument = unix.SOL_TCP
	SOL_TIPC     SocketLevelArgument = unix.SOL_TIPC
	SOL_TLS      SocketLevelArgument = unix.SOL_TLS
	SOL_X25      SocketLevelArgument = unix.SOL_X25
	SOL_XDP      SocketLevelArgument = unix.SOL_XDP

	// The following are newer, so aren't included in the unix package
	SOL_MCTCP SocketLevelArgument = 284
	SOL_MCTP  SocketLevelArgument = 285
	SOL_SMC   SocketLevelArgument = 286
)

func (socketLevel SocketLevelArgument) Value() uint64 { return uint64(socketLevel) }

var socketLevelStringMap = map[SocketLevelArgument]string{
	SOL_SOCKET:   "SOL_SOCKET",
	SOL_AAL:      "SOL_AAL",
	SOL_ALG:      "SOL_ALG",
	SOL_ATM:      "SOL_ATM",
	SOL_CAIF:     "SOL_CAIF",
	SOL_CAN_BASE: "SOL_CAN_BASE",
	SOL_CAN_RAW:  "SOL_CAN_RAW",
	SOL_DCCP:     "SOL_DCCP",
	SOL_DECNET:   "SOL_DECNET",
	SOL_ICMPV6:   "SOL_ICMPV6",
	SOL_IP:       "SOL_IP",
	SOL_IPV6:     "SOL_IPV6",
	SOL_IRDA:     "SOL_IRDA",
	SOL_IUCV:     "SOL_IUCV",
	SOL_KCM:      "SOL_KCM",
	SOL_LLC:      "SOL_LLC",
	SOL_NETBEUI:  "SOL_NETBEUI",
	SOL_NETLINK:  "SOL_NETLINK",
	SOL_NFC:      "SOL_NFC",
	SOL_PACKET:   "SOL_PACKET",
	SOL_PNPIPE:   "SOL_PNPIPE",
	SOL_PPPOL2TP: "SOL_PPPOL2TP",
	SOL_RAW:      "SOL_RAW",
	SOL_RDS:      "SOL_RDS",
	SOL_RXRPC:    "SOL_RXRPC",
	SOL_TCP:      "SOL_TCP",
	SOL_TIPC:     "SOL_TIPC",
	SOL_TLS:      "SOL_TLS",
	SOL_X25:      "SOL_X25",
	SOL_XDP:      "SOL_XDP",
	SOL_MCTCP:    "SOL_MCTCP",
	SOL_MCTP:     "SOL_MCTP",
	SOL_SMC:      "SOL_SMC",
}

func (socketLevel SocketLevelArgument) String() string {
	var res string

	if sdName, ok := socketLevelStringMap[socketLevel]; ok {
		res = sdName
	} else {
		res = strconv.Itoa(int(socketLevel))
	}

	return res
}

var socketLevelMap = map[uint64]SocketLevelArgument{
	SOL_SOCKET.Value():   SOL_SOCKET,
	SOL_AAL.Value():      SOL_AAL,
	SOL_ALG.Value():      SOL_ALG,
	SOL_ATM.Value():      SOL_ATM,
	SOL_CAIF.Value():     SOL_CAIF,
	SOL_CAN_BASE.Value(): SOL_CAN_BASE,
	SOL_CAN_RAW.Value():  SOL_CAN_RAW,
	SOL_DCCP.Value():     SOL_DCCP,
	SOL_DECNET.Value():   SOL_DECNET,
	SOL_ICMPV6.Value():   SOL_ICMPV6,
	SOL_IP.Value():       SOL_IP,
	SOL_IPV6.Value():     SOL_IPV6,
	SOL_IRDA.Value():     SOL_IRDA,
	SOL_IUCV.Value():     SOL_IUCV,
	SOL_KCM.Value():      SOL_KCM,
	SOL_LLC.Value():      SOL_LLC,
	SOL_NETBEUI.Value():  SOL_NETBEUI,
	SOL_NETLINK.Value():  SOL_NETLINK,
	SOL_NFC.Value():      SOL_NFC,
	SOL_PACKET.Value():   SOL_PACKET,
	SOL_PNPIPE.Value():   SOL_PNPIPE,
	SOL_PPPOL2TP.Value(): SOL_PPPOL2TP,
	SOL_RAW.Value():      SOL_RAW,
	SOL_RDS.Value():      SOL_RDS,
	SOL_RXRPC.Value():    SOL_RXRPC,
	SOL_TCP.Value():      SOL_TCP,
	SOL_TIPC.Value():     SOL_TIPC,
	SOL_TLS.Value():      SOL_TLS,
	SOL_X25.Value():      SOL_X25,
	SOL_XDP.Value():      SOL_XDP,
	SOL_MCTCP.Value():    SOL_MCTCP,
	SOL_MCTP.Value():     SOL_MCTP,
	SOL_SMC.Value():      SOL_SMC,
}

// ParseSocketLevel parses the `level` argument of the `setsockopt` and `getsockopt` syscalls.
// https://man7.org/linux/man-pages/man2/setsockopt.2.html
// https://elixir.bootlin.com/linux/latest/source/include/linux/socket.h
func ParseSocketLevel(rawValue uint64) (SocketLevelArgument, error) {
	v, ok := socketLevelMap[rawValue]
	if !ok {
		return 0, fmt.Errorf("not a valid argument: %d", rawValue)
	}
	return v, nil
}

type SocketOptionArgument struct {
	value uint64
	name  string
}

// revive:disable

var (
	SO_DEBUG                         = SocketOptionArgument{unix.SO_DEBUG, "SO_DEBUG"}
	SO_REUSEADDR                     = SocketOptionArgument{unix.SO_REUSEADDR, "SO_REUSEADDR"}
	SO_TYPE                          = SocketOptionArgument{unix.SO_TYPE, "SO_TYPE"}
	SO_ERROR                         = SocketOptionArgument{unix.SO_ERROR, "SO_ERROR"}
	SO_DONTROUTE                     = SocketOptionArgument{unix.SO_DONTROUTE, "SO_DONTROUTE"}
	SO_BROADCAST                     = SocketOptionArgument{unix.SO_BROADCAST, "SO_BROADCAST"}
	SO_SNDBUF                        = SocketOptionArgument{unix.SO_SNDBUF, "SO_SNDBUF"}
	SO_RCVBUF                        = SocketOptionArgument{unix.SO_RCVBUF, "SO_RCVBUF"}
	SO_SNDBUFFORCE                   = SocketOptionArgument{unix.SO_SNDBUFFORCE, "SO_SNDBUFFORCE"}
	SO_RCVBUFFORCE                   = SocketOptionArgument{unix.SO_RCVBUFFORCE, "SO_RCVBUFFORCE"}
	SO_KEEPALIVE                     = SocketOptionArgument{unix.SO_KEEPALIVE, "SO_KEEPALIVE"}
	SO_OOBINLINE                     = SocketOptionArgument{unix.SO_OOBINLINE, "SO_OOBINLINE"}
	SO_NO_CHECK                      = SocketOptionArgument{unix.SO_NO_CHECK, "SO_NO_CHECK"}
	SO_PRIORITY                      = SocketOptionArgument{unix.SO_PRIORITY, "SO_PRIORITY"}
	SO_LINGER                        = SocketOptionArgument{unix.SO_LINGER, "SO_LINGER"}
	SO_BSDCOMPAT                     = SocketOptionArgument{unix.SO_BSDCOMPAT, "SO_BSDCOMPAT"}
	SO_REUSEPORT                     = SocketOptionArgument{unix.SO_REUSEPORT, "SO_REUSEPORT"}
	SO_PASSCRED                      = SocketOptionArgument{unix.SO_PASSCRED, "SO_PASSCRED"}
	SO_PEERCRED                      = SocketOptionArgument{unix.SO_PEERCRED, "SO_PEERCRED"}
	SO_RCVLOWAT                      = SocketOptionArgument{unix.SO_RCVLOWAT, "SO_RCVLOWAT"}
	SO_SNDLOWAT                      = SocketOptionArgument{unix.SO_SNDLOWAT, "SO_SNDLOWAT"}
	SO_SECURITY_AUTHENTICATION       = SocketOptionArgument{unix.SO_SECURITY_AUTHENTICATION, "SO_SECURITY_AUTHENTICATION"}
	SO_SECURITY_ENCRYPTION_TRANSPORT = SocketOptionArgument{unix.SO_SECURITY_ENCRYPTION_TRANSPORT, "SO_SECURITY_ENCRYPTION_TRANSPORT"}
	SO_SECURITY_ENCRYPTION_NETWORK   = SocketOptionArgument{unix.SO_SECURITY_ENCRYPTION_NETWORK, "SO_SECURITY_ENCRYPTION_NETWORK"}
	SO_BINDTODEVICE                  = SocketOptionArgument{unix.SO_BINDTODEVICE, "SO_BINDTODEVICE"}
	SO_ATTACH_FILTER                 = SocketOptionArgument{unix.SO_ATTACH_FILTER, "SO_ATTACH_FILTER"}
	SO_GET_FILTER                    = SocketOptionArgument{unix.SO_GET_FILTER, "SO_GET_FILTER"}
	SO_DETACH_FILTER                 = SocketOptionArgument{unix.SO_DETACH_FILTER, "SO_DETACH_FILTER"}
	SO_PEERNAME                      = SocketOptionArgument{unix.SO_PEERNAME, "SO_PEERNAME"}
	SO_ACCEPTCONN                    = SocketOptionArgument{unix.SO_ACCEPTCONN, "SO_ACCEPTCONN"}
	SO_PEERSEC                       = SocketOptionArgument{unix.SO_PEERSEC, "SO_PEERSEC"}
	SO_PASSSEC                       = SocketOptionArgument{unix.SO_PASSSEC, "SO_PASSSEC"}
	SO_MARK                          = SocketOptionArgument{unix.SO_MARK, "SO_MARK"}
	SO_PROTOCOL                      = SocketOptionArgument{unix.SO_PROTOCOL, "SO_PROTOCOL"}
	SO_DOMAIN                        = SocketOptionArgument{unix.SO_DOMAIN, "SO_DOMAIN"}
	SO_RXQ_OVFL                      = SocketOptionArgument{unix.SO_RXQ_OVFL, "SO_RXQ_OVFL"}
	SO_WIFI_STATUS                   = SocketOptionArgument{unix.SO_WIFI_STATUS, "SO_WIFI_STATUS"}
	SO_PEEK_OFF                      = SocketOptionArgument{unix.SO_PEEK_OFF, "SO_PEEK_OFF"}
	SO_NOFCS                         = SocketOptionArgument{unix.SO_NOFCS, "SO_NOFCS"}
	SO_LOCK_FILTER                   = SocketOptionArgument{unix.SO_LOCK_FILTER, "SO_LOCK_FILTER"}
	SO_SELECT_ERR_QUEUE              = SocketOptionArgument{unix.SO_SELECT_ERR_QUEUE, "SO_SELECT_ERR_QUEUE"}
	SO_BUSY_POLL                     = SocketOptionArgument{unix.SO_BUSY_POLL, "SO_BUSY_POLL"}
	SO_MAX_PACING_RATE               = SocketOptionArgument{unix.SO_MAX_PACING_RATE, "SO_MAX_PACING_RATE"}
	SO_BPF_EXTENSIONS                = SocketOptionArgument{unix.SO_BPF_EXTENSIONS, "SO_BPF_EXTENSIONS"}
	SO_INCOMING_CPU                  = SocketOptionArgument{unix.SO_INCOMING_CPU, "SO_INCOMING_CPU"}
	SO_ATTACH_BPF                    = SocketOptionArgument{unix.SO_ATTACH_BPF, "SO_ATTACH_BPF"}
	SO_ATTACH_REUSEPORT_CBPF         = SocketOptionArgument{unix.SO_ATTACH_REUSEPORT_CBPF, "SO_ATTACH_REUSEPORT_CBPF"}
	SO_ATTACH_REUSEPORT_EBPF         = SocketOptionArgument{unix.SO_ATTACH_REUSEPORT_EBPF, "SO_ATTACH_REUSEPORT_EBPF"}
	SO_CNX_ADVICE                    = SocketOptionArgument{unix.SO_CNX_ADVICE, "SO_CNX_ADVICE"}
	SCM_TIMESTAMPING_OPT_STATS       = SocketOptionArgument{unix.SCM_TIMESTAMPING_OPT_STATS, "SCM_TIMESTAMPING_OPT_STATS"}
	SO_MEMINFO                       = SocketOptionArgument{unix.SO_MEMINFO, "SO_MEMINFO"}
	SO_INCOMING_NAPI_ID              = SocketOptionArgument{unix.SO_INCOMING_NAPI_ID, "SO_INCOMING_NAPI_ID"}
	SO_COOKIE                        = SocketOptionArgument{unix.SO_COOKIE, "SO_COOKIE"}
	SCM_TIMESTAMPING_PKTINFO         = SocketOptionArgument{unix.SCM_TIMESTAMPING_PKTINFO, "SCM_TIMESTAMPING_PKTINFO"}
	SO_PEERGROUPS                    = SocketOptionArgument{unix.SO_PEERGROUPS, "SO_PEERGROUPS"}
	SO_ZEROCOPY                      = SocketOptionArgument{unix.SO_ZEROCOPY, "SO_ZEROCOPY"}
	SO_TXTIME                        = SocketOptionArgument{unix.SO_TXTIME, "SO_TXTIME"}
	SO_BINDTOIFINDEX                 = SocketOptionArgument{unix.SO_BINDTOIFINDEX, "SO_BINDTOIFINDEX"}
	SO_TIMESTAMP_NEW                 = SocketOptionArgument{unix.SO_TIMESTAMP_NEW, "SO_TIMESTAMP_NEW"}
	SO_TIMESTAMPNS_NEW               = SocketOptionArgument{unix.SO_TIMESTAMPNS_NEW, "SO_TIMESTAMPNS_NEW"}
	SO_TIMESTAMPING_NEW              = SocketOptionArgument{unix.SO_TIMESTAMPING_NEW, "SO_TIMESTAMPING_NEW"}
	SO_RCVTIMEO_NEW                  = SocketOptionArgument{unix.SO_RCVTIMEO_NEW, "SO_RCVTIMEO_NEW"}
	SO_SNDTIMEO_NEW                  = SocketOptionArgument{unix.SO_SNDTIMEO_NEW, "SO_SNDTIMEO_NEW"}
	SO_DETACH_REUSEPORT_BPF          = SocketOptionArgument{unix.SO_DETACH_REUSEPORT_BPF, "SO_DETACH_REUSEPORT_BPF"}
	SO_PREFER_BUSY_POLL              = SocketOptionArgument{unix.SO_PREFER_BUSY_POLL, "SO_PREFER_BUSY_POLL"}
	SO_BUSY_POLL_BUDGET              = SocketOptionArgument{unix.SO_BUSY_POLL_BUDGET, "SO_BUSY_POLL_BUDGET"}
	SO_TIMESTAMP                     = SocketOptionArgument{unix.SO_TIMESTAMP, "SO_TIMESTAMP"}
	SO_TIMESTAMPNS                   = SocketOptionArgument{unix.SO_TIMESTAMPNS, "SO_TIMESTAMPNS"}
	SO_TIMESTAMPING                  = SocketOptionArgument{unix.SO_TIMESTAMPING, "SO_TIMESTAMPING"}
	SO_RCVTIMEO                      = SocketOptionArgument{unix.SO_RCVTIMEO, "SO_RCVTIMEO"}
	SO_SNDTIMEO                      = SocketOptionArgument{unix.SO_SNDTIMEO, "SO_SNDTIMEO"}

	// The following are newer, so aren't included in the unix package
	SO_NETNS_COOKIE SocketOptionArgument = SocketOptionArgument{71, "SO_NETNS_COOKIE"}
	SO_BUF_LOCK     SocketOptionArgument = SocketOptionArgument{72, "SO_BUF_LOCK"}
	SO_RESERVE_MEM  SocketOptionArgument = SocketOptionArgument{73, "SO_RESERVE_MEM"}
	SO_TXREHASH     SocketOptionArgument = SocketOptionArgument{74, "SO_TXREHASH"}
)

// revive:enable

func (socketOption SocketOptionArgument) Value() uint64 { return socketOption.value }

func (socketOption SocketOptionArgument) String() string {
	return socketOption.name
}

var setSocketOptionMap = map[uint64]SocketOptionArgument{
	SO_DEBUG.Value():                         SO_DEBUG,
	SO_REUSEADDR.Value():                     SO_REUSEADDR,
	SO_TYPE.Value():                          SO_TYPE,
	SO_ERROR.Value():                         SO_ERROR,
	SO_DONTROUTE.Value():                     SO_DONTROUTE,
	SO_BROADCAST.Value():                     SO_BROADCAST,
	SO_SNDBUF.Value():                        SO_SNDBUF,
	SO_RCVBUF.Value():                        SO_RCVBUF,
	SO_SNDBUFFORCE.Value():                   SO_SNDBUFFORCE,
	SO_RCVBUFFORCE.Value():                   SO_RCVBUFFORCE,
	SO_KEEPALIVE.Value():                     SO_KEEPALIVE,
	SO_OOBINLINE.Value():                     SO_OOBINLINE,
	SO_NO_CHECK.Value():                      SO_NO_CHECK,
	SO_PRIORITY.Value():                      SO_PRIORITY,
	SO_LINGER.Value():                        SO_LINGER,
	SO_BSDCOMPAT.Value():                     SO_BSDCOMPAT,
	SO_REUSEPORT.Value():                     SO_REUSEPORT,
	SO_PASSCRED.Value():                      SO_PASSCRED,
	SO_PEERCRED.Value():                      SO_PEERCRED,
	SO_RCVLOWAT.Value():                      SO_RCVLOWAT,
	SO_SNDLOWAT.Value():                      SO_SNDLOWAT,
	SO_SECURITY_AUTHENTICATION.Value():       SO_SECURITY_AUTHENTICATION,
	SO_SECURITY_ENCRYPTION_TRANSPORT.Value(): SO_SECURITY_ENCRYPTION_TRANSPORT,
	SO_SECURITY_ENCRYPTION_NETWORK.Value():   SO_SECURITY_ENCRYPTION_NETWORK,
	SO_BINDTODEVICE.Value():                  SO_BINDTODEVICE,
	SO_ATTACH_FILTER.Value():                 SO_ATTACH_FILTER,
	SO_DETACH_FILTER.Value():                 SO_DETACH_FILTER,
	SO_PEERNAME.Value():                      SO_PEERNAME,
	SO_ACCEPTCONN.Value():                    SO_ACCEPTCONN,
	SO_PEERSEC.Value():                       SO_PEERSEC,
	SO_PASSSEC.Value():                       SO_PASSSEC,
	SO_MARK.Value():                          SO_MARK,
	SO_PROTOCOL.Value():                      SO_PROTOCOL,
	SO_DOMAIN.Value():                        SO_DOMAIN,
	SO_RXQ_OVFL.Value():                      SO_RXQ_OVFL,
	SO_WIFI_STATUS.Value():                   SO_WIFI_STATUS,
	SO_PEEK_OFF.Value():                      SO_PEEK_OFF,
	SO_NOFCS.Value():                         SO_NOFCS,
	SO_LOCK_FILTER.Value():                   SO_LOCK_FILTER,
	SO_SELECT_ERR_QUEUE.Value():              SO_SELECT_ERR_QUEUE,
	SO_BUSY_POLL.Value():                     SO_BUSY_POLL,
	SO_MAX_PACING_RATE.Value():               SO_MAX_PACING_RATE,
	SO_BPF_EXTENSIONS.Value():                SO_BPF_EXTENSIONS,
	SO_INCOMING_CPU.Value():                  SO_INCOMING_CPU,
	SO_ATTACH_BPF.Value():                    SO_ATTACH_BPF,
	SO_ATTACH_REUSEPORT_CBPF.Value():         SO_ATTACH_REUSEPORT_CBPF,
	SO_ATTACH_REUSEPORT_EBPF.Value():         SO_ATTACH_REUSEPORT_EBPF,
	SO_CNX_ADVICE.Value():                    SO_CNX_ADVICE,
	SCM_TIMESTAMPING_OPT_STATS.Value():       SCM_TIMESTAMPING_OPT_STATS,
	SO_MEMINFO.Value():                       SO_MEMINFO,
	SO_INCOMING_NAPI_ID.Value():              SO_INCOMING_NAPI_ID,
	SO_COOKIE.Value():                        SO_COOKIE,
	SCM_TIMESTAMPING_PKTINFO.Value():         SCM_TIMESTAMPING_PKTINFO,
	SO_PEERGROUPS.Value():                    SO_PEERGROUPS,
	SO_ZEROCOPY.Value():                      SO_ZEROCOPY,
	SO_TXTIME.Value():                        SO_TXTIME,
	SO_BINDTOIFINDEX.Value():                 SO_BINDTOIFINDEX,
	SO_TIMESTAMP_NEW.Value():                 SO_TIMESTAMP_NEW,
	SO_TIMESTAMPNS_NEW.Value():               SO_TIMESTAMPNS_NEW,
	SO_TIMESTAMPING_NEW.Value():              SO_TIMESTAMPING_NEW,
	SO_RCVTIMEO_NEW.Value():                  SO_RCVTIMEO_NEW,
	SO_SNDTIMEO_NEW.Value():                  SO_SNDTIMEO_NEW,
	SO_DETACH_REUSEPORT_BPF.Value():          SO_DETACH_REUSEPORT_BPF,
	SO_PREFER_BUSY_POLL.Value():              SO_PREFER_BUSY_POLL,
	SO_BUSY_POLL_BUDGET.Value():              SO_BUSY_POLL_BUDGET,
	SO_NETNS_COOKIE.Value():                  SO_NETNS_COOKIE,
	SO_BUF_LOCK.Value():                      SO_BUF_LOCK,
	SO_RESERVE_MEM.Value():                   SO_RESERVE_MEM,
	SO_TIMESTAMP.Value():                     SO_TIMESTAMP,
	SO_TIMESTAMPNS.Value():                   SO_TIMESTAMPNS,
	SO_TIMESTAMPING.Value():                  SO_TIMESTAMPING,
	SO_RCVTIMEO.Value():                      SO_RCVTIMEO,
	SO_SNDTIMEO.Value():                      SO_SNDTIMEO,
	SO_TXREHASH.Value():                      SO_TXREHASH,
}

var getSocketOptionMap = func(m map[uint64]SocketOptionArgument) map[uint64]SocketOptionArgument {
	newMap := make(map[uint64]SocketOptionArgument, len(m))
	for k, v := range m {
		newMap[k] = v
	}
	// Will override the value of SO_ATTACH_FILTER
	newMap[SO_GET_FILTER.Value()] = SO_GET_FILTER
	return newMap
}(setSocketOptionMap)

// ParseSetSocketOption parses the `optname` argument of the `setsockopt` syscall.
// https://man7.org/linux/man-pages/man2/setsockopt.2.html
// https://elixir.bootlin.com/linux/latest/source/include/uapi/asm-generic/socket.h
func ParseSetSocketOption(rawValue uint64) (SocketOptionArgument, error) {
	v, ok := setSocketOptionMap[rawValue]
	if !ok {
		return SocketOptionArgument{}, fmt.Errorf("not a valid argument: %d", rawValue)
	}
	return v, nil
}

// ParseGetSocketOption parses the `optname` argument of the `getsockopt` syscall.
// https://man7.org/linux/man-pages/man2/getsockopt.2.html
// https://elixir.bootlin.com/linux/latest/source/include/uapi/asm-generic/socket.h
func ParseGetSocketOption(rawValue uint64) (SocketOptionArgument, error) {
	v, ok := getSocketOptionMap[rawValue]
	if !ok {
		return SocketOptionArgument{}, fmt.Errorf("not a valid argument: %d", rawValue)
	}
	return v, nil
}

// BPFProgType is an enumeration of BPF program types defined in:
// https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h
type BPFProgType uint32

const (
	BPFProgTypeUnspec BPFProgType = iota
	BPFProgTypeSocketFilter
	BPFProgTypeKprobe
	BPFProgTypeSchedCls
	BPFProgTypeSchedAct
	BPFProgTypeTracepoint
	BPFProgTypeXdp
	BPFProgTypePerfEvent
	BPFProgTypeCgroupSkb
	BPFProgTypeCgroupSock
	BPFProgTypeLwtIn
	BPFProgTypeLwtOut
	BPFProgTypeLwtXmit
	BPFProgTypeSockOps
	BPFProgTypeSkSkb
	BPFProgTypeCgroupDevice
	BPFProgTypeSkMsg
	BPFProgTypeRawTracepoint
	BPFProgTypeCgroupSockAddr
	BPFProgTypeLwtSeg6Local
	BPFProgTypeLircMode2
	BPFProgTypeSkReuseport
	BPFProgTypeFlowDissector
	BPFProgTypeCgroupSysctl
	BPFProgTypeRawTracepointWritable
	BPFProgTypeCgroupSockopt
	BPFProgTypeTracing
	BPFProgTypeStructOps
	BPFProgTypeExt
	BPFProgTypeLsm
	BPFProgTypeSkLookup
	BPFProgTypeSyscall
)

func (b BPFProgType) Value() uint64 {
	return uint64(b)
}

func (b BPFProgType) String() string {
	x := map[BPFProgType]string{
		BPFProgTypeUnspec:                "BPF_PROG_TYPE_UNSPEC",
		BPFProgTypeSocketFilter:          "BPF_PROG_TYPE_SOCKET_FILTER",
		BPFProgTypeKprobe:                "BPF_PROG_TYPE_KPROBE",
		BPFProgTypeSchedCls:              "BPF_PROG_TYPE_SCHED_CLS",
		BPFProgTypeSchedAct:              "BPF_PROG_TYPE_SCHED_ACT",
		BPFProgTypeTracepoint:            "BPF_PROG_TYPE_TRACEPOINT",
		BPFProgTypeXdp:                   "BPF_PROG_TYPE_XDP",
		BPFProgTypePerfEvent:             "BPF_PROG_TYPE_PERF_EVENT",
		BPFProgTypeCgroupSkb:             "BPF_PROG_TYPE_CGROUP_SKB",
		BPFProgTypeCgroupSock:            "BPF_PROG_TYPE_CGROUP_SOCK",
		BPFProgTypeLwtIn:                 "BPF_PROG_TYPE_LWT_IN",
		BPFProgTypeLwtOut:                "BPF_PROG_TYPE_LWT_OUT",
		BPFProgTypeLwtXmit:               "BPF_PROG_TYPE_LWT_XMIT",
		BPFProgTypeSockOps:               "BPF_PROG_TYPE_SOCK_OPS",
		BPFProgTypeSkSkb:                 "BPF_PROG_TYPE_SK_SKB",
		BPFProgTypeCgroupDevice:          "BPF_PROG_TYPE_CGROUP_DEVICE",
		BPFProgTypeSkMsg:                 "BPF_PROG_TYPE_SK_MSG",
		BPFProgTypeRawTracepoint:         "BPF_PROG_TYPE_RAW_TRACEPOINT",
		BPFProgTypeCgroupSockAddr:        "BPF_PROG_TYPE_CGROUP_SOCK_ADDR",
		BPFProgTypeLwtSeg6Local:          "BPF_PROG_TYPE_LWT_SEG6LOCAL",
		BPFProgTypeLircMode2:             "BPF_PROG_TYPE_LIRC_MODE2",
		BPFProgTypeSkReuseport:           "BPF_PROG_TYPE_SK_REUSEPORT",
		BPFProgTypeFlowDissector:         "BPF_PROG_TYPE_FLOW_DISSECTOR",
		BPFProgTypeCgroupSysctl:          "BPF_PROG_TYPE_CGROUP_SYSCTL",
		BPFProgTypeRawTracepointWritable: "BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE",
		BPFProgTypeCgroupSockopt:         "BPF_PROG_TYPE_CGROUP_SOCKOPT",
		BPFProgTypeTracing:               "BPF_PROG_TYPE_TRACING",
		BPFProgTypeStructOps:             "BPF_PROG_TYPE_STRUCT_OPS",
		BPFProgTypeExt:                   "BPF_PROG_TYPE_EXT",
		BPFProgTypeLsm:                   "BPF_PROG_TYPE_LSM",
		BPFProgTypeSkLookup:              "BPF_PROG_TYPE_SK_LOOKUP",
		BPFProgTypeSyscall:               "BPF_PROG_TYPE_SYSCALL",
	}
	str, found := x[b]
	if !found {
		str = BPFProgTypeUnspec.String()
	}
	return str
}

var bpfProgTypeMap = map[uint64]BPFProgType{
	BPFProgTypeUnspec.Value():                BPFProgTypeUnspec,
	BPFProgTypeSocketFilter.Value():          BPFProgTypeSocketFilter,
	BPFProgTypeKprobe.Value():                BPFProgTypeKprobe,
	BPFProgTypeSchedCls.Value():              BPFProgTypeSchedCls,
	BPFProgTypeSchedAct.Value():              BPFProgTypeSchedAct,
	BPFProgTypeTracepoint.Value():            BPFProgTypeTracepoint,
	BPFProgTypeXdp.Value():                   BPFProgTypeXdp,
	BPFProgTypePerfEvent.Value():             BPFProgTypePerfEvent,
	BPFProgTypeCgroupSkb.Value():             BPFProgTypeCgroupSkb,
	BPFProgTypeCgroupSock.Value():            BPFProgTypeCgroupSock,
	BPFProgTypeLwtIn.Value():                 BPFProgTypeLwtIn,
	BPFProgTypeLwtOut.Value():                BPFProgTypeLwtOut,
	BPFProgTypeLwtXmit.Value():               BPFProgTypeLwtXmit,
	BPFProgTypeSockOps.Value():               BPFProgTypeSockOps,
	BPFProgTypeSkSkb.Value():                 BPFProgTypeSkSkb,
	BPFProgTypeCgroupDevice.Value():          BPFProgTypeCgroupDevice,
	BPFProgTypeSkMsg.Value():                 BPFProgTypeSkMsg,
	BPFProgTypeRawTracepoint.Value():         BPFProgTypeRawTracepoint,
	BPFProgTypeCgroupSockAddr.Value():        BPFProgTypeCgroupSockAddr,
	BPFProgTypeLwtSeg6Local.Value():          BPFProgTypeLwtSeg6Local,
	BPFProgTypeLircMode2.Value():             BPFProgTypeLircMode2,
	BPFProgTypeSkReuseport.Value():           BPFProgTypeSkReuseport,
	BPFProgTypeFlowDissector.Value():         BPFProgTypeFlowDissector,
	BPFProgTypeCgroupSysctl.Value():          BPFProgTypeCgroupSysctl,
	BPFProgTypeRawTracepointWritable.Value(): BPFProgTypeRawTracepointWritable,
	BPFProgTypeCgroupSockopt.Value():         BPFProgTypeCgroupSockopt,
	BPFProgTypeTracing.Value():               BPFProgTypeTracing,
	BPFProgTypeStructOps.Value():             BPFProgTypeStructOps,
	BPFProgTypeExt.Value():                   BPFProgTypeExt,
	BPFProgTypeLsm.Value():                   BPFProgTypeLsm,
	BPFProgTypeSkLookup.Value():              BPFProgTypeSkLookup,
	BPFProgTypeSyscall.Value():               BPFProgTypeSyscall,
}

func ParseBPFProgType(rawValue uint64) (BPFProgType, error) {
	v, ok := bpfProgTypeMap[rawValue]
	if !ok {
		return BPFProgType(0), fmt.Errorf("not a valid argument: %d", rawValue)
	}
	return v, nil
}

// BPFFunc is an enumeration of BPF functions (helpers) defined in:
// https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h
type BPFFunc uint32

const (
	BPFFuncUnspec BPFFunc = iota
	BPFFuncMapLookupElem
	BPFFuncMapUpdateElem
	BPFFuncMapDeleteElem
	BPFFuncProbeRead
	BPFFuncKtimeGetNs
	BPFFuncTracePrintk
	BPFFuncGetPrandomU32
	BPFFuncGetSmpProcessorId
	BPFFuncSkbStoreBytes
	BPFFuncL3CsumReplace
	BPFFuncL4CsumReplace
	BPFFuncTailCall
	BPFFuncCloneRedirect
	BPFFuncGetCurrentPidTgid
	BPFFuncGetCurrentUidGid
	BPFFuncGetCurrentComm
	BPFFuncGetCgroupClassid
	BPFFuncSkbVlanPush
	BPFFuncSkbVlanPop
	BPFFuncSkbGetTunnelKey
	BPFFuncSkbSetTunnelKey
	BPFFuncPerfEventRead
	BPFFuncRedirect
	BPFFuncGetRouteRealm
	BPFFuncPerfEventOutput
	BPFFuncSkbLoadBytes
	BPFFuncGetStackid
	BPFFuncCsumDiff
	BPFFuncSkbGetTunnelOpt
	BPFFuncSkbSetTunnelOpt
	BPFFuncSkbChangeProto
	BPFFuncSkbChangeType
	BPFFuncSkbUnderCgroup
	BPFFuncGetHashRecalc
	BPFFuncGetCurrentTask
	BPFFuncProbeWriteUser
	BPFFuncCurrentTaskUnderCgroup
	BPFFuncSkbChangeTail
	BPFFuncSkbPullData
	BPFFuncCsumUpdate
	BPFFuncSetHashInvalid
	BPFFuncGetNumaNodeId
	BPFFuncSkbChangeHead
	BPFFuncXdpAdjustHead
	BPFFuncProbeReadStr
	BPFFuncGetSocketCookie
	BPFFuncGetSocketUid
	BPFFuncSetHash
	BPFFuncSetsockopt
	BPFFuncSkbAdjustRoom
	BPFFuncRedirectMap
	BPFFuncSkRedirectMap
	BPFFuncSockMapUpdate
	BPFFuncXdpAdjustMeta
	BPFFuncPerfEventReadValue
	BPFFuncPerfProgReadValue
	BPFFuncGetsockopt
	BPFFuncOverrideReturn
	BPFFuncSockOpsCbFlagsSet
	BPFFuncMsgRedirectMap
	BPFFuncMsgApplyBytes
	BPFFuncMsgCorkBytes
	BPFFuncMsgPullData
	BPFFuncBind
	BPFFuncXdpAdjustTail
	BPFFuncSkbGetXfrmState
	BPFFuncGetStack
	BPFFuncSkbLoadBytesRelative
	BPFFuncFibLookup
	BPFFuncSockHashUpdate
	BPFFuncMsgRedirectHash
	BPFFuncSkRedirectHash
	BPFFuncLwtPushEncap
	BPFFuncLwtSeg6StoreBytes
	BPFFuncLwtSeg6AdjustSrh
	BPFFuncLwtSeg6Action
	BPFFuncRcRepeat
	BPFFuncRcKeydown
	BPFFuncSkbCgroupId
	BPFFuncGetCurrentCgroupId
	BPFFuncGetLocalStorage
	BPFFuncSkSelectReuseport
	BPFFuncSkbAncestorCgroupId
	BPFFuncSkLookupTcp
	BPFFuncSkLookupUdp
	BPFFuncSkRelease
	BPFFuncMapPushElem
	BPFFuncMapPopElem
	BPFFuncMapPeekElem
	BPFFuncMsgPushData
	BPFFuncMsgPopData
	BPFFuncRcPointerRel
	BPFFuncSpinLock
	BPFFuncSpinUnlock
	BPFFuncSkFullsock
	BPFFuncTcpSock
	BPFFuncSkbEcnSetCe
	BPFFuncGetListenerSock
	BPFFuncSkcLookupTcp
	BPFFuncTcpCheckSyncookie
	BPFFuncSysctlGetName
	BPFFuncSysctlGetCurrentValue
	BPFFuncSysctlGetNewValue
	BPFFuncSysctlSetNewValue
	BPFFuncStrtol
	BPFFuncStrtoul
	BPFFuncSkStorageGet
	BPFFuncSkStorageDelete
	BPFFuncSendSignal
	BPFFuncTcpGenSyncookie
	BPFFuncSkbOutput
	BPFFuncProbeReadUser
	BPFFuncProbeReadKernel
	BPFFuncProbeReadUserStr
	BPFFuncProbeReadKernelStr
	BPFFuncTcpSendAck
	BPFFuncSendSignalThread
	BPFFuncJiffies64
	BPFFuncReadBranchRecords
	BPFFuncGetNsCurrentPidTgid
	BPFFuncXdpOutput
	BPFFuncGetNetnsCookie
	BPFFuncGetCurrentAncestorCgroupId
	BPFFuncSkAssign
	BPFFuncKtimeGetBootNs
	BPFFuncSeqPrintf
	BPFFuncSeqWrite
	BPFFuncSkCgroupId
	BPFFuncSkAncestorCgroupId
	BPFFuncRingbufOutput
	BPFFuncRingbufReserve
	BPFFuncRingbufSubmit
	BPFFuncRingbufDiscard
	BPFFuncRingbufQuery
	BPFFuncCsumLevel
	BPFFuncSkcToTcp6Sock
	BPFFuncSkcToTcpSock
	BPFFuncSkcToTcpTimewaitSock
	BPFFuncSkcToTcpRequestSock
	BPFFuncSkcToUdp6Sock
	BPFFuncGetTaskStack
	BPFFuncLoadHdrOpt
	BPFFuncStoreHdrOpt
	BPFFuncReserveHdrOpt
	BPFFuncInodeStorageGet
	BPFFuncInodeStorageDelete
	BPFFuncDPath
	BPFFuncCopyFromUser
	BPFFuncSnprintfBtf
	BPFFuncSeqPrintfBtf
	BPFFuncSkbCgroupClassid
	BPFFuncRedirectNeigh
	BPFFuncPerCpuPtr
	BPFFuncThisCpuPtr
	BPFFuncRedirectPeer
	BPFFuncTaskStorageGet
	BPFFuncTaskStorageDelete
	BPFFuncGetCurrentTaskBtf
	BPFFuncBprmOptsSet
	BPFFuncKtimeGetCoarseNs
	BPFFuncImaInodeHash
	BPFFuncSockFromFile
	BPFFuncCheckMtu
	BPFFuncForEachMapElem
	BPFFuncSnprintf
	BPFFuncSysBpf
	BPFFuncBtfFindByNameKind
	BPFFuncSysClose
	BPFFuncTimerInit
	BPFFuncTimerSetCallback
	BPFFuncTimerStart
	BPFFuncTimerCancel
	BPFFuncGetFuncIp
	BPFFuncGetAttachCookie
	BPFFuncTaskPtRegs
	BPFFuncGetBranchSnapshot
	BPFFuncTraceVprintk
	BPFFuncSkcToUnixSock
	BPFFuncKallsymsLookupName
	BPFFuncFindVma
	BPFFuncLoop
	BPFFuncStrncmp
	BPFFuncGetFuncArg
	BPFFuncGetFuncRet
	BPFFuncGetFuncArgCnt
	BPFFuncGetRetval
	BPFFuncSetRetval
	BPFFuncXdpGetBuffLen
	BPFFuncXdpLoadBytes
	BPFFuncXdpStoreBytes
	BPFFuncCopyFromUserTask
	BPFFuncSkbSetTstamp
	BPFFuncImaFileHash
	BPFFuncKptrXchg
	BPFFuncMapLookupPercpuElem
	BPFFuncSkcToMptcpSock
	BPFFuncDynptrFromMem
	BPFFuncRingbufReserveDynptr
	BPFFuncRingbufSubmitDynptr
	BPFFuncRingbufDiscardDynptr
	BPFFuncDynptrRead
	BPFFuncDynptrWrite
	BPFFuncDynptrData
	BPFFuncTcpRawGenSyncookieIpv4
	BPFFuncTcpRawGenSyncookieIpv6
	BPFFuncTcpRawCheckSyncookieIpv4
	BPFFuncTcpRawCheckSyncookieIpv6
	BPFFuncKtimeGetTaiNs
	BPFFuncUserRingbufDrain
	BPFFuncCgrpStorageGet
	BPFFuncCgrpStorageDelete
)

func (b BPFFunc) Value() uint64 {
	return uint64(b)
}

func (b BPFFunc) String() string {
	x := map[BPFFunc]string{
		BPFFuncUnspec:                     "unspec",
		BPFFuncMapLookupElem:              "map_lookup_elem",
		BPFFuncMapUpdateElem:              "map_update_elem",
		BPFFuncMapDeleteElem:              "map_delete_elem",
		BPFFuncProbeRead:                  "probe_read",
		BPFFuncKtimeGetNs:                 "ktime_get_ns",
		BPFFuncTracePrintk:                "trace_printk",
		BPFFuncGetPrandomU32:              "get_prandom_u32",
		BPFFuncGetSmpProcessorId:          "get_smp_processor_id",
		BPFFuncSkbStoreBytes:              "skb_store_bytes",
		BPFFuncL3CsumReplace:              "l3_csum_replace",
		BPFFuncL4CsumReplace:              "l4_csum_replace",
		BPFFuncTailCall:                   "tail_call",
		BPFFuncCloneRedirect:              "clone_redirect",
		BPFFuncGetCurrentPidTgid:          "get_current_pid_tgid",
		BPFFuncGetCurrentUidGid:           "get_current_uid_gid",
		BPFFuncGetCurrentComm:             "get_current_comm",
		BPFFuncGetCgroupClassid:           "get_cgroup_classid",
		BPFFuncSkbVlanPush:                "skb_vlan_push",
		BPFFuncSkbVlanPop:                 "skb_vlan_pop",
		BPFFuncSkbGetTunnelKey:            "skb_get_tunnel_key",
		BPFFuncSkbSetTunnelKey:            "skb_set_tunnel_key",
		BPFFuncPerfEventRead:              "perf_event_read",
		BPFFuncRedirect:                   "redirect",
		BPFFuncGetRouteRealm:              "get_route_realm",
		BPFFuncPerfEventOutput:            "perf_event_output",
		BPFFuncSkbLoadBytes:               "skb_load_bytes",
		BPFFuncGetStackid:                 "get_stackid",
		BPFFuncCsumDiff:                   "csum_diff",
		BPFFuncSkbGetTunnelOpt:            "skb_get_tunnel_opt",
		BPFFuncSkbSetTunnelOpt:            "skb_set_tunnel_opt",
		BPFFuncSkbChangeProto:             "skb_change_proto",
		BPFFuncSkbChangeType:              "skb_change_type",
		BPFFuncSkbUnderCgroup:             "skb_under_cgroup",
		BPFFuncGetHashRecalc:              "get_hash_recalc",
		BPFFuncGetCurrentTask:             "get_current_task",
		BPFFuncProbeWriteUser:             "probe_write_user",
		BPFFuncCurrentTaskUnderCgroup:     "current_task_under_cgroup",
		BPFFuncSkbChangeTail:              "skb_change_tail",
		BPFFuncSkbPullData:                "skb_pull_data",
		BPFFuncCsumUpdate:                 "csum_update",
		BPFFuncSetHashInvalid:             "set_hash_invalid",
		BPFFuncGetNumaNodeId:              "get_numa_node_id",
		BPFFuncSkbChangeHead:              "skb_change_head",
		BPFFuncXdpAdjustHead:              "xdp_adjust_head",
		BPFFuncProbeReadStr:               "probe_read_str",
		BPFFuncGetSocketCookie:            "get_socket_cookie",
		BPFFuncGetSocketUid:               "get_socket_uid",
		BPFFuncSetHash:                    "set_hash",
		BPFFuncSetsockopt:                 "setsockopt",
		BPFFuncSkbAdjustRoom:              "skb_adjust_room",
		BPFFuncRedirectMap:                "redirect_map",
		BPFFuncSkRedirectMap:              "sk_redirect_map",
		BPFFuncSockMapUpdate:              "sock_map_update",
		BPFFuncXdpAdjustMeta:              "xdp_adjust_meta",
		BPFFuncPerfEventReadValue:         "perf_event_read_value",
		BPFFuncPerfProgReadValue:          "perf_prog_read_value",
		BPFFuncGetsockopt:                 "getsockopt",
		BPFFuncOverrideReturn:             "override_return",
		BPFFuncSockOpsCbFlagsSet:          "sock_ops_cb_flags_set",
		BPFFuncMsgRedirectMap:             "msg_redirect_map",
		BPFFuncMsgApplyBytes:              "msg_apply_bytes",
		BPFFuncMsgCorkBytes:               "msg_cork_bytes",
		BPFFuncMsgPullData:                "msg_pull_data",
		BPFFuncBind:                       "bind",
		BPFFuncXdpAdjustTail:              "xdp_adjust_tail",
		BPFFuncSkbGetXfrmState:            "skb_get_xfrm_state",
		BPFFuncGetStack:                   "get_stack",
		BPFFuncSkbLoadBytesRelative:       "skb_load_bytes_relative",
		BPFFuncFibLookup:                  "fib_lookup",
		BPFFuncSockHashUpdate:             "sock_hash_update",
		BPFFuncMsgRedirectHash:            "msg_redirect_hash",
		BPFFuncSkRedirectHash:             "sk_redirect_hash",
		BPFFuncLwtPushEncap:               "lwt_push_encap",
		BPFFuncLwtSeg6StoreBytes:          "lwt_seg6_store_bytes",
		BPFFuncLwtSeg6AdjustSrh:           "lwt_seg6_adjust_srh",
		BPFFuncLwtSeg6Action:              "lwt_seg6_action",
		BPFFuncRcRepeat:                   "rc_repeat",
		BPFFuncRcKeydown:                  "rc_keydown",
		BPFFuncSkbCgroupId:                "skb_cgroup_id",
		BPFFuncGetCurrentCgroupId:         "get_current_cgroup_id",
		BPFFuncGetLocalStorage:            "get_local_storage",
		BPFFuncSkSelectReuseport:          "sk_select_reuseport",
		BPFFuncSkbAncestorCgroupId:        "skb_ancestor_cgroup_id",
		BPFFuncSkLookupTcp:                "sk_lookup_tcp",
		BPFFuncSkLookupUdp:                "sk_lookup_udp",
		BPFFuncSkRelease:                  "sk_release",
		BPFFuncMapPushElem:                "map_push_elem",
		BPFFuncMapPopElem:                 "map_pop_elem",
		BPFFuncMapPeekElem:                "map_peek_elem",
		BPFFuncMsgPushData:                "msg_push_data",
		BPFFuncMsgPopData:                 "msg_pop_data",
		BPFFuncRcPointerRel:               "rc_pointer_rel",
		BPFFuncSpinLock:                   "spin_lock",
		BPFFuncSpinUnlock:                 "spin_unlock",
		BPFFuncSkFullsock:                 "sk_fullsock",
		BPFFuncTcpSock:                    "tcp_sock",
		BPFFuncSkbEcnSetCe:                "skb_ecn_set_ce",
		BPFFuncGetListenerSock:            "get_listener_sock",
		BPFFuncSkcLookupTcp:               "skc_lookup_tcp",
		BPFFuncTcpCheckSyncookie:          "tcp_check_syncookie",
		BPFFuncSysctlGetName:              "sysctl_get_name",
		BPFFuncSysctlGetCurrentValue:      "sysctl_get_current_value",
		BPFFuncSysctlGetNewValue:          "sysctl_get_new_value",
		BPFFuncSysctlSetNewValue:          "sysctl_set_new_value",
		BPFFuncStrtol:                     "strtol",
		BPFFuncStrtoul:                    "strtoul",
		BPFFuncSkStorageGet:               "sk_storage_get",
		BPFFuncSkStorageDelete:            "sk_storage_delete",
		BPFFuncSendSignal:                 "send_signal",
		BPFFuncTcpGenSyncookie:            "tcp_gen_syncookie",
		BPFFuncSkbOutput:                  "skb_output",
		BPFFuncProbeReadUser:              "probe_read_user",
		BPFFuncProbeReadKernel:            "probe_read_kernel",
		BPFFuncProbeReadUserStr:           "probe_read_user_str",
		BPFFuncProbeReadKernelStr:         "probe_read_kernel_str",
		BPFFuncTcpSendAck:                 "tcp_send_ack",
		BPFFuncSendSignalThread:           "send_signal_thread",
		BPFFuncJiffies64:                  "jiffies64",
		BPFFuncReadBranchRecords:          "read_branch_records",
		BPFFuncGetNsCurrentPidTgid:        "get_ns_current_pid_tgid",
		BPFFuncXdpOutput:                  "xdp_output",
		BPFFuncGetNetnsCookie:             "get_netns_cookie",
		BPFFuncGetCurrentAncestorCgroupId: "get_current_ancestor_cgroup_id",
		BPFFuncSkAssign:                   "sk_assign",
		BPFFuncKtimeGetBootNs:             "ktime_get_boot_ns",
		BPFFuncSeqPrintf:                  "seq_printf",
		BPFFuncSeqWrite:                   "seq_write",
		BPFFuncSkCgroupId:                 "sk_cgroup_id",
		BPFFuncSkAncestorCgroupId:         "sk_ancestor_cgroup_id",
		BPFFuncRingbufOutput:              "ringbuf_output",
		BPFFuncRingbufReserve:             "ringbuf_reserve",
		BPFFuncRingbufSubmit:              "ringbuf_submit",
		BPFFuncRingbufDiscard:             "ringbuf_discard",
		BPFFuncRingbufQuery:               "ringbuf_query",
		BPFFuncCsumLevel:                  "csum_level",
		BPFFuncSkcToTcp6Sock:              "skc_to_tcp6_sock",
		BPFFuncSkcToTcpSock:               "skc_to_tcp_sock",
		BPFFuncSkcToTcpTimewaitSock:       "skc_to_tcp_timewait_sock",
		BPFFuncSkcToTcpRequestSock:        "skc_to_tcp_request_sock",
		BPFFuncSkcToUdp6Sock:              "skc_to_udp6_sock",
		BPFFuncGetTaskStack:               "get_task_stack",
		BPFFuncLoadHdrOpt:                 "load_hdr_opt",
		BPFFuncStoreHdrOpt:                "store_hdr_opt",
		BPFFuncReserveHdrOpt:              "reserve_hdr_opt",
		BPFFuncInodeStorageGet:            "inode_storage_get",
		BPFFuncInodeStorageDelete:         "inode_storage_delete",
		BPFFuncDPath:                      "d_path",
		BPFFuncCopyFromUser:               "copy_from_user",
		BPFFuncSnprintfBtf:                "snprintf_btf",
		BPFFuncSeqPrintfBtf:               "seq_printf_btf",
		BPFFuncSkbCgroupClassid:           "skb_cgroup_classid",
		BPFFuncRedirectNeigh:              "redirect_neigh",
		BPFFuncPerCpuPtr:                  "per_cpu_ptr",
		BPFFuncThisCpuPtr:                 "this_cpu_ptr",
		BPFFuncRedirectPeer:               "redirect_peer",
		BPFFuncTaskStorageGet:             "task_storage_get",
		BPFFuncTaskStorageDelete:          "task_storage_delete",
		BPFFuncGetCurrentTaskBtf:          "get_current_task_btf",
		BPFFuncBprmOptsSet:                "bprm_opts_set",
		BPFFuncKtimeGetCoarseNs:           "ktime_get_coarse_ns",
		BPFFuncImaInodeHash:               "ima_inode_hash",
		BPFFuncSockFromFile:               "sock_from_file",
		BPFFuncCheckMtu:                   "check_mtu",
		BPFFuncForEachMapElem:             "for_each_map_elem",
		BPFFuncSnprintf:                   "snprintf",
		BPFFuncSysBpf:                     "sys_bpf",
		BPFFuncBtfFindByNameKind:          "btf_find_by_name_kind",
		BPFFuncSysClose:                   "sys_close",
		BPFFuncTimerInit:                  "timer_init",
		BPFFuncTimerSetCallback:           "timer_set_callback",
		BPFFuncTimerStart:                 "timer_start",
		BPFFuncTimerCancel:                "timer_cancel",
		BPFFuncGetFuncIp:                  "get_func_ip",
		BPFFuncGetAttachCookie:            "get_attach_cookie",
		BPFFuncTaskPtRegs:                 "task_pt_regs",
		BPFFuncGetBranchSnapshot:          "get_branch_snapshot",
		BPFFuncTraceVprintk:               "trace_vprintk",
		BPFFuncSkcToUnixSock:              "skc_to_unix_sock",
		BPFFuncKallsymsLookupName:         "kallsyms_lookup_name",
		BPFFuncFindVma:                    "find_vma",
		BPFFuncLoop:                       "loop",
		BPFFuncStrncmp:                    "strncmp",
		BPFFuncGetFuncArg:                 "get_func_arg",
		BPFFuncGetFuncRet:                 "get_func_ret",
		BPFFuncGetFuncArgCnt:              "get_func_arg_cnt",
		BPFFuncGetRetval:                  "get_retval",
		BPFFuncSetRetval:                  "set_retval",
		BPFFuncXdpGetBuffLen:              "xdp_get_buff_len",
		BPFFuncXdpLoadBytes:               "xdp_load_bytes",
		BPFFuncXdpStoreBytes:              "xdp_store_bytes",
		BPFFuncCopyFromUserTask:           "copy_from_user_task",
		BPFFuncSkbSetTstamp:               "skb_set_tstamp",
		BPFFuncImaFileHash:                "ima_file_hash",
		BPFFuncKptrXchg:                   "kptr_xchg",
		BPFFuncMapLookupPercpuElem:        "map_lookup_percpu_elem",
		BPFFuncSkcToMptcpSock:             "skc_to_mptcp_sock",
		BPFFuncDynptrFromMem:              "dynptr_from_mem",
		BPFFuncRingbufReserveDynptr:       "ringbuf_reserve_dynptr",
		BPFFuncRingbufSubmitDynptr:        "ringbuf_submit_dynptr",
		BPFFuncRingbufDiscardDynptr:       "ringbuf_discard_dynptr",
		BPFFuncDynptrRead:                 "dynptr_read",
		BPFFuncDynptrWrite:                "dynptr_write",
		BPFFuncDynptrData:                 "dynptr_data",
		BPFFuncTcpRawGenSyncookieIpv4:     "tcp_raw_gen_syncookie_ipv4",
		BPFFuncTcpRawGenSyncookieIpv6:     "tcp_raw_gen_syncookie_ipv6",
		BPFFuncTcpRawCheckSyncookieIpv4:   "tcp_raw_check_syncookie_ipv4",
		BPFFuncTcpRawCheckSyncookieIpv6:   "tcp_raw_check_syncookie_ipv6",
		BPFFuncKtimeGetTaiNs:              "ktime_get_tai_ns",
		BPFFuncUserRingbufDrain:           "user_ringbuf_drain",
		BPFFuncCgrpStorageGet:             "cgrp_storage_get",
		BPFFuncCgrpStorageDelete:          "cgrp_storage_delete",
	}
	str, found := x[b]
	if !found {
		str = BPFFuncUnspec.String()
	}
	return str
}

var bpfFuncsMap = map[uint64]BPFFunc{
	BPFFuncUnspec.Value():                     BPFFuncUnspec,
	BPFFuncMapLookupElem.Value():              BPFFuncMapLookupElem,
	BPFFuncMapUpdateElem.Value():              BPFFuncMapUpdateElem,
	BPFFuncMapDeleteElem.Value():              BPFFuncMapDeleteElem,
	BPFFuncProbeRead.Value():                  BPFFuncProbeRead,
	BPFFuncKtimeGetNs.Value():                 BPFFuncKtimeGetNs,
	BPFFuncTracePrintk.Value():                BPFFuncTracePrintk,
	BPFFuncGetPrandomU32.Value():              BPFFuncGetPrandomU32,
	BPFFuncGetSmpProcessorId.Value():          BPFFuncGetSmpProcessorId,
	BPFFuncSkbStoreBytes.Value():              BPFFuncSkbStoreBytes,
	BPFFuncL3CsumReplace.Value():              BPFFuncL3CsumReplace,
	BPFFuncL4CsumReplace.Value():              BPFFuncL4CsumReplace,
	BPFFuncTailCall.Value():                   BPFFuncTailCall,
	BPFFuncCloneRedirect.Value():              BPFFuncCloneRedirect,
	BPFFuncGetCurrentPidTgid.Value():          BPFFuncGetCurrentPidTgid,
	BPFFuncGetCurrentUidGid.Value():           BPFFuncGetCurrentUidGid,
	BPFFuncGetCurrentComm.Value():             BPFFuncGetCurrentComm,
	BPFFuncGetCgroupClassid.Value():           BPFFuncGetCgroupClassid,
	BPFFuncSkbVlanPush.Value():                BPFFuncSkbVlanPush,
	BPFFuncSkbVlanPop.Value():                 BPFFuncSkbVlanPop,
	BPFFuncSkbGetTunnelKey.Value():            BPFFuncSkbGetTunnelKey,
	BPFFuncSkbSetTunnelKey.Value():            BPFFuncSkbSetTunnelKey,
	BPFFuncPerfEventRead.Value():              BPFFuncPerfEventRead,
	BPFFuncRedirect.Value():                   BPFFuncRedirect,
	BPFFuncGetRouteRealm.Value():              BPFFuncGetRouteRealm,
	BPFFuncPerfEventOutput.Value():            BPFFuncPerfEventOutput,
	BPFFuncSkbLoadBytes.Value():               BPFFuncSkbLoadBytes,
	BPFFuncGetStackid.Value():                 BPFFuncGetStackid,
	BPFFuncCsumDiff.Value():                   BPFFuncCsumDiff,
	BPFFuncSkbGetTunnelOpt.Value():            BPFFuncSkbGetTunnelOpt,
	BPFFuncSkbSetTunnelOpt.Value():            BPFFuncSkbSetTunnelOpt,
	BPFFuncSkbChangeProto.Value():             BPFFuncSkbChangeProto,
	BPFFuncSkbChangeType.Value():              BPFFuncSkbChangeType,
	BPFFuncSkbUnderCgroup.Value():             BPFFuncSkbUnderCgroup,
	BPFFuncGetHashRecalc.Value():              BPFFuncGetHashRecalc,
	BPFFuncGetCurrentTask.Value():             BPFFuncGetCurrentTask,
	BPFFuncProbeWriteUser.Value():             BPFFuncProbeWriteUser,
	BPFFuncCurrentTaskUnderCgroup.Value():     BPFFuncCurrentTaskUnderCgroup,
	BPFFuncSkbChangeTail.Value():              BPFFuncSkbChangeTail,
	BPFFuncSkbPullData.Value():                BPFFuncSkbPullData,
	BPFFuncCsumUpdate.Value():                 BPFFuncCsumUpdate,
	BPFFuncSetHashInvalid.Value():             BPFFuncSetHashInvalid,
	BPFFuncGetNumaNodeId.Value():              BPFFuncGetNumaNodeId,
	BPFFuncSkbChangeHead.Value():              BPFFuncSkbChangeHead,
	BPFFuncXdpAdjustHead.Value():              BPFFuncXdpAdjustHead,
	BPFFuncProbeReadStr.Value():               BPFFuncProbeReadStr,
	BPFFuncGetSocketCookie.Value():            BPFFuncGetSocketCookie,
	BPFFuncGetSocketUid.Value():               BPFFuncGetSocketUid,
	BPFFuncSetHash.Value():                    BPFFuncSetHash,
	BPFFuncSetsockopt.Value():                 BPFFuncSetsockopt,
	BPFFuncSkbAdjustRoom.Value():              BPFFuncSkbAdjustRoom,
	BPFFuncRedirectMap.Value():                BPFFuncRedirectMap,
	BPFFuncSkRedirectMap.Value():              BPFFuncSkRedirectMap,
	BPFFuncSockMapUpdate.Value():              BPFFuncSockMapUpdate,
	BPFFuncXdpAdjustMeta.Value():              BPFFuncXdpAdjustMeta,
	BPFFuncPerfEventReadValue.Value():         BPFFuncPerfEventReadValue,
	BPFFuncPerfProgReadValue.Value():          BPFFuncPerfProgReadValue,
	BPFFuncGetsockopt.Value():                 BPFFuncGetsockopt,
	BPFFuncOverrideReturn.Value():             BPFFuncOverrideReturn,
	BPFFuncSockOpsCbFlagsSet.Value():          BPFFuncSockOpsCbFlagsSet,
	BPFFuncMsgRedirectMap.Value():             BPFFuncMsgRedirectMap,
	BPFFuncMsgApplyBytes.Value():              BPFFuncMsgApplyBytes,
	BPFFuncMsgCorkBytes.Value():               BPFFuncMsgCorkBytes,
	BPFFuncMsgPullData.Value():                BPFFuncMsgPullData,
	BPFFuncBind.Value():                       BPFFuncBind,
	BPFFuncXdpAdjustTail.Value():              BPFFuncXdpAdjustTail,
	BPFFuncSkbGetXfrmState.Value():            BPFFuncSkbGetXfrmState,
	BPFFuncGetStack.Value():                   BPFFuncGetStack,
	BPFFuncSkbLoadBytesRelative.Value():       BPFFuncSkbLoadBytesRelative,
	BPFFuncFibLookup.Value():                  BPFFuncFibLookup,
	BPFFuncSockHashUpdate.Value():             BPFFuncSockHashUpdate,
	BPFFuncMsgRedirectHash.Value():            BPFFuncMsgRedirectHash,
	BPFFuncSkRedirectHash.Value():             BPFFuncSkRedirectHash,
	BPFFuncLwtPushEncap.Value():               BPFFuncLwtPushEncap,
	BPFFuncLwtSeg6StoreBytes.Value():          BPFFuncLwtSeg6StoreBytes,
	BPFFuncLwtSeg6AdjustSrh.Value():           BPFFuncLwtSeg6AdjustSrh,
	BPFFuncLwtSeg6Action.Value():              BPFFuncLwtSeg6Action,
	BPFFuncRcRepeat.Value():                   BPFFuncRcRepeat,
	BPFFuncRcKeydown.Value():                  BPFFuncRcKeydown,
	BPFFuncSkbCgroupId.Value():                BPFFuncSkbCgroupId,
	BPFFuncGetCurrentCgroupId.Value():         BPFFuncGetCurrentCgroupId,
	BPFFuncGetLocalStorage.Value():            BPFFuncGetLocalStorage,
	BPFFuncSkSelectReuseport.Value():          BPFFuncSkSelectReuseport,
	BPFFuncSkbAncestorCgroupId.Value():        BPFFuncSkbAncestorCgroupId,
	BPFFuncSkLookupTcp.Value():                BPFFuncSkLookupTcp,
	BPFFuncSkLookupUdp.Value():                BPFFuncSkLookupUdp,
	BPFFuncSkRelease.Value():                  BPFFuncSkRelease,
	BPFFuncMapPushElem.Value():                BPFFuncMapPushElem,
	BPFFuncMapPopElem.Value():                 BPFFuncMapPopElem,
	BPFFuncMapPeekElem.Value():                BPFFuncMapPeekElem,
	BPFFuncMsgPushData.Value():                BPFFuncMsgPushData,
	BPFFuncMsgPopData.Value():                 BPFFuncMsgPopData,
	BPFFuncRcPointerRel.Value():               BPFFuncRcPointerRel,
	BPFFuncSpinLock.Value():                   BPFFuncSpinLock,
	BPFFuncSpinUnlock.Value():                 BPFFuncSpinUnlock,
	BPFFuncSkFullsock.Value():                 BPFFuncSkFullsock,
	BPFFuncTcpSock.Value():                    BPFFuncTcpSock,
	BPFFuncSkbEcnSetCe.Value():                BPFFuncSkbEcnSetCe,
	BPFFuncGetListenerSock.Value():            BPFFuncGetListenerSock,
	BPFFuncSkcLookupTcp.Value():               BPFFuncSkcLookupTcp,
	BPFFuncTcpCheckSyncookie.Value():          BPFFuncTcpCheckSyncookie,
	BPFFuncSysctlGetName.Value():              BPFFuncSysctlGetName,
	BPFFuncSysctlGetCurrentValue.Value():      BPFFuncSysctlGetCurrentValue,
	BPFFuncSysctlGetNewValue.Value():          BPFFuncSysctlGetNewValue,
	BPFFuncSysctlSetNewValue.Value():          BPFFuncSysctlSetNewValue,
	BPFFuncStrtol.Value():                     BPFFuncStrtol,
	BPFFuncStrtoul.Value():                    BPFFuncStrtoul,
	BPFFuncSkStorageGet.Value():               BPFFuncSkStorageGet,
	BPFFuncSkStorageDelete.Value():            BPFFuncSkStorageDelete,
	BPFFuncSendSignal.Value():                 BPFFuncSendSignal,
	BPFFuncTcpGenSyncookie.Value():            BPFFuncTcpGenSyncookie,
	BPFFuncSkbOutput.Value():                  BPFFuncSkbOutput,
	BPFFuncProbeReadUser.Value():              BPFFuncProbeReadUser,
	BPFFuncProbeReadKernel.Value():            BPFFuncProbeReadKernel,
	BPFFuncProbeReadUserStr.Value():           BPFFuncProbeReadUserStr,
	BPFFuncProbeReadKernelStr.Value():         BPFFuncProbeReadKernelStr,
	BPFFuncTcpSendAck.Value():                 BPFFuncTcpSendAck,
	BPFFuncSendSignalThread.Value():           BPFFuncSendSignalThread,
	BPFFuncJiffies64.Value():                  BPFFuncJiffies64,
	BPFFuncReadBranchRecords.Value():          BPFFuncReadBranchRecords,
	BPFFuncGetNsCurrentPidTgid.Value():        BPFFuncGetNsCurrentPidTgid,
	BPFFuncXdpOutput.Value():                  BPFFuncXdpOutput,
	BPFFuncGetNetnsCookie.Value():             BPFFuncGetNetnsCookie,
	BPFFuncGetCurrentAncestorCgroupId.Value(): BPFFuncGetCurrentAncestorCgroupId,
	BPFFuncSkAssign.Value():                   BPFFuncSkAssign,
	BPFFuncKtimeGetBootNs.Value():             BPFFuncKtimeGetBootNs,
	BPFFuncSeqPrintf.Value():                  BPFFuncSeqPrintf,
	BPFFuncSeqWrite.Value():                   BPFFuncSeqWrite,
	BPFFuncSkCgroupId.Value():                 BPFFuncSkCgroupId,
	BPFFuncSkAncestorCgroupId.Value():         BPFFuncSkAncestorCgroupId,
	BPFFuncRingbufOutput.Value():              BPFFuncRingbufOutput,
	BPFFuncRingbufReserve.Value():             BPFFuncRingbufReserve,
	BPFFuncRingbufSubmit.Value():              BPFFuncRingbufSubmit,
	BPFFuncRingbufDiscard.Value():             BPFFuncRingbufDiscard,
	BPFFuncRingbufQuery.Value():               BPFFuncRingbufQuery,
	BPFFuncCsumLevel.Value():                  BPFFuncCsumLevel,
	BPFFuncSkcToTcp6Sock.Value():              BPFFuncSkcToTcp6Sock,
	BPFFuncSkcToTcpSock.Value():               BPFFuncSkcToTcpSock,
	BPFFuncSkcToTcpTimewaitSock.Value():       BPFFuncSkcToTcpTimewaitSock,
	BPFFuncSkcToTcpRequestSock.Value():        BPFFuncSkcToTcpRequestSock,
	BPFFuncSkcToUdp6Sock.Value():              BPFFuncSkcToUdp6Sock,
	BPFFuncGetTaskStack.Value():               BPFFuncGetTaskStack,
	BPFFuncLoadHdrOpt.Value():                 BPFFuncLoadHdrOpt,
	BPFFuncStoreHdrOpt.Value():                BPFFuncStoreHdrOpt,
	BPFFuncReserveHdrOpt.Value():              BPFFuncReserveHdrOpt,
	BPFFuncInodeStorageGet.Value():            BPFFuncInodeStorageGet,
	BPFFuncInodeStorageDelete.Value():         BPFFuncInodeStorageDelete,
	BPFFuncDPath.Value():                      BPFFuncDPath,
	BPFFuncCopyFromUser.Value():               BPFFuncCopyFromUser,
	BPFFuncSnprintfBtf.Value():                BPFFuncSnprintfBtf,
	BPFFuncSeqPrintfBtf.Value():               BPFFuncSeqPrintfBtf,
	BPFFuncSkbCgroupClassid.Value():           BPFFuncSkbCgroupClassid,
	BPFFuncRedirectNeigh.Value():              BPFFuncRedirectNeigh,
	BPFFuncPerCpuPtr.Value():                  BPFFuncPerCpuPtr,
	BPFFuncThisCpuPtr.Value():                 BPFFuncThisCpuPtr,
	BPFFuncRedirectPeer.Value():               BPFFuncRedirectPeer,
	BPFFuncTaskStorageGet.Value():             BPFFuncTaskStorageGet,
	BPFFuncTaskStorageDelete.Value():          BPFFuncTaskStorageDelete,
	BPFFuncGetCurrentTaskBtf.Value():          BPFFuncGetCurrentTaskBtf,
	BPFFuncBprmOptsSet.Value():                BPFFuncBprmOptsSet,
	BPFFuncKtimeGetCoarseNs.Value():           BPFFuncKtimeGetCoarseNs,
	BPFFuncImaInodeHash.Value():               BPFFuncImaInodeHash,
	BPFFuncSockFromFile.Value():               BPFFuncSockFromFile,
	BPFFuncCheckMtu.Value():                   BPFFuncCheckMtu,
	BPFFuncForEachMapElem.Value():             BPFFuncForEachMapElem,
	BPFFuncSnprintf.Value():                   BPFFuncSnprintf,
	BPFFuncSysBpf.Value():                     BPFFuncSysBpf,
	BPFFuncBtfFindByNameKind.Value():          BPFFuncBtfFindByNameKind,
	BPFFuncSysClose.Value():                   BPFFuncSysClose,
	BPFFuncTimerInit.Value():                  BPFFuncTimerInit,
	BPFFuncTimerSetCallback.Value():           BPFFuncTimerSetCallback,
	BPFFuncTimerStart.Value():                 BPFFuncTimerStart,
	BPFFuncTimerCancel.Value():                BPFFuncTimerCancel,
	BPFFuncGetFuncIp.Value():                  BPFFuncGetFuncIp,
	BPFFuncGetAttachCookie.Value():            BPFFuncGetAttachCookie,
	BPFFuncTaskPtRegs.Value():                 BPFFuncTaskPtRegs,
	BPFFuncGetBranchSnapshot.Value():          BPFFuncGetBranchSnapshot,
	BPFFuncTraceVprintk.Value():               BPFFuncTraceVprintk,
	BPFFuncSkcToUnixSock.Value():              BPFFuncSkcToUnixSock,
	BPFFuncKallsymsLookupName.Value():         BPFFuncKallsymsLookupName,
	BPFFuncFindVma.Value():                    BPFFuncFindVma,
	BPFFuncLoop.Value():                       BPFFuncLoop,
	BPFFuncStrncmp.Value():                    BPFFuncStrncmp,
	BPFFuncGetFuncArg.Value():                 BPFFuncGetFuncArg,
	BPFFuncGetFuncRet.Value():                 BPFFuncGetFuncRet,
	BPFFuncGetFuncArgCnt.Value():              BPFFuncGetFuncArgCnt,
	BPFFuncGetRetval.Value():                  BPFFuncGetRetval,
	BPFFuncSetRetval.Value():                  BPFFuncSetRetval,
	BPFFuncXdpGetBuffLen.Value():              BPFFuncXdpGetBuffLen,
	BPFFuncXdpLoadBytes.Value():               BPFFuncXdpLoadBytes,
	BPFFuncXdpStoreBytes.Value():              BPFFuncXdpStoreBytes,
	BPFFuncCopyFromUserTask.Value():           BPFFuncCopyFromUserTask,
	BPFFuncSkbSetTstamp.Value():               BPFFuncSkbSetTstamp,
	BPFFuncImaFileHash.Value():                BPFFuncImaFileHash,
	BPFFuncKptrXchg.Value():                   BPFFuncKptrXchg,
	BPFFuncMapLookupPercpuElem.Value():        BPFFuncMapLookupPercpuElem,
	BPFFuncSkcToMptcpSock.Value():             BPFFuncSkcToMptcpSock,
	BPFFuncDynptrFromMem.Value():              BPFFuncDynptrFromMem,
	BPFFuncRingbufReserveDynptr.Value():       BPFFuncRingbufReserveDynptr,
	BPFFuncRingbufSubmitDynptr.Value():        BPFFuncRingbufSubmitDynptr,
	BPFFuncRingbufDiscardDynptr.Value():       BPFFuncRingbufDiscardDynptr,
	BPFFuncDynptrRead.Value():                 BPFFuncDynptrRead,
	BPFFuncDynptrWrite.Value():                BPFFuncDynptrWrite,
	BPFFuncDynptrData.Value():                 BPFFuncDynptrData,
	BPFFuncTcpRawGenSyncookieIpv4.Value():     BPFFuncTcpRawGenSyncookieIpv4,
	BPFFuncTcpRawGenSyncookieIpv6.Value():     BPFFuncTcpRawGenSyncookieIpv6,
	BPFFuncTcpRawCheckSyncookieIpv4.Value():   BPFFuncTcpRawCheckSyncookieIpv4,
	BPFFuncTcpRawCheckSyncookieIpv6.Value():   BPFFuncTcpRawCheckSyncookieIpv6,
	BPFFuncKtimeGetTaiNs.Value():              BPFFuncKtimeGetTaiNs,
	BPFFuncUserRingbufDrain.Value():           BPFFuncUserRingbufDrain,
	BPFFuncCgrpStorageGet.Value():             BPFFuncCgrpStorageGet,
	BPFFuncCgrpStorageDelete.Value():          BPFFuncCgrpStorageDelete,
}

func ParseBPFFunc(rawValue uint64) (BPFFunc, error) {
	v, ok := bpfFuncsMap[rawValue]
	if !ok {
		return BPFFunc(0), fmt.Errorf("not a valid argument: %d", rawValue)
	}
	return v, nil
}

type MmapFlagArgument struct {
	rawValue    uint32
	stringValue string
}

const (
	HugetlbFlagEncodeShift = 26
	MapHugeSizeMask        = ((1 << 6) - 1) << HugetlbFlagEncodeShift
)

// revive:disable

var (
	MapShared         MmapFlagArgument = MmapFlagArgument{rawValue: unix.MAP_SHARED, stringValue: "MAP_SHARED"}
	MapPrivate        MmapFlagArgument = MmapFlagArgument{rawValue: unix.MAP_PRIVATE, stringValue: "MAP_PRIVATE"}
	MapSharedValidate MmapFlagArgument = MmapFlagArgument{rawValue: unix.MAP_SHARED_VALIDATE, stringValue: "MAP_SHARED_VALIDATE"}
	MapType           MmapFlagArgument = MmapFlagArgument{rawValue: unix.MAP_TYPE, stringValue: "MAP_TYPE"}
	MapFixed          MmapFlagArgument = MmapFlagArgument{rawValue: unix.MAP_FIXED, stringValue: "MAP_FIXED"}
	MapAnonymous      MmapFlagArgument = MmapFlagArgument{rawValue: unix.MAP_ANONYMOUS, stringValue: "MAP_ANONYMOUS"}
	MapPopulate       MmapFlagArgument = MmapFlagArgument{rawValue: unix.MAP_POPULATE, stringValue: "MAP_POPULATE"}
	MapNonblock       MmapFlagArgument = MmapFlagArgument{rawValue: unix.MAP_NONBLOCK, stringValue: "MAP_NONBLOCK"}
	MapStack          MmapFlagArgument = MmapFlagArgument{rawValue: unix.MAP_STACK, stringValue: "MAP_STACK"}
	MapHugetlb        MmapFlagArgument = MmapFlagArgument{rawValue: unix.MAP_HUGETLB, stringValue: "MAP_HUGETLB"}
	MapSync           MmapFlagArgument = MmapFlagArgument{rawValue: unix.MAP_SYNC, stringValue: "MAP_SYNC"}
	MapFixedNoreplace MmapFlagArgument = MmapFlagArgument{rawValue: unix.MAP_FIXED_NOREPLACE, stringValue: "MAP_FIXED_NOREPLACE"}
	MapGrowsdown      MmapFlagArgument = MmapFlagArgument{rawValue: unix.MAP_GROWSDOWN, stringValue: "MAP_GROWSDOWN"}
	MapDenywrite      MmapFlagArgument = MmapFlagArgument{rawValue: unix.MAP_DENYWRITE, stringValue: "MAP_DENYWRITE"}
	MapExecutable     MmapFlagArgument = MmapFlagArgument{rawValue: unix.MAP_EXECUTABLE, stringValue: "MAP_EXECUTABLE"}
	MapLocked         MmapFlagArgument = MmapFlagArgument{rawValue: unix.MAP_LOCKED, stringValue: "MAP_LOCKED"}
	MapNoreserve      MmapFlagArgument = MmapFlagArgument{rawValue: unix.MAP_NORESERVE, stringValue: "MAP_NORESERVE"}
	MapFile           MmapFlagArgument = MmapFlagArgument{rawValue: unix.MAP_FILE, stringValue: "MAP_FILE"}
	MapHuge2MB        MmapFlagArgument = MmapFlagArgument{rawValue: 21 << HugetlbFlagEncodeShift, stringValue: "MAP_HUGE_2MB"}
	MapHuge1GB        MmapFlagArgument = MmapFlagArgument{rawValue: 30 << HugetlbFlagEncodeShift, stringValue: "MAP_HUGE_1GB"}
	MapSYNC           MmapFlagArgument = MmapFlagArgument{rawValue: unix.MAP_SYNC, stringValue: "MAP_SYNC"}
	// TODO: Add support for MAP_UNINITIALIZED which collide with Huge TLB size bits
)

// revive:enable

var mmapFlagMap = map[uint64]MmapFlagArgument{
	MapShared.Value():         MapShared,
	MapPrivate.Value():        MapPrivate,
	MapSharedValidate.Value(): MapSharedValidate,
	MapType.Value():           MapType,
	MapFixed.Value():          MapFixed,
	MapAnonymous.Value():      MapAnonymous,
	MapPopulate.Value():       MapPopulate,
	MapNonblock.Value():       MapNonblock,
	MapStack.Value():          MapStack,
	MapHugetlb.Value():        MapHugetlb,
	MapSync.Value():           MapSync,
	MapFixedNoreplace.Value(): MapFixedNoreplace,
	MapGrowsdown.Value():      MapGrowsdown,
	MapDenywrite.Value():      MapDenywrite,
	MapExecutable.Value():     MapExecutable,
	MapLocked.Value():         MapLocked,
	MapNoreserve.Value():      MapNoreserve,
	MapFile.Value():           MapFile,
	MapHuge2MB.Value():        MapHuge2MB,
	MapHuge1GB.Value():        MapHuge1GB,
	MapSYNC.Value():           MapSYNC,
}

func (mf MmapFlagArgument) Value() uint64 {
	return uint64(mf.rawValue)
}

func (mf MmapFlagArgument) String() string {
	return mf.stringValue
}

// getHugeMapSizeFlagString extract the huge flag size flag from the mmap flags.
// This flag is special, because it is 6-bits representation of the log2 of the size.
// For more information - https://elixir.bootlin.com/linux/latest/source/include/uapi/asm-generic/hugetlb_encode.h
func getHugeMapSizeFlagString(flags uint32) MmapFlagArgument {
	hugeSizeFlagVal := flags & MapHugeSizeMask
	// The size given in the flags is log2 of the size of the pages
	mapHugeSizePower := hugeSizeFlagVal >> HugetlbFlagEncodeShift

	// Create a name of a flag matching given huge page size
	// The size is 6 bits, so maximum value is 16EB
	unitsPrefix := []string{"", "K", "M", "G", "T", "P", "E"}
	var unitPrefix string
	var inUnitSize uint
	for i, prefix := range unitsPrefix {
		if mapHugeSizePower < ((uint32(i) + 1) * 10) {
			unitPrefix = prefix
			inUnitSize = 1 << (mapHugeSizePower % 10)
			break
		}
	}
	return MmapFlagArgument{rawValue: hugeSizeFlagVal, stringValue: fmt.Sprintf("MAP_HUGE_%d%sB", inUnitSize, unitPrefix)}
}

// ParseMmapFlags parses the `flags` bitmask argument of the `mmap` syscall
// http://man7.org/linux/man-pages/man2/mmap.2.html
// https://elixir.bootlin.com/linux/v5.5.3/source/include/uapi/asm-generic/mman-common.h#L19
func ParseMmapFlags(rawValue uint64) MmapFlagArgument {
	var f []string
	for i := 0; i < HugetlbFlagEncodeShift; i++ {
		flagMask := 1 << i

		if (rawValue & uint64(flagMask)) != 0 {
			flag, ok := mmapFlagMap[1<<i]
			if ok {
				f = append(f, flag.String())
			} else {
				f = append(f, fmt.Sprintf("UNKNOWN_FLAG_0X%s", strings.ToUpper(strconv.FormatUint(flag.Value(), 16))))
			}
		}
	}

	if (rawValue & MapHugeSizeMask) != 0 {
		hugeMapFlag := getHugeMapSizeFlagString(uint32(rawValue))
		f = append(f, hugeMapFlag.String())
	}

	return MmapFlagArgument{stringValue: strings.Join(f, "|"), rawValue: uint32(rawValue)}
}

type IoUringSetupFlag struct {
	rawValue    uint32
	stringValue string
}

const IoUringSetupFlagShiftMax = 15

// revive:disable

// These values are copied from uapi/linux/io_uring.h
var (
	IORING_SETUP_IOPOLL             = IoUringSetupFlag{rawValue: 1 << 0, stringValue: "IORING_SETUP_IOPOLL"}
	IORING_SETUP_SQPOLL             = IoUringSetupFlag{rawValue: 1 << 1, stringValue: "IORING_SETUP_SQPOLL"}
	IORING_SETUP_SQ_AFF             = IoUringSetupFlag{rawValue: 1 << 2, stringValue: "IORING_SETUP_SQ_AFF"}
	IORING_SETUP_CQSIZE             = IoUringSetupFlag{rawValue: 1 << 3, stringValue: "IORING_SETUP_CQSIZE"}
	IORING_SETUP_CLAMP              = IoUringSetupFlag{rawValue: 1 << 4, stringValue: "IORING_SETUP_CLAMP"}
	IORING_SETUP_ATTACH_WQ          = IoUringSetupFlag{rawValue: 1 << 5, stringValue: "IORING_SETUP_ATTACH_WQ"}
	IORING_SETUP_R_DISABLED         = IoUringSetupFlag{rawValue: 1 << 6, stringValue: "IORING_SETUP_R_DISABLED"}
	IORING_SETUP_SUBMIT_ALL         = IoUringSetupFlag{rawValue: 1 << 7, stringValue: "IORING_SETUP_SUBMIT_ALL"}
	IORING_SETUP_COOP_TASKRUN       = IoUringSetupFlag{rawValue: 1 << 8, stringValue: "IORING_SETUP_COOP_TASKRUN"}
	IORING_SETUP_TASKRUN_FLAG       = IoUringSetupFlag{rawValue: 1 << 9, stringValue: "IORING_SETUP_TASKRUN_FLAG"}
	IORING_SETUP_SQE128             = IoUringSetupFlag{rawValue: 1 << 10, stringValue: "IORING_SETUP_SQE128"}
	IORING_SETUP_CQE32              = IoUringSetupFlag{rawValue: 1 << 11, stringValue: "IORING_SETUP_CQE32"}
	IORING_SETUP_SINGLE_ISSUER      = IoUringSetupFlag{rawValue: 1 << 12, stringValue: "IORING_SETUP_SINGLE_ISSUER"}
	IORING_SETUP_DEFER_TASKRUN      = IoUringSetupFlag{rawValue: 1 << 13, stringValue: "IORING_SETUP_DEFER_TASKRUN"}
	IORING_SETUP_NO_MMAP            = IoUringSetupFlag{rawValue: 1 << 14, stringValue: "IORING_SETUP_NO_MMAP"}
	IORING_SETUP_REGISTERED_FD_ONLY = IoUringSetupFlag{rawValue: 1 << 15, stringValue: "IORING_SETUP_REGISTERED_FD_ONLY"}
)

// revive:enable

var ioUringSetupFlagMap = map[uint64]IoUringSetupFlag{
	IORING_SETUP_IOPOLL.Value():             IORING_SETUP_IOPOLL,
	IORING_SETUP_SQPOLL.Value():             IORING_SETUP_SQPOLL,
	IORING_SETUP_SQ_AFF.Value():             IORING_SETUP_SQ_AFF,
	IORING_SETUP_CQSIZE.Value():             IORING_SETUP_CQSIZE,
	IORING_SETUP_CLAMP.Value():              IORING_SETUP_CLAMP,
	IORING_SETUP_ATTACH_WQ.Value():          IORING_SETUP_ATTACH_WQ,
	IORING_SETUP_R_DISABLED.Value():         IORING_SETUP_R_DISABLED,
	IORING_SETUP_SUBMIT_ALL.Value():         IORING_SETUP_SUBMIT_ALL,
	IORING_SETUP_COOP_TASKRUN.Value():       IORING_SETUP_COOP_TASKRUN,
	IORING_SETUP_TASKRUN_FLAG.Value():       IORING_SETUP_TASKRUN_FLAG,
	IORING_SETUP_SQE128.Value():             IORING_SETUP_SQE128,
	IORING_SETUP_CQE32.Value():              IORING_SETUP_CQE32,
	IORING_SETUP_SINGLE_ISSUER.Value():      IORING_SETUP_SINGLE_ISSUER,
	IORING_SETUP_DEFER_TASKRUN.Value():      IORING_SETUP_DEFER_TASKRUN,
	IORING_SETUP_NO_MMAP.Value():            IORING_SETUP_NO_MMAP,
	IORING_SETUP_REGISTERED_FD_ONLY.Value(): IORING_SETUP_REGISTERED_FD_ONLY,
}

func (iusf IoUringSetupFlag) Value() uint64 {
	return uint64(iusf.rawValue)
}

func (iusf IoUringSetupFlag) String() string {
	return iusf.stringValue
}

// ParseIoUringSetupFlags parses the `flags` bitmask argument of the `io_uring_setup` syscall
func ParseIoUringSetupFlags(rawValue uint64) IoUringSetupFlag {
	var f []string
	for i := 0; i <= IoUringSetupFlagShiftMax; i++ {
		var flagMask uint64 = 1 << i

		if (rawValue & flagMask) != 0 {
			flag, ok := ioUringSetupFlagMap[flagMask]
			if ok {
				f = append(f, flag.String())
			} else {
				f = append(f, fmt.Sprintf("UNKNOWN_FLAG_0X%s", strings.ToUpper(strconv.FormatUint(flagMask, 16))))
			}
		}
	}

	return IoUringSetupFlag{stringValue: strings.Join(f, "|"), rawValue: uint32(rawValue)}
}

type IoUringOp struct {
	rawValue    uint32
	stringValue string
}

// revive:disable

// These values are copied from uapi/linux/io_uring.h
var (
	IORING_OP_NOP             = IoUringOp{rawValue: 0, stringValue: "IORING_OP_NOP"}
	IORING_OP_READV           = IoUringOp{rawValue: 1, stringValue: "IORING_OP_READV"}
	IORING_OP_WRITEV          = IoUringOp{rawValue: 2, stringValue: "IORING_OP_WRITEV"}
	IORING_OP_FSYNC           = IoUringOp{rawValue: 3, stringValue: "IORING_OP_FSYNC"}
	IORING_OP_READ_FIXED      = IoUringOp{rawValue: 4, stringValue: "IORING_OP_READ_FIXED"}
	IORING_OP_WRITE_FIXED     = IoUringOp{rawValue: 5, stringValue: "IORING_OP_WRITE_FIXED"}
	IORING_OP_POLL_ADD        = IoUringOp{rawValue: 6, stringValue: "IORING_OP_POLL_ADD"}
	IORING_OP_POLL_REMOVE     = IoUringOp{rawValue: 7, stringValue: "IORING_OP_POLL_REMOVE"}
	IORING_OP_SYNC_FILE_RANGE = IoUringOp{rawValue: 8, stringValue: "IORING_OP_SYNC_FILE_RANGE"}
	IORING_OP_SENDMSG         = IoUringOp{rawValue: 9, stringValue: "IORING_OP_SENDMSG"}
	IORING_OP_RECVMSG         = IoUringOp{rawValue: 10, stringValue: "IORING_OP_RECVMSG"}
	IORING_OP_TIMEOUT         = IoUringOp{rawValue: 11, stringValue: "IORING_OP_TIMEOUT"}
	IORING_OP_TIMEOUT_REMOVE  = IoUringOp{rawValue: 12, stringValue: "IORING_OP_TIMEOUT_REMOVE"}
	IORING_OP_ACCEPT          = IoUringOp{rawValue: 13, stringValue: "IORING_OP_ACCEPT"}
	IORING_OP_ASYNC_CANCEL    = IoUringOp{rawValue: 14, stringValue: "IORING_OP_ASYNC_CANCEL"}
	IORING_OP_LINK_TIMEOUT    = IoUringOp{rawValue: 15, stringValue: "IORING_OP_LINK_TIMEOUT"}
	IORING_OP_CONNECT         = IoUringOp{rawValue: 16, stringValue: "IORING_OP_CONNECT"}
	IORING_OP_FALLOCATE       = IoUringOp{rawValue: 17, stringValue: "IORING_OP_FALLOCATE"}
	IORING_OP_OPENAT          = IoUringOp{rawValue: 18, stringValue: "IORING_OP_OPENAT"}
	IORING_OP_CLOSE           = IoUringOp{rawValue: 19, stringValue: "IORING_OP_CLOSE"}
	IORING_OP_FILES_UPDATE    = IoUringOp{rawValue: 20, stringValue: "IORING_OP_FILES_UPDATE"}
	IORING_OP_STATX           = IoUringOp{rawValue: 21, stringValue: "IORING_OP_STATX"}
	IORING_OP_READ            = IoUringOp{rawValue: 22, stringValue: "IORING_OP_READ"}
	IORING_OP_WRITE           = IoUringOp{rawValue: 23, stringValue: "IORING_OP_WRITE"}
	IORING_OP_FADVISE         = IoUringOp{rawValue: 24, stringValue: "IORING_OP_FADVISE"}
	IORING_OP_MADVISE         = IoUringOp{rawValue: 25, stringValue: "IORING_OP_MADVISE"}
	IORING_OP_SEND            = IoUringOp{rawValue: 26, stringValue: "IORING_OP_SEND"}
	IORING_OP_RECV            = IoUringOp{rawValue: 27, stringValue: "IORING_OP_RECV"}
	IORING_OP_OPENAT2         = IoUringOp{rawValue: 28, stringValue: "IORING_OP_OPENAT2"}
	IORING_OP_EPOLL_CTL       = IoUringOp{rawValue: 29, stringValue: "IORING_OP_EPOLL_CTL"}
	IORING_OP_SPLICE          = IoUringOp{rawValue: 30, stringValue: "IORING_OP_SPLICE"}
	IORING_OP_PROVIDE_BUFFERS = IoUringOp{rawValue: 31, stringValue: "IORING_OP_PROVIDE_BUFFERS"}
	IORING_OP_REMOVE_BUFFERS  = IoUringOp{rawValue: 32, stringValue: "IORING_OP_REMOVE_BUFFERS"}
	IORING_OP_TEE             = IoUringOp{rawValue: 33, stringValue: "IORING_OP_TEE"}
	IORING_OP_SHUTDOWN        = IoUringOp{rawValue: 34, stringValue: "IORING_OP_SHUTDOWN"}
	IORING_OP_RENAMEAT        = IoUringOp{rawValue: 35, stringValue: "IORING_OP_RENAMEAT"}
	IORING_OP_UNLINKAT        = IoUringOp{rawValue: 36, stringValue: "IORING_OP_UNLINKAT"}
	IORING_OP_MKDIRAT         = IoUringOp{rawValue: 37, stringValue: "IORING_OP_MKDIRAT"}
	IORING_OP_SYMLINKAT       = IoUringOp{rawValue: 38, stringValue: "IORING_OP_SYMLINKAT"}
	IORING_OP_LINKAT          = IoUringOp{rawValue: 39, stringValue: "IORING_OP_LINKAT"}
	IORING_OP_MSG_RING        = IoUringOp{rawValue: 40, stringValue: "IORING_OP_MSG_RING"}
	IORING_OP_FSETXATTR       = IoUringOp{rawValue: 41, stringValue: "IORING_OP_FSETXATTR"}
	IORING_OP_SETXATTR        = IoUringOp{rawValue: 42, stringValue: "IORING_OP_SETXATTR"}
	IORING_OP_FGETXATTR       = IoUringOp{rawValue: 43, stringValue: "IORING_OP_FGETXATTR"}
	IORING_OP_GETXATTR        = IoUringOp{rawValue: 44, stringValue: "IORING_OP_GETXATTR"}
	IORING_OP_SOCKET          = IoUringOp{rawValue: 45, stringValue: "IORING_OP_SOCKET"}
	IORING_OP_URING_CMD       = IoUringOp{rawValue: 46, stringValue: "IORING_OP_URING_CMD"}
	IORING_OP_SEND_ZC         = IoUringOp{rawValue: 47, stringValue: "IORING_OP_SEND_ZC"}
	IORING_OP_SENDMSG_ZC      = IoUringOp{rawValue: 48, stringValue: "IORING_OP_SENDMSG_ZC"}
	IORING_OP_LAST            = IoUringOp{rawValue: 49, stringValue: "IORING_OP_LAST"}
)

// revive:enable

var ioUringOpMap = map[uint64]IoUringOp{
	IORING_OP_NOP.Value():             IORING_OP_NOP,
	IORING_OP_READV.Value():           IORING_OP_READV,
	IORING_OP_WRITEV.Value():          IORING_OP_WRITEV,
	IORING_OP_FSYNC.Value():           IORING_OP_FSYNC,
	IORING_OP_READ_FIXED.Value():      IORING_OP_READ_FIXED,
	IORING_OP_WRITE_FIXED.Value():     IORING_OP_WRITE_FIXED,
	IORING_OP_POLL_ADD.Value():        IORING_OP_POLL_ADD,
	IORING_OP_POLL_REMOVE.Value():     IORING_OP_POLL_REMOVE,
	IORING_OP_SYNC_FILE_RANGE.Value(): IORING_OP_SYNC_FILE_RANGE,
	IORING_OP_SENDMSG.Value():         IORING_OP_SENDMSG,
	IORING_OP_RECVMSG.Value():         IORING_OP_RECVMSG,
	IORING_OP_TIMEOUT.Value():         IORING_OP_TIMEOUT,
	IORING_OP_TIMEOUT_REMOVE.Value():  IORING_OP_TIMEOUT_REMOVE,
	IORING_OP_ACCEPT.Value():          IORING_OP_ACCEPT,
	IORING_OP_ASYNC_CANCEL.Value():    IORING_OP_ASYNC_CANCEL,
	IORING_OP_LINK_TIMEOUT.Value():    IORING_OP_LINK_TIMEOUT,
	IORING_OP_CONNECT.Value():         IORING_OP_CONNECT,
	IORING_OP_FALLOCATE.Value():       IORING_OP_FALLOCATE,
	IORING_OP_OPENAT.Value():          IORING_OP_OPENAT,
	IORING_OP_CLOSE.Value():           IORING_OP_CLOSE,
	IORING_OP_FILES_UPDATE.Value():    IORING_OP_FILES_UPDATE,
	IORING_OP_STATX.Value():           IORING_OP_STATX,
	IORING_OP_READ.Value():            IORING_OP_READ,
	IORING_OP_WRITE.Value():           IORING_OP_WRITE,
	IORING_OP_FADVISE.Value():         IORING_OP_FADVISE,
	IORING_OP_MADVISE.Value():         IORING_OP_MADVISE,
	IORING_OP_SEND.Value():            IORING_OP_SEND,
	IORING_OP_RECV.Value():            IORING_OP_RECV,
	IORING_OP_OPENAT2.Value():         IORING_OP_OPENAT2,
	IORING_OP_EPOLL_CTL.Value():       IORING_OP_EPOLL_CTL,
	IORING_OP_SPLICE.Value():          IORING_OP_SPLICE,
	IORING_OP_PROVIDE_BUFFERS.Value(): IORING_OP_PROVIDE_BUFFERS,
	IORING_OP_REMOVE_BUFFERS.Value():  IORING_OP_REMOVE_BUFFERS,
	IORING_OP_TEE.Value():             IORING_OP_TEE,
	IORING_OP_SHUTDOWN.Value():        IORING_OP_SHUTDOWN,
	IORING_OP_RENAMEAT.Value():        IORING_OP_RENAMEAT,
	IORING_OP_UNLINKAT.Value():        IORING_OP_UNLINKAT,
	IORING_OP_MKDIRAT.Value():         IORING_OP_MKDIRAT,
	IORING_OP_SYMLINKAT.Value():       IORING_OP_SYMLINKAT,
	IORING_OP_LINKAT.Value():          IORING_OP_LINKAT,
	IORING_OP_MSG_RING.Value():        IORING_OP_MSG_RING,
	IORING_OP_FSETXATTR.Value():       IORING_OP_FSETXATTR,
	IORING_OP_SETXATTR.Value():        IORING_OP_SETXATTR,
	IORING_OP_FGETXATTR.Value():       IORING_OP_FGETXATTR,
	IORING_OP_GETXATTR.Value():        IORING_OP_GETXATTR,
	IORING_OP_SOCKET.Value():          IORING_OP_SOCKET,
	IORING_OP_URING_CMD.Value():       IORING_OP_URING_CMD,
	IORING_OP_SEND_ZC.Value():         IORING_OP_SEND_ZC,
	IORING_OP_SENDMSG_ZC.Value():      IORING_OP_SENDMSG_ZC,
	IORING_OP_LAST.Value():            IORING_OP_LAST,
}

func (iuo IoUringOp) Value() uint64 {
	return uint64(iuo.rawValue)
}

func (iuo IoUringOp) String() string {
	return iuo.stringValue
}

// ParseIoUringOp parses the opcode of io_uring operation
func ParseIoUringOp(rawValue uint64) (IoUringOp, error) {
	v, ok := ioUringOpMap[rawValue]
	if !ok {
		return IoUringOp{}, fmt.Errorf("not a valid argument: %d", rawValue)
	}
	return v, nil
}

// =====================================================

type IoUringRequestFlag struct {
	rawValue    uint32
	stringValue string
}

const IoUringRequestFlagShiftMax = 14

// revive:disable

// These values are copied from include/linux/io_uring_types.h
var (
	REQ_F_FIXED_FILE      = IoUringRequestFlag{rawValue: 1 << 0, stringValue: "REQ_F_FIXED_FILE"}
	REQ_F_IO_DRAIN        = IoUringRequestFlag{rawValue: 1 << 1, stringValue: "REQ_F_IO_DRAIN"}
	REQ_F_LINK            = IoUringRequestFlag{rawValue: 1 << 2, stringValue: "REQ_F_LINK"}
	REQ_F_HARDLINK        = IoUringRequestFlag{rawValue: 1 << 3, stringValue: "REQ_F_HARDLINK"}
	REQ_F_FORCE_ASYNC     = IoUringRequestFlag{rawValue: 1 << 4, stringValue: "REQ_F_FORCE_ASYNC"}
	REQ_F_BUFFER_SELECT   = IoUringRequestFlag{rawValue: 1 << 5, stringValue: "REQ_F_BUFFER_SELECT"}
	REQ_F_CQE_SKIP        = IoUringRequestFlag{rawValue: 1 << 6, stringValue: "REQ_F_CQE_SKIP"}
	REQ_F_FAIL            = IoUringRequestFlag{rawValue: 1 << 7, stringValue: "REQ_F_FAIL"}
	REQ_F_INFLIGHT        = IoUringRequestFlag{rawValue: 1 << 8, stringValue: "REQ_F_INFLIGHT"}
	REQ_F_CUR_POS         = IoUringRequestFlag{rawValue: 1 << 9, stringValue: "REQ_F_CUR_POS"}
	REQ_F_NOWAIT          = IoUringRequestFlag{rawValue: 1 << 10, stringValue: "REQ_F_NOWAIT"}
	REQ_F_LINK_TIMEOUT    = IoUringRequestFlag{rawValue: 1 << 11, stringValue: "REQ_F_LINK_TIMEOUT"}
	REQ_F_NEED_CLEANUP    = IoUringRequestFlag{rawValue: 1 << 12, stringValue: "REQ_F_NEED_CLEANUP"}
	REQ_F_POLLED          = IoUringRequestFlag{rawValue: 1 << 13, stringValue: "REQ_F_POLLED"}
	REQ_F_BUFFER_SELECTED = IoUringRequestFlag{rawValue: 1 << 14, stringValue: "REQ_F_BUFFER_SELECTED"}
	REQ_F_BUFFER_RING     = IoUringRequestFlag{rawValue: 1 << 15, stringValue: "REQ_F_BUFFER_RING"}
	REQ_F_REISSUE         = IoUringRequestFlag{rawValue: 1 << 0, stringValue: "REQ_F_REISSUE"}
	REQ_F_SUPPORT_NOWAIT  = IoUringRequestFlag{rawValue: 1 << 1, stringValue: "REQ_F_SUPPORT_NOWAIT"}
	REQ_F_ISREG           = IoUringRequestFlag{rawValue: 1 << 2, stringValue: "REQ_F_ISREG"}
	REQ_F_CREDS           = IoUringRequestFlag{rawValue: 1 << 3, stringValue: "REQ_F_CREDS"}
	REQ_F_REFCOUNT        = IoUringRequestFlag{rawValue: 1 << 4, stringValue: "REQ_F_REFCOUNT"}
	REQ_F_ARM_LTIMEOUT    = IoUringRequestFlag{rawValue: 1 << 5, stringValue: "REQ_F_ARM_LTIMEOUT"}
	REQ_F_ASYNC_DATA      = IoUringRequestFlag{rawValue: 1 << 6, stringValue: "REQ_F_ASYNC_DATA"}
	REQ_F_SKIP_LINK_CQES  = IoUringRequestFlag{rawValue: 1 << 7, stringValue: "REQ_F_SKIP_LINK_CQES"}
	REQ_F_SINGLE_POLL     = IoUringRequestFlag{rawValue: 1 << 8, stringValue: "REQ_F_SINGLE_POLL"}
	REQ_F_DOUBLE_POLL     = IoUringRequestFlag{rawValue: 1 << 9, stringValue: "REQ_F_DOUBLE_POLL"}
	REQ_F_PARTIAL_IO      = IoUringRequestFlag{rawValue: 1 << 10, stringValue: "REQ_F_PARTIAL_IO"}
	REQ_F_APOLL_MULTISHOT = IoUringRequestFlag{rawValue: 1 << 11, stringValue: "REQ_F_APOLL_MULTISHOT"}
	REQ_F_CQE32_INIT      = IoUringRequestFlag{rawValue: 1 << 12, stringValue: "REQ_F_CQE32_INIT"}
	REQ_F_CLEAR_POLLIN    = IoUringRequestFlag{rawValue: 1 << 13, stringValue: "REQ_F_CLEAR_POLLIN"}
	REQ_F_HASH_LOCKED     = IoUringRequestFlag{rawValue: 1 << 14, stringValue: "REQ_F_HASH_LOCKED"}
)

// revive:enable

var ioUringRequestFlagMap = map[uint64]IoUringRequestFlag{
	REQ_F_FIXED_FILE.Value():      REQ_F_FIXED_FILE,
	REQ_F_IO_DRAIN.Value():        REQ_F_IO_DRAIN,
	REQ_F_LINK.Value():            REQ_F_LINK,
	REQ_F_HARDLINK.Value():        REQ_F_HARDLINK,
	REQ_F_FORCE_ASYNC.Value():     REQ_F_FORCE_ASYNC,
	REQ_F_BUFFER_SELECT.Value():   REQ_F_BUFFER_SELECT,
	REQ_F_CQE_SKIP.Value():        REQ_F_CQE_SKIP,
	REQ_F_FAIL.Value():            REQ_F_FAIL,
	REQ_F_INFLIGHT.Value():        REQ_F_INFLIGHT,
	REQ_F_CUR_POS.Value():         REQ_F_CUR_POS,
	REQ_F_NOWAIT.Value():          REQ_F_NOWAIT,
	REQ_F_LINK_TIMEOUT.Value():    REQ_F_LINK_TIMEOUT,
	REQ_F_NEED_CLEANUP.Value():    REQ_F_NEED_CLEANUP,
	REQ_F_POLLED.Value():          REQ_F_POLLED,
	REQ_F_BUFFER_SELECTED.Value(): REQ_F_BUFFER_SELECTED,
	REQ_F_BUFFER_RING.Value():     REQ_F_BUFFER_RING,
	REQ_F_REISSUE.Value():         REQ_F_REISSUE,
	REQ_F_SUPPORT_NOWAIT.Value():  REQ_F_SUPPORT_NOWAIT,
	REQ_F_ISREG.Value():           REQ_F_ISREG,
	REQ_F_CREDS.Value():           REQ_F_CREDS,
	REQ_F_REFCOUNT.Value():        REQ_F_REFCOUNT,
	REQ_F_ARM_LTIMEOUT.Value():    REQ_F_ARM_LTIMEOUT,
	REQ_F_ASYNC_DATA.Value():      REQ_F_ASYNC_DATA,
	REQ_F_SKIP_LINK_CQES.Value():  REQ_F_SKIP_LINK_CQES,
	REQ_F_SINGLE_POLL.Value():     REQ_F_SINGLE_POLL,
	REQ_F_DOUBLE_POLL.Value():     REQ_F_DOUBLE_POLL,
	REQ_F_PARTIAL_IO.Value():      REQ_F_PARTIAL_IO,
	REQ_F_APOLL_MULTISHOT.Value(): REQ_F_APOLL_MULTISHOT,
	REQ_F_CQE32_INIT.Value():      REQ_F_CQE32_INIT,
	REQ_F_CLEAR_POLLIN.Value():    REQ_F_CLEAR_POLLIN,
	REQ_F_HASH_LOCKED.Value():     REQ_F_HASH_LOCKED,
}

func (iurf IoUringRequestFlag) Value() uint64 {
	return uint64(iurf.rawValue)
}

func (iurf IoUringRequestFlag) String() string {
	return iurf.stringValue
}

// ParseIoUringRequestFlags parses the flags bitmask if io_uring request
func ParseIoUringRequestFlags(rawValue uint64) IoUringRequestFlag {
	var f []string
	for i := 0; i <= IoUringRequestFlagShiftMax; i++ {
		var flagMask uint64 = 1 << i

		if (rawValue & flagMask) != 0 {
			flag, ok := ioUringRequestFlagMap[flagMask]
			if ok {
				f = append(f, flag.String())
			} else {
				f = append(f, fmt.Sprintf("UNKNOWN_FLAG_0X%s", strings.ToUpper(strconv.FormatUint(flagMask, 16))))
			}
		}
	}

	return IoUringRequestFlag{stringValue: strings.Join(f, "|"), rawValue: uint32(rawValue)}
}

// =====================================================

// GUPFlag represents GUP (Get User Pages) flags since version 6.3
type GUPFlag struct {
	rawValue    uint32
	stringValue string
}

const GupFlagShiftMax = 21

// revive:disable

// These values are copied from include/linux/mm_types.h and include/lunux/internal.h
var (
	FOLL_WRITE            = GUPFlag{rawValue: 1 << 0, stringValue: "FOLL_WRITE"}
	FOLL_GET              = GUPFlag{rawValue: 1 << 1, stringValue: "FOLL_GET"}
	FOLL_DUMP             = GUPFlag{rawValue: 1 << 2, stringValue: "FOLL_DUMP"}
	FOLL_FORCE            = GUPFlag{rawValue: 1 << 3, stringValue: "FOLL_FORCE"}
	FOLL_NOWAIT           = GUPFlag{rawValue: 1 << 4, stringValue: "FOLL_NOWAIT"}
	FOLL_NOFAULT          = GUPFlag{rawValue: 1 << 5, stringValue: "FOLL_NOFAULT"}
	FOLL_HWPOISON         = GUPFlag{rawValue: 1 << 6, stringValue: "FOLL_HWPOISON"}
	FOLL_ANON             = GUPFlag{rawValue: 1 << 7, stringValue: "FOLL_ANON"}
	FOLL_LONGTERM         = GUPFlag{rawValue: 1 << 8, stringValue: "FOLL_LONGTERM"}
	FOLL_SPLIT_PMD        = GUPFlag{rawValue: 1 << 9, stringValue: "FOLL_SPLIT_PMD"}
	FOLL_PCI_P2PDMA       = GUPFlag{rawValue: 1 << 10, stringValue: "FOLL_PCI_P2PDMA"}
	FOLL_INTERRUPTIBLE    = GUPFlag{rawValue: 1 << 11, stringValue: "FOLL_INTERRUPTIBLE"}
	FOLL_HONOR_NUMA_FAULT = GUPFlag{rawValue: 1 << 12, stringValue: "FOLL_HONOR_NUMA_FAULT"}
	FOLL_TOUCH            = GUPFlag{rawValue: 1 << 16, stringValue: "FOLL_TOUCH"}
	FOLL_TRIED            = GUPFlag{rawValue: 1 << 17, stringValue: "FOLL_TRIED"}
	FOLL_REMOTE           = GUPFlag{rawValue: 1 << 18, stringValue: "FOLL_REMOTE"}
	FOLL_PIN              = GUPFlag{rawValue: 1 << 19, stringValue: "FOLL_PIN"}
	FOLL_FAST_ONLY        = GUPFlag{rawValue: 1 << 20, stringValue: "FOLL_FAST_ONLY"}
	FOLL_UNLOCKABLE       = GUPFlag{rawValue: 1 << 21, stringValue: "FOLL_UNLOCKABLE"}
)

// revive:enable

var GUPFlagMap = map[uint64]GUPFlag{
	FOLL_WRITE.Value():            FOLL_WRITE,
	FOLL_GET.Value():              FOLL_GET,
	FOLL_DUMP.Value():             FOLL_DUMP,
	FOLL_FORCE.Value():            FOLL_FORCE,
	FOLL_NOWAIT.Value():           FOLL_NOWAIT,
	FOLL_NOFAULT.Value():          FOLL_NOFAULT,
	FOLL_HWPOISON.Value():         FOLL_HWPOISON,
	FOLL_ANON.Value():             FOLL_ANON,
	FOLL_LONGTERM.Value():         FOLL_LONGTERM,
	FOLL_SPLIT_PMD.Value():        FOLL_SPLIT_PMD,
	FOLL_PCI_P2PDMA.Value():       FOLL_PCI_P2PDMA,
	FOLL_INTERRUPTIBLE.Value():    FOLL_INTERRUPTIBLE,
	FOLL_HONOR_NUMA_FAULT.Value(): FOLL_HONOR_NUMA_FAULT,
	FOLL_TOUCH.Value():            FOLL_TOUCH,
	FOLL_TRIED.Value():            FOLL_TRIED,
	FOLL_REMOTE.Value():           FOLL_REMOTE,
	FOLL_PIN.Value():              FOLL_PIN,
	FOLL_FAST_ONLY.Value():        FOLL_FAST_ONLY,
	FOLL_UNLOCKABLE.Value():       FOLL_UNLOCKABLE,
}

func (gupf GUPFlag) Value() uint64 {
	return uint64(gupf.rawValue)
}

func (gupf GUPFlag) String() string {
	return gupf.stringValue
}

// ParseGUPFlags parses the flags bitmask of gup (get user pages) operation for kernels since
// version 6.3
func ParseGUPFlags(rawValue uint64) GUPFlag {
	var f []string
	for i := 0; i <= GupFlagShiftMax; i++ {
		var flagMask uint64 = 1 << i

		if (rawValue & flagMask) != 0 {
			flag, ok := GUPFlagMap[flagMask]
			if ok {
				f = append(f, flag.String())
			} else {
				f = append(
					f,
					fmt.Sprintf(
						"UNKNOWN_FLAG_0X%s",
						strings.ToUpper(strconv.FormatUint(flagMask, 16)),
					),
				)
			}
		}
	}

	return GUPFlag{stringValue: strings.Join(f, "|"), rawValue: uint32(rawValue)}
}

// =====================================================

// LegacyGUPFlag represents GUP (Get User Pages) flags up to version 6.3
type LegacyGUPFlag struct {
	rawValue    uint32
	stringValue string
}

const LegacyGupFlagShiftMax = 22

// revive:disable

// These values are copied from include/linux/mm.h
var (
	LEGACY_FOLL_WRITE     = LegacyGUPFlag{rawValue: 1 << 0, stringValue: "FOLL_WRITE"}
	LEGACY_FOLL_TOUCH     = LegacyGUPFlag{rawValue: 1 << 1, stringValue: "FOLL_TOUCH"}
	LEGACY_FOLL_GET       = LegacyGUPFlag{rawValue: 1 << 2, stringValue: "FOLL_GET"}
	LEGACY_FOLL_DUMP      = LegacyGUPFlag{rawValue: 1 << 3, stringValue: "FOLL_DUMP"}
	LEGACY_FOLL_FORCE     = LegacyGUPFlag{rawValue: 1 << 4, stringValue: "FOLL_FORCE"}
	LEGACY_FOLL_NOWAIT    = LegacyGUPFlag{rawValue: 1 << 5, stringValue: "FOLL_NOWAIT"}
	LEGACY_FOLL_POPULATE  = LegacyGUPFlag{rawValue: 1 << 6, stringValue: "FOLL_POPULATE"}
	LEGACY_FOLL_SPLIT     = LegacyGUPFlag{rawValue: 1 << 7, stringValue: "FOLL_SPLIT"}
	LEGACY_FOLL_HWPOISON  = LegacyGUPFlag{rawValue: 1 << 8, stringValue: "FOLL_HWPOISON"}
	LEGACY_FOLL_NUMA      = LegacyGUPFlag{rawValue: 1 << 9, stringValue: "FOLL_NUMA"}
	LEGACY_FOLL_MIGRATION = LegacyGUPFlag{rawValue: 1 << 10, stringValue: "FOLL_MIGRATION"}
	LEGACY_FOLL_TRIED     = LegacyGUPFlag{rawValue: 1 << 11, stringValue: "FOLL_TRIED"}
	LEGACY_FOLL_MLOCK     = LegacyGUPFlag{rawValue: 1 << 12, stringValue: "FOLL_MLOCK"}
	LEGACY_FOLL_REMOTE    = LegacyGUPFlag{rawValue: 1 << 16, stringValue: "FOLL_REMOTE"}
	LEGACY_FOLL_COW       = LegacyGUPFlag{rawValue: 1 << 17, stringValue: "FOLL_COW"}
	LEGACY_FOLL_ANON      = LegacyGUPFlag{rawValue: 1 << 18, stringValue: "FOLL_ANON"}
	LEGACY_FOLL_LONGTERM  = LegacyGUPFlag{rawValue: 1 << 19, stringValue: "FOLL_LONGTERM"}
	LEGACY_FOLL_SPLIT_PMD = LegacyGUPFlag{rawValue: 1 << 20, stringValue: "FOLL_SPLIT_PMD"}
	LEGACY_FOLL_PIN       = LegacyGUPFlag{rawValue: 1 << 21, stringValue: "FOLL_PIN"}
	LEGACY_FOLL_FAST_ONLY = LegacyGUPFlag{rawValue: 1 << 22, stringValue: "FOLL_FAST_ONLY"}
)

// revive:enable

var LegacyGUPFlagMap = map[uint64]LegacyGUPFlag{
	LEGACY_FOLL_WRITE.Value():     LEGACY_FOLL_WRITE,
	LEGACY_FOLL_TOUCH.Value():     LEGACY_FOLL_TOUCH,
	LEGACY_FOLL_GET.Value():       LEGACY_FOLL_GET,
	LEGACY_FOLL_DUMP.Value():      LEGACY_FOLL_DUMP,
	LEGACY_FOLL_FORCE.Value():     LEGACY_FOLL_FORCE,
	LEGACY_FOLL_NOWAIT.Value():    LEGACY_FOLL_NOWAIT,
	LEGACY_FOLL_POPULATE.Value():  LEGACY_FOLL_POPULATE,
	LEGACY_FOLL_SPLIT.Value():     LEGACY_FOLL_SPLIT,
	LEGACY_FOLL_HWPOISON.Value():  LEGACY_FOLL_HWPOISON,
	LEGACY_FOLL_NUMA.Value():      LEGACY_FOLL_NUMA,
	LEGACY_FOLL_MIGRATION.Value(): LEGACY_FOLL_MIGRATION,
	LEGACY_FOLL_TRIED.Value():     LEGACY_FOLL_TRIED,
	LEGACY_FOLL_MLOCK.Value():     LEGACY_FOLL_MLOCK,
	LEGACY_FOLL_REMOTE.Value():    LEGACY_FOLL_REMOTE,
	LEGACY_FOLL_COW.Value():       LEGACY_FOLL_COW,
	LEGACY_FOLL_ANON.Value():      LEGACY_FOLL_ANON,
	LEGACY_FOLL_LONGTERM.Value():  LEGACY_FOLL_LONGTERM,
	LEGACY_FOLL_SPLIT_PMD.Value(): LEGACY_FOLL_SPLIT_PMD,
	LEGACY_FOLL_PIN.Value():       LEGACY_FOLL_PIN,
	LEGACY_FOLL_FAST_ONLY.Value(): LEGACY_FOLL_FAST_ONLY,
}

func (lgupf LegacyGUPFlag) Value() uint64 {
	return uint64(lgupf.rawValue)
}

func (lgupf LegacyGUPFlag) String() string {
	return lgupf.stringValue
}

// ParseLegacyGUPFlags parses the flags bitmask of gup (get user pages) operation for kernels up to
// version 6.3
func ParseLegacyGUPFlags(rawValue uint64) LegacyGUPFlag {
	var f []string
	for i := 0; i <= LegacyGupFlagShiftMax; i++ {
		var flagMask uint64 = 1 << i

		if (rawValue & flagMask) != 0 {
			flag, ok := LegacyGUPFlagMap[flagMask]
			if ok {
				f = append(f, flag.String())
			} else {
				f = append(
					f,
					fmt.Sprintf(
						"UNKNOWN_FLAG_0X%s",
						strings.ToUpper(strconv.FormatUint(flagMask, 16)),
					),
				)
			}
		}
	}

	return LegacyGUPFlag{stringValue: strings.Join(f, "|"), rawValue: uint32(rawValue)}
}

var currentOSGUPFlagsParse uint32
var skipDetermineGUPFlagsFunc uint32

const gupFlagsChangeVersion = "6.3.0"

// ParseGUPFlagsCurrentOS parse the GUP flags received according to current machine OS version.
// It uses optimizations to perform better than ParseGUPFlagsForOS
func ParseGUPFlagsCurrentOS(rawValue uint64) (SystemFunctionArgument, error) {
	const (
		newVersionsParsing = iota
		legacyParsing
	)
	if atomic.LoadUint32(&skipDetermineGUPFlagsFunc) == 0 {
		osInfo, err := environment.GetOSInfo()
		if err != nil {
			return nil, fmt.Errorf("error getting current OS info - %s", err)
		}
		compare, err := osInfo.CompareOSBaseKernelRelease(gupFlagsChangeVersion)
		if err != nil {
			return nil, fmt.Errorf(
				"error comparing OS versions to determine how to parse GUP flags - %s",
				err,
			)
		}
		if compare == environment.KernelVersionOlder {
			atomic.StoreUint32(&currentOSGUPFlagsParse, legacyParsing)
		} else {
			atomic.StoreUint32(&currentOSGUPFlagsParse, newVersionsParsing)
		}
		// Avoid doing this check in the future
		atomic.StoreUint32(&skipDetermineGUPFlagsFunc, 1)
	}

	// Don't really need to use atomics here, as the value is only used here
	// and is set in an atomic way
	switch currentOSGUPFlagsParse {
	case legacyParsing:
		return ParseLegacyGUPFlags(rawValue), nil
	case newVersionsParsing:
		return ParseGUPFlags(rawValue), nil
	default:
		return nil, fmt.Errorf("no parsing function for GUP flags was found to this OD version")
	}
}

// ParseGUPFlagsForOS parse the GUP flags received according to given OS version.
func ParseGUPFlagsForOS(osInfo *environment.OSInfo, rawValue uint64) (SystemFunctionArgument, error) {
	compare, err := osInfo.CompareOSBaseKernelRelease(gupFlagsChangeVersion)
	if err != nil {
		return nil, fmt.Errorf(
			"error comparing OS versions to determine how to parse GUP flags - %s",
			err,
		)
	}

	if compare == environment.KernelVersionOlder {
		return ParseLegacyGUPFlags(rawValue), nil
	}
	return ParseGUPFlags(rawValue), nil
}

// =====================================================

// VmFlag represents the flags in the `vm_area_struct` in x86 64bit architecture
type VmFlag struct {
	rawValue    uint64
	stringValue string
}

const VmFlagShiftMax = 37

// revive:disable

// These values are copied from include/linux/mm.h
var (
	VM_READ         = VmFlag{rawValue: 1 << 0, stringValue: "VM_READ"}
	VM_WRITE        = VmFlag{rawValue: 1 << 1, stringValue: "VM_WRITE"}
	VM_EXEC         = VmFlag{rawValue: 1 << 2, stringValue: "VM_EXEC"}
	VM_SHARED       = VmFlag{rawValue: 1 << 3, stringValue: "VM_SHARED"}
	VM_MAYREAD      = VmFlag{rawValue: 1 << 4, stringValue: "VM_MAYREAD"}
	VM_MAYWRITE     = VmFlag{rawValue: 1 << 5, stringValue: "VM_MAYWRITE"}
	VM_MAYEXEC      = VmFlag{rawValue: 1 << 6, stringValue: "VM_MAYEXEC"}
	VM_MAYSHARE     = VmFlag{rawValue: 1 << 7, stringValue: "VM_MAYSHARE"}
	VM_GROWSDOWN    = VmFlag{rawValue: 1 << 8, stringValue: "VM_GROWSDOWN"}
	VM_UFFD_MISSING = VmFlag{rawValue: 1 << 9, stringValue: "VM_UFFD_MISSING"}
	VM_PFNMAP       = VmFlag{rawValue: 1 << 10, stringValue: "VM_PFNMAP"}
	VM_UFFD_WP      = VmFlag{rawValue: 1 << 12, stringValue: "VM_UFFD_WP"}
	VM_LOCKED       = VmFlag{rawValue: 1 << 13, stringValue: "VM_LOCKED"}
	VM_IO           = VmFlag{rawValue: 1 << 14, stringValue: "VM_IO"}
	VM_SEQ_READ     = VmFlag{rawValue: 1 << 15, stringValue: "VM_SEQ_READ"}
	VM_RAND_READ    = VmFlag{rawValue: 1 << 16, stringValue: "VM_RAND_READ"}
	VM_DONTCOPY     = VmFlag{rawValue: 1 << 17, stringValue: "VM_DONTCOPY"}
	VM_DONTEXPAND   = VmFlag{rawValue: 1 << 18, stringValue: "VM_DONTEXPAND"}
	VM_LOCKONFAULT  = VmFlag{rawValue: 1 << 19, stringValue: "VM_LOCKONFAULT"}
	VM_ACCOUNT      = VmFlag{rawValue: 1 << 20, stringValue: "VM_ACCOUNT"}
	VM_NORESERVE    = VmFlag{rawValue: 1 << 21, stringValue: "VM_NORESERVE"}
	VM_HUGETLB      = VmFlag{rawValue: 1 << 22, stringValue: "VM_HUGETLB"}
	VM_SYNC         = VmFlag{rawValue: 1 << 23, stringValue: "VM_SYNC"}
	VM_PAT          = VmFlag{rawValue: 1 << 24, stringValue: "VM_PAT"}
	VM_WIPEONFORK   = VmFlag{rawValue: 1 << 25, stringValue: "VM_WIPEONFORK"}
	VM_DONTDUMP     = VmFlag{rawValue: 1 << 26, stringValue: "VM_DONTDUMP"}
	VM_SOFTDIRTY    = VmFlag{rawValue: 1 << 27, stringValue: "VM_SOFTDIRTY"}
	VM_MIXEDMAP     = VmFlag{rawValue: 1 << 28, stringValue: "VM_MIXEDMAP"}
	VM_HUGEPAGE     = VmFlag{rawValue: 1 << 29, stringValue: "VM_HUGEPAGE"}
	VM_NOHUGEPAGE   = VmFlag{rawValue: 1 << 30, stringValue: "VM_NOHUGEPAGE"}
	VM_MERGEABLE    = VmFlag{rawValue: 1 << 31, stringValue: "VM_MERGEABLE"}
	VM_PKEY_BIT0    = VmFlag{rawValue: 1 << 32, stringValue: "VM_PKEY_BIT0"}
	VM_PKEY_BIT1    = VmFlag{rawValue: 1 << 33, stringValue: "VM_PKEY_BIT1"}
	VM_PKEY_BIT3    = VmFlag{rawValue: 1 << 34, stringValue: "VM_PKEY_BIT3"}
	VM_PKEY_BIT4    = VmFlag{rawValue: 1 << 35, stringValue: "VM_PKEY_BIT4"}
	VM_UFFD_MINOR   = VmFlag{rawValue: 1 << 37, stringValue: "VM_UFFD_MINOR"}
)

// revive:enable

var VmFlagMap = map[uint64]VmFlag{
	VM_READ.Value():         VM_READ,
	VM_WRITE.Value():        VM_WRITE,
	VM_EXEC.Value():         VM_EXEC,
	VM_SHARED.Value():       VM_SHARED,
	VM_MAYREAD.Value():      VM_MAYREAD,
	VM_MAYWRITE.Value():     VM_MAYWRITE,
	VM_MAYEXEC.Value():      VM_MAYEXEC,
	VM_MAYSHARE.Value():     VM_MAYSHARE,
	VM_GROWSDOWN.Value():    VM_GROWSDOWN,
	VM_UFFD_MISSING.Value(): VM_UFFD_MISSING,
	VM_PFNMAP.Value():       VM_PFNMAP,
	VM_UFFD_WP.Value():      VM_UFFD_WP,
	VM_LOCKED.Value():       VM_LOCKED,
	VM_IO.Value():           VM_IO,
	VM_SEQ_READ.Value():     VM_SEQ_READ,
	VM_RAND_READ.Value():    VM_RAND_READ,
	VM_DONTCOPY.Value():     VM_DONTCOPY,
	VM_DONTEXPAND.Value():   VM_DONTEXPAND,
	VM_LOCKONFAULT.Value():  VM_LOCKONFAULT,
	VM_ACCOUNT.Value():      VM_ACCOUNT,
	VM_NORESERVE.Value():    VM_NORESERVE,
	VM_HUGETLB.Value():      VM_HUGETLB,
	VM_SYNC.Value():         VM_SYNC,
	VM_PAT.Value():          VM_PAT,
	VM_WIPEONFORK.Value():   VM_WIPEONFORK,
	VM_DONTDUMP.Value():     VM_DONTDUMP,
	VM_SOFTDIRTY.Value():    VM_SOFTDIRTY,
	VM_MIXEDMAP.Value():     VM_MIXEDMAP,
	VM_HUGEPAGE.Value():     VM_HUGEPAGE,
	VM_NOHUGEPAGE.Value():   VM_NOHUGEPAGE,
	VM_MERGEABLE.Value():    VM_MERGEABLE,
	VM_PKEY_BIT0.Value():    VM_PKEY_BIT0,
	VM_PKEY_BIT1.Value():    VM_PKEY_BIT1,
	VM_PKEY_BIT3.Value():    VM_PKEY_BIT3,
	VM_PKEY_BIT4.Value():    VM_PKEY_BIT4,
	VM_UFFD_MINOR.Value():   VM_UFFD_MINOR,
}

func (vmf VmFlag) Value() uint64 {
	return vmf.rawValue
}

func (vmf VmFlag) String() string {
	return vmf.stringValue
}

// ParseVmFlags parses the flags of vm_area_struct for x86 64bit architecture
func ParseVmFlags(rawValue uint64) VmFlag {
	var f []string
	for i := 0; i <= VmFlagShiftMax; i++ {
		var flagMask uint64 = 1 << i

		if (rawValue & flagMask) != 0 {
			flag, ok := VmFlagMap[flagMask]
			if ok {
				f = append(f, flag.String())
			} else {
				f = append(
					f,
					fmt.Sprintf(
						"UNKNOWN_FLAG_0X%s",
						strings.ToUpper(strconv.FormatUint(flagMask, 16)),
					),
				)
			}
		}
	}

	return VmFlag{stringValue: strings.Join(f, "|"), rawValue: rawValue}
}

// =====================================================

// FsNotifyMask represents the event mask used by the dnotify, inotify and fanotify APIs
type FsNotifyMask struct {
	rawValue    uint64
	stringValue string
}

const FsNotifyMaskShiftMax = 30

// revive:disable

// These values are copied from include/linux/fsnotify_backend.h
var (
	FS_ACCESS         = FsNotifyMask{rawValue: 0x00000001, stringValue: "FS_ACCESS"}
	FS_MODIFY         = FsNotifyMask{rawValue: 0x00000002, stringValue: "FS_MODIFY"}
	FS_ATTRIB         = FsNotifyMask{rawValue: 0x00000004, stringValue: "FS_ATTRIB"}
	FS_CLOSE_WRITE    = FsNotifyMask{rawValue: 0x00000008, stringValue: "FS_CLOSE_WRITE"}
	FS_CLOSE_NOWRITE  = FsNotifyMask{rawValue: 0x00000010, stringValue: "FS_CLOSE_NOWRITE"}
	FS_OPEN           = FsNotifyMask{rawValue: 0x00000020, stringValue: "FS_CLOSE_OPEN"}
	FS_MOVED_FROM     = FsNotifyMask{rawValue: 0x00000040, stringValue: "FS_MOVED_FROM"}
	FS_MOVED_TO       = FsNotifyMask{rawValue: 0x00000080, stringValue: "FS_MOVED_TO"}
	FS_CREATE         = FsNotifyMask{rawValue: 0x00000100, stringValue: "FS_CREATE"}
	FS_DELETE         = FsNotifyMask{rawValue: 0x00000200, stringValue: "FS_DELETE"}
	FS_DELETE_SELF    = FsNotifyMask{rawValue: 0x00000400, stringValue: "FS_DELETE_SELF"}
	FS_MOVE_SELF      = FsNotifyMask{rawValue: 0x00000800, stringValue: "FS_MOVE_SELF"}
	FS_OPEN_EXEC      = FsNotifyMask{rawValue: 0x00001000, stringValue: "FS_OPEN_EXEC"}
	FS_UNMOUNT        = FsNotifyMask{rawValue: 0x00002000, stringValue: "FS_UNMOUNT"}
	FS_Q_OVERFLOW     = FsNotifyMask{rawValue: 0x00004000, stringValue: "FS_Q_OVERFLOW"}
	FS_ERROR          = FsNotifyMask{rawValue: 0x00008000, stringValue: "FS_ERROR"}
	FS_OPEN_PERM      = FsNotifyMask{rawValue: 0x00010000, stringValue: "FS_OPEN_PERM"}
	FS_ACCESS_PERM    = FsNotifyMask{rawValue: 0x00020000, stringValue: "FS_ACCESS_PERM"}
	FS_OPEN_EXEC_PERM = FsNotifyMask{rawValue: 0x00040000, stringValue: "FS_OPEN_EXEC_PERM"}
	FS_EVENT_ON_CHILD = FsNotifyMask{rawValue: 0x08000000, stringValue: "FS_EVENT_ON_CHILD"}
	FS_RENAME         = FsNotifyMask{rawValue: 0x10000000, stringValue: "FS_RENAME"}
	FS_DN_MULTISHOT   = FsNotifyMask{rawValue: 0x20000000, stringValue: "FS_DN_MULTISHOT"}
	FS_ISDIR          = FsNotifyMask{rawValue: 0x40000000, stringValue: "FS_ISDIR"}
)

// revive:enable

var FsNotifyMaskMap = map[uint64]FsNotifyMask{
	FS_ACCESS.Value():         FS_ACCESS,
	FS_MODIFY.Value():         FS_MODIFY,
	FS_ATTRIB.Value():         FS_ATTRIB,
	FS_CLOSE_WRITE.Value():    FS_CLOSE_WRITE,
	FS_CLOSE_NOWRITE.Value():  FS_CLOSE_NOWRITE,
	FS_OPEN.Value():           FS_OPEN,
	FS_MOVED_FROM.Value():     FS_MOVED_FROM,
	FS_MOVED_TO.Value():       FS_MOVED_TO,
	FS_CREATE.Value():         FS_CREATE,
	FS_DELETE.Value():         FS_DELETE,
	FS_DELETE_SELF.Value():    FS_DELETE_SELF,
	FS_MOVE_SELF.Value():      FS_MOVE_SELF,
	FS_OPEN_EXEC.Value():      FS_OPEN_EXEC,
	FS_UNMOUNT.Value():        FS_UNMOUNT,
	FS_Q_OVERFLOW.Value():     FS_Q_OVERFLOW,
	FS_ERROR.Value():          FS_ERROR,
	FS_OPEN_PERM.Value():      FS_OPEN_PERM,
	FS_ACCESS_PERM.Value():    FS_ACCESS_PERM,
	FS_OPEN_EXEC_PERM.Value(): FS_OPEN_EXEC_PERM,
	FS_EVENT_ON_CHILD.Value(): FS_EVENT_ON_CHILD,
	FS_RENAME.Value():         FS_RENAME,
	FS_DN_MULTISHOT.Value():   FS_DN_MULTISHOT,
	FS_ISDIR.Value():          FS_ISDIR,
}

func (mask FsNotifyMask) Value() uint64 {
	return mask.rawValue
}

func (mask FsNotifyMask) String() string {
	return mask.stringValue
}

// ParseFsNotifyMask parses the event mask used by the dnotify, inotify and fanotify APIs
func ParseFsNotifyMask(rawValue uint64) FsNotifyMask {
	var f []string
	for i := 0; i <= FsNotifyMaskShiftMax; i++ {
		var mask uint64 = 1 << i

		if (rawValue & mask) != 0 {
			flag, ok := FsNotifyMaskMap[mask]
			if ok {
				f = append(f, flag.String())
			} else {
				f = append(
					f,
					fmt.Sprintf(
						"UNKNOWN_FLAG_0X%s",
						strings.ToUpper(strconv.FormatUint(mask, 16)),
					),
				)
			}
		}
	}

	return FsNotifyMask{stringValue: strings.Join(f, "|"), rawValue: rawValue}
}

// =====================================================

// FsNotifyObjType represents the type of filesystem object being watched
type FsNotifyObjType struct {
	rawValue    uint32
	stringValue string
}

// revive:disable

// These values are copied from include/linux/fsnotify_backend.h
var (
	FSNOTIFY_OBJ_TYPE_INODE    = FsNotifyObjType{rawValue: 0, stringValue: "FSNOTIFY_OBJ_TYPE_INODE"}
	FSNOTIFY_OBJ_TYPE_VFSMOUNT = FsNotifyObjType{rawValue: 1, stringValue: "FSNOTIFY_OBJ_TYPE_VFSMOUNT"}
	FSNOTIFY_OBJ_TYPE_SB       = FsNotifyObjType{rawValue: 2, stringValue: "FSNOTIFY_OBJ_TYPE_SB"}
	FSNOTIFY_OBJ_TYPE_DETACHED = FsNotifyObjType{rawValue: 3, stringValue: "FSNOTIFY_OBJ_TYPE_DETACHED"}
)

// revive:enable

var fsNotifyObjTypeMap = map[uint64]FsNotifyObjType{
	FSNOTIFY_OBJ_TYPE_INODE.Value():    FSNOTIFY_OBJ_TYPE_INODE,
	FSNOTIFY_OBJ_TYPE_VFSMOUNT.Value(): FSNOTIFY_OBJ_TYPE_VFSMOUNT,
	FSNOTIFY_OBJ_TYPE_SB.Value():       FSNOTIFY_OBJ_TYPE_SB,
	FSNOTIFY_OBJ_TYPE_DETACHED.Value(): FSNOTIFY_OBJ_TYPE_DETACHED,
}

func (objType FsNotifyObjType) Value() uint64 {
	return uint64(objType.rawValue)
}

func (objType FsNotifyObjType) String() string {
	return objType.stringValue
}

// ParseFsNotifyObjType parses the filesystem object type of an fsnotify watch
func ParseFsNotifyObjType(rawValue uint64) (FsNotifyObjType, error) {
	v, ok := fsNotifyObjTypeMap[rawValue]
	if !ok {
		return FsNotifyObjType{}, fmt.Errorf("not a valid argument: %d", rawValue)
	}
	return v, nil
}
