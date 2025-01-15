//go:build amd64
// +build amd64

package parsers

import (
	"golang.org/x/sys/unix"
)

var (
	// from asm-generic/fcntl.h
	// NOT sequential values
	// gap
	O_LARGEFILE = SystemFunctionArgument{rawValue: 00100000, stringValue: "O_LARGEFILE"}
)

var openFlagsValues = []SystemFunctionArgument{
	// O_ACCMODE, // macro for access mode, so not included

	// special cases checked before the loop in ParseOpenFlagArgument
	// O_RDONLY,
	// O_WRONLY,
	// O_RDWR,
	O_CREAT,
	O_EXCL,
	O_NOCTTY,
	O_TRUNC,
	O_APPEND,
	O_NONBLOCK,
	O_DSYNC,
	O_SYNC,
	FASYNC,
	O_DIRECT,
	O_LARGEFILE,
	O_DIRECTORY,
	O_NOFOLLOW,
	O_NOATIME,
	O_CLOEXEC,
	O_PATH,
	O_TMPFILE,
}

var (
	// from linux/ptrace.h and sys/ptrace.h
	// NOT sequential values
	// gap
	PTRACE_GETREGS   = SystemFunctionArgument{rawValue: 12, stringValue: "PTRACE_GETREGS"}
	PTRACE_SETREGS   = SystemFunctionArgument{rawValue: 13, stringValue: "PTRACE_SETREGS"}
	PTRACE_GETFPREGS = SystemFunctionArgument{rawValue: 14, stringValue: "PTRACE_GETFPREGS"}
	PTRACE_SETFPREGS = SystemFunctionArgument{rawValue: 15, stringValue: "PTRACE_SETFPREGS"}
	// gap
	PTRACE_GETFPXREGS = SystemFunctionArgument{rawValue: 18, stringValue: "PTRACE_GETFPXREGS"}
	PTRACE_SETFPXREGS = SystemFunctionArgument{rawValue: 19, stringValue: "PTRACE_SETFPXREGS"}
	// gap
	PTRACE_GET_THREAD_AREA = SystemFunctionArgument{rawValue: 25, stringValue: "PTRACE_GET_THREAD_AREA"}
	PTRACE_SET_THREAD_AREA = SystemFunctionArgument{rawValue: 26, stringValue: "PTRACE_SET_THREAD_AREA"}
	// gap
	PTRACE_ARCH_PRCTL = SystemFunctionArgument{rawValue: 30, stringValue: "PTRACE_ARCH_PRCTL"}
	// gap
	PTRACE_SINGLEBLOCK = SystemFunctionArgument{rawValue: 33, stringValue: "PTRACE_SINGLEBLOCK"}
	// gap
	PTRACE_SET_SYSCALL_USER_DISPATCH_CONFIG = SystemFunctionArgument{rawValue: 0x4210, stringValue: "PTRACE_SET_SYSCALL_USER_DISPATCH_CONFIG"}
	PTRACE_GET_SYSCALL_USER_DISPATCH_CONFIG = SystemFunctionArgument{rawValue: 0x4211, stringValue: "PTRACE_GET_SYSCALL_USER_DISPATCH_CONFIG"}
)

var ptraceRequestValues = []SystemFunctionArgument{
	PTRACE_TRACEME,
	PTRACE_PEEKTEXT,
	PTRACE_PEEKDATA,
	PTRACE_PEEKUSR,
	PTRACE_POKETEXT,
	PTRACE_POKEDATA,
	PTRACE_POKEUSR,
	PTRACE_CONT,
	PTRACE_KILL,
	PTRACE_SINGLESTEP,
	PTRACE_GETREGS,
	PTRACE_SETREGS,
	PTRACE_GETFPREGS,
	PTRACE_SETFPREGS,
	PTRACE_ATTACH,
	PTRACE_DETACH,
	PTRACE_GETFPXREGS,
	PTRACE_SETFPXREGS,
	PTRACE_SYSCALL,
	PTRACE_GET_THREAD_AREA,
	PTRACE_SET_THREAD_AREA,
	PTRACE_ARCH_PRCTL,
	PTRACE_SYSEMU,
	PTRACE_SYSEMU_SINGLESTEP,
	PTRACE_SINGLEBLOCK,
	// PTRACE_PEEKMTETAGS,
	// PTRACE_POKEMTETAGS,
	PTRACE_SETOPTIONS,
	PTRACE_GETEVENTMSG,
	PTRACE_GETSIGINFO,
	PTRACE_SETSIGINFO,
	PTRACE_GETREGSET,
	PTRACE_SETREGSET,
	PTRACE_SEIZE,
	PTRACE_INTERRUPT,
	PTRACE_LISTEN,
	PTRACE_PEEKSIGINFO,
	PTRACE_GETSIGMASK,
	PTRACE_SETSIGMASK,
	PTRACE_SECCOMP_GET_FILTER,
	PTRACE_SECCOMP_GET_METADATA,
	PTRACE_GET_SYSCALL_INFO,
	PTRACE_GET_RSEQ_CONFIGURATION,
	PTRACE_SET_SYSCALL_USER_DISPATCH_CONFIG,
	PTRACE_GET_SYSCALL_USER_DISPATCH_CONFIG,
}

var (
	Map32bit = MmapFlagArgument{rawValue: unix.MAP_32BIT, stringValue: "MAP_32BIT"}
)

func init() {
	mmapFlagMap[Map32bit.Value()] = Map32bit
}
