package events

import (
	"bytes"
	"fmt"
	"strconv"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/aquasecurity/tracee/types/trace"
)

type fdArgTask struct {
	PID uint32
	TID uint32
	FD  int32
}

func ParseArgs(event *trace.Event) error {
	for i := range event.Args {
		if ptr, isUintptr := event.Args[i].Value.(uintptr); isUintptr {
			event.Args[i].Value = "0x" + strconv.FormatUint(uint64(ptr), 16)
		}
	}

	EmptyString := func(arg *trace.Argument) {
		arg.Type = "string"
		arg.Value = ""
	}

	ParseOrEmptyString := func(arg *trace.Argument, sysArg helpers.SystemFunctionArgument, err error) {
		EmptyString(arg)
		if err == nil {
			arg.Value = sysArg.String()
		}
	}

	switch ID(event.EventID) {
	case MemProtAlert:
		if alertArg := GetArg(event, "alert"); alertArg != nil {
			if alert, isUint32 := alertArg.Value.(uint32); isUint32 {
				alertArg.Value = trace.MemProtAlert(alert).String()
				alertArg.Type = "string"
			}
		}
	case SysEnter, SysExit, CapCapable, CommitCreds, SecurityFileOpen, TaskRename, SecurityMmapFile:
		if syscallArg := GetArg(event, "syscall"); syscallArg != nil {
			if id, isInt32 := syscallArg.Value.(int32); isInt32 {
				if event, isKnown := Definitions.GetSafe(ID(id)); isKnown {
					if event.Syscall {
						syscallArg.Value = event.Name
						syscallArg.Type = "string"
					}
				}
			}
		}
		if ID(event.EventID) == CapCapable {
			if capArg := GetArg(event, "cap"); capArg != nil {
				if capability, isInt32 := capArg.Value.(int32); isInt32 {
					capabilityFlagArgument, err := helpers.ParseCapability(uint64(capability))
					ParseOrEmptyString(capArg, capabilityFlagArgument, err)
				}
			}
		}
		if ID(event.EventID) == SecurityFileOpen {
			if flagsArg := GetArg(event, "flags"); flagsArg != nil {
				if flags, isInt32 := flagsArg.Value.(int32); isInt32 {
					openFlagArgument, err := helpers.ParseOpenFlagArgument(uint64(flags))
					ParseOrEmptyString(flagsArg, openFlagArgument, err)
				}
			}
		}
		if ID(event.EventID) == SecurityMmapFile {
			if protArg := GetArg(event, "prot"); protArg != nil {
				if prot, isInt32 := protArg.Value.(int32); isInt32 {
					mmapProtArgument := helpers.ParseMmapProt(uint64(prot))
					ParseOrEmptyString(protArg, mmapProtArgument, nil)
				}
			}
		}
	case Mmap, Mprotect, PkeyMprotect, SecurityFileMprotect:
		if protArg := GetArg(event, "prot"); protArg != nil {
			if prot, isInt32 := protArg.Value.(int32); isInt32 {
				mmapProtArgument := helpers.ParseMmapProt(uint64(prot))
				ParseOrEmptyString(protArg, mmapProtArgument, nil)
			}
		}
	case Ptrace:
		if reqArg := GetArg(event, "request"); reqArg != nil {
			if req, isInt64 := reqArg.Value.(int64); isInt64 {
				ptraceRequestArgument, err := helpers.ParsePtraceRequestArgument(uint64(req))
				ParseOrEmptyString(reqArg, ptraceRequestArgument, err)
			}
		}
	case Prctl:
		if optArg := GetArg(event, "option"); optArg != nil {
			if opt, isInt32 := optArg.Value.(int32); isInt32 {
				prctlOptionArgument, err := helpers.ParsePrctlOption(uint64(opt))
				ParseOrEmptyString(optArg, prctlOptionArgument, err)
			}
		}
	case Socket:
		if domArg := GetArg(event, "domain"); domArg != nil {
			if dom, isInt32 := domArg.Value.(int32); isInt32 {
				socketDomainArgument, err := helpers.ParseSocketDomainArgument(uint64(dom))
				ParseOrEmptyString(domArg, socketDomainArgument, err)
			}
		}
		if typeArg := GetArg(event, "type"); typeArg != nil {
			if typ, isInt32 := typeArg.Value.(int32); isInt32 {
				socketTypeArgument, err := helpers.ParseSocketType(uint64(typ))
				ParseOrEmptyString(typeArg, socketTypeArgument, err)
			}
		}
	case SecuritySocketCreate:
		if domArg := GetArg(event, "family"); domArg != nil {
			if dom, isInt32 := domArg.Value.(int32); isInt32 {
				socketDomainArgument, err := helpers.ParseSocketDomainArgument(uint64(dom))
				ParseOrEmptyString(domArg, socketDomainArgument, err)
			}
		}
		if typeArg := GetArg(event, "type"); typeArg != nil {
			if typ, isInt32 := typeArg.Value.(int32); isInt32 {
				socketTypeArgument, err := helpers.ParseSocketType(uint64(typ))
				ParseOrEmptyString(typeArg, socketTypeArgument, err)
			}
		}
	case Access, Faccessat:
		if modeArg := GetArg(event, "mode"); modeArg != nil {
			if mode, isInt32 := modeArg.Value.(int32); isInt32 {
				accessModeArgument, err := helpers.ParseAccessMode(uint64(mode))
				ParseOrEmptyString(modeArg, accessModeArgument, err)
			}
		}
	case Execveat:
		if flagsArg := GetArg(event, "flags"); flagsArg != nil {
			if flags, isInt32 := flagsArg.Value.(int32); isInt32 {
				execFlagArgument, err := helpers.ParseExecFlag(uint64(flags))
				ParseOrEmptyString(flagsArg, execFlagArgument, err)
			}
		}
	case Open, Openat:
		if flagsArg := GetArg(event, "flags"); flagsArg != nil {
			if flags, isInt32 := flagsArg.Value.(int32); isInt32 {
				openFlagArgument, err := helpers.ParseOpenFlagArgument(uint64(flags))
				ParseOrEmptyString(flagsArg, openFlagArgument, err)
			}
		}
	case Mknod, Mknodat, Chmod, Fchmod, Fchmodat:
		if modeArg := GetArg(event, "mode"); modeArg != nil {
			if mode, isUint32 := modeArg.Value.(uint32); isUint32 {
				inodeModeArgument, err := helpers.ParseInodeMode(uint64(mode))
				ParseOrEmptyString(modeArg, inodeModeArgument, err)
			}
		}
	case SecurityInodeMknod:
		if modeArg := GetArg(event, "mode"); modeArg != nil {
			if mode, isUint16 := modeArg.Value.(uint16); isUint16 {
				inodeModeArgument, err := helpers.ParseInodeMode(uint64(mode))
				ParseOrEmptyString(modeArg, inodeModeArgument, err)
			}
		}
	case Clone:
		if flagsArg := GetArg(event, "flags"); flagsArg != nil {
			if flags, isUint64 := flagsArg.Value.(uint64); isUint64 {
				cloneFlagArgument, err := helpers.ParseCloneFlags(uint64(flags))
				ParseOrEmptyString(flagsArg, cloneFlagArgument, err)
			}
		}
	case Bpf, SecurityBPF:
		if cmdArg := GetArg(event, "cmd"); cmdArg != nil {
			if cmd, isInt32 := cmdArg.Value.(int32); isInt32 {
				bpfCommandArgument, err := helpers.ParseBPFCmd(uint64(cmd))
				ParseOrEmptyString(cmdArg, bpfCommandArgument, err)
			}
		}
	case SecurityKernelReadFile, SecurityPostReadFile:
		if typeArg := GetArg(event, "type"); typeArg != nil {
			if readFileId, isInt32 := typeArg.Value.(int32); isInt32 {
				EmptyString(typeArg)
				if typeIdStr, err := parseKernelReadFileId(readFileId); err == nil {
					typeArg.Value = typeIdStr
				}
			}
		}
	case SchedProcessExec:
		if modeArg := GetArg(event, "stdin_type"); modeArg != nil {
			if mode, isUint16 := modeArg.Value.(uint16); isUint16 {
				inodeModeArgument, err := helpers.ParseInodeMode(uint64(mode))
				ParseOrEmptyString(modeArg, inodeModeArgument, err)
			}
		}
	case DirtyPipeSplice:
		if modeArg := GetArg(event, "in_file_type"); modeArg != nil {
			if mode, isUint16 := modeArg.Value.(uint16); isUint16 {
				inodeModeArgument, err := helpers.ParseInodeMode(uint64(mode))
				ParseOrEmptyString(modeArg, inodeModeArgument, err)
			}
		}
	case SecuritySocketSetsockopt, Setsockopt, Getsockopt:
		if levelArg := GetArg(event, "level"); levelArg != nil {
			if level, isInt := levelArg.Value.(int32); isInt {
				levelArgument, err := helpers.ParseSocketLevel(uint64(level))
				ParseOrEmptyString(levelArg, levelArgument, err)
			}
		}
		if optionNameArg := GetArg(event, "optname"); optionNameArg != nil {
			if opt, isInt := optionNameArg.Value.(int32); isInt {
				var optionNameArgument helpers.SocketOptionArgument
				var err error
				if ID(event.EventID) == Getsockopt {
					optionNameArgument, err = helpers.ParseGetSocketOption(uint64(opt))
				} else {
					optionNameArgument, err = helpers.ParseSetSocketOption(uint64(opt))
				}
				ParseOrEmptyString(optionNameArg, optionNameArgument, err)
			}
		}
	}

	return nil
}

func ParseArgsFDs(event *trace.Event, fdArgPathMap *bpf.BPFMap) error {
	if fdArg := GetArg(event, "fd"); fdArg != nil {
		if fd, isInt32 := fdArg.Value.(int32); isInt32 {
			fdArgTask := &fdArgTask{
				PID: uint32(event.ProcessID),
				TID: uint32(event.ThreadID),
				FD:  fd,
			}
			bs, err := fdArgPathMap.GetValue(unsafe.Pointer(fdArgTask))
			if err != nil {
				return err
			}

			fpath := string(bytes.Trim(bs, "\x00"))
			fdArg.Value = fmt.Sprintf("%d=%s", fd, fpath)
		}
	}

	return nil
}

func GetArg(event *trace.Event, argName string) *trace.Argument {
	for i := range event.Args {
		if event.Args[i].Name == argName {
			return &event.Args[i]
		}
	}
	return nil
}

// initializing kernelReadFileIdStrs once at init.
var kernelReadFileIdStrs map[int32]string

func init() {
	osInfo, err := helpers.GetOSInfo()
	if err != nil {
		return
	}

	kernel593ComparedToRunningKernel, err := osInfo.CompareOSBaseKernelRelease("5.9.3")
	if err != nil {
		return
	}
	kernel570ComparedToRunningKernel, err := osInfo.CompareOSBaseKernelRelease("5.7.0")
	if err != nil {
		return
	}
	kernel592ComparedToRunningKernel, err := osInfo.CompareOSBaseKernelRelease("5.9.2")
	if err != nil {
		return
	}
	kernel5818ComparedToRunningKernel, err := osInfo.CompareOSBaseKernelRelease("5.8.18")
	if err != nil {
		return
	}
	kernel4180ComparedToRunningKernel, err := osInfo.CompareOSBaseKernelRelease("4.18.0")
	if err != nil {
		return
	}

	if kernel593ComparedToRunningKernel == helpers.KernelVersionOlder {
		// running kernel version: >=5.9.3
		kernelReadFileIdStrs = map[int32]string{
			0: "unknown",
			1: "firmware",
			2: "kernel-module",
			3: "kexec-image",
			4: "kexec-initramfs",
			5: "security-policy",
			6: "x509-certificate",
		}
	} else if kernel570ComparedToRunningKernel == helpers.KernelVersionOlder /* Running kernel is newer than 5.7.0 */ &&
		kernel592ComparedToRunningKernel != helpers.KernelVersionOlder /* Running kernel is equal or older than 5.9.2*/ &&
		kernel5818ComparedToRunningKernel != helpers.KernelVersionEqual /* Running kernel is not 5.8.18 */ {
		// running kernel version: >=5.7 && <=5.9.2 && !=5.8.18
		kernelReadFileIdStrs = map[int32]string{
			0: "unknown",
			1: "firmware",
			2: "firmware",
			3: "firmware",
			4: "kernel-module",
			5: "kexec-image",
			6: "kexec-initramfs",
			7: "security-policy",
			8: "x509-certificate",
		}
	} else if kernel5818ComparedToRunningKernel == helpers.KernelVersionEqual /* Running kernel is 5.8.18*/ &&
		(kernel570ComparedToRunningKernel == helpers.KernelVersionNewer && /* Running kernel is older than 5.7.0*/
			kernel4180ComparedToRunningKernel != helpers.KernelVersionOlder) /* Running kernel is 4.18 or newer */ {
		// running kernel version: ==5.8.18 || (<5.7 && >=4.18)
		kernelReadFileIdStrs = map[int32]string{
			0: "unknown",
			1: "firmware",
			2: "firmware",
			3: "kernel-module",
			4: "kexec-image",
			5: "kexec-initramfs",
			6: "security-policy",
			7: "x509-certificate",
		}
	}
}

func parseKernelReadFileId(id int32) (string, error) {
	kernelReadFileIdStr, idExists := kernelReadFileIdStrs[id]
	if !idExists {
		return "", fmt.Errorf("kernelReadFileId doesn't exist in kernelReadFileIdStrs map")
	}
	return kernelReadFileIdStr, nil
}

type CustomFunctionArgument struct {
	val uint64
	str string
}

func (arg CustomFunctionArgument) String() string {
	return arg.str
}
func (arg CustomFunctionArgument) Value() uint64 {
	return arg.val
}
