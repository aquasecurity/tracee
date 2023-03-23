package events

import (
	"bytes"
	"fmt"
	"strconv"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/errfmt"
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
		if protArg := GetArg(event, "prot"); protArg != nil {
			if prot, isInt32 := protArg.Value.(int32); isInt32 {
				mmapProtArgument := helpers.ParseMmapProt(uint64(prot))
				ParseOrEmptyString(protArg, mmapProtArgument, nil)
			}
		}
		if prevProtArg := GetArg(event, "prev_prot"); prevProtArg != nil {
			if prevProt, isInt32 := prevProtArg.Value.(int32); isInt32 {
				mmapProtArgument := helpers.ParseMmapProt(uint64(prevProt))
				ParseOrEmptyString(prevProtArg, mmapProtArgument, nil)
			}
		}
	case SysEnter, SysExit:
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
	case SecurityMmapFile, DoMmap:
		if protArg := GetArg(event, "prot"); protArg != nil {
			if prot, isUint64 := protArg.Value.(uint64); isUint64 {
				mmapProtArgument := helpers.ParseMmapProt(prot)
				ParseOrEmptyString(protArg, mmapProtArgument, nil)
			}
		}
	case Mmap, Mprotect, PkeyMprotect:
		if protArg := GetArg(event, "prot"); protArg != nil {
			if prot, isInt32 := protArg.Value.(int32); isInt32 {
				mmapProtArgument := helpers.ParseMmapProt(uint64(prot))
				ParseOrEmptyString(protArg, mmapProtArgument, nil)
			}
		}
	case SecurityFileMprotect:
		if protArg := GetArg(event, "prot"); protArg != nil {
			if prot, isInt32 := protArg.Value.(int32); isInt32 {
				mmapProtArgument := helpers.ParseMmapProt(uint64(prot))
				ParseOrEmptyString(protArg, mmapProtArgument, nil)
			}
		}
		if prevProtArg := GetArg(event, "prev_prot"); prevProtArg != nil {
			if prevProt, isInt32 := prevProtArg.Value.(int32); isInt32 {
				mmapProtArgument := helpers.ParseMmapProt(uint64(prevProt))
				ParseOrEmptyString(prevProtArg, mmapProtArgument, nil)
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
	case Open, Openat, SecurityFileOpen:
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
			if readFileId, isInt32 := typeArg.Value.(trace.KernelReadType); isInt32 {
				EmptyString(typeArg)
				typeArg.Value = readFileId.String()
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
	case BpfAttach:
		if progTypeArg := GetArg(event, "prog_type"); progTypeArg != nil {
			if progType, isInt := progTypeArg.Value.(int32); isInt {
				progTypeArgument, err := helpers.ParseBPFProgType(uint64(progType))
				ParseOrEmptyString(progTypeArg, progTypeArgument, err)
			}
		}
		if helpersArg := GetArg(event, "prog_helpers"); helpersArg != nil {
			if helpersList, isUintSlice := helpersArg.Value.([]uint64); isUintSlice {
				parsedHelpersList, err := parseBpfHelpersUsage(helpersList)
				if err != nil {
					return err
				}
				helpersArg.Type = "const char**"
				helpersArg.Value = parsedHelpersList
			}
		}
		if perfTypeArg := GetArg(event, "perf_type"); perfTypeArg != nil {
			if perfType, isInt := perfTypeArg.Value.(int32); isInt {
				perfTypestr, err := parseBpfAttachPerfType(perfType)
				EmptyString(perfTypeArg)
				if err == nil {
					perfTypeArg.Value = perfTypestr
				}
			}
		}
	case SecurityBpfProg:
		if progTypeArg := GetArg(event, "type"); progTypeArg != nil {
			if progType, isInt := progTypeArg.Value.(int32); isInt {
				progTypeArgument, err := helpers.ParseBPFProgType(uint64(progType))
				ParseOrEmptyString(progTypeArg, progTypeArgument, err)
			}
		}
		if helpersArg := GetArg(event, "helpers"); helpersArg != nil {
			if helpersList, isUintSlice := helpersArg.Value.([]uint64); isUintSlice {
				parsedHelpersList, err := parseBpfHelpersUsage(helpersList)
				if err != nil {
					return err
				}
				helpersArg.Type = "const char**"
				helpersArg.Value = parsedHelpersList
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
				return errfmt.WrapError(err)
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

func parseBpfHelpersUsage(helpersList []uint64) ([]string, error) {

	var usedHelpers []string

	for i := 0; i < len(helpersList)*64; i++ {
		if (helpersList[i/64] & (1 << (i % 64))) > 0 {
			// helper number <i> is used. get its name from libbpfgo
			bpfHelper, err := helpers.ParseBPFFunc(uint64(i))
			if err != nil {
				continue
			}
			usedHelpers = append(usedHelpers, bpfHelper.String())
		}
	}

	return usedHelpers, nil
}

func parseBpfAttachPerfType(perfType int32) (string, error) {
	switch perfType {
	case 0:
		return "tracepoint", nil
	case 1:
		return "kprobe", nil
	case 2:
		return "kretprobe", nil
	case 3:
		return "uprobe", nil
	case 4:
		return "uretprobe", nil
	default:
		return "", errfmt.Errorf("unknown perf_type got from bpf_attach event")
	}
}
