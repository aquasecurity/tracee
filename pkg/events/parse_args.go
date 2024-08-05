package events

import (
	"bytes"
	"fmt"
	"strconv"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events/parsers"
	"github.com/aquasecurity/tracee/types/trace"
)

func emptyString(arg *trace.Argument) {
	arg.Type = "string"
	arg.Value = ""
}

func parseOrEmptyString(arg *trace.Argument, sysArg parsers.SystemFunctionArgument, err error) {
	emptyString(arg)
	if err == nil {
		arg.Value = sysArg.String()
	}
}

func ParseArgs(event *trace.Event) error {
	for i := range event.Args {
		if ptr, isUintptr := event.Args[i].Value.(uintptr); isUintptr {
			v := []byte{'0', 'x'}
			v = strconv.AppendUint(v, uint64(ptr), 16)
			event.Args[i].Value = string(v)
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
				mmapProtArgument := parsers.ParseMmapProt(uint64(prot))
				parseOrEmptyString(protArg, mmapProtArgument, nil)
			}
		}
		if prevProtArg := GetArg(event, "prev_prot"); prevProtArg != nil {
			if prevProt, isInt32 := prevProtArg.Value.(int32); isInt32 {
				mmapProtArgument := parsers.ParseMmapProt(uint64(prevProt))
				parseOrEmptyString(prevProtArg, mmapProtArgument, nil)
			}
		}
	case SysEnter, SysExit:
		if syscallArg := GetArg(event, "syscall"); syscallArg != nil {
			if id, isInt32 := syscallArg.Value.(int32); isInt32 {
				if Core.IsDefined(ID(id)) {
					eventDefinition := Core.GetDefinitionByID(ID(id))
					if eventDefinition.IsSyscall() {
						syscallArg.Value = eventDefinition.GetName()
						syscallArg.Type = "string"
					}
				}
			}
		}
	case CapCapable:
		if capArg := GetArg(event, "cap"); capArg != nil {
			if capability, isInt32 := capArg.Value.(int32); isInt32 {
				capabilityFlagArgument, err := parsers.ParseCapability(uint64(capability))
				parseOrEmptyString(capArg, capabilityFlagArgument, err)
			}
		}
	case SecurityMmapFile, DoMmap:
		if protArg := GetArg(event, "prot"); protArg != nil {
			if prot, isUint64 := protArg.Value.(uint64); isUint64 {
				mmapProtArgument := parsers.ParseMmapProt(prot)
				parseOrEmptyString(protArg, mmapProtArgument, nil)
			}
		}
	case Mmap, Mprotect, PkeyMprotect:
		if protArg := GetArg(event, "prot"); protArg != nil {
			if prot, isInt32 := protArg.Value.(int32); isInt32 {
				mmapProtArgument := parsers.ParseMmapProt(uint64(prot))
				parseOrEmptyString(protArg, mmapProtArgument, nil)
			}
		}
	case SecurityFileMprotect:
		if protArg := GetArg(event, "prot"); protArg != nil {
			if prot, isInt32 := protArg.Value.(int32); isInt32 {
				mmapProtArgument := parsers.ParseMmapProt(uint64(prot))
				parseOrEmptyString(protArg, mmapProtArgument, nil)
			}
		}
		if prevProtArg := GetArg(event, "prev_prot"); prevProtArg != nil {
			if prevProt, isInt32 := prevProtArg.Value.(int32); isInt32 {
				mmapProtArgument := parsers.ParseMmapProt(uint64(prevProt))
				parseOrEmptyString(prevProtArg, mmapProtArgument, nil)
			}
		}
	case PtraceSyscallNoSysenter:
		if reqArg := GetArg(event, "request"); reqArg != nil {
			if req, isInt64 := reqArg.Value.(int64); isInt64 {
				ptraceRequestArgument, err := parsers.ParsePtraceRequestArgument(uint64(req))
				parseOrEmptyString(reqArg, ptraceRequestArgument, err)
			}
		}
	case Prctl:
		if optArg := GetArg(event, "option"); optArg != nil {
			if opt, isInt32 := optArg.Value.(int32); isInt32 {
				prctlOptionArgument, err := parsers.ParsePrctlOption(uint64(opt))
				parseOrEmptyString(optArg, prctlOptionArgument, err)
			}
		}
	case Socketcall:
		if callArg := GetArg(event, "call"); callArg != nil {
			if call, isInt32 := callArg.Value.(int32); isInt32 {
				socketcallArgument, err := parsers.ParseSocketcallCall(uint64(call))
				parseOrEmptyString(callArg, socketcallArgument, err)
			}
		}
	case Socket:
		if domArg := GetArg(event, "domain"); domArg != nil {
			if dom, isInt32 := domArg.Value.(int32); isInt32 {
				socketDomainArgument, err := parsers.ParseSocketDomainArgument(uint64(dom))
				parseOrEmptyString(domArg, socketDomainArgument, err)
			}
		}
		if typeArg := GetArg(event, "type"); typeArg != nil {
			if typ, isInt32 := typeArg.Value.(int32); isInt32 {
				socketTypeArgument, err := parsers.ParseSocketType(uint64(typ))
				parseOrEmptyString(typeArg, socketTypeArgument, err)
			}
		}
	case SecuritySocketCreate, SecuritySocketConnect:
		if domArg := GetArg(event, "family"); domArg != nil {
			if dom, isInt32 := domArg.Value.(int32); isInt32 {
				socketDomainArgument, err := parsers.ParseSocketDomainArgument(uint64(dom))
				parseOrEmptyString(domArg, socketDomainArgument, err)
			}
		}
		if typeArg := GetArg(event, "type"); typeArg != nil {
			if typ, isInt32 := typeArg.Value.(int32); isInt32 {
				socketTypeArgument, err := parsers.ParseSocketType(uint64(typ))
				parseOrEmptyString(typeArg, socketTypeArgument, err)
			}
		}
	case Access, Faccessat:
		if modeArg := GetArg(event, "mode"); modeArg != nil {
			if mode, isInt32 := modeArg.Value.(int32); isInt32 {
				accessModeArgument, err := parsers.ParseAccessMode(uint64(mode))
				parseOrEmptyString(modeArg, accessModeArgument, err)
			}
		}
	case Execveat:
		if flagsArg := GetArg(event, "flags"); flagsArg != nil {
			if flags, isInt32 := flagsArg.Value.(int32); isInt32 {
				execFlagArgument, err := parsers.ParseExecFlag(uint64(flags))
				parseOrEmptyString(flagsArg, execFlagArgument, err)
			}
		}
	case Open, Openat, SecurityFileOpen:
		if flagsArg := GetArg(event, "flags"); flagsArg != nil {
			if flags, isInt32 := flagsArg.Value.(int32); isInt32 {
				openFlagArgument, err := parsers.ParseOpenFlagArgument(uint64(flags))
				parseOrEmptyString(flagsArg, openFlagArgument, err)
			}
		}
	case Mknod, Mknodat, Chmod, Fchmod, Fchmodat:
		if modeArg := GetArg(event, "mode"); modeArg != nil {
			if mode, isUint32 := modeArg.Value.(uint32); isUint32 {
				inodeModeArgument, err := parsers.ParseInodeMode(uint64(mode))
				parseOrEmptyString(modeArg, inodeModeArgument, err)
			}
		}
	case SecurityInodeMknod:
		if modeArg := GetArg(event, "mode"); modeArg != nil {
			if mode, isUint16 := modeArg.Value.(uint16); isUint16 {
				inodeModeArgument, err := parsers.ParseInodeMode(uint64(mode))
				parseOrEmptyString(modeArg, inodeModeArgument, err)
			}
		}
	case Clone:
		if flagsArg := GetArg(event, "flags"); flagsArg != nil {
			if flags, isUint64 := flagsArg.Value.(uint64); isUint64 {
				cloneFlagArgument, err := parsers.ParseCloneFlags(uint64(flags))
				parseOrEmptyString(flagsArg, cloneFlagArgument, err)
			}
		}
	case Bpf, SecurityBPF:
		if cmdArg := GetArg(event, "cmd"); cmdArg != nil {
			if cmd, isInt32 := cmdArg.Value.(int32); isInt32 {
				bpfCommandArgument, err := parsers.ParseBPFCmd(uint64(cmd))
				parseOrEmptyString(cmdArg, bpfCommandArgument, err)
			}
		}
	case SecurityKernelReadFile, SecurityPostReadFile:
		if typeArg := GetArg(event, "type"); typeArg != nil {
			if readFileId, isInt32 := typeArg.Value.(trace.KernelReadType); isInt32 {
				emptyString(typeArg)
				typeArg.Value = readFileId.String()
			}
		}
	case SchedProcessExec:
		if modeArg := GetArg(event, "stdin_type"); modeArg != nil {
			if mode, isUint16 := modeArg.Value.(uint16); isUint16 {
				inodeModeArgument, err := parsers.ParseInodeMode(uint64(mode))
				parseOrEmptyString(modeArg, inodeModeArgument, err)
			}
		}
	case DirtyPipeSplice:
		if modeArg := GetArg(event, "in_file_type"); modeArg != nil {
			if mode, isUint16 := modeArg.Value.(uint16); isUint16 {
				inodeModeArgument, err := parsers.ParseInodeMode(uint64(mode))
				parseOrEmptyString(modeArg, inodeModeArgument, err)
			}
		}
	case SecuritySocketSetsockopt, Setsockopt, Getsockopt:
		if levelArg := GetArg(event, "level"); levelArg != nil {
			if level, isInt := levelArg.Value.(int32); isInt {
				levelArgument, err := parsers.ParseSocketLevel(uint64(level))
				parseOrEmptyString(levelArg, levelArgument, err)
			}
		}
		if optionNameArg := GetArg(event, "optname"); optionNameArg != nil {
			if opt, isInt := optionNameArg.Value.(int32); isInt {
				var optionNameArgument parsers.SocketOptionArgument
				var err error
				if ID(event.EventID) == Getsockopt {
					optionNameArgument, err = parsers.ParseGetSocketOption(uint64(opt))
				} else {
					optionNameArgument, err = parsers.ParseSetSocketOption(uint64(opt))
				}
				parseOrEmptyString(optionNameArg, optionNameArgument, err)
			}
		}
	case BpfAttach:
		if progTypeArg := GetArg(event, "prog_type"); progTypeArg != nil {
			if progType, isInt := progTypeArg.Value.(int32); isInt {
				progTypeArgument, err := parsers.ParseBPFProgType(uint64(progType))
				parseOrEmptyString(progTypeArg, progTypeArgument, err)
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
		if attachTypeArg := GetArg(event, "attach_type"); attachTypeArg != nil {
			if attachType, isInt := attachTypeArg.Value.(int32); isInt {
				attachTypestr, err := parseBpfAttachType(attachType)
				emptyString(attachTypeArg)
				if err == nil {
					attachTypeArg.Value = attachTypestr
				}
			}
		}
	case SecurityBpfProg:
		if progTypeArg := GetArg(event, "type"); progTypeArg != nil {
			if progType, isInt := progTypeArg.Value.(int32); isInt {
				progTypeArgument, err := parsers.ParseBPFProgType(uint64(progType))
				parseOrEmptyString(progTypeArg, progTypeArgument, err)
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
	case SecurityPathNotify:
		if maskArg := GetArg(event, "mask"); maskArg != nil {
			if mask, isUint64 := maskArg.Value.(uint64); isUint64 {
				fsNotifyMaskArgument := parsers.ParseFsNotifyMask(mask)
				parseOrEmptyString(maskArg, fsNotifyMaskArgument, nil)
			}
		}
		if objTypeArg := GetArg(event, "obj_type"); objTypeArg != nil {
			if objType, isUint := objTypeArg.Value.(uint32); isUint {
				objTypeArgument, err := parsers.ParseFsNotifyObjType(uint64(objType))
				parseOrEmptyString(objTypeArg, objTypeArgument, err)
			}
		}
	}

	return nil
}

func ParseArgsFDs(event *trace.Event, origTimestamp uint64, fdArgPathMap *bpf.BPFMap) error {
	if fdArg := GetArg(event, "fd"); fdArg != nil {
		if fd, isInt32 := fdArg.Value.(int32); isInt32 {
			ts := origTimestamp
			bs, err := fdArgPathMap.GetValue(unsafe.Pointer(&ts))
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

func SetArgValue(event *trace.Event, argName string, value any) error {
	arg := GetArg(event, argName)
	if arg == nil {
		return fmt.Errorf("event %s has no argument named %s", event.EventName, argName)
	}
	arg.Value = value
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
			bpfHelper, err := parsers.ParseBPFFunc(uint64(i))
			if err != nil {
				continue
			}
			usedHelpers = append(usedHelpers, bpfHelper.String())
		}
	}

	return usedHelpers, nil
}

func parseBpfAttachType(attachType int32) (string, error) {
	switch attachType {
	case 0:
		return "raw_tracepoint", nil
	case 1:
		return "tracepoint", nil
	case 2:
		return "kprobe", nil
	case 3:
		return "kretprobe", nil
	case 4:
		return "uprobe", nil
	case 5:
		return "uretprobe", nil
	default:
		return "", errfmt.Errorf("unknown attach_type got from bpf_attach event")
	}
}
