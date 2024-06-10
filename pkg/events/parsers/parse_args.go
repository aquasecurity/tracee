package parsers

import (
	"fmt"
	"strconv"

	"github.com/aquasecurity/tracee/types/trace"
)

func ParseArgs(event *trace.Event) error {
	for _, arg := range event.Args {
		if ptr, isUintptr := arg.Value.(uintptr); isUintptr {
			err := SetArgValue(event, arg.Name, "0x"+strconv.FormatUint(uint64(ptr), 16))
			if err != nil {
				return err
			}
		}
	}

	emptyString := func(arg *trace.Argument) {
		arg.Type = "string"
		arg.Value = ""
	}

	parseOrEmptyString := func(arg *trace.Argument, sysArg SystemFunctionArgument, err error) {
		emptyString(arg)
		if err == nil {
			arg.Value = sysArg.String()
		}
	}

	switch event.EventName {
	case "mem_prot_alert":
		if alertArg := GetArg(event, "alert"); alertArg != nil {
			if alert, isUint32 := alertArg.Value.(uint32); isUint32 {
				alertArg.Value = trace.MemProtAlert(alert).String()
				alertArg.Type = "string"
			}
		}
		if protArg := GetArg(event, "prot"); protArg != nil {
			if prot, isInt32 := protArg.Value.(int32); isInt32 {
				mmapProtArgument := ParseMmapProt(uint64(prot))
				parseOrEmptyString(protArg, mmapProtArgument, nil)
			}
		}
		if prevProtArg := GetArg(event, "prev_prot"); prevProtArg != nil {
			if prevProt, isInt32 := prevProtArg.Value.(int32); isInt32 {
				mmapProtArgument := ParseMmapProt(uint64(prevProt))
				parseOrEmptyString(prevProtArg, mmapProtArgument, nil)
			}
		}
		// TODO: Add support for syscall id to name parsing
	// case "sys_enter", "sys_exit":
	// 	if syscallArg := GetArg(event, "syscall"); syscallArg != nil {
	// 		if id, isInt32 := syscallArg.Value.(int32); isInt32 {
	// 			if events.Core.IsDefined(events.ID(id)) {
	// 				eventDefinition := events.Core.GetDefinitionByID(events.ID(id))
	// 				if eventDefinition.IsSyscall() {
	// 					syscallArg.Value = eventDefinition.GetName()
	// 					syscallArg.Type = "string"
	// 				}
	// 			}
	// 		}
	// 	}
	case "cap_capable":
		if capArg := GetArg(event, "cap"); capArg != nil {
			if capability, isInt32 := capArg.Value.(int32); isInt32 {
				capabilityFlagArgument, err := ParseCapability(uint64(capability))
				parseOrEmptyString(capArg, capabilityFlagArgument, err)
			}
		}
	case "security_mmap_file", "do_mmap":
		if protArg := GetArg(event, "prot"); protArg != nil {
			if prot, isUint64 := protArg.Value.(uint64); isUint64 {
				mmapProtArgument := ParseMmapProt(prot)
				parseOrEmptyString(protArg, mmapProtArgument, nil)
			}
		}
	case "mmap", "mprotect", "pkey_mprotect":
		if protArg := GetArg(event, "prot"); protArg != nil {
			if prot, isInt32 := protArg.Value.(int32); isInt32 {
				mmapProtArgument := ParseMmapProt(uint64(prot))
				parseOrEmptyString(protArg, mmapProtArgument, nil)
			}
		}
	case "security_file_mprotect":
		if protArg := GetArg(event, "prot"); protArg != nil {
			if prot, isInt32 := protArg.Value.(int32); isInt32 {
				mmapProtArgument := ParseMmapProt(uint64(prot))
				parseOrEmptyString(protArg, mmapProtArgument, nil)
			}
		}
		if prevProtArg := GetArg(event, "prev_prot"); prevProtArg != nil {
			if prevProt, isInt32 := prevProtArg.Value.(int32); isInt32 {
				mmapProtArgument := ParseMmapProt(uint64(prevProt))
				parseOrEmptyString(prevProtArg, mmapProtArgument, nil)
			}
		}
	case "ptrace":
		if reqArg := GetArg(event, "request"); reqArg != nil {
			if req, isInt64 := reqArg.Value.(int64); isInt64 {
				ptraceRequestArgument, err := ParsePtraceRequestArgument(uint64(req))
				parseOrEmptyString(reqArg, ptraceRequestArgument, err)
			}
		}
	case "prctl":
		if optArg := GetArg(event, "option"); optArg != nil {
			if opt, isInt32 := optArg.Value.(int32); isInt32 {
				prctlOptionArgument, err := ParsePrctlOption(uint64(opt))
				parseOrEmptyString(optArg, prctlOptionArgument, err)
			}
		}
	case "socketcall":
		if callArg := GetArg(event, "call"); callArg != nil {
			if call, isInt32 := callArg.Value.(int32); isInt32 {
				socketcallArgument, err := ParseSocketcallCall(uint64(call))
				parseOrEmptyString(callArg, socketcallArgument, err)
			}
		}
	case "socket":
		if domArg := GetArg(event, "domain"); domArg != nil {
			if dom, isInt32 := domArg.Value.(int32); isInt32 {
				socketDomainArgument, err := ParseSocketDomainArgument(uint64(dom))
				parseOrEmptyString(domArg, socketDomainArgument, err)
			}
		}
		if typeArg := GetArg(event, "type"); typeArg != nil {
			if typ, isInt32 := typeArg.Value.(int32); isInt32 {
				socketTypeArgument, err := ParseSocketType(uint64(typ))
				parseOrEmptyString(typeArg, socketTypeArgument, err)
			}
		}
	case "security_socket_create", "security_socket_connect":
		if domArg := GetArg(event, "family"); domArg != nil {
			if dom, isInt32 := domArg.Value.(int32); isInt32 {
				socketDomainArgument, err := ParseSocketDomainArgument(uint64(dom))
				parseOrEmptyString(domArg, socketDomainArgument, err)
			}
		}
		if typeArg := GetArg(event, "type"); typeArg != nil {
			if typ, isInt32 := typeArg.Value.(int32); isInt32 {
				socketTypeArgument, err := ParseSocketType(uint64(typ))
				parseOrEmptyString(typeArg, socketTypeArgument, err)
			}
		}
	case "access", "faccessat":
		if modeArg := GetArg(event, "mode"); modeArg != nil {
			if mode, isInt32 := modeArg.Value.(int32); isInt32 {
				accessModeArgument, err := ParseAccessMode(uint64(mode))
				parseOrEmptyString(modeArg, accessModeArgument, err)
			}
		}
	case "execveat":
		if flagsArg := GetArg(event, "flags"); flagsArg != nil {
			if flags, isInt32 := flagsArg.Value.(int32); isInt32 {
				execFlagArgument, err := ParseExecFlag(uint64(flags))
				parseOrEmptyString(flagsArg, execFlagArgument, err)
			}
		}
	case "open", "openat", "security_file_open":
		if flagsArg := GetArg(event, "flags"); flagsArg != nil {
			if flags, isInt32 := flagsArg.Value.(int32); isInt32 {
				openFlagArgument, err := ParseOpenFlagArgument(uint64(flags))
				parseOrEmptyString(flagsArg, openFlagArgument, err)
			}
		}
	case "mknod", "mknodat", "chmod", "fchmod", "fchmodat":
		if modeArg := GetArg(event, "mode"); modeArg != nil {
			if mode, isUint32 := modeArg.Value.(uint32); isUint32 {
				inodeModeArgument, err := ParseInodeMode(uint64(mode))
				parseOrEmptyString(modeArg, inodeModeArgument, err)
			}
		}
	case "security_inode_mknod":
		if modeArg := GetArg(event, "mode"); modeArg != nil {
			if mode, isUint16 := modeArg.Value.(uint16); isUint16 {
				inodeModeArgument, err := ParseInodeMode(uint64(mode))
				parseOrEmptyString(modeArg, inodeModeArgument, err)
			}
		}
	case "clone":
		if flagsArg := GetArg(event, "flags"); flagsArg != nil {
			if flags, isUint64 := flagsArg.Value.(uint64); isUint64 {
				cloneFlagArgument, err := ParseCloneFlags(uint64(flags))
				parseOrEmptyString(flagsArg, cloneFlagArgument, err)
			}
		}
	case "bpf", "security_bpf":
		if cmdArg := GetArg(event, "cmd"); cmdArg != nil {
			if cmd, isInt32 := cmdArg.Value.(int32); isInt32 {
				bpfCommandArgument, err := ParseBPFCmd(uint64(cmd))
				parseOrEmptyString(cmdArg, bpfCommandArgument, err)
			}
		}
	case "security_kernel_read_file", "security_post_read_file":
		if typeArg := GetArg(event, "type"); typeArg != nil {
			if readFileId, isInt32 := typeArg.Value.(trace.KernelReadType); isInt32 {
				emptyString(typeArg)
				typeArg.Value = readFileId.String()
			}
		}
	case "sched_process_exec":
		if modeArg := GetArg(event, "stdin_type"); modeArg != nil {
			if mode, isUint16 := modeArg.Value.(uint16); isUint16 {
				inodeModeArgument, err := ParseInodeMode(uint64(mode))
				parseOrEmptyString(modeArg, inodeModeArgument, err)
			}
		}
	case "dirty_pipe_splice":
		if modeArg := GetArg(event, "in_file_type"); modeArg != nil {
			if mode, isUint16 := modeArg.Value.(uint16); isUint16 {
				inodeModeArgument, err := ParseInodeMode(uint64(mode))
				parseOrEmptyString(modeArg, inodeModeArgument, err)
			}
		}
	case "security_socket_setsockopt", "setsockopt", "getsockopt":
		if levelArg := GetArg(event, "level"); levelArg != nil {
			if level, isInt := levelArg.Value.(int32); isInt {
				levelArgument, err := ParseSocketLevel(uint64(level))
				parseOrEmptyString(levelArg, levelArgument, err)
			}
		}
		if optionNameArg := GetArg(event, "optname"); optionNameArg != nil {
			if opt, isInt := optionNameArg.Value.(int32); isInt {
				var optionNameArgument SocketOptionArgument
				var err error
				if event.EventName == "getsockopt" {
					optionNameArgument, err = ParseGetSocketOption(uint64(opt))
				} else {
					optionNameArgument, err = ParseSetSocketOption(uint64(opt))
				}
				parseOrEmptyString(optionNameArg, optionNameArgument, err)
			}
		}
	case "bpf_attach":
		if progTypeArg := GetArg(event, "prog_type"); progTypeArg != nil {
			if progType, isInt := progTypeArg.Value.(int32); isInt {
				progTypeArgument, err := ParseBPFProgType(uint64(progType))
				parseOrEmptyString(progTypeArg, progTypeArgument, err)
			}
		}
		if helpersArg := GetArg(event, "prog_helpers"); helpersArg != nil {
			if helpersList, isUintSlice := helpersArg.Value.([]uint64); isUintSlice {
				parsedHelpersList, err := ParseBpfHelpersUsage(helpersList)
				if err != nil {
					return err
				}
				helpersArg.Type = "const char**"
				helpersArg.Value = parsedHelpersList
			}
		}
		if attachTypeArg := GetArg(event, "attach_type"); attachTypeArg != nil {
			if attachType, isInt := attachTypeArg.Value.(int32); isInt {
				attachTypeArgument, err := ParseBpfAttachType(attachType)
				parseOrEmptyString(attachTypeArg, attachTypeArgument, err)
			}
		}
	case "security_bpf_prog":
		if progTypeArg := GetArg(event, "type"); progTypeArg != nil {
			if progType, isInt := progTypeArg.Value.(int32); isInt {
				progTypeArgument, err := ParseBPFProgType(uint64(progType))
				parseOrEmptyString(progTypeArg, progTypeArgument, err)
			}
		}
		if helpersArg := GetArg(event, "helpers"); helpersArg != nil {
			if helpersList, isUintSlice := helpersArg.Value.([]uint64); isUintSlice {
				parsedHelpersList, err := ParseBpfHelpersUsage(helpersList)
				if err != nil {
					return err
				}
				helpersArg.Type = "const char**"
				helpersArg.Value = parsedHelpersList
			}
		}
	case "security_path_notify":
		if maskArg := GetArg(event, "mask"); maskArg != nil {
			if mask, isUint64 := maskArg.Value.(uint64); isUint64 {
				fsNotifyMaskArgument := ParseFsNotifyMask(mask)
				parseOrEmptyString(maskArg, fsNotifyMaskArgument, nil)
			}
		}
		if objTypeArg := GetArg(event, "obj_type"); objTypeArg != nil {
			if objType, isUint := objTypeArg.Value.(uint32); isUint {
				objTypeArgument, err := ParseFsNotifyObjType(uint64(objType))
				parseOrEmptyString(objTypeArg, objTypeArgument, err)
			}
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

// ParseBpfHelpersUsage parse number of bpf helpers to their matching names.
func ParseBpfHelpersUsage(helpersList []uint64) ([]string, error) {
	var usedHelpers []string

	for i := 0; i < len(helpersList)*64; i++ {
		if (helpersList[i/64] & (1 << (i % 64))) > 0 {
			// helper number <i> is used. get its name
			bpfHelper, err := ParseBPFFunc(uint64(i))
			if err != nil {
				continue
			}
			usedHelpers = append(usedHelpers, bpfHelper.String())
		}
	}

	return usedHelpers, nil
}
