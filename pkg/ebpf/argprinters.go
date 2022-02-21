package ebpf

import (
	"fmt"
	"strconv"

	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/aquasecurity/tracee/pkg/external"
)

func (t *Tracee) parseArgs(event *external.Event) error {
	for i := range event.Args {
		if ptr, isUintptr := event.Args[i].Value.(uintptr); isUintptr {
			event.Args[i].Value = "0x" + strconv.FormatUint(uint64(ptr), 16)
		}
	}

	EmptyString := func(arg *external.Argument) {
		arg.Type = "string"
		arg.Value = ""
	}

	ParseOrEmptyString := func(arg *external.Argument, sysArg helpers.SystemFunctionArgument, err error) {
		EmptyString(arg)
		if err == nil {
			arg.Value = sysArg.String()
		}
	}

	switch int32(event.EventID) {
	case MemProtAlertEventID:
		if alertArg := getEventArg(event, "alert"); alertArg != nil {
			if alert, isUint32 := alertArg.Value.(uint32); isUint32 {
				alertArg.Value = external.MemProtAlert(alert).String()
			}
		}
	case SysEnterEventID, SysExitEventID, CapCapableEventID, CommitCredsEventID, SecurityFileOpenEventID:
		if syscallArg := getEventArg(event, "syscall"); syscallArg != nil {
			if id, isInt32 := syscallArg.Value.(int32); isInt32 {
				if event, isKnown := EventsDefinitions[id]; isKnown {
					if event.Probes[0].attach == sysCall {
						syscallArg.Value = event.Probes[0].event
					}
				}
			}
		}
		if int32(event.EventID) == CapCapableEventID {
			if capArg := getEventArg(event, "cap"); capArg != nil {
				if capability, isInt32 := capArg.Value.(int32); isInt32 {
					capabilityFlagArgument, err := helpers.ParseCapability(uint64(capability))
					ParseOrEmptyString(capArg, capabilityFlagArgument, err)
				}
			}
		}
		if int32(event.EventID) == SecurityFileOpenEventID {
			if flagsArg := getEventArg(event, "flags"); flagsArg != nil {
				if flags, isInt32 := flagsArg.Value.(int32); isInt32 {
					openFlagArgument, err := helpers.ParseOpenFlagArgument(uint64(flags))
					ParseOrEmptyString(flagsArg, openFlagArgument, err)
				}
			}
		}
	case MmapEventID, MprotectEventID, PkeyMprotectEventID:
		if protArg := getEventArg(event, "prot"); protArg != nil {
			if prot, isInt32 := protArg.Value.(int32); isInt32 {
				mmapProtArgument := helpers.ParseMmapProt(uint64(prot))
				ParseOrEmptyString(protArg, mmapProtArgument, nil)
			}
		}
	case PtraceEventID:
		if reqArg := getEventArg(event, "request"); reqArg != nil {
			if req, isInt64 := reqArg.Value.(int64); isInt64 {
				ptraceRequestArgument, err := helpers.ParsePtraceRequestArgument(uint64(req))
				ParseOrEmptyString(reqArg, ptraceRequestArgument, err)
			}
		}
	case PrctlEventID:
		if optArg := getEventArg(event, "option"); optArg != nil {
			if opt, isInt32 := optArg.Value.(int32); isInt32 {
				prctlOptionArgument, err := helpers.ParsePrctlOption(uint64(opt))
				ParseOrEmptyString(optArg, prctlOptionArgument, err)
			}
		}
	case SocketEventID:
		if domArg := getEventArg(event, "domain"); domArg != nil {
			if dom, isInt32 := domArg.Value.(int32); isInt32 {
				socketDomainArgument, err := helpers.ParseSocketDomainArgument(uint64(dom))
				ParseOrEmptyString(domArg, socketDomainArgument, err)
			}
		}
		if typeArg := getEventArg(event, "type"); typeArg != nil {
			if typ, isInt32 := typeArg.Value.(int32); isInt32 {
				socketTypeArgument, err := helpers.ParseSocketType(uint64(typ))
				ParseOrEmptyString(typeArg, socketTypeArgument, err)
			}
		}
	case SecuritySocketCreateEventID:
		if domArg := getEventArg(event, "family"); domArg != nil {
			if dom, isInt32 := domArg.Value.(int32); isInt32 {
				socketDomainArgument, err := helpers.ParseSocketDomainArgument(uint64(dom))
				ParseOrEmptyString(domArg, socketDomainArgument, err)
			}
		}
		if typeArg := getEventArg(event, "type"); typeArg != nil {
			if typ, isInt32 := typeArg.Value.(int32); isInt32 {
				socketTypeArgument, err := helpers.ParseSocketType(uint64(typ))
				ParseOrEmptyString(typeArg, socketTypeArgument, err)
			}
		}
	case AccessEventID, FaccessatEventID:
		if modeArg := getEventArg(event, "mode"); modeArg != nil {
			if mode, isInt32 := modeArg.Value.(int32); isInt32 {
				accessModeArgument, err := helpers.ParseAccessMode(uint64(mode))
				ParseOrEmptyString(modeArg, accessModeArgument, err)
			}
		}
	case ExecveatEventID:
		if flagsArg := getEventArg(event, "flags"); flagsArg != nil {
			if flags, isInt32 := flagsArg.Value.(int32); isInt32 {
				execFlagArgument, err := helpers.ParseExecFlag(uint64(flags))
				ParseOrEmptyString(flagsArg, execFlagArgument, err)
			}
		}
	case OpenEventID, OpenatEventID:
		if flagsArg := getEventArg(event, "flags"); flagsArg != nil {
			if flags, isInt32 := flagsArg.Value.(int32); isInt32 {
				openFlagArgument, err := helpers.ParseOpenFlagArgument(uint64(flags))
				ParseOrEmptyString(flagsArg, openFlagArgument, err)
			}
		}
	case MknodEventID, MknodatEventID, ChmodEventID, FchmodEventID, FchmodatEventID:
		if modeArg := getEventArg(event, "mode"); modeArg != nil {
			if mode, isUint32 := modeArg.Value.(uint32); isUint32 {
				inodeModeArgument, err := helpers.ParseInodeMode(uint64(mode))
				ParseOrEmptyString(modeArg, inodeModeArgument, err)
			}
		}
	case SecurityInodeMknodEventID:
		if modeArg := getEventArg(event, "mode"); modeArg != nil {
			if mode, isUint16 := modeArg.Value.(uint16); isUint16 {
				inodeModeArgument, err := helpers.ParseInodeMode(uint64(mode))
				ParseOrEmptyString(modeArg, inodeModeArgument, err)
			}
		}
	case CloneEventID:
		if flagsArg := getEventArg(event, "flags"); flagsArg != nil {
			if flags, isUint64 := flagsArg.Value.(uint64); isUint64 {
				cloneFlagArgument, err := helpers.ParseCloneFlags(uint64(flags))
				ParseOrEmptyString(flagsArg, cloneFlagArgument, err)
			}
		}
	case BpfEventID, SecurityBPFEventID:
		if cmdArg := getEventArg(event, "cmd"); cmdArg != nil {
			if cmd, isInt32 := cmdArg.Value.(int32); isInt32 {
				bpfCommandArgument, err := helpers.ParseBPFCmd(uint64(cmd))
				ParseOrEmptyString(cmdArg, bpfCommandArgument, err)
			}
		}
	case SecurityKernelReadFileEventID, SecurityPostReadFileEventID:
		if typeArg := getEventArg(event, "type"); typeArg != nil {
			if readFileId, isInt32 := typeArg.Value.(int32); isInt32 {
				EmptyString(typeArg)
				if typeIdStr, err := ParseKernelReadFileId(readFileId); err == nil {
					typeArg.Value = typeIdStr
				}
			}
		}
	case SchedProcessExecEventID:
		if modeArg := getEventArg(event, "stdin_type"); modeArg != nil {
			if mode, isUint16 := modeArg.Value.(uint16); isUint16 {
				inodeModeArgument, err := helpers.ParseInodeMode(uint64(mode))
				ParseOrEmptyString(modeArg, inodeModeArgument, err)
			}
		}
	}

	return nil
}

func getEventArg(event *external.Event, argName string) *external.Argument {
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

	if osInfo.CompareOSBaseKernelRelease("5.9.3") != 1 {
		// kernel version: >=5.9.3
		kernelReadFileIdStrs = map[int32]string{
			0: "unknown",
			1: "firmware",
			2: "kernel-module",
			3: "kexec-image",
			4: "kexec-initramfs",
			5: "security-policy",
			6: "x509-certificate",
		}
	} else if osInfo.CompareOSBaseKernelRelease("5.7.0") != 1 && osInfo.CompareOSBaseKernelRelease("5.9.2") != -1 && osInfo.CompareOSBaseKernelRelease("5.8.18") != 0 {
		// kernel version: >=5.7 && <=5.9.2 && !=5.8.18
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
	} else if osInfo.CompareOSBaseKernelRelease("5.8.18") == 0 || (osInfo.CompareOSBaseKernelRelease("4.18.0") != 1 && osInfo.CompareOSBaseKernelRelease("5.7.0") == 1) {
		// kernel version: ==5.8.18 || (<5.7 && >=4.18)
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

func ParseKernelReadFileId(id int32) (string, error) {
	kernelReadFileIdStr, idExists := kernelReadFileIdStrs[id]
	if !idExists {
		return "", fmt.Errorf("kernelReadFileId doesn't exist in kernelReadFileIdStrs map")
	}
	return kernelReadFileIdStr, nil
}
