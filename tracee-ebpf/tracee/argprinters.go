package tracee

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/aquasecurity/tracee/pkg/external"
)

// PrintUint32IP prints the IP address encoded as a uint32
func PrintUint32IP(in uint32) string {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, in)
	return ip.String()
}

// Print16BytesSliceIP prints the IP address encoded as 16 bytes long PrintBytesSliceIP
// It would be more correct to accept a [16]byte instead of variable lenth slice, but that would cause unnecessary memory copying and type conversions
func Print16BytesSliceIP(in []byte) string {
	ip := net.IP(in)
	return ip.String()
}

func (t *Tracee) parseArgs(event *external.Event) error {
	for i := range event.Args {
		if ptr, isUintptr := event.Args[i].Value.(uintptr); isUintptr {
			event.Args[i].Value = fmt.Sprintf("0x%X", ptr)
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
			//show syscall name instead of id
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
					capArg.Value = helpers.ParseCapability(capability)
					capArg.Type = "string"
				}
			}
		}
		if int32(event.EventID) == SecurityFileOpenEventID {
			if flagsArg := getEventArg(event, "flags"); flagsArg != nil {
				if flags, isInt32 := flagsArg.Value.(int32); isInt32 {
					flagsArg.Value = helpers.ParseOpenFlags(uint32(flags))
					flagsArg.Type = "string"
				}
			}
		}
	case MmapEventID, MprotectEventID, PkeyMprotectEventID:
		if protArg := getEventArg(event, "prot"); protArg != nil {
			if prot, isInt32 := protArg.Value.(int32); isInt32 {
				protArg.Value = helpers.ParseMemProt(uint32(prot))
				protArg.Type = "string"
			}
		}
	case PtraceEventID:
		if reqArg := getEventArg(event, "request"); reqArg != nil {
			if req, isInt64 := reqArg.Value.(int64); isInt64 {
				reqArg.Value = helpers.ParsePtraceRequest(req)
				reqArg.Type = "string"
			}
		}
	case PrctlEventID:
		if optArg := getEventArg(event, "option"); optArg != nil {
			if opt, isInt32 := optArg.Value.(int32); isInt32 {
				optArg.Value = helpers.ParsePrctlOption(opt)
				optArg.Type = "string"
			}
		}
	case SocketEventID:
		if domArg := getEventArg(event, "domain"); domArg != nil {
			if dom, isInt32 := domArg.Value.(int32); isInt32 {
				domArg.Value = helpers.ParseSocketDomain(uint32(dom))
				domArg.Type = "string"
			}
		}
		if typeArg := getEventArg(event, "type"); typeArg != nil {
			if typ, isInt32 := typeArg.Value.(int32); isInt32 {
				typeArg.Value = helpers.ParseSocketType(uint32(typ))
				typeArg.Type = "string"
			}
		}
	case SecuritySocketCreateEventID:
		if domArg := getEventArg(event, "family"); domArg != nil {
			if dom, isInt32 := domArg.Value.(int32); isInt32 {
				domArg.Value = helpers.ParseSocketDomain(uint32(dom))
				domArg.Type = "string"
			}
		}
		if typeArg := getEventArg(event, "type"); typeArg != nil {
			if typ, isInt32 := typeArg.Value.(int32); isInt32 {
				typeArg.Value = helpers.ParseSocketType(uint32(typ))
				typeArg.Type = "string"
			}
		}
	case AccessEventID, FaccessatEventID:
		if modeArg := getEventArg(event, "mode"); modeArg != nil {
			if mode, isInt32 := modeArg.Value.(int32); isInt32 {
				modeArg.Value = helpers.ParseAccessMode(uint32(mode))
				modeArg.Type = "string"
			}
		}
	case ExecveatEventID:
		if flagsArg := getEventArg(event, "flags"); flagsArg != nil {
			if flags, isInt32 := flagsArg.Value.(int32); isInt32 {
				flagsArg.Value = helpers.ParseExecFlags(uint32(flags))
				flagsArg.Type = "string"
			}
		}
	case OpenEventID, OpenatEventID:
		if flagsArg := getEventArg(event, "flags"); flagsArg != nil {
			if flags, isInt32 := flagsArg.Value.(int32); isInt32 {
				flagsArg.Value = helpers.ParseOpenFlags(uint32(flags))
				flagsArg.Type = "string"
			}
		}
	case MknodEventID, MknodatEventID, ChmodEventID, FchmodEventID, FchmodatEventID:
		if modeArg := getEventArg(event, "mode"); modeArg != nil {
			if mode, isUint32 := modeArg.Value.(uint32); isUint32 {
				modeArg.Value = helpers.ParseInodeMode(mode)
				modeArg.Type = "string"
			}
		}
	case SecurityInodeMknodEventID:
		if modeArg := getEventArg(event, "mode"); modeArg != nil {
			if mode, isUint16 := modeArg.Value.(uint16); isUint16 {
				modeArg.Value = helpers.ParseInodeMode(uint32(mode))
				modeArg.Type = "string"
			}
		}
	case CloneEventID:
		if flagsArg := getEventArg(event, "flags"); flagsArg != nil {
			if flags, isUint64 := flagsArg.Value.(uint64); isUint64 {
				flagsArg.Value = helpers.ParseCloneFlags(flags)
				flagsArg.Type = "string"
			}
		}
	case BpfEventID, SecurityBPFEventID:
		if cmdArg := getEventArg(event, "cmd"); cmdArg != nil {
			if cmd, isInt32 := cmdArg.Value.(int32); isInt32 {
				cmdArg.Value = helpers.ParseBPFCmd(cmd)
				cmdArg.Type = "string"
			}
		}
	case SecurityKernelReadFileEventID, SecurityPostReadFileEventID:
		if typeArg := getEventArg(event, "type"); typeArg != nil {
			if readFileId, isInt32 := typeArg.Value.(int32); isInt32 {
				typeIdStr, err := ParseKernelReadFileId(readFileId)
				if err == nil {
					typeArg.Value = typeIdStr
					typeArg.Type = "string"
				}
			}
		}
	case SchedProcessExecEventID:
		if modeArg := getEventArg(event, "stdin_type"); modeArg != nil {
			if mode, isUint16 := modeArg.Value.(uint16); isUint16 {
				modeArg.Value = helpers.ParseInodeMode(uint32(mode))
				modeArg.Type = "string"
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
