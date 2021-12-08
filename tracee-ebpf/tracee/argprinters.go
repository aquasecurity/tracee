package tracee

import (
	"encoding/binary"
	"fmt"
	"github.com/aquasecurity/libbpfgo/helpers"
	"net"

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

func (t *Tracee) parseArgs(ctx *context, args map[string]interface{}) error {
	for key, arg := range args {
		if ptr, isUintptr := arg.(uintptr); isUintptr {
			args[key] = fmt.Sprintf("0x%X", ptr)
		}
	}

	switch ctx.EventID {
	case MemProtAlertEventID:
		if alert, isUint32 := args["alert"].(uint32); isUint32 {
			args["alert"] = external.MemProtAlert(alert).String()
		}
	case SysEnterEventID, SysExitEventID, CapCapableEventID, CommitCredsEventID, SecurityFileOpenEventID:
		//show syscall name instead of id
		if id, isInt32 := args["syscall"].(int32); isInt32 {
			if event, isKnown := EventsIDToEvent[id]; isKnown {
				if event.Probes[0].attach == sysCall {
					args["syscall"] = event.Probes[0].event
				}
			}
		}
		if ctx.EventID == CapCapableEventID {
			if capability, isInt32 := args["cap"].(int32); isInt32 {
				args["cap"] = helpers.ParseCapability(capability)
			}
		}
		if ctx.EventID == SecurityFileOpenEventID {
			if flags, isInt32 := args["flags"].(int32); isInt32 {
				args["flags"] = helpers.ParseOpenFlags(uint32(flags))
			}
		}
	case MmapEventID, MprotectEventID, PkeyMprotectEventID:
		if prot, isInt32 := args["prot"].(int32); isInt32 {
			args["prot"] = helpers.ParseMemProt(uint32(prot))
		}
	case PtraceEventID:
		if req, isInt64 := args["request"].(int64); isInt64 {
			args["request"] = helpers.ParsePtraceRequest(req)
		}
	case PrctlEventID:
		if opt, isInt32 := args["option"].(int32); isInt32 {
			args["option"] = helpers.ParsePrctlOption(opt)
		}
	case SocketEventID:
		if dom, isInt32 := args["domain"].(int32); isInt32 {
			args["domain"] = helpers.ParseSocketDomain(uint32(dom))
		}
		if typ, isInt32 := args["type"].(int32); isInt32 {
			args["type"] = helpers.ParseSocketType(uint32(typ))
		}
	case SecuritySocketCreateEventID:
		if dom, isInt32 := args["family"].(int32); isInt32 {
			args["family"] = helpers.ParseSocketDomain(uint32(dom))
		}
		if typ, isInt32 := args["type"].(int32); isInt32 {
			args["type"] = helpers.ParseSocketType(uint32(typ))
		}
	case AccessEventID, FaccessatEventID:
		if mode, isInt32 := args["mode"].(int32); isInt32 {
			args["mode"] = helpers.ParseAccessMode(uint32(mode))
		}
	case ExecveatEventID:
		if flags, isInt32 := args["flags"].(int32); isInt32 {
			args["flags"] = helpers.ParseExecFlags(uint32(flags))
		}
	case OpenEventID, OpenatEventID:
		if flags, isInt32 := args["flags"].(int32); isInt32 {
			args["flags"] = helpers.ParseOpenFlags(uint32(flags))
		}
	case MknodEventID, MknodatEventID, ChmodEventID, FchmodEventID, FchmodatEventID:
		if mode, isUint32 := args["mode"].(uint32); isUint32 {
			args["mode"] = helpers.ParseInodeMode(mode)
		}
	case SecurityInodeMknodEventID:
		if mode, isUint16 := args["mode"].(uint16); isUint16 {
			args["mode"] = helpers.ParseInodeMode(uint32(mode))
		}
	case CloneEventID:
		if flags, isUint64 := args["flags"].(uint64); isUint64 {
			args["flags"] = helpers.ParseCloneFlags(flags)
		}
	case BpfEventID, SecurityBPFEventID:
		if cmd, isInt32 := args["cmd"].(int32); isInt32 {
			args["cmd"] = helpers.ParseBPFCmd(cmd)
		}
	case SecurityKernelReadFileEventID, SecurityPostReadFileEventID:
		if readFileId, isInt32 := args["type"].(int32); isInt32 {
			typeIdStr, err := ParseKernelReadFileId(readFileId)
			if err == nil {
				args["type"] = typeIdStr
			}
		}
	case SchedProcessExecEventID:
		if mode, isUint16 := args["stdin_type"].(uint16); isUint16 {
			args["stdin_type"] = helpers.ParseInodeMode(uint32(mode))
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
