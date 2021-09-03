package tracee

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/aquasecurity/libbpfgo/helpers"
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

// PrintAlert prints the encoded alert message and output file path if required
func PrintAlert(alert alert) string {
	var res string

	var securityAlerts = map[uint32]string{
		1: "Mmaped region with W+E permissions!",
		2: "Protection changed to Executable!",
		3: "Protection changed from E to W+E!",
		4: "Protection changed from W+E to E!",
	}

	if msg, ok := securityAlerts[alert.Msg]; ok {
		res = msg
	} else {
		res = strconv.Itoa(int(alert.Msg))
	}

	if alert.Payload != 0 {
		res += " Saving data to bin." + strconv.Itoa(int(alert.Ts))
	}

	return res
}

func (t *Tracee) prepareArgs(ctx *context, args map[string]interface{}) error {
	for key, arg := range args {
		if ptr, isUintptr := arg.(uintptr); isUintptr {
			args[key] = fmt.Sprintf("0x%X", ptr)
		}
	}
	switch ctx.EventID {
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
	case ConnectEventID, AcceptEventID, Accept4EventID, BindEventID, GetsocknameEventID:
		if sockAddr, isStrMap := args["addr"].(map[string]string); isStrMap {
			var s string
			for key, val := range sockAddr {
				s += fmt.Sprintf("'%s': '%s',", key, val)
			}
			s = strings.TrimSuffix(s, ",")
			s = fmt.Sprintf("{%s}", s)
			args["addr"] = s
		}
	case SecuritySocketBindEventID, SecuritySocketAcceptEventID, SecuritySocketListenEventID:
		if sockAddr, isStrMap := args["local_addr"].(map[string]string); isStrMap {
			var s string
			for key, val := range sockAddr {
				s += fmt.Sprintf("'%s': '%s',", key, val)
			}
			s = strings.TrimSuffix(s, ",")
			s = fmt.Sprintf("{%s}", s)
			args["local_addr"] = s
		}
	case SecuritySocketConnectEventID:
		if sockAddr, isStrMap := args["remote_addr"].(map[string]string); isStrMap {
			var s string
			for key, val := range sockAddr {
				s += fmt.Sprintf("'%s': '%s',", key, val)
			}
			s = strings.TrimSuffix(s, ",")
			s = fmt.Sprintf("{%s}", s)
			args["remote_addr"] = s
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
	case MemProtAlertEventID:
		if alert, isAlert := args["alert"].(alert); isAlert {
			args["alert"] = PrintAlert(alert)
		}
	case CloneEventID:
		if flags, isUint64 := args["flags"].(uint64); isUint64 {
			args["flags"] = helpers.ParseCloneFlags(flags)
		}
	case SendtoEventID, RecvfromEventID:
		addrType := "dest_addr"
		if ctx.EventID == RecvfromEventID {
			addrType = "src_addr"
		}
		if sockAddr, isStrMap := args[addrType].(map[string]string); isStrMap {
			var s string
			for key, val := range sockAddr {
				s += fmt.Sprintf("'%s': '%s',", key, val)
			}
			s = strings.TrimSuffix(s, ",")
			s = fmt.Sprintf("{%s}", s)
			args[addrType] = s
		}
	case BpfEventID:
		if cmd, isInt32 := args["cmd"].(int32); isInt32 {
			args["cmd"] = helpers.ParseBPFCmd(cmd)
		}
	}

	return nil
}
