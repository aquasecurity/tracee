package parse

import (
	"time"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/types/trace"
)

func ArgVal[T any](args []trace.Argument, argName string) (T, error) {
	var ok bool
	var val T
	var foundAndNotOk bool

	var i int
	for i = range len(args) {
		if args[i].Name != argName {
			continue
		}

		val, ok = args[i].Value.(T)
		if !ok {
			foundAndNotOk = true
			break
		}

		return val, nil
	}

	var zeroVal T
	if foundAndNotOk {
		return zeroVal,
			errfmt.Errorf(
				"argument %s is not of type %T, is of type %T",
				argName,
				zeroVal,
				args[i].Value,
			)
	}

	return zeroVal, errfmt.Errorf("argument %s not found", argName)
}

func ArgZeroValueFromType(t string) interface{} {
	switch t {
	case "char", "byte":
		return byte(0)
	case "[]byte":
		return []byte{}
	case "int8":
		return int8(0)
	case "uint8":
		return uint8(0)
	case "int16":
		return int16(0)
	case "uint16":
		return uint16(0)
	case "int32":
		return int32(0)
	case "uint32":
		return uint32(0)
	case "[2]int32":
		return [2]int32{}
	case "int64":
		return int64(0)
	case "uint64":
		return uint64(0)
	case "[]uint64":
		return []uint64{}
	case "string":
		return string("")
	case "[]string":
		return []string{}
	case "bool":
		return false
	case "float":
		return float32(0)
	case "float64":
		return float64(0)
	case "time.Time":
		// TODO: is this the right choice? Maybe abuse the any and return int(0)?
		return time.Unix(0, 0)
	case "trace.SlimCred":
		return trace.SlimCred{}
	case "trace.ProtoIPv4":
		return trace.ProtoIPv4{}
	case "trace.ProtoIPv6":
		return trace.ProtoIPv6{}
	case "trace.ProtoTCP":
		return trace.ProtoTCP{}
	case "trace.ProtoUDP":
		return trace.ProtoUDP{}
	case "trace.ProtoICMP":
		return trace.ProtoICMP{}
	case "trace.ProtoICMPv6":
		return trace.ProtoICMPv6{}
	case "trace.PktMeta":
		return trace.PktMeta{}
	case "trace.ProtoDNS":
		return trace.ProtoDNS{}
	case "[]trace.DnsQueryData":
		return []trace.DnsQueryData{}
	case "[]trace.DnsResponseData":
		return []trace.DnsResponseData{}
	case "trace.ProtoHTTP":
		return trace.ProtoHTTP{}
	case "trace.ProtoHTTPRequest":
		return trace.ProtoHTTPRequest{}
	case "trace.ProtoHTTPResponse":
		return trace.ProtoHTTPResponse{}
	case "trace.PacketMetadata":
		return trace.PacketMetadata{}
	case "[]trace.HookedSymbolData":
		return []trace.HookedSymbolData{}
	case "map[string]trace.HookedSymbolData":
		return map[string]trace.HookedSymbolData{}
	case "void*":
		// pointer types
		return trace.Pointer(0)
	}
	// unknown type
	return nil
}

// ArgIndex find the index of an argument by name
func ArgIndex(args []trace.Argument, argName string) int {
	for index, arg := range args {
		if arg.Name == argName {
			return index
		}
	}
	return -1
}
