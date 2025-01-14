package parse

import (
	"strings"

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
	case "char":
		return byte(0)
	case "bytes":
		return []byte{}
	case "s8":
		return int8(0)
	case "u8":
		return uint8(0)
	case "s16",
		"short":
		return int16(0)
	case "u16",
		"unsigned short",
		"old_gid_t",
		"old_uid_t",
		"umode_t":
		return uint16(0)
	case "s32",
		"int",
		"pid_t",
		"key_t",
		"clockid_t",
		"const clockid_t",
		"timer_t",
		"mqd_t",
		"key_serial_t",
		"landlock_rule_type":
		return int32(0)
	case "u32",
		"unsigned int",
		"dev_t",
		"uid_t",
		"gid_t",
		"mode_t",
		"qid_t":
		return uint32(0)
	case "int[2]":
		return [2]int32{}
	case "s64",
		"long",
		"long long",
		"off_t",
		"loff_t":
		return int64(0)
	case "u64",
		"unsigned long",
		"unsigned long long",
		"const unsigned long",
		"const unsigned long long",
		"size_t",
		"aio_context_t":
		return uint64(0)
	case "unsigned long[]":
		return []uint64{}
	case "char*",
		"const char*",
		"const char *":
		return string("")
	case "const char**",
		"const char **":
		return []string{}
	case "bool":
		return false
	case "float":
		return float32(0)
	case "float64":
		return float64(0)
	case "slim_cred_t":
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
	default:
		//
		// pointer types
		//
		switch {
		case strings.HasSuffix(t, "*"),
			strings.HasSuffix(t, " *restrict"):
			return uintptr(0)
		}
		switch t {
		case "cap_user_header_t",
			"cap_user_data_t",
			"const cap_user_data_t",
			"sighandler_t":
			return uintptr(0)
		}

		// unknown type
		return nil
	}
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
