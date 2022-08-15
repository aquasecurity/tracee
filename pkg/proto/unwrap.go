package proto

import (
	"strconv"

	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

func Unwrap(e *Event) (protocol.Event, error) {
	traceEvt, err := unwrap(e)
	if err != nil {
		return protocol.Event{}, err
	}

	return traceEvt.ToProtocol(), nil
}

func unwrap(event *Event) (trace.Event, error) {
	args, err := fromArgs(event)
	if err != nil {
		return trace.Event{}, err
	}
	return trace.Event{
		Timestamp:           int(event.Timestamp),
		ThreadStartTime:     int(event.ThreadStartTime),
		ProcessorID:         int(event.ProcessorId),
		ProcessID:           int(event.ProcessId),
		CgroupID:            uint(event.CgroupId),
		ThreadID:            int(event.ThreadId),
		ParentProcessID:     int(event.ParentProcessId),
		HostProcessID:       int(event.HostProcessId),
		HostThreadID:        int(event.HostThreadId),
		HostParentProcessID: int(event.HostParentProcessId),
		UserID:              int(event.UserId),
		MountNS:             int(event.MountNs),
		PIDNS:               int(event.Pidns),
		ProcessName:         event.ProcessName,
		HostName:            event.HostName,
		ContainerID:         event.ContainerId,
		ContainerImage:      event.ContainerImage,
		ContainerName:       event.ContainerName,
		PodName:             event.PodName,
		PodNamespace:        event.PodNamespace,
		PodUID:              event.PodUid,
		EventID:             int(event.EventId),
		EventName:           event.EventName,
		ArgsNum:             int(event.ArgsNum),
		ReturnValue:         int(event.ReturnValue),
		StackAddresses:      event.StackAddresses,
		ContextFlags:        fromContextFlags(event.ContextFlags),
		Args:                args,
	}, nil
}

func fromArgs(event *Event) ([]trace.Argument, error) {
	if event.Args == nil {
		return nil, nil
	}
	args := make([]trace.Argument, len(event.Args))
	for index, source := range event.Args {
		var err error
		args[index], err = fromArg(source)
		if err != nil {
			return nil, err
		}
	}
	return args, nil
}

// var (
// 	valueTypeToString = map[ValueType]string{
// 		ValueType_STRING:       "string",
// 		ValueType_STRING_ARRAY: "const char**",

// 		ValueType_BOOL: "bool",

// 		ValueType_BYTES: "bytes",

// 		ValueType_POINTER: "void*",

// 		ValueType_UINT64: "unsigned long",
// 		ValueType_INT32:  "int",
// 		ValueType_INT64:  "long",
// 		ValueType_UINT32: "unsigned int",

// 		ValueType_SOCKADDR:            "struct sockaddr*",
// 		ValueType_SLIM_CRED:           "slim_cred_t",
// 		ValueType_HOOKED_SYMBOL_ARRAY: "[]trace.HookedSymbolData",
// 		ValueType_HOOKED_SYMBOL_MAP:   "map[string]trace.HookedSymbolData",
// 	}
// )

func fromArg(arg *Argument) (trace.Argument, error) {
	argVal, err := unwrapArgVal(arg.Value, arg.ValueType)
	if err != nil {
		return trace.Argument{}, err
	}
	return trace.Argument{
		ArgMeta: trace.ArgMeta{
			Name: arg.Name,
			Type: arg.ValueTypeName,
		},
		Value: argVal,
	}, nil
}

// unwraps the argument value from the protobuf
// note, "primitive" pointer types such as slices and maps are sent as nil if empty
// as such when "v" is empty for them, being nil is a valid state
func unwrapArgVal(val *Value, valType ValueType) (interface{}, error) {
	switch valType {
	case ValueType_STRING:
		v := val.StringValue
		if v == nil {
			return nil, FailArgUnwrapError(valType.String())
		}
		return *v, nil
	case ValueType_STRING_ARRAY:
		v := val.StringArrayValue
		if v == nil {
			return []string{}, nil // here v == nil represents an empty string slice
		}
		return v, nil
	case ValueType_BOOL:
		v := val.BoolValue
		if v == nil {
			return nil, FailArgUnwrapError(valType.String())
		}
		return *v, nil
	case ValueType_BYTES:
		v := val.BytesValue
		if v == nil {
			return []byte{}, nil
		}
		return v, nil
	case ValueType_UINT64:
		v := val.Uint64Value
		if v == nil {
			return nil, FailArgUnwrapError(valType.String())
		}
		return *v, nil
	case ValueType_UINT32:
		v := val.Uint32Value
		if v == nil {
			return nil, FailArgUnwrapError(valType.String())
		}
		return *v, nil
	case ValueType_INT64:
		v := val.Int64Value
		if v == nil {
			return nil, FailArgUnwrapError(valType.String())
		}
		return *v, nil
	case ValueType_INT32:
		v := val.Int32Value
		if v == nil {
			return nil, FailArgUnwrapError(valType.String())
		}
		return *v, nil
	// unwrap pointer value (see wrap.go)
	case ValueType_POINTER, ValueType_UNKNOWN_VALUE_TYPE:
		v := val.PointerValue
		if v == nil {
			return nil, FailArgUnwrapError(valType.String())
		}
		return uintptr(*v), nil
	case ValueType_SOCKADDR:
		v := val.SockaddrValue
		if v == nil {
			return nil, FailArgUnwrapError(valType.String())
		}
		return fromSockaddr(v), nil
	case ValueType_SLIM_CRED:
		v := val.SlimcredValue
		if v == nil {
			return nil, FailArgUnwrapError(valType.String())
		}
		return fromSlimcred(v), nil
	case ValueType_HOOKED_SYMBOL_ARRAY:
		v := val.HookedSymbolArrayValue
		if v == nil {
			return []trace.HookedSymbolData{}, nil
		}
		return fromHookedSymbolArr(v), nil
	case ValueType_HOOKED_SYMBOL_MAP:
		v := val.HookedSymbolMapValue
		if v == nil {
			return map[string]trace.HookedSymbolData{}, nil
		}
		return fromHookedSymbolMap(v), nil
	}
	// sanity
	return nil, FailArgUnwrapError(valType.String())
}

func fromContextFlags(flags *ContextFlags) trace.ContextFlags {
	if flags == nil {
		return trace.ContextFlags{}
	}
	return trace.ContextFlags{
		ContainerStarted: flags.ContainerStarted,
	}
}

func fromSockaddr(v *Sockaddr) map[string]string {
	return map[string]string{
		"sa_family": saFamilyString(v.SaFamily),
		"sun_path":  v.SunPath,
		"sin_addr":  v.SinAddr,
		"sin6_addr": v.Sin6Addr,
		"sin_port":  strconv.FormatUint(uint64(v.SinPort), 10),
		"sin6_port": strconv.FormatUint(uint64(v.Sin6Port), 10),
	}
}

func saFamilyString(sa SaFamilyT) string {
	switch sa {
	case SaFamilyT_AF_INET:
		return "AF_INET"
	case SaFamilyT_AF_INET6:
		return "AF_INET6"
	case SaFamilyT_AF_UNIX:
		return "AF_UNIX"
	case SaFamilyT_SA_FAMILY_T_UNSPEC:
		return ""
	default:
		return ""
	}
}

func fromSlimcred(v *Slimcred) trace.SlimCred {
	return trace.SlimCred{
		Uid:            v.Uid,
		Gid:            v.Gid,
		Suid:           v.Suid,
		Sgid:           v.Sgid,
		Euid:           v.Euid,
		Egid:           v.Egid,
		Fsuid:          v.Fsuid,
		Fsgid:          v.Fsgid,
		UserNamespace:  v.UserNamespace,
		SecureBits:     v.SecureBits,
		CapInheritable: v.CapInheritable,
		CapPermitted:   v.CapPermitted,
		CapEffective:   v.CapEffective,
		CapBounding:    v.CapBounding,
		CapAmbient:     v.CapAmbient,
	}
}

func fromHookedSymbolArr(v []*Hookedsymbol) []trace.HookedSymbolData {
	res := make([]trace.HookedSymbolData, len(v))
	for i := range v {
		res[i] = trace.HookedSymbolData{
			SymbolName:  v[i].SymbolName,
			ModuleOwner: v[i].ModuleOwner,
		}
	}

	return res
}

func fromHookedSymbolMap(v map[string]*Hookedsymbol) map[string]trace.HookedSymbolData {
	res := map[string]trace.HookedSymbolData{}
	for key, val := range v {
		res[key] = trace.HookedSymbolData{
			SymbolName:  val.SymbolName,
			ModuleOwner: val.ModuleOwner,
		}
	}

	return res
}
