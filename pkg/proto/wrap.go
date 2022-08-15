package proto

import (
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/aquasecurity/tracee/types/trace"
)

// Wrap the specified protocol.Event as Event so we can use cel-go without implementing custom ref.TypeProvider.
func Wrap(event trace.Event) (*Event, error) {
	args, err := toArgs(event)
	if err != nil {
		return nil, err
	}
	return &Event{
		Timestamp:           int64(event.Timestamp),
		ThreadStartTime:     int64(event.ThreadStartTime),
		ProcessorId:         int64(event.ProcessorID),
		ProcessId:           int64(event.ProcessID),
		CgroupId:            uint64(event.CgroupID),
		ThreadId:            int64(event.ThreadID),
		ParentProcessId:     int64(event.ParentProcessID),
		HostProcessId:       int64(event.HostProcessID),
		HostThreadId:        int64(event.HostThreadID),
		HostParentProcessId: int64(event.HostParentProcessID),
		UserId:              int64(event.UserID),
		MountNs:             int64(event.MountNS),
		Pidns:               int64(event.PIDNS),
		ProcessName:         event.ProcessName,
		HostName:            event.HostName,
		ContainerId:         event.ContainerID,
		ContainerImage:      event.ContainerImage,
		ContainerName:       event.ContainerName,
		PodName:             event.PodName,
		PodNamespace:        event.PodNamespace,
		PodUid:              event.PodUID,
		EventId:             int64(event.EventID),
		EventName:           event.EventName,
		ArgsNum:             int64(event.ArgsNum),
		ReturnValue:         int64(event.ReturnValue),
		StackAddresses:      event.StackAddresses,
		ContextFlags: &ContextFlags{
			ContainerStarted: event.ContextFlags.ContainerStarted,
		},
		Args: args,
	}, nil
}

func toArgs(event trace.Event) ([]*Argument, error) {
	if event.Args == nil {
		return nil, nil
	}
	args := make([]*Argument, len(event.Args))
	for index, source := range event.Args {
		var err error
		args[index], err = newArg(event, source)
		if err != nil {
			return nil, err
		}
	}
	return args, nil
}

func mapType(str string) ValueType {
	switch str {
	case "string", "const char*":
		return ValueType_STRING
	case "const char**", "const char*const*":
		return ValueType_STRING_ARRAY
	case "bool":
		return ValueType_BOOL

	case "bytes":
		return ValueType_BYTES

	case "unsigned long":
		return ValueType_UINT64

	case "long":
		return ValueType_INT64

	case "unsigned int", "u32", "dev_t", "umode_t", "mode_t":
		return ValueType_UINT32

	case "int", "pid_t":
		return ValueType_INT32

	// pointer types (see eventsreader.go)
	// these types either are specifically pointers OR undefined
	case "void*", "const void*", "struct stat*", "int*", "usigned int*", "unsigned long*":
		return ValueType_POINTER

	case "struct sockaddr*", "const struct sockaddr*":
		return ValueType_SOCKADDR
	case "slim_cred_t":
		return ValueType_SLIM_CRED
	case "[]trace.HookedSymbolData":
		return ValueType_HOOKED_SYMBOL_ARRAY
	case "map[string]trace.HookedSymbolData":
		return ValueType_HOOKED_SYMBOL_MAP
	}
	return ValueType_UNKNOWN_VALUE_TYPE
}

// NOTE There might be cases where casting Go types to Protocol Buffer will panic
// because we don't implement safe type mapping for all available argument types.
// See https://github.com/aquasecurity/tracee/pull/1766

var (
	unrecognizedTypes = sync.Map{}
)

func newArg(event trace.Event, source trace.Argument) (*Argument, error) {
	if source.Type == "" || source.Value == nil {
		return nil, ErrInvalidArgument
	}
	valueType := mapType(source.Type)
	if valueType == ValueType_UNKNOWN_VALUE_TYPE {
		// Since we now handle unrecognized types as pointers by default, this print can spam stderr
		// As such this silenced with a sync.Map check (similar to what's done in loaded_symbols event)
		// This should be moved to debug log once we have a logger enabled
		_, known := unrecognizedTypes.LoadOrStore(source.Type, true)
		if !known {
			fmt.Fprintf(os.Stderr, "\tUnrecognized event arg: eventName: %q name: %q type: %q valueType: %T value: %v\n", event.EventName, source.Name, source.Type, source.Value, source.Value)
		}
	}

	var value Value

	switch valueType {
	case ValueType_STRING:
		v, ok := source.Value.(string)
		if !ok {
			return nil, FailArgWrapError(source.Type)
		}
		value = Value{
			StringValue: &v,
		}
	case ValueType_STRING_ARRAY:
		v, ok := source.Value.([]string)
		if !ok {
			return nil, FailArgWrapError(source.Type)
		}
		value = Value{
			StringArrayValue: v,
		}
	case ValueType_BOOL:
		v, ok := source.Value.(bool)
		if !ok {
			return nil, FailArgWrapError(source.Type)
		}
		value = Value{
			BoolValue: &v,
		}
	case ValueType_BYTES:
		v, ok := source.Value.([]byte)
		if !ok {
			return nil, FailArgWrapError(source.Type)
		}
		value = Value{
			BytesValue: v,
		}
	case ValueType_UINT32:
		switch source.Value.(type) {
		case uint32:
			v, ok := source.Value.(uint32)
			if !ok {
				return nil, FailArgWrapError(source.Type)
			}
			value = Value{
				Uint32Value: &v,
			}
		case uint16:
			v, ok := source.Value.(uint16)
			if !ok {
				return nil, FailArgWrapError(source.Type)
			}
			v32 := uint32(v)
			value = Value{
				Uint32Value: &v32,
			}
		default:
			fmt.Fprintf(os.Stderr, "Unhandled unsigned integer type: %T", source.Value)
		}
	case ValueType_UINT64:
		v, ok := source.Value.(uint64)
		if !ok {
			return nil, FailArgWrapError(source.Type)
		}
		value = Value{
			Uint64Value: &v,
		}
	case ValueType_INT32:
		v, ok := source.Value.(int32)
		if !ok {
			return nil, FailArgWrapError(source.Type)
		}
		value = Value{
			Int32Value: &v,
		}
	case ValueType_INT64:
		v, ok := source.Value.(int64)
		if !ok {
			return nil, FailArgWrapError(source.Type)
		}
		value = Value{
			Int64Value: &v,
		}
	// equivalent to default logic in eventsreader.go
	case ValueType_POINTER, ValueType_UNKNOWN_VALUE_TYPE:
		v, ok := source.Value.(uintptr)
		if !ok {
			return nil, FailArgWrapError(source.Type)
		}
		v64 := uint64(v)
		value = Value{
			PointerValue: &v64,
		}
	case ValueType_SOCKADDR:
		v, ok := source.Value.(map[string]string)
		if !ok {
			return nil, FailArgWrapError(source.Type)
		}
		sockaddr, err := newSockaddr(v)
		if err != nil {
			return nil, err
		}
		value = Value{
			SockaddrValue: sockaddr,
		}
	case ValueType_SLIM_CRED:
		v, ok := source.Value.(trace.SlimCred)
		if !ok {
			return nil, FailArgWrapError(source.Type)
		}
		value = Value{
			SlimcredValue: newSlimcred(v),
		}
	case ValueType_HOOKED_SYMBOL_ARRAY:
		v, ok := source.Value.([]trace.HookedSymbolData)
		if !ok {
			return nil, FailArgWrapError(source.Type)
		}
		value = Value{
			HookedSymbolArrayValue: newHookedSymbolArr(v),
		}
	case ValueType_HOOKED_SYMBOL_MAP:
		v, ok := source.Value.(map[string]trace.HookedSymbolData)
		if !ok {
			return nil, FailArgWrapError(source.Type)
		}
		value = Value{
			HookedSymbolMapValue: newHookedSymbolMap(v),
		}
	default:
		value = Value{}
	}

	return &Argument{
		Name:          source.Name,
		ValueType:     valueType,
		ValueTypeName: source.Type,
		Value:         &value,
	}, nil
}

func newSockaddr(v map[string]string) (*Sockaddr, error) {
	sinPort, err := parsePort(v["sin_port"])
	if err != nil {
		return nil, err
	}
	sin6Port, err := parsePort(v["sin6_port"])
	if err != nil {
		return nil, err
	}
	return &Sockaddr{
		SaFamily: parseSaFamily(v["sa_family"]),
		SunPath:  v["sun_path"],
		SinAddr:  v["sin_addr"],
		SinPort:  sinPort,
		Sin6Addr: v["sin6_addr"],
		Sin6Port: sin6Port,
	}, nil
}

func parseSaFamily(value string) SaFamilyT {
	switch value {
	case "AF_UNIX":
		return SaFamilyT_AF_UNIX
	case "AF_INET":
		return SaFamilyT_AF_INET
	case "AF_INET6":
		return SaFamilyT_AF_INET6
	default:
		return SaFamilyT_SA_FAMILY_T_UNSPEC
	}
}

func parsePort(value string) (uint32, error) {
	if value == "" {
		return 0, nil
	}
	i, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(i), nil
}

func newSlimcred(v trace.SlimCred) *Slimcred {
	return &Slimcred{
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

func newHookedSymbolArr(v []trace.HookedSymbolData) []*Hookedsymbol {
	res := make([]*Hookedsymbol, len(v))
	for i := range v {
		res[i] = &Hookedsymbol{
			SymbolName:  v[i].SymbolName,
			ModuleOwner: v[i].ModuleOwner,
		}
	}

	return res
}

func newHookedSymbolMap(v map[string]trace.HookedSymbolData) map[string]*Hookedsymbol {
	res := map[string]*Hookedsymbol{}
	for key, val := range v {
		res[key] = &Hookedsymbol{
			SymbolName:  val.SymbolName,
			ModuleOwner: val.ModuleOwner,
		}
	}

	return res
}
