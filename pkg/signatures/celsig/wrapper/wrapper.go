package wrapper

import (
	"fmt"
	"strconv"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

// Wrap the specified protocol.Event as Event so we can use cel-go without implementing custom ref.TypeProvider.
func Wrap(envelope protocol.Event) (*Event, error) {
	event, ok := envelope.Payload.(trace.Event)
	if !ok {
		return nil, fmt.Errorf("unexpected event payload %T", envelope.Payload)
	}
	args, err := toArgs(event)
	if err != nil {
		return nil, err
	}
	return &Event{
		Timestamp:           timestamppb.New(time.Unix(int64(event.Timestamp), 0)),
		ProcessorID:         int64(event.ProcessorID),
		ProcessID:           int64(event.ProcessID),
		CgroupID:            uint64(event.CgroupID),
		ThreadID:            int64(event.ThreadID),
		ParentProcessID:     int64(event.ParentProcessID),
		HostProcessID:       int64(event.HostProcessID),
		HostThreadID:        int64(event.HostThreadID),
		HostParentProcessID: int64(event.HostParentProcessID),
		UserID:              int64(event.UserID),
		MountNS:             int64(event.MountNS),
		PIDNS:               int64(event.PIDNS),
		ProcessName:         event.ProcessName,
		HostName:            event.HostName,
		Container:           wrapContainerData(&event.Container),
		Kubernetes:          wrapKubernetesData(&event.Kubernetes),
		EventID:             int64(event.EventID),
		EventName:           event.EventName,
		ArgsNum:             int64(event.ArgsNum),
		ReturnValue:         int64(event.ReturnValue),
		StackAddresses:      event.StackAddresses,
		Args:                args,
	}, nil
}

func toArgs(event trace.Event) ([]*Argument, error) {
	if event.Args == nil {
		return nil, nil
	}
	args := make([]*Argument, len(event.Args))
	for index, source := range event.Args {
		var err error
		args[index], err = toArg(event, source)
		if err != nil {
			return nil, err
		}
	}
	return args, nil
}

var (
	typesMapping = map[string]ValueType{
		"string":       ValueType_STRING,
		"const char*":  ValueType_STRING,
		"const char**": ValueType_STRING_ARRAY,

		"unsigned long": ValueType_UINT64,
		"int":           ValueType_INT32,

		"dev_t":   ValueType_UINT32,
		"pid_t":   ValueType_INT32,
		"umode_t": ValueType_UINT32,
		"mode_t":  ValueType_UINT32,

		"void*":            ValueType_STRING,
		"struct sockaddr*": ValueType_SOCKADDR,
	}
)

// NOTE There might be cases where casting Go types to Protocol Buffer will panic
// because we don't implement safe type mapping for all available argument types.
// See https://github.com/aquasecurity/tracee/pull/1766
func toArg(event trace.Event, source trace.Argument) (*Argument, error) {
	valueType, ok := typesMapping[source.Type]
	if !ok {
		logger.Errorw("Unrecognized event arg",
			"eventName", event.EventName,
			"name", source.Name,
			"type", source.Type,
			"valueType", fmt.Sprintf("%T", source.Value),
			"value", source.Value,
		)
		valueType = ValueType_UNKNOWN_VALUE_TYPE
	}

	if source.Value == nil {
		return &Argument{
			Name:      source.Name,
			ValueType: valueType,
			Value:     &Value{},
		}, nil
	}

	var value Value

	switch valueType {
	case ValueType_STRING:
		v := source.Value.(string)
		value = Value{
			StringValue: &v,
		}
	case ValueType_STRING_ARRAY:
		v := source.Value.([]string)
		value = Value{
			StringArrayValue: v,
		}
	case ValueType_UINT32:
		switch source.Value.(type) {
		case uint32:
			v := source.Value.(uint32)
			value = Value{
				Uint32Value: &v,
			}
		case uint16:
			v := uint32(source.Value.(uint16))
			value = Value{
				Uint32Value: &v,
			}
		default:
			logger.Errorw("Unhandled unsigned integer type", "type", fmt.Sprintf("%T", source.Value))
		}
	case ValueType_UINT64:
		v := source.Value.(uint64)
		value = Value{
			Uint64Value: &v,
		}
	case ValueType_INT32:
		v := source.Value.(int32)
		value = Value{
			Int32Value: &v,
		}
	case ValueType_INT64:
		v := source.Value.(int64)
		value = Value{
			Int64Value: &v,
		}
	case ValueType_SOCKADDR:
		v := source.Value.(map[string]string)
		sockaddr, err := newSockaddr(v)
		if err != nil {
			return nil, err
		}
		value = Value{
			SockaddrValue: sockaddr,
		}
	default:
		value = Value{}
	}

	return &Argument{
		Name:      source.Name,
		ValueType: valueType,
		Value:     &value,
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

func wrapContainerData(cont *trace.Container) *Container {
	return &Container{
		Id:            cont.ID,
		ImageName:     cont.ImageName,
		ImageDigest:   cont.ImageDigest,
		ContainerName: cont.Name,
	}
}

func wrapKubernetesData(kube *trace.Kubernetes) *Kubernetes {
	return &Kubernetes{
		PodName:      kube.PodName,
		PodNamespace: kube.PodNamespace,
		PodUID:       kube.PodUID,
		PodSandbox:   kube.PodSandbox,
	}
}
