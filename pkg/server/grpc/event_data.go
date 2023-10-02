package grpc

import (
	"strconv"

	"github.com/golang/protobuf/ptypes/wrappers"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	pb "github.com/aquasecurity/tracee/types/api/v1beta1"
	"github.com/aquasecurity/tracee/types/trace"
)

// This was copied for this version, I didn't want to export the types yet,
// because the code for creating a proto will all be removed from here after
// we finish integrating the event structure
const (
	noneT bufferdecoder.ArgType = iota
	intT
	uintT
	longT
	ulongT
	offT
	modeT
	devT
	sizeT
	pointerT
	strT
	strArrT
	sockAddrT
	bytesT
	u16T
	credT
	intArr2T
	uint64ArrT
	u8T
	timespecT
)

const (
	argsArrT bufferdecoder.ArgType = iota + 0x80
	boolT
)

func getEventData(e trace.Event) (map[string]*pb.EventValue, error) {
	data := make(map[string]*pb.EventValue)

	// for syscaslls
	args := make([]*pb.EventValue, 0)

	for _, arg := range e.Args {
		eventValue, err := getEventValue(arg)
		if err != nil {
			return nil, err
		}

		if events.Core.GetDefinitionByID(events.ID(e.EventID)).IsSyscall() {
			args = append(args, eventValue)
			continue
		}

		data[arg.ArgMeta.Name] = eventValue
	}

	if len(args) > 0 {
		data["args"] = &pb.EventValue{
			Value: &pb.EventValue_Args{
				Args: &pb.ArgsValue{
					Value: args,
				},
			},
		}

		data["returnValue"] = &pb.EventValue{
			Value: &pb.EventValue_Int64{
				Int64: wrapperspb.Int64(int64(e.ReturnValue)),
			},
		}
	}

	return data, nil
}

func getEventValue(arg trace.Argument) (*pb.EventValue, error) {

	if arg.Value == nil {
		return nil, nil
	}

	var eventValue *pb.EventValue

	switch bufferdecoder.GetParamType(arg.Type) {
	case intT:
		if v, ok := arg.Value.(int32); ok {
			eventValue = &pb.EventValue{
				Value: &pb.EventValue_Int32{
					Int32: wrapperspb.Int32(v),
				},
			}
		}
	case u8T:
		if v, ok := arg.Value.(uint8); ok {
			eventValue = &pb.EventValue{
				Value: &pb.EventValue_UInt32{
					UInt32: wrapperspb.UInt32(uint32(v)),
				},
			}
		}
	case u16T:
		if v, ok := arg.Value.(uint16); ok {
			eventValue = &pb.EventValue{
				Value: &pb.EventValue_UInt32{
					UInt32: wrapperspb.UInt32(uint32(v)),
				},
			}
		}
	case uintT, modeT, devT, sizeT:
		if v, ok := arg.Value.(uint32); ok {
			eventValue = &pb.EventValue{
				Value: &pb.EventValue_UInt32{
					UInt32: wrapperspb.UInt32(v),
				},
			}
		}
	case longT:
		if v, ok := arg.Value.(int64); ok {
			eventValue = &pb.EventValue{
				Value: &pb.EventValue_Int64{
					Int64: wrapperspb.Int64(v),
				},
			}
		}
	case ulongT, offT:
		if v, ok := arg.Value.(uint64); ok {
			eventValue = &pb.EventValue{
				Value: &pb.EventValue_UInt64{
					UInt64: wrapperspb.UInt64(v),
				},
			}
		}
	case boolT:
		if v, ok := arg.Value.(bool); ok {
			eventValue = &pb.EventValue{
				Value: &pb.EventValue_Bool{
					Bool: wrapperspb.Bool(v),
				},
			}
		}
	case strT:
		if v, ok := arg.Value.(string); ok {
			eventValue = &pb.EventValue{
				Value: &pb.EventValue_Str{
					Str: wrapperspb.String(v),
				},
			}
		}
	case strArrT, argsArrT:
		if v, ok := arg.Value.([]string); ok {
			strArray := make([]*wrappers.StringValue, 0, len(v))

			for _, str := range v {
				strArray = append(strArray, &wrappers.StringValue{Value: str})
			}

			eventValue = &pb.EventValue{
				Value: &pb.EventValue_StrArray{
					StrArray: &pb.StringArrayValue{
						Value: strArray,
					},
				},
			}
		}
	case sockAddrT:
		if v, ok := arg.Value.(map[string]string); ok {
			sockaddr, err := getSockaddr(v)
			if err != nil {
				return nil, err
			}
			eventValue = sockaddr
		}
	case bytesT:
		if v, ok := arg.Value.([]byte); ok {
			eventValue = &pb.EventValue{
				Value: &pb.EventValue_Bytes{
					Bytes: &wrappers.BytesValue{
						Value: v,
					},
				},
			}
		}
	case intArr2T:
		if v, ok := arg.Value.([2]int32); ok {
			intArray := make([]*wrappers.Int32Value, 0, len(v))

			for _, i := range v {
				intArray = append(intArray, &wrappers.Int32Value{Value: i})
			}

			eventValue = &pb.EventValue{
				Value: &pb.EventValue_Int32Array{
					Int32Array: &pb.Int32ArrayValue{
						Value: intArray,
					},
				},
			}
		}
	case credT:
		if v, ok := arg.Value.(trace.SlimCred); ok {
			eventValue = &pb.EventValue{
				Value: &pb.EventValue_Cred{
					Cred: &pb.CredValue{
						Uid:            wrapperspb.UInt32(v.Uid),
						Gid:            wrapperspb.UInt32(v.Gid),
						Suid:           wrapperspb.UInt32(v.Suid),
						Sgid:           wrapperspb.UInt32(v.Sgid),
						Euid:           wrapperspb.UInt32(v.Euid),
						Egid:           wrapperspb.UInt32(v.Egid),
						Fsuid:          wrapperspb.UInt32(v.Fsuid),
						Fsgid:          wrapperspb.UInt32(v.Fsgid),
						UserNamespace:  wrapperspb.UInt32(v.UserNamespace),
						SecureBits:     wrapperspb.UInt32(v.SecureBits),
						CapInheritable: getCaps(v.CapInheritable),
						CapPermitted:   getCaps(v.CapPermitted),
						CapEffective:   getCaps(v.CapEffective),
						CapBounding:    getCaps(v.CapBounding),
						CapAmbient:     getCaps(v.CapAmbient),
					},
				},
			}
		}
	case uint64ArrT:
		if v, ok := arg.Value.([]uint64); ok {
			uintArray := make([]*wrappers.UInt64Value, 0, len(v))

			for _, i := range v {
				uintArray = append(uintArray, &wrappers.UInt64Value{Value: i})
			}

			eventValue = &pb.EventValue{
				Value: &pb.EventValue_UInt64Array{
					UInt64Array: &pb.UInt64ArrayValue{
						Value: uintArray,
					},
				},
			}
		}
	case timespecT:
		if v, ok := arg.Value.(float64); ok {
			eventValue = &pb.EventValue{
				Value: &pb.EventValue_Timespec{
					Timespec: &pb.TimespecValue{
						Value: wrapperspb.Double(v),
					},
				},
			}
		}
	case pointerT:
		if v, ok := arg.Value.(uintptr); ok {
			eventValue = &pb.EventValue{
				Value: &pb.EventValue_UInt64{
					UInt64: wrapperspb.UInt64(uint64(v)),
				},
			}
		}
	default:
		return nil, errfmt.Errorf("unknown arg type: %s - %v", arg.Name, arg.Type)
	}

	if eventValue == nil {
		return nil, errfmt.Errorf("can't convert event data: %s - %v - %T", arg.Name, arg.Value, arg.Value)
	}

	return eventValue, nil
}

func getCaps(c uint64) []pb.Capability {
	if c == 0 {
		return nil
	}

	caps := make([]pb.Capability, 0)

	for i := uint64(0); i < 64; i++ {
		if (1<<i)&c != 0 {
			e := pb.Capability(i)
			caps = append(caps, e)
		}
	}

	return caps
}

func getSockaddr(v map[string]string) (*pb.EventValue, error) {
	var sockaddr *pb.SockAddrValue
	switch v["sa_family"] {
	case "AF_INET":
		sinport, err := strconv.ParseUint(v["sin_port"], 10, 32)
		if err != nil {
			return nil, err
		}

		sockaddr = &pb.SockAddrValue{
			SaFamily: pb.SaFamilyT_AF_INET,
			SinPort:  uint32(sinport),
			SinAddr:  v["sin_addr"],
		}
	case "AF_UNIX":
		sockaddr = &pb.SockAddrValue{
			SaFamily: pb.SaFamilyT_AF_UNIX,
			SunPath:  v["sun_path"],
		}
	case "AF_INET6":
		sinport, err := strconv.ParseUint(v["sin6_port"], 10, 32)
		if err != nil {
			return nil, err
		}

		sin6Flowinfo, err := strconv.ParseUint(v["sin6_flowinfo"], 10, 32)
		if err != nil {
			return nil, err
		}

		sin6Scopeid, err := strconv.ParseUint(v["sin6_scopeid"], 10, 32)
		if err != nil {
			return nil, err
		}

		sockaddr = &pb.SockAddrValue{
			SaFamily:     pb.SaFamilyT_AF_INET6,
			Sin6Port:     uint32(sinport),
			Sin6Flowinfo: uint32(sin6Flowinfo),
			Sin6Scopeid:  uint32(sin6Scopeid),
			Sin6Addr:     v["sin6_addr"],
		}
	}

	return &pb.EventValue{
		Value: &pb.EventValue_Sockaddr{
			Sockaddr: sockaddr,
		},
	}, nil
}
