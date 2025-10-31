package events

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

// ConvertToProto converts a trace.Event to v1beta1.Event for the detector API.
// This is a simplified conversion focused on fields needed by detectors.
// For full conversion (used by gRPC streaming), see pkg/server/grpc/ConvertTraceeEventToProto.
func ConvertToProto(e trace.Event) *pb.Event {
	event := &pb.Event{
		Id:   pb.EventId(e.EventID),
		Name: e.EventName,
	}

	if e.Timestamp != 0 {
		event.Timestamp = timestamppb.New(time.Unix(0, int64(e.Timestamp)))
	}

	// Build workload
	workload := &pb.Workload{}
	hasWorkload := false

	// Process info
	if e.ProcessID != 0 || e.ProcessName != "" {
		thread := &pb.Thread{
			Name:     e.ProcessName,
			UniqueId: wrapperspb.UInt32(e.ThreadEntityId),
			Tid:      wrapperspb.UInt32(uint32(e.ThreadID)),
			HostTid:  wrapperspb.UInt32(uint32(e.HostThreadID)),
			Syscall:  e.Syscall,
			Compat:   e.ContextFlags.IsCompat, // Compat mode (32-bit on 64-bit)
		}
		if e.ThreadStartTime != 0 {
			thread.StartTime = timestamppb.New(time.Unix(0, int64(e.ThreadStartTime)))
		}

		process := &pb.Process{
			Pid:      wrapperspb.UInt32(uint32(e.ProcessID)),
			HostPid:  wrapperspb.UInt32(uint32(e.HostProcessID)),
			UniqueId: wrapperspb.UInt32(e.ProcessEntityId),
			RealUser: &pb.User{
				Id: wrapperspb.UInt32(uint32(e.UserID)),
			},
			Thread: thread,
		}
		if e.Executable.Path != "" {
			process.Executable = &pb.Executable{Path: e.Executable.Path}
		}
		// Add parent/ancestor info if present
		if e.ParentEntityId != 0 {
			process.Ancestors = []*pb.Process{
				{
					UniqueId: wrapperspb.UInt32(e.ParentEntityId),
					HostPid:  wrapperspb.UInt32(uint32(e.HostParentProcessID)),
					Pid:      wrapperspb.UInt32(uint32(e.ParentProcessID)),
				},
			}
		}

		workload.Process = process
		hasWorkload = true
	}

	// Container info
	if e.Container.ID != "" {
		workload.Container = &pb.Container{
			Id:        e.Container.ID,
			Name:      e.Container.Name,
			IsRunning: e.ContextFlags.ContainerStarted,
		}
		if e.Container.ImageName != "" {
			workload.Container.Image = &pb.ContainerImage{
				Name: e.Container.ImageName,
			}
			if e.Container.ImageDigest != "" {
				workload.Container.Image.RepoDigests = []string{e.Container.ImageDigest}
			}
		}
		hasWorkload = true
	}

	// Kubernetes info
	if e.Kubernetes.PodName != "" {
		workload.K8S = &pb.K8S{
			Namespace: &pb.K8SNamespace{
				Name: e.Kubernetes.PodNamespace,
			},
			Pod: &pb.Pod{
				Name: e.Kubernetes.PodName,
				Uid:  e.Kubernetes.PodUID,
			},
		}
		hasWorkload = true
	}

	if hasWorkload {
		event.Workload = workload
	}

	// Policies
	if len(e.MatchedPolicies) > 0 {
		event.Policies = &pb.Policies{
			Matched: e.MatchedPolicies,
		}
	}

	// Threat info from metadata
	if e.Metadata != nil {
		event.Threat = &pb.Threat{
			Name:        e.Metadata.Description,
			Description: e.Metadata.Description,
		}
	}

	// Convert event data (Args) to Data field
	eventData, err := getEventData(e)
	if err != nil {
		logger.Errorw("Failed to convert event data", "event", e.EventName, "error", err)
		// Continue with partial conversion rather than failing completely
	}
	event.Data = eventData

	// Handle DetectedFrom field
	for _, arg := range e.Args {
		if arg.ArgMeta.Name == "detectedFrom" {
			detectedFrom, err := getDetectedFrom(arg)
			if err != nil {
				logger.Errorw("Failed to convert DetectedFrom", "event", e.EventName, "error", err)
			} else {
				event.DetectedFrom = detectedFrom
			}
			break
		}
	}

	return event
}

// ConvertFromProto converts a v1beta1.Event back to trace.Event for the pipeline.
// This is used for detector outputs that need to flow through the rest of the pipeline.
func ConvertFromProto(e *pb.Event) *trace.Event {
	event := &trace.Event{
		EventID:   int(e.Id),
		EventName: e.Name,
	}

	if e.Timestamp != nil {
		event.Timestamp = int(e.Timestamp.AsTime().UnixNano())
	}

	// Convert workload info
	if e.Workload != nil && e.Workload.Process != nil {
		p := e.Workload.Process
		if p.Pid != nil {
			event.ProcessID = int(p.Pid.Value)
		}
		if p.HostPid != nil {
			event.HostProcessID = int(p.HostPid.Value)
		}
		if p.UniqueId != nil {
			event.ProcessEntityId = p.UniqueId.Value
		}
		if p.RealUser != nil && p.RealUser.Id != nil {
			event.UserID = int(p.RealUser.Id.Value)
		}
		if p.Thread != nil {
			event.ProcessName = p.Thread.Name
			event.Syscall = p.Thread.Syscall
			event.ContextFlags.IsCompat = p.Thread.Compat // Compat mode (32-bit on 64-bit)
			if p.Thread.UniqueId != nil {
				event.ThreadEntityId = p.Thread.UniqueId.Value
			}
			if p.Thread.Tid != nil {
				event.ThreadID = int(p.Thread.Tid.Value)
			}
			if p.Thread.HostTid != nil {
				event.HostThreadID = int(p.Thread.HostTid.Value)
			}
			if p.Thread.StartTime != nil {
				event.ThreadStartTime = int(p.Thread.StartTime.AsTime().UnixNano())
			}
		}
		if p.Executable != nil {
			event.Executable.Path = p.Executable.Path
		}
		// Convert parent/ancestor info
		if len(p.Ancestors) > 0 {
			parent := p.Ancestors[0]
			if parent.UniqueId != nil {
				event.ParentEntityId = parent.UniqueId.Value
			}
			if parent.HostPid != nil {
				event.HostParentProcessID = int(parent.HostPid.Value)
			}
			if parent.Pid != nil {
				event.ParentProcessID = int(parent.Pid.Value)
			}
		}
	}

	// Convert container info
	if e.Workload != nil && e.Workload.Container != nil {
		c := e.Workload.Container
		event.ContainerID = c.Id
		event.Container = trace.Container{
			ID:   c.Id,
			Name: c.Name,
		}
		event.ContextFlags.ContainerStarted = c.IsRunning
		if c.Image != nil {
			event.Container.ImageName = c.Image.Name
			if len(c.Image.RepoDigests) > 0 {
				event.Container.ImageDigest = c.Image.RepoDigests[0]
			}
		}
	}

	// Convert kubernetes info
	if e.Workload != nil && e.Workload.K8S != nil && e.Workload.K8S.Pod != nil {
		event.Kubernetes = trace.Kubernetes{
			PodName: e.Workload.K8S.Pod.Name,
			PodUID:  e.Workload.K8S.Pod.Uid,
		}
		if e.Workload.K8S.Namespace != nil {
			event.Kubernetes.PodNamespace = e.Workload.K8S.Namespace.Name
		}
	}

	// Convert policies
	if e.Policies != nil {
		event.MatchedPolicies = e.Policies.Matched
	}

	// Convert threat info to metadata
	if e.Threat != nil {
		event.Metadata = &trace.Metadata{
			Description: e.Threat.Name,
			Properties:  make(map[string]interface{}),
		}
	}

	// Convert Data field back to Args
	if len(e.Data) > 0 {
		event.Args = convertDataToArgs(e.Data)
	}

	// Convert DetectedFrom back to detectedFrom argument
	if e.DetectedFrom != nil {
		detectedFromArg := convertDetectedFromToArg(e.DetectedFrom)
		event.Args = append(event.Args, detectedFromArg)
	}

	return event
}

// getEventData converts trace.Event.Args to protobuf EventValue array
func getEventData(e trace.Event) ([]*pb.EventValue, error) {
	data := make([]*pb.EventValue, 0, len(e.Args))

	for _, arg := range e.Args {
		// Handle special detectedFrom argument (corresponds to DetectedFrom in protobuf)
		if arg.ArgMeta.Name == "detectedFrom" {
			// Skip it here - it will be handled separately in ConvertToProto
			continue
		}

		eventValue, err := parseArgument(arg)
		if err != nil {
			return nil, errfmt.Errorf("can't convert event data: %s - %v - %T", arg.Name, arg.Value, arg.Value)
		}

		// Skip if conversion not supported for this type
		if eventValue == nil {
			logger.Errorw(
				"Can't convert event argument. Please add it as a GRPC event data type or implement detect.FindingDataStruct interface.",
				"name", arg.Name,
				"type", fmt.Sprintf("%T", arg.Value),
			)
			continue
		}

		eventValue.Name = arg.ArgMeta.Name
		data = append(data, eventValue)
	}

	// Add return value for syscalls
	def := Core.GetDefinitionByID(ID(e.EventID))
	if def.IsSyscall() {
		data = append(data, &pb.EventValue{
			Name: "returnValue",
			Value: &pb.EventValue_Int64{
				Int64: int64(e.ReturnValue),
			},
		})
	}

	return data, nil
}

// parseArgument converts a single trace.Argument to protobuf EventValue
func parseArgument(arg trace.Argument) (*pb.EventValue, error) {
	switch v := arg.Value.(type) {
	case nil:
		return &pb.EventValue{Value: nil}, nil

	case int:
		return &pb.EventValue{Value: &pb.EventValue_Int64{Int64: int64(v)}}, nil

	case int32:
		return &pb.EventValue{Value: &pb.EventValue_Int32{Int32: v}}, nil

	case uint8:
		return &pb.EventValue{Value: &pb.EventValue_UInt32{UInt32: uint32(v)}}, nil

	case uint16:
		return &pb.EventValue{Value: &pb.EventValue_UInt32{UInt32: uint32(v)}}, nil

	case uint32:
		return &pb.EventValue{Value: &pb.EventValue_UInt32{UInt32: v}}, nil

	case int64:
		return &pb.EventValue{Value: &pb.EventValue_Int64{Int64: v}}, nil

	case uint64:
		return &pb.EventValue{Value: &pb.EventValue_UInt64{UInt64: v}}, nil

	case bool:
		return &pb.EventValue{Value: &pb.EventValue_Bool{Bool: v}}, nil

	case string:
		return &pb.EventValue{Value: &pb.EventValue_Str{Str: v}}, nil

	case []string:
		return &pb.EventValue{Value: &pb.EventValue_StrArray{StrArray: &pb.StringArray{Value: v}}}, nil

	case map[string]string:
		return getSockaddr(v)

	case []byte:
		return &pb.EventValue{Value: &pb.EventValue_Bytes{Bytes: v}}, nil

	case [2]int32:
		intArray := make([]int32, 0, len(v))
		for _, i := range v {
			intArray = append(intArray, i)
		}
		return &pb.EventValue{Value: &pb.EventValue_Int32Array{Int32Array: &pb.Int32Array{Value: intArray}}}, nil

	case trace.SlimCred:
		return &pb.EventValue{
			Value: &pb.EventValue_Credentials{
				Credentials: &pb.Credentials{
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
		}, nil

	case []uint64:
		return &pb.EventValue{Value: &pb.EventValue_UInt64Array{UInt64Array: &pb.UInt64Array{Value: v}}}, nil

	case float64:
		return &pb.EventValue{Value: &pb.EventValue_Timespec{Timespec: &pb.Timespec{Value: wrapperspb.Double(v)}}}, nil

	case time.Time:
		// Convert time.Time to nanoseconds since epoch (uint64)
		return &pb.EventValue{Value: &pb.EventValue_UInt64{UInt64: uint64(v.UnixNano())}}, nil

	case uintptr:
		return &pb.EventValue{Value: &pb.EventValue_UInt64{UInt64: uint64(v)}}, nil

	case trace.ProtoIPv4:
		return convertIpv4(&v)
	case *trace.ProtoIPv4:
		return convertIpv4(v)

	case trace.ProtoIPv6:
		return convertIpv6(&v)
	case *trace.ProtoIPv6:
		return convertIpv6(v)

	case trace.ProtoTCP:
		return convertTcp(&v)
	case *trace.ProtoTCP:
		return convertTcp(v)

	case trace.ProtoUDP:
		return convertUdp(&v)
	case *trace.ProtoUDP:
		return convertUdp(v)

	case trace.ProtoICMP:
		return convertIcmp(&v)
	case *trace.ProtoICMP:
		return convertIcmp(v)

	case trace.ProtoICMPv6:
		return convertIcmpv6(&v)
	case *trace.ProtoICMPv6:
		return convertIcmpv6(v)

	case trace.ProtoDNS:
		return convertDns(&v)
	case *trace.ProtoDNS:
		return convertDns(v)

	case trace.PktMeta:
		return convertPktMeta(&v)
	case *trace.PktMeta:
		return convertPktMeta(v)

	case trace.ProtoHTTP:
		return convertProtoHttp(&v)
	case *trace.ProtoHTTP:
		return convertProtoHttp(v)

	case trace.ProtoHTTPRequest:
		return convertProtoHttpRequest(&v)
	case *trace.ProtoHTTPRequest:
		return convertProtoHttpRequest(v)

	case trace.ProtoHTTPResponse:
		return convertProtoHTTPResponse(&v)
	case *trace.ProtoHTTPResponse:
		return convertProtoHTTPResponse(v)

	case []trace.DnsQueryData:
		questions := make([]*pb.DnsQueryData, len(v))
		for i, q := range v {
			questions[i] = &pb.DnsQueryData{
				Query:      q.Query,
				QueryType:  q.QueryType,
				QueryClass: q.QueryClass,
			}
		}
		return &pb.EventValue{
			Value: &pb.EventValue_DnsQuestions{
				DnsQuestions: &pb.DnsQuestions{Questions: questions},
			},
		}, nil

	case []trace.DnsResponseData:
		responses := make([]*pb.DnsResponseData, len(v))
		for i, r := range v {
			answer := make([]*pb.DnsAnswer, len(r.DnsAnswer))
			for j, a := range r.DnsAnswer {
				answer[j] = &pb.DnsAnswer{
					Type:   a.Type,
					Ttl:    a.Ttl,
					Answer: a.Answer,
				}
			}
			responses[i] = &pb.DnsResponseData{
				DnsQueryData: &pb.DnsQueryData{
					Query:      r.QueryData.Query,
					QueryType:  r.QueryData.QueryType,
					QueryClass: r.QueryData.QueryClass,
				},
				DnsAnswer: answer,
			}
		}
		return &pb.EventValue{
			Value: &pb.EventValue_DnsResponses{
				DnsResponses: &pb.DnsResponses{Responses: responses},
			},
		}, nil

	case []trace.HookedSymbolData:
		syscalls := make([]*pb.HookedSymbolData, len(v))
		for i, s := range v {
			syscalls[i] = &pb.HookedSymbolData{
				SymbolName:  s.SymbolName,
				ModuleOwner: s.ModuleOwner,
			}
		}
		return &pb.EventValue{
			Value: &pb.EventValue_HookedSyscalls{
				HookedSyscalls: &pb.HookedSyscalls{Value: syscalls},
			},
		}, nil

	case map[string]trace.HookedSymbolData:
		m := make(map[string]*pb.HookedSymbolData)
		for k, v := range v {
			m[k] = &pb.HookedSymbolData{
				SymbolName:  v.SymbolName,
				ModuleOwner: v.ModuleOwner,
			}
		}
		return &pb.EventValue{
			Value: &pb.EventValue_HookedSeqOps{
				HookedSeqOps: &pb.HookedSeqOps{Value: m},
			},
		}, nil

	case net.IP: // DNS events use net.IP on src/dst
		return &pb.EventValue{Value: &pb.EventValue_Str{Str: v.String()}}, nil
	}

	// Try struct conversion for custom types
	return convertToStruct(arg)
}

// Helper functions for specific type conversions

func getCaps(c uint64) []pb.Capability {
	if c == 0 {
		return nil
	}

	caps := make([]pb.Capability, 0)
	for i := uint64(0); i < 64; i++ {
		if (1<<i)&c != 0 {
			caps = append(caps, pb.Capability(i))
		}
	}
	return caps
}

func getSockaddr(v map[string]string) (*pb.EventValue, error) {
	var sockaddr *pb.SockAddr
	switch v["sa_family"] {
	case "AF_INET":
		sinport, err := strconv.ParseUint(v["sin_port"], 10, 32)
		if err != nil {
			return nil, err
		}
		sockaddr = &pb.SockAddr{
			SaFamily: pb.SaFamilyT_AF_INET,
			SinPort:  uint32(sinport),
			SinAddr:  v["sin_addr"],
		}

	case "AF_UNIX":
		sockaddr = &pb.SockAddr{
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
		sockaddr = &pb.SockAddr{
			SaFamily:     pb.SaFamilyT_AF_INET6,
			Sin6Port:     uint32(sinport),
			Sin6Flowinfo: uint32(sin6Flowinfo),
			Sin6Scopeid:  uint32(sin6Scopeid),
			Sin6Addr:     v["sin6_addr"],
		}
	}

	return &pb.EventValue{Value: &pb.EventValue_Sockaddr{Sockaddr: sockaddr}}, nil
}

// getDetectedFrom converts detectedFrom argument to DetectedFrom protobuf message
func getDetectedFrom(detectedFromArg trace.Argument) (*pb.DetectedFrom, error) {
	m, ok := detectedFromArg.Value.(map[string]interface{})
	if !ok {
		return nil, errfmt.Errorf("error getting detected from event: %v", detectedFromArg.Value)
	}

	detectedFrom := &pb.DetectedFrom{}

	id, ok := m["id"].(int)
	if !ok {
		return nil, errfmt.Errorf("error getting id of detected from event: %v", m)
	}
	detectedFrom.Id = uint32(id)

	name, ok := m["name"].(string)
	if !ok {
		return nil, errfmt.Errorf("error getting name of detected from event: %v", m)
	}
	detectedFrom.Name = name

	detectedFromEventArgs, ok := m["args"].([]trace.Argument)
	if !ok {
		return nil, errfmt.Errorf("error getting args of detected from event: %v", m)
	}

	data := make([]*pb.EventValue, 0, len(detectedFromEventArgs))
	for _, arg := range detectedFromEventArgs {
		eventValue, err := parseArgument(arg)
		if err != nil {
			return nil, err
		}
		eventValue.Name = arg.ArgMeta.Name
		data = append(data, eventValue)
	}

	def := Core.GetDefinitionByID(ID(id))
	if def.IsSyscall() {
		data = append(data, &pb.EventValue{
			Name: "returnValue",
			Value: &pb.EventValue_Int64{
				Int64: int64(m["returnValue"].(int)),
			},
		})
	}

	detectedFrom.Data = data
	return detectedFrom, nil
}

// Network protocol converters

func convertIpv4(v *trace.ProtoIPv4) (*pb.EventValue, error) {
	return &pb.EventValue{
		Value: &pb.EventValue_Ipv4{
			Ipv4: &pb.IPv4{
				Version:    uint32(v.Version),
				Ihl:        uint32(v.IHL),
				Tos:        uint32(v.TOS),
				Length:     uint32(v.Length),
				Id:         uint32(v.Id),
				Flags:      uint32(v.Flags),
				FragOffset: uint32(v.FragOffset),
				Ttl:        uint32(v.TTL),
				Protocol:   v.Protocol,
				Checksum:   uint32(v.Checksum),
				SrcIp:      v.SrcIP,
				DstIp:      v.DstIP,
			},
		},
	}, nil
}

func convertIpv6(v *trace.ProtoIPv6) (*pb.EventValue, error) {
	return &pb.EventValue{
		Value: &pb.EventValue_Ipv6{
			Ipv6: &pb.IPv6{
				Version:      uint32(v.Version),
				TrafficClass: uint32(v.TrafficClass),
				FlowLabel:    v.FlowLabel,
				Length:       uint32(v.Length),
				NextHeader:   v.NextHeader,
				HopLimit:     uint32(v.HopLimit),
				SrcIp:        v.SrcIP,
				DstIp:        v.DstIP,
			},
		},
	}, nil
}

func convertTcp(v *trace.ProtoTCP) (*pb.EventValue, error) {
	return &pb.EventValue{
		Value: &pb.EventValue_Tcp{
			Tcp: &pb.TCP{
				SrcPort:    uint32(v.SrcPort),
				DstPort:    uint32(v.DstPort),
				Seq:        v.Seq,
				Ack:        v.Ack,
				DataOffset: uint32(v.DataOffset),
				FinFlag:    uint32(v.FIN),
				SynFlag:    uint32(v.SYN),
				RstFlag:    uint32(v.RST),
				PshFlag:    uint32(v.PSH),
				AckFlag:    uint32(v.ACK),
				UrgFlag:    uint32(v.URG),
				EceFlag:    uint32(v.ECE),
				CwrFlag:    uint32(v.CWR),
				NsFlag:     uint32(v.NS),
				Window:     uint32(v.Window),
				Checksum:   uint32(v.Checksum),
				Urgent:     uint32(v.Urgent),
			},
		},
	}, nil
}

func convertUdp(v *trace.ProtoUDP) (*pb.EventValue, error) {
	return &pb.EventValue{
		Value: &pb.EventValue_Udp{
			Udp: &pb.UDP{
				SrcPort:  uint32(v.SrcPort),
				DstPort:  uint32(v.DstPort),
				Length:   uint32(v.Length),
				Checksum: uint32(v.Checksum),
			},
		},
	}, nil
}

func convertIcmp(v *trace.ProtoICMP) (*pb.EventValue, error) {
	return &pb.EventValue{
		Value: &pb.EventValue_Icmp{
			Icmp: &pb.ICMP{
				TypeCode: v.TypeCode,
				Checksum: uint32(v.Checksum),
				Id:       uint32(v.Id),
				Seq:      uint32(v.Seq),
			},
		},
	}, nil
}

func convertIcmpv6(v *trace.ProtoICMPv6) (*pb.EventValue, error) {
	return &pb.EventValue{
		Value: &pb.EventValue_Icmpv6{
			Icmpv6: &pb.ICMPv6{
				TypeCode: v.TypeCode,
				Checksum: uint32(v.Checksum),
			},
		},
	}, nil
}

func convertDns(v *trace.ProtoDNS) (*pb.EventValue, error) {
	questions := make([]*pb.DNSQuestion, len(v.Questions))
	for i, q := range v.Questions {
		questions[i] = &pb.DNSQuestion{
			Name:  q.Name,
			Type:  q.Type,
			Class: q.Class,
		}
	}

	answers := make([]*pb.DNSResourceRecord, len(v.Answers))
	for i, a := range v.Answers {
		answers[i] = getDNSResourceRecord(a)
	}

	authorities := make([]*pb.DNSResourceRecord, len(v.Authorities))
	for i, a := range v.Authorities {
		authorities[i] = getDNSResourceRecord(a)
	}

	additionals := make([]*pb.DNSResourceRecord, len(v.Additionals))
	for i, a := range v.Additionals {
		additionals[i] = getDNSResourceRecord(a)
	}

	return &pb.EventValue{
		Value: &pb.EventValue_Dns{
			Dns: &pb.DNS{
				Id:           uint32(v.ID),
				Qr:           uint32(v.QR),
				OpCode:       v.OpCode,
				Aa:           uint32(v.AA),
				Tc:           uint32(v.TC),
				Rd:           uint32(v.RD),
				Ra:           uint32(v.RA),
				Z:            uint32(v.Z),
				ResponseCode: v.ResponseCode,
				QdCount:      uint32(v.QDCount),
				AnCount:      uint32(v.ANCount),
				NsCount:      uint32(v.NSCount),
				ArCount:      uint32(v.ARCount),
				Questions:    questions,
				Answers:      answers,
				Authorities:  authorities,
				Additionals:  additionals,
			},
		},
	}, nil
}

func getDNSResourceRecord(source trace.ProtoDNSResourceRecord) *pb.DNSResourceRecord {
	opts := make([]*pb.DNSOPT, len(source.OPT))
	for i, o := range source.OPT {
		opts[i] = &pb.DNSOPT{
			Code: o.Code,
			Data: o.Data,
		}
	}

	return &pb.DNSResourceRecord{
		Name:  source.Name,
		Type:  source.Type,
		Class: source.Class,
		Ttl:   uint32(source.TTL),
		Ip:    source.IP,
		Ns:    source.NS,
		Cname: source.CNAME,
		Ptr:   source.PTR,
		Txts:  source.TXTs,
		Soa: &pb.DNSSOA{
			Mname:   source.SOA.MName,
			Rname:   source.SOA.RName,
			Serial:  source.SOA.Serial,
			Refresh: source.SOA.Refresh,
			Retry:   source.SOA.Retry,
			Expire:  source.SOA.Expire,
			Minimum: source.SOA.Minimum,
		},
		Srv: &pb.DNSSRV{
			Priority: uint32(source.SRV.Priority),
			Weight:   uint32(source.SRV.Weight),
			Port:     uint32(source.SRV.Port),
			Name:     source.SRV.Name,
		},
		Mx: &pb.DNSMX{
			Preference: uint32(source.MX.Preference),
			Name:       source.MX.Name,
		},
		Opt: opts,
		Uri: &pb.DNSURI{
			Priority: uint32(source.URI.Priority),
			Weight:   uint32(source.URI.Weight),
			Target:   source.URI.Target,
		},
		Txt: source.TXT,
	}
}

func convertPktMeta(v *trace.PktMeta) (*pb.EventValue, error) {
	return &pb.EventValue{
		Value: &pb.EventValue_PacketMetadata{
			PacketMetadata: &pb.PacketMetadata{
				SrcIp:     v.SrcIP,
				DstIp:     v.DstIP,
				SrcPort:   uint32(v.SrcPort),
				DstPort:   uint32(v.DstPort),
				Protocol:  uint32(v.Protocol),
				PacketLen: v.PacketLen,
				Iface:     v.Iface,
			},
		},
	}, nil
}

// HTTP protocol converters

func getHeaders(source http.Header) map[string]*pb.HttpHeader {
	headers := make(map[string]*pb.HttpHeader)
	for k, v := range source {
		headers[k] = &pb.HttpHeader{Header: v}
	}
	return headers
}

func convertProtoHTTPResponse(v *trace.ProtoHTTPResponse) (*pb.EventValue, error) {
	return &pb.EventValue{
		Value: &pb.EventValue_HttpResponse{
			HttpResponse: &pb.HTTPResponse{
				Status:        v.Status,
				StatusCode:    int32(v.StatusCode),
				Protocol:      v.Protocol,
				Headers:       getHeaders(v.Headers),
				ContentLength: v.ContentLength,
			},
		},
	}, nil
}

func convertProtoHttpRequest(v *trace.ProtoHTTPRequest) (*pb.EventValue, error) {
	return &pb.EventValue{
		Value: &pb.EventValue_HttpRequest{
			HttpRequest: &pb.HTTPRequest{
				Method:        v.Method,
				Protocol:      v.Protocol,
				Host:          v.Host,
				UriPath:       v.URIPath,
				Headers:       getHeaders(v.Headers),
				ContentLength: v.ContentLength,
			},
		},
	}, nil
}

func convertProtoHttp(v *trace.ProtoHTTP) (*pb.EventValue, error) {
	return &pb.EventValue{
		Value: &pb.EventValue_Http{
			Http: &pb.HTTP{
				Direction:     v.Direction,
				Method:        v.Method,
				Protocol:      v.Protocol,
				Host:          v.Host,
				UriPath:       v.URIPath,
				Status:        v.Status,
				StatusCode:    int32(v.StatusCode),
				Headers:       getHeaders(v.Headers),
				ContentLength: v.ContentLength,
			},
		},
	}, nil
}

func convertToStruct(arg trace.Argument) (*pb.EventValue, error) {
	i, ok := arg.Value.(detect.FindingDataStruct)
	if !ok {
		return nil, nil
	}

	if m := i.ToMap(); m != nil {
		structValue, err := structpb.NewStruct(m)
		if err != nil {
			return nil, err
		}

		return &pb.EventValue{
			Value: &pb.EventValue_Struct{Struct: structValue},
		}, nil
	}

	return nil, nil
}

// convertDataToArgs converts protobuf EventValue array back to trace.Argument array
func convertDataToArgs(data []*pb.EventValue) []trace.Argument {
	args := make([]trace.Argument, 0, len(data))

	for _, ev := range data {
		// Skip returnValue as it's handled separately
		if ev.Name == "returnValue" {
			continue
		}

		arg := trace.Argument{
			ArgMeta: trace.ArgMeta{
				Name: ev.Name,
			},
		}

		// Convert EventValue back to appropriate Go type
		switch v := ev.Value.(type) {
		case *pb.EventValue_Int32:
			arg.Value = v.Int32
		case *pb.EventValue_Int64:
			arg.Value = v.Int64
		case *pb.EventValue_UInt32:
			arg.Value = v.UInt32
		case *pb.EventValue_UInt64:
			arg.Value = v.UInt64
		case *pb.EventValue_Str:
			arg.Value = v.Str
		case *pb.EventValue_Bool:
			arg.Value = v.Bool
		case *pb.EventValue_Bytes:
			arg.Value = v.Bytes
		case *pb.EventValue_StrArray:
			if v.StrArray != nil {
				arg.Value = v.StrArray.Value
			}
		case *pb.EventValue_Int32Array:
			if v.Int32Array != nil {
				arg.Value = v.Int32Array.Value
			}
		case *pb.EventValue_UInt64Array:
			if v.UInt64Array != nil {
				arg.Value = v.UInt64Array.Value
			}
		default:
			// For complex types, store the protobuf value directly
			// The receiver can handle protobuf types if needed
			arg.Value = ev
		}

		args = append(args, arg)
	}

	return args
}

// convertDetectedFromToArg converts DetectedFrom protobuf message back to detectedFrom argument
func convertDetectedFromToArg(detectedFrom *pb.DetectedFrom) trace.Argument {
	// Build the map structure expected by trace.Argument
	detectedFromMap := make(map[string]interface{})
	detectedFromMap["id"] = int(detectedFrom.Id)
	detectedFromMap["name"] = detectedFrom.Name

	// Convert data back to args
	args := convertDataToArgs(detectedFrom.Data)
	detectedFromMap["args"] = args

	// Extract return value if present
	for _, ev := range detectedFrom.Data {
		if ev.Name == "returnValue" {
			if v, ok := ev.Value.(*pb.EventValue_Int64); ok {
				detectedFromMap["returnValue"] = int(v.Int64)
			}
		}
	}

	return trace.Argument{
		ArgMeta: trace.ArgMeta{
			Name: "detectedFrom",
		},
		Value: detectedFromMap,
	}
}
