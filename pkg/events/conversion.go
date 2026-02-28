package events

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/gopacket/layers"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

// ConvertTraceeEventToProto converts a trace.Event to v1beta1.Event with full error handling.
// This function matches the signature expected by the gRPC server and can be used as a drop-in replacement.
// It uses the event ID translation table to convert internal event IDs to external protobuf Event IDs.
func ConvertTraceeEventToProto(e trace.Event) (*pb.Event, error) {
	event := ConvertToProto(&e)
	// Apply event ID translation for gRPC API compatibility
	event.Id = TranslateEventID(e.EventID)
	return event, nil
}

// ConvertToProto converts a trace.Event to v1beta1.Event.
// This allocates a fresh slab from the pool. For pipeline use, prefer
// PipelineEvent.ToProto() which manages slab lifecycle automatically.
func ConvertToProto(e *trace.Event) *pb.Event {
	slab := protoSlabPool.Get().(*eventSlab)
	slab.reset()
	return FillProtoSlab(e, slab)
}

// FillProtoSlab converts a trace.Event into the slab-allocated pb.Event.
// All sub-objects (Workload, Process, Thread, etc.) point into the slab
// instead of being individually heap-allocated.
func FillProtoSlab(e *trace.Event, s *eventSlab) *pb.Event {
	event := &s.event
	event.Id = pb.EventId(e.EventID)
	event.Name = sanitizeStringForProtobuf(e.EventName)

	if e.Timestamp != 0 {
		t := time.Unix(0, int64(e.Timestamp))
		s.timestamps[0].Seconds = t.Unix()
		s.timestamps[0].Nanos = int32(t.Nanosecond())
		event.Timestamp = &s.timestamps[0]
	}

	// Build workload using slab-allocated sub-objects
	workload := &s.workload
	hasWorkload := false

	// Process info
	if e.ProcessID != 0 || e.ProcessName != "" {
		var userStackTrace *pb.UserStackTrace
		if len(e.StackAddresses) > 0 {
			s.userStackTrace.Addresses = getStackAddress(e.StackAddresses)
			userStackTrace = &s.userStackTrace
		}

		thread := &s.thread
		thread.Name = sanitizeStringForProtobuf(e.ProcessName)
		s.uint32s[0].Value = e.ThreadEntityId
		thread.UniqueId = &s.uint32s[0]
		s.uint32s[1].Value = uint32(e.ThreadID)
		thread.Tid = &s.uint32s[1]
		s.uint32s[2].Value = uint32(e.HostThreadID)
		thread.HostTid = &s.uint32s[2]
		thread.Syscall = sanitizeStringForProtobuf(e.Syscall)
		thread.Compat = e.ContextFlags.IsCompat
		thread.UserStackTrace = userStackTrace

		if e.ThreadStartTime != 0 {
			t := time.Unix(0, int64(e.ThreadStartTime))
			s.timestamps[1].Seconds = t.Unix()
			s.timestamps[1].Nanos = int32(t.Nanosecond())
			thread.StartTime = &s.timestamps[1]
		}

		process := &s.process
		s.uint32s[3].Value = uint32(e.ProcessID)
		process.Pid = &s.uint32s[3]
		s.uint32s[4].Value = uint32(e.HostProcessID)
		process.HostPid = &s.uint32s[4]
		s.uint32s[5].Value = e.ProcessEntityId
		process.UniqueId = &s.uint32s[5]

		user := &s.user
		s.uint32s[6].Value = uint32(e.UserID)
		user.Id = &s.uint32s[6]
		process.RealUser = user

		process.Thread = thread

		if e.Executable.Path != "" {
			s.executable.Path = sanitizeStringForProtobuf(e.Executable.Path)
			process.Executable = &s.executable
		}

		// Add parent/ancestor info if present
		if e.ParentEntityId != 0 {
			ancestor := &s.ancestor
			s.uint32s[7].Value = e.ParentEntityId
			ancestor.UniqueId = &s.uint32s[7]
			s.uint32s[8].Value = uint32(e.HostParentProcessID)
			ancestor.HostPid = &s.uint32s[8]
			s.uint32s[9].Value = uint32(e.ParentProcessID)
			ancestor.Pid = &s.uint32s[9]
			process.Ancestors = []*pb.Process{ancestor}
		}

		workload.Process = process
		hasWorkload = true
	}

	// Container info
	if e.Container.ID != "" {
		container := &s.container
		container.Id = sanitizeStringForProtobuf(e.Container.ID)
		container.Name = sanitizeStringForProtobuf(e.Container.Name)
		container.Started = e.ContextFlags.ContainerStarted

		if e.Container.ImageName != "" {
			img := &s.containerImage
			img.Name = sanitizeStringForProtobuf(e.Container.ImageName)
			if e.Container.ImageDigest != "" {
				img.RepoDigests = []string{sanitizeStringForProtobuf(e.Container.ImageDigest)}
			}
			container.Image = img
		}
		workload.Container = container
		hasWorkload = true
	}

	// Kubernetes info
	if e.Kubernetes.PodName != "" {
		k8s := &s.k8s
		ns := &s.k8sNamespace
		ns.Name = sanitizeStringForProtobuf(e.Kubernetes.PodNamespace)
		k8s.Namespace = ns
		pod := &s.pod
		pod.Name = e.Kubernetes.PodName
		pod.Uid = e.Kubernetes.PodUID
		k8s.Pod = pod
		workload.K8S = k8s
		hasWorkload = true
	}

	if hasWorkload {
		event.Workload = workload
	}

	// Policies
	if len(e.MatchedPolicies) > 0 {
		s.policies.Matched = sanitizeStringArrayForProtobuf(e.MatchedPolicies)
		event.Policies = &s.policies
	}

	// Threat info from metadata
	if e.Metadata != nil {
		event.Threat = getThreat(e.Metadata.Description, e.Metadata.Properties)
	}

	// Convert event data (Args) using slab-allocated EventValues
	eventData, err := getEventDataSlab(*e, s)
	if err != nil {
		logger.Errorw("Failed to convert event data", "event", e.EventName, "error", err)
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
		event.ContextFlags.ContainerStarted = c.Started
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
		event.ArgsNum = len(event.Args)
	}

	// Convert DetectedFrom back to detectedFrom argument
	if e.DetectedFrom != nil {
		detectedFromArg := convertDetectedFromToArg(e.DetectedFrom)
		event.Args = append(event.Args, detectedFromArg)
		event.ArgsNum = len(event.Args)
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

		eventValue.Name = sanitizeStringForProtobuf(arg.ArgMeta.Name)
		data = append(data, eventValue)
	}

	return data, nil
}

// getEventDataSlab converts trace.Event.Args to protobuf EventValue array,
// using the slab's pre-allocated EventValue slots for the first maxSlabArgs args.
func getEventDataSlab(e trace.Event, s *eventSlab) ([]*pb.EventValue, error) {
	data := make([]*pb.EventValue, 0, len(e.Args))
	slabIdx := 0

	for _, arg := range e.Args {
		if arg.ArgMeta.Name == "detectedFrom" {
			continue
		}

		var ev *pb.EventValue
		if slabIdx < maxSlabArgs {
			ev = &s.dataValues[slabIdx]
			s.dataPtrs[slabIdx] = ev
			err := fillEventValue(ev, arg)
			if err != nil {
				return nil, errfmt.Errorf("can't convert event data: %s - %v - %T", arg.Name, arg.Value, arg.Value)
			}
			// fillEventValue returns a nil-value sentinel for unsupported types
			if ev.Value == nil && arg.Value != nil {
				// Try struct conversion as fallback (allocates)
				allocated, err := convertToStruct(arg)
				if err != nil {
					return nil, errfmt.Errorf("can't convert event data: %s - %v - %T", arg.Name, arg.Value, arg.Value)
				}
				if allocated == nil {
					logger.Errorw(
						"Can't convert event argument. Please add it as a GRPC event data type or implement detect.FindingDataStruct interface.",
						"name", arg.Name,
						"type", fmt.Sprintf("%T", arg.Value),
					)
					continue
				}
				allocated.Name = sanitizeStringForProtobuf(arg.ArgMeta.Name)
				data = append(data, allocated)
				continue
			}
			slabIdx++
		} else {
			// Overflow: fall back to heap-allocated EventValue
			var err error
			ev, err = parseArgument(arg)
			if err != nil {
				return nil, errfmt.Errorf("can't convert event data: %s - %v - %T", arg.Name, arg.Value, arg.Value)
			}
			if ev == nil {
				logger.Errorw(
					"Can't convert event argument. Please add it as a GRPC event data type or implement detect.FindingDataStruct interface.",
					"name", arg.Name,
					"type", fmt.Sprintf("%T", arg.Value),
				)
				continue
			}
		}

		ev.Name = sanitizeStringForProtobuf(arg.ArgMeta.Name)
		data = append(data, ev)
	}

	return data, nil
}

// fillEventValue sets the value on an existing (slab-allocated) EventValue
// instead of allocating a new one. Returns nil error on success.
// For unsupported types, it leaves ev.Value as nil so the caller can try
// struct conversion.
func fillEventValue(ev *pb.EventValue, arg trace.Argument) error {
	switch v := arg.Value.(type) {
	case nil:
		ev.Value = nil
	case int:
		ev.Value = &pb.EventValue_Int64{Int64: int64(v)}
	case int32:
		ev.Value = &pb.EventValue_Int32{Int32: v}
	case uint8:
		ev.Value = &pb.EventValue_UInt32{UInt32: uint32(v)}
	case uint16:
		ev.Value = &pb.EventValue_UInt32{UInt32: uint32(v)}
	case uint32:
		ev.Value = &pb.EventValue_UInt32{UInt32: v}
	case int64:
		ev.Value = &pb.EventValue_Int64{Int64: v}
	case uint64:
		ev.Value = &pb.EventValue_UInt64{UInt64: v}
	case bool:
		ev.Value = &pb.EventValue_Bool{Bool: v}
	case string:
		ev.Value = &pb.EventValue_Str{Str: sanitizeStringForProtobuf(v)}
	case []string:
		ev.Value = &pb.EventValue_StrArray{StrArray: &pb.StringArray{Value: sanitizeStringArrayForProtobuf(v)}}
	case []byte:
		ev.Value = &pb.EventValue_Bytes{Bytes: v}
	case uintptr:
		ev.Value = &pb.EventValue_UInt64{UInt64: uint64(v)}
	case trace.Pointer:
		ev.Value = &pb.EventValue_Pointer{Pointer: uint64(v)}
	case time.Time:
		ev.Value = &pb.EventValue_UInt64{UInt64: uint64(v.UnixNano())}
	case layers.TCPPort:
		ev.Value = &pb.EventValue_UInt32{UInt32: uint32(v)}
	case layers.UDPPort:
		ev.Value = &pb.EventValue_UInt32{UInt32: uint32(v)}
	case []uint64:
		ev.Value = &pb.EventValue_UInt64Array{UInt64Array: &pb.UInt64Array{Value: v}}
	case float64:
		ev.Value = &pb.EventValue_Timespec{Timespec: &pb.Timespec{Value: wrapperspb.Double(v)}}
	case [2]int32:
		intArray := make([]int32, 0, len(v))
		for _, i := range v {
			intArray = append(intArray, i)
		}
		ev.Value = &pb.EventValue_Int32Array{Int32Array: &pb.Int32Array{Value: intArray}}
	default:
		// For complex types (network protocols, maps, SlimCred, etc.), delegate to
		// parseArgument which handles all remaining cases. The caller detects this
		// by checking ev.Value == nil && arg.Value != nil.
		result, err := parseArgument(arg)
		if err != nil {
			return err
		}
		if result != nil {
			ev.Name = result.Name
			ev.Value = result.Value
		}
		// If result is nil, ev.Value stays nil — caller handles unsupported type
	}
	return nil
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
		return &pb.EventValue{Value: &pb.EventValue_Str{Str: sanitizeStringForProtobuf(v)}}, nil

	case []string:
		return &pb.EventValue{Value: &pb.EventValue_StrArray{StrArray: &pb.StringArray{Value: sanitizeStringArrayForProtobuf(v)}}}, nil

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

	case trace.Pointer:
		return &pb.EventValue{Value: &pb.EventValue_Pointer{Pointer: uint64(v)}}, nil

	// Network port types from gopacket/layers
	case layers.TCPPort:
		return &pb.EventValue{Value: &pb.EventValue_UInt32{UInt32: uint32(v)}}, nil
	case layers.UDPPort:
		return &pb.EventValue{Value: &pb.EventValue_UInt32{UInt32: uint32(v)}}, nil

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

	case trace.PacketMetadata:
		return convertPacketMetadata(&v)
	case *trace.PacketMetadata:
		return convertPacketMetadata(v)

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
				Query:      sanitizeStringForProtobuf(q.Query),
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
					Answer: sanitizeStringForProtobuf(a.Answer),
				}
			}
			responses[i] = &pb.DnsResponseData{
				DnsQueryData: &pb.DnsQueryData{
					Query:      sanitizeStringForProtobuf(r.QueryData.Query),
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
				SymbolName:  sanitizeStringForProtobuf(s.SymbolName),
				ModuleOwner: sanitizeStringForProtobuf(s.ModuleOwner),
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
				SymbolName:  sanitizeStringForProtobuf(v.SymbolName),
				ModuleOwner: sanitizeStringForProtobuf(v.ModuleOwner),
			}
		}
		return &pb.EventValue{
			Value: &pb.EventValue_HookedSeqOps{
				HookedSeqOps: &pb.HookedSeqOps{Value: m},
			},
		}, nil

	case net.IP: // DNS events use net.IP on src/dst
		return &pb.EventValue{Value: &pb.EventValue_Str{Str: sanitizeStringForProtobuf(v.String())}}, nil

	case map[string]interface{}:
		// Handle generic map (e.g., detectedFrom nested structures)
		sanitizedMap := sanitizeMapForProtobuf(v)
		structValue, err := structpb.NewStruct(sanitizedMap)
		if err != nil {
			return nil, err
		}
		return &pb.EventValue{Value: &pb.EventValue_Struct{Struct: structValue}}, nil

	// Handle arrays of maps
	case []map[string]string:
		// Convert to []interface{} and wrap in struct for protobuf
		items := make([]interface{}, len(v))
		for i, m := range v {
			// Convert map[string]string to map[string]interface{}
			converted := make(map[string]interface{})
			for k, val := range m {
				converted[k] = val
			}
			items[i] = sanitizeMapForProtobuf(converted)
		}
		wrapper := map[string]interface{}{"items": items}
		structValue, err := structpb.NewStruct(wrapper)
		if err == nil {
			return &pb.EventValue{Value: &pb.EventValue_Struct{Struct: structValue}}, nil
		}

	case []map[string]interface{}:
		// Wrap array in struct for protobuf
		items := make([]interface{}, len(v))
		for i, m := range v {
			items[i] = sanitizeMapForProtobuf(m)
		}
		wrapper := map[string]interface{}{"items": items}
		structValue, err := structpb.NewStruct(wrapper)
		if err == nil {
			return &pb.EventValue{Value: &pb.EventValue_Struct{Struct: structValue}}, nil
		}
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

// sanitizeStringForProtobuf removes invalid UTF-8 characters from a string
// to prevent protobuf serialization errors
func sanitizeStringForProtobuf(s string) string {
	if utf8.ValidString(s) {
		return s
	}

	// Build a new string with only valid UTF-8 characters
	var builder strings.Builder
	builder.Grow(len(s)) // Pre-allocate space for efficiency

	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		if r != utf8.RuneError {
			builder.WriteRune(r)
		}
		// Skip invalid bytes by advancing the position
		s = s[size:]
	}

	return builder.String()
}

// sanitizeStringArrayForProtobuf sanitizes all string elements in a slice
// to ensure they contain only valid UTF-8 characters
func sanitizeStringArrayForProtobuf(arr []string) []string {
	for i, s := range arr {
		arr[i] = sanitizeStringForProtobuf(s)
	}
	return arr
}

// sanitizeMapForProtobuf recursively sanitizes string values in a map
// to ensure they contain only valid UTF-8 characters
func sanitizeMapForProtobuf(m map[string]interface{}) map[string]interface{} {
	sanitizedMap := make(map[string]interface{}, len(m))

	for k, v := range m {
		switch val := v.(type) {
		case string:
			sanitizedMap[k] = sanitizeStringForProtobuf(val)
		case map[string]interface{}:
			sanitizedMap[k] = sanitizeMapForProtobuf(val)
		case []trace.Argument:
			// Handle []trace.Argument (e.g., from nested detectedFrom in signature-on-signature chains)
			sanitizedMap[k] = sanitizeArgumentsForProtobuf(val)
		default:
			sanitizedMap[k] = val
		}
	}

	return sanitizedMap
}

// getStackAddress converts stack addresses to protobuf format
func getStackAddress(stackAddresses []uint64) []*pb.StackAddress {
	var out []*pb.StackAddress
	for _, addr := range stackAddresses {
		out = append(out, &pb.StackAddress{Address: addr})
	}

	return out
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
	detectedFrom.Name = sanitizeStringForProtobuf(name)

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
		if eventValue == nil {
			// Skip arguments that can't be converted
			logger.Errorw(
				"Can't convert detectedFrom argument. Please add it as a GRPC event data type or implement detect.FindingDataStruct interface.",
				"name", arg.ArgMeta.Name,
				"type", fmt.Sprintf("%T", arg.Value),
			)
			continue
		}
		eventValue.Name = sanitizeStringForProtobuf(arg.ArgMeta.Name)
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

	// Recursively convert parent chain
	if parentMap, ok := m["parent"].(map[string]interface{}); ok {
		parentArg := trace.Argument{
			ArgMeta: trace.ArgMeta{Name: "detectedFrom"},
			Value:   parentMap,
		}
		parent, err := getDetectedFrom(parentArg)
		if err != nil {
			return nil, errfmt.Errorf("failed to convert parent DetectedFrom: %v", err)
		}
		detectedFrom.Parent = parent
	}

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
				Protocol:   sanitizeStringForProtobuf(v.Protocol),
				Checksum:   uint32(v.Checksum),
				SrcIp:      v.SrcIP,
				DstIp:      sanitizeStringForProtobuf(v.DstIP),
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
				NextHeader:   sanitizeStringForProtobuf(v.NextHeader),
				HopLimit:     uint32(v.HopLimit),
				SrcIp:        sanitizeStringForProtobuf(v.SrcIP),
				DstIp:        sanitizeStringForProtobuf(v.DstIP),
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
				TypeCode: sanitizeStringForProtobuf(v.TypeCode),
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
				TypeCode: sanitizeStringForProtobuf(v.TypeCode),
				Checksum: uint32(v.Checksum),
			},
		},
	}, nil
}

func convertDns(v *trace.ProtoDNS) (*pb.EventValue, error) {
	questions := make([]*pb.DNSQuestion, len(v.Questions))
	for i, q := range v.Questions {
		questions[i] = &pb.DNSQuestion{
			Name:  sanitizeStringForProtobuf(q.Name),
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
				OpCode:       sanitizeStringForProtobuf(v.OpCode),
				Aa:           uint32(v.AA),
				Tc:           uint32(v.TC),
				Rd:           uint32(v.RD),
				Ra:           uint32(v.RA),
				Z:            uint32(v.Z),
				ResponseCode: sanitizeStringForProtobuf(v.ResponseCode),
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
			Data: sanitizeStringForProtobuf(o.Data),
		}
	}

	return &pb.DNSResourceRecord{
		Name:  sanitizeStringForProtobuf(source.Name),
		Type:  source.Type,
		Class: source.Class,
		Ttl:   uint32(source.TTL),
		Ip:    source.IP,
		Ns:    sanitizeStringForProtobuf(source.NS),
		Cname: sanitizeStringForProtobuf(source.CNAME),
		Ptr:   sanitizeStringForProtobuf(source.PTR),
		Txts:  sanitizeStringArrayForProtobuf(source.TXTs),
		Soa: &pb.DNSSOA{
			Mname:   sanitizeStringForProtobuf(source.SOA.MName),
			Rname:   sanitizeStringForProtobuf(source.SOA.RName),
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
			Name:     sanitizeStringForProtobuf(source.SRV.Name),
		},
		Mx: &pb.DNSMX{
			Preference: uint32(source.MX.Preference),
			Name:       sanitizeStringForProtobuf(source.MX.Name),
		},
		Opt: opts,
		Uri: &pb.DNSURI{
			Priority: uint32(source.URI.Priority),
			Weight:   uint32(source.URI.Weight),
			Target:   sanitizeStringForProtobuf(source.URI.Target),
		},
		Txt: sanitizeStringForProtobuf(source.TXT),
	}
}

func convertPktMeta(v *trace.PktMeta) (*pb.EventValue, error) {
	return &pb.EventValue{
		Value: &pb.EventValue_PacketMetadata{
			PacketMetadata: &pb.PacketMetadata{
				SrcIp:     sanitizeStringForProtobuf(v.SrcIP),
				DstIp:     sanitizeStringForProtobuf(v.DstIP),
				SrcPort:   uint32(v.SrcPort),
				DstPort:   uint32(v.DstPort),
				Protocol:  uint32(v.Protocol),
				PacketLen: v.PacketLen,
				Iface:     sanitizeStringForProtobuf(v.Iface),
			},
		},
	}, nil
}

func convertPacketMetadata(v *trace.PacketMetadata) (*pb.EventValue, error) {
	// PacketMetadata only contains direction, map it to a string
	direction := "unknown"
	switch v.Direction {
	case trace.PacketIngress:
		direction = "ingress"
	case trace.PacketEgress:
		direction = "egress"
	}

	return &pb.EventValue{
		Value: &pb.EventValue_Str{
			Str: direction,
		},
	}, nil
}

// HTTP protocol converters

func getHeaders(source http.Header) map[string]*pb.HttpHeader {
	headers := make(map[string]*pb.HttpHeader)
	for k, v := range source {
		headers[k] = &pb.HttpHeader{Header: sanitizeStringArrayForProtobuf(v)}
	}
	return headers
}

func convertProtoHTTPResponse(v *trace.ProtoHTTPResponse) (*pb.EventValue, error) {
	return &pb.EventValue{
		Value: &pb.EventValue_HttpResponse{
			HttpResponse: &pb.HTTPResponse{
				Status:        sanitizeStringForProtobuf(v.Status),
				StatusCode:    int32(v.StatusCode),
				Protocol:      sanitizeStringForProtobuf(v.Protocol),
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
				Method:        sanitizeStringForProtobuf(v.Method),
				Protocol:      sanitizeStringForProtobuf(v.Protocol),
				Host:          v.Host,
				UriPath:       sanitizeStringForProtobuf(v.URIPath),
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
				Method:        sanitizeStringForProtobuf(v.Method),
				Protocol:      sanitizeStringForProtobuf(v.Protocol),
				Host:          sanitizeStringForProtobuf(v.Host),
				UriPath:       sanitizeStringForProtobuf(v.URIPath),
				Status:        sanitizeStringForProtobuf(v.Status),
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
		// Sanitize string values to ensure valid UTF-8 before protobuf conversion
		sanitizedMap := sanitizeMapForProtobuf(m)

		structValue, err := structpb.NewStruct(sanitizedMap)
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
		case *pb.EventValue_Pointer:
			arg.Value = trace.Pointer(v.Pointer)
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

	// Recursively convert parent chain
	if detectedFrom.Parent != nil {
		parentArg := convertDetectedFromToArg(detectedFrom.Parent)
		detectedFromMap["parent"] = parentArg.Value
	}

	return trace.Argument{
		ArgMeta: trace.ArgMeta{
			Name: "detectedFrom",
		},
		Value: detectedFromMap,
	}
}
