package grpc

import (
	"fmt"
	"net"
	"net/http"
	"strconv"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

func getEventData(e trace.Event) ([]*pb.EventValue, error) {
	data := make([]*pb.EventValue, 0)

	for _, arg := range e.Args {
		if arg.ArgMeta.Name == "triggeredBy" {
			triggerEvent, err := getTriggerBy(arg)
			if err != nil {
				return nil, err
			}

			data = append(data, &pb.EventValue{
				Name: "triggeredBy",
				Value: &pb.EventValue_TriggeredBy{
					TriggeredBy: triggerEvent,
				},
			})

			continue
		}

		eventValue, err := getEventValue(arg)
		if err != nil {
			return nil, err
		}

		// if convertStruct was not able to convert an argument is because we don't support the conversion
		if eventValue == nil {
			logger.Errorw(
				"Can't convert event argument. Please add it as a GRPC event data type or implement detect.FindingDataStruct interface.",
				"name",
				arg.Name,
				"type",
				fmt.Sprintf("%T", arg.Value),
			)

			continue
		}

		eventValue.Name = arg.ArgMeta.Name
		data = append(data, eventValue)
	}

	if events.Core.GetDefinitionByID(events.ID(e.EventID)).IsSyscall() {
		data = append(data, &pb.EventValue{
			Name: "returnValue",
			Value: &pb.EventValue_Int64{
				Int64: int64(e.ReturnValue),
			},
		})
	}

	return data, nil
}

func getEventValue(arg trace.Argument) (*pb.EventValue, error) {
	var eventValue *pb.EventValue

	eventValue, err := parseArgument(arg)
	if err != nil {
		return nil, errfmt.Errorf("can't convert event data: %s - %v - %T", arg.Name, arg.Value, arg.Value)
	}

	return eventValue, nil
}

// parseArgument converts tracee argument to protobuf EventValue
// based on the value type
func parseArgument(arg trace.Argument) (*pb.EventValue, error) {
	switch v := arg.Value.(type) {
	case nil:
		return &pb.EventValue{
			Value: nil,
		}, nil
	case int:
		return &pb.EventValue{
			Value: &pb.EventValue_Int64{
				Int64: int64(v),
			},
		}, nil
	case int32:
		return &pb.EventValue{
			Value: &pb.EventValue_Int32{
				Int32: v,
			},
		}, nil
	case uint8:
		return &pb.EventValue{
			Value: &pb.EventValue_UInt32{
				UInt32: uint32(v),
			},
		}, nil
	case uint16:
		return &pb.EventValue{
			Value: &pb.EventValue_UInt32{
				UInt32: uint32(v),
			},
		}, nil
	case uint32:
		return &pb.EventValue{
			Value: &pb.EventValue_UInt32{
				UInt32: v,
			},
		}, nil
	case int64:
		return &pb.EventValue{
			Value: &pb.EventValue_Int64{
				Int64: v,
			},
		}, nil
	case uint64:
		return &pb.EventValue{
			Value: &pb.EventValue_UInt64{
				UInt64: v,
			},
		}, nil
	case bool:
		return &pb.EventValue{
			Value: &pb.EventValue_Bool{
				Bool: v,
			},
		}, nil
	case string:
		return &pb.EventValue{
			Value: &pb.EventValue_Str{
				Str: v,
			},
		}, nil
	case []string:
		return &pb.EventValue{
			Value: &pb.EventValue_StrArray{
				StrArray: &pb.StringArray{
					Value: v,
				},
			},
		}, nil
	case map[string]string:
		sockaddr, err := getSockaddr(v)
		if err != nil {
			return nil, err
		}
		return sockaddr, nil
	case []byte:
		return &pb.EventValue{
			Value: &pb.EventValue_Bytes{
				Bytes: v,
			},
		}, nil
	case [2]int32:
		intArray := make([]int32, 0, len(v))

		for _, i := range v {
			intArray = append(intArray, i)
		}

		return &pb.EventValue{
			Value: &pb.EventValue_Int32Array{
				Int32Array: &pb.Int32Array{
					Value: intArray,
				},
			},
		}, nil
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
			}}, nil
	case []uint64:
		return &pb.EventValue{
			Value: &pb.EventValue_UInt64Array{
				UInt64Array: &pb.UInt64Array{
					Value: v,
				},
			},
		}, nil
	case float64:
		return &pb.EventValue{
			Value: &pb.EventValue_Timespec{
				Timespec: &pb.Timespec{
					Value: wrapperspb.Double(v),
				},
			},
		}, nil
	case uintptr:
		return &pb.EventValue{
			Value: &pb.EventValue_UInt64{
				UInt64: uint64(v),
			},
		}, nil
	case trace.ProtoIPv4:
		return convertHttpIpv4(&v)
	case *trace.ProtoIPv4:
		return convertHttpIpv4(v)
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
		return converProtoHttp(&v)
	case *trace.ProtoHTTP:
		return converProtoHttp(v)
	case trace.ProtoHTTPRequest:
		return converProtoHttpRequest(&v)
	case *trace.ProtoHTTPRequest:
		return converProtoHttpRequest(v)
	case trace.ProtoHTTPResponse:
		return converProtoHTTPResponse(&v)
	case *trace.ProtoHTTPResponse:
		return converProtoHTTPResponse(v)
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
				DnsQuestions: &pb.DnsQuestions{
					Questions: questions,
				},
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
				DnsResponses: &pb.DnsResponses{
					Responses: responses,
				},
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
				HookedSyscalls: &pb.HookedSyscalls{
					Value: syscalls,
				},
			}}, nil
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
				HookedSeqOps: &pb.HookedSeqOps{
					Value: m,
				},
			},
		}, nil
	case net.IP: // dns events use net.IP on src/dst
		return &pb.EventValue{
			Value: &pb.EventValue_Str{
				Str: v.String(),
			},
		}, nil
	}

	return convertToStruct(arg)
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

	return &pb.EventValue{
		Value: &pb.EventValue_Sockaddr{
			Sockaddr: sockaddr,
		},
	}, nil
}

func getTriggerBy(triggeredByArg trace.Argument) (*pb.TriggeredBy, error) {
	var triggerEvent *pb.TriggeredBy

	m, ok := triggeredByArg.Value.(map[string]interface{})
	if !ok {
		return nil, errfmt.Errorf("error getting triggering event: %v", triggeredByArg.Value)
	}

	triggerEvent = &pb.TriggeredBy{}

	id, ok := m["id"].(int)
	if !ok {
		return nil, errfmt.Errorf("error getting id of triggering event: %v", m)
	}
	triggerEvent.Id = uint32(id)

	name, ok := m["name"].(string)
	if !ok {
		return nil, errfmt.Errorf("error getting name of triggering event: %v", m)
	}
	triggerEvent.Name = name

	triggerEventArgs, ok := m["args"].([]trace.Argument)
	if !ok {
		return nil, errfmt.Errorf("error getting args of triggering event: %v", m)
	}

	data := make([]*pb.EventValue, 0)

	for _, arg := range triggerEventArgs {
		eventValue, err := getEventValue(arg)
		if err != nil {
			return nil, err
		}

		eventValue.Name = arg.ArgMeta.Name
		data = append(data, eventValue)
	}

	if events.Core.GetDefinitionByID(events.ID(id)).IsSyscall() {
		data = append(data, &pb.EventValue{
			Name: "returnValue",
			Value: &pb.EventValue_Int64{
				Int64: int64(m["returnValue"].(int)),
			},
		})
	}

	triggerEvent.Data = data

	return triggerEvent, nil
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
		Opt: []*pb.DNSOPT{},
		Uri: &pb.DNSURI{
			Priority: uint32(source.URI.Priority),
			Weight:   uint32(source.URI.Weight),
			Target:   source.URI.Target,
		},
		Txt: source.TXT,
	}
}

func getHeaders(source http.Header) map[string]*pb.HttpHeader {
	headers := make(map[string]*pb.HttpHeader)

	for k, v := range source {
		headers[k] = &pb.HttpHeader{
			Header: v,
		}
	}

	return headers
}

func converProtoHTTPResponse(v *trace.ProtoHTTPResponse) (*pb.EventValue, error) {
	return &pb.EventValue{
		Value: &pb.EventValue_HttpResponse{
			HttpResponse: &pb.HTTPResponse{
				Status:        v.Status,
				StatusCode:    int32(v.StatusCode),
				Protocol:      v.Protocol,
				Headers:       getHeaders(v.Headers),
				ContentLength: v.ContentLength,
			},
		}}, nil
}

func converProtoHttpRequest(v *trace.ProtoHTTPRequest) (*pb.EventValue, error) {
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
		}}, nil
}

func converProtoHttp(v *trace.ProtoHTTP) (*pb.EventValue, error) {
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
		}}, nil
}

func convertHttpIpv4(v *trace.ProtoIPv4) (*pb.EventValue, error) {
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
		}}, nil
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
		}}, nil
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
		}}, nil
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
		}}, nil
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
		}}, nil
}

func convertIcmpv6(v *trace.ProtoICMPv6) (*pb.EventValue, error) {
	return &pb.EventValue{
		Value: &pb.EventValue_Icmpv6{
			Icmpv6: &pb.ICMPv6{
				TypeCode: v.TypeCode,
				Checksum: uint32(v.Checksum),
			},
		}}, nil
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
		}}, nil
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
		}}, nil
}

func convertPacketMetadata(v *trace.PacketMetadata) (*pb.EventValue, error) {
	return &pb.EventValue{
		Value: &pb.EventValue_PacketMetadata{
			PacketMetadata: &pb.PacketMetadata{
				Direction: pb.PacketDirection(v.Direction),
			},
		}}, nil
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
			Value: &pb.EventValue_Struct{
				Struct: structValue,
			},
		}, nil
	}

	return nil, nil
}
