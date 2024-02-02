package derive

import (
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

//
// Layer 3 (Network Layer)
//

func NetPacketIPv4() DeriveFunction {
	return deriveSingleEvent(events.NetPacketIPv4,
		func(event trace.Event) ([]interface{}, error) {
			layer3TypeFlag, _ := getLayer3TypeFlagFromEvent(&event)
			if layer3TypeFlag != familyIPv4 {
				return nil, nil // no event if not IPv4
			}
			packet, err := createPacketFromEvent(&event)
			if err != nil {
				return nil, err
			}
			layer3IP, err := getLayer3IPv4FromPacket(packet)
			if err != nil {
				return nil, err
			}
			return []interface{}{
				layer3IP.SrcIP.String(),
				layer3IP.DstIP.String(),
				trace.PacketMetadata{
					Direction: getPacketDirection(&event),
				},
				getProtoIPv4(layer3IP),
			}, nil
		},
	)
}

func NetPacketIPv6() DeriveFunction {
	return deriveSingleEvent(events.NetPacketIPv6,
		func(event trace.Event) ([]interface{}, error) {
			layer3TypeFlag, _ := getLayer3TypeFlagFromEvent(&event)
			if layer3TypeFlag != familyIPv6 {
				return nil, nil // no event if not IPv6
			}
			packet, err := createPacketFromEvent(&event)
			if err != nil {
				return nil, err
			}
			layer3IP, err := getLayer3IPv6FromPacket(packet)
			if err != nil {
				return nil, err
			}
			return []interface{}{
				layer3IP.SrcIP.String(),
				layer3IP.DstIP.String(),
				trace.PacketMetadata{
					Direction: getPacketDirection(&event),
				},
				getProtoIPv6(layer3IP),
			}, nil
		},
	)
}

//
// Layer 4 (Transport Layer)
//

func NetPacketTCP() DeriveFunction {
	return deriveSingleEvent(events.NetPacketTCP,
		func(event trace.Event) ([]interface{}, error) {
			packet, err := createPacketFromEvent(&event)
			if err != nil {
				return nil, err
			}
			layer3IP, err := getLayer3IPv4FromPacket(packet)
			if err != nil {
				return nil, err
			}
			layer4TCP, err := getLayer4TCPFromPacket(packet)
			if err != nil {
				return nil, err
			}
			return []interface{}{
				layer3IP.SrcIP.String(),
				layer3IP.DstIP.String(),
				layer4TCP.SrcPort,
				layer4TCP.DstPort,
				trace.PacketMetadata{
					Direction: getPacketDirection(&event),
				},
				getProtoTCP(layer4TCP),
			}, nil
		},
	)
}

func NetPacketUDP() DeriveFunction {
	return deriveSingleEvent(events.NetPacketUDP,
		func(event trace.Event) ([]interface{}, error) {
			packet, err := createPacketFromEvent(&event)
			if err != nil {
				return nil, err
			}
			layer3IP, err := getLayer3IPv4FromPacket(packet)
			if err != nil {
				return nil, err
			}
			layer4UDP, err := getLayer4UDPFromPacket(packet)
			if err != nil {
				return nil, err
			}
			return []interface{}{
				layer3IP.SrcIP.String(),
				layer3IP.DstIP.String(),
				layer4UDP.SrcPort,
				layer4UDP.DstPort,
				trace.PacketMetadata{
					Direction: getPacketDirection(&event),
				},
				getProtoUDP(layer4UDP),
			}, nil
		},
	)
}

//
// Special Layer (Some consider it as Layer 4, others Layer 3)
//

func NetPacketICMP() DeriveFunction {
	return deriveSingleEvent(events.NetPacketICMP,
		func(event trace.Event) ([]interface{}, error) {
			packet, err := createPacketFromEvent(&event)
			if err != nil {
				return nil, err
			}
			layer3IP, err := getLayer3IPv4FromPacket(packet)
			if err != nil {
				return nil, err
			}
			layerICMP, err := getLayerICMPFromPacket(packet)
			if err != nil {
				return nil, err
			}
			return []interface{}{
				layer3IP.SrcIP.String(),
				layer3IP.DstIP.String(),
				trace.PacketMetadata{
					Direction: getPacketDirection(&event),
				},
				getProtoICMP(layerICMP),
			}, nil
		},
	)
}

func NetPacketICMPv6() DeriveFunction {
	return deriveSingleEvent(events.NetPacketICMPv6,
		func(event trace.Event) ([]interface{}, error) {
			packet, err := createPacketFromEvent(&event)
			if err != nil {
				return nil, err
			}
			layer3IP, err := getLayer3IPv6FromPacket(packet)
			if err != nil {
				return nil, err
			}
			layerICMPv6, err := getLayerICMPv6FromPacket(packet)
			if err != nil {
				return nil, err
			}
			return []interface{}{
				layer3IP.SrcIP.String(),
				layer3IP.DstIP.String(),
				trace.PacketMetadata{
					Direction: getPacketDirection(&event),
				},
				getProtoICMPv6(layerICMPv6),
			}, nil
		},
	)
}

//
// Layer 7 (Application Layer)
//

func NetPacketDNS() DeriveFunction {
	return deriveSingleEvent(events.NetPacketDNS,
		func(event trace.Event) ([]interface{}, error) {
			packet, err := createPacketFromEvent(&event)
			if err != nil {
				return nil, err
			}
			layer7DNS, err := getLayer7DNSFromPacket(packet)
			if err != nil {
				return nil, nil // regular tcp/ip packet without DNS payload
			}
			srcIP, dstIP, err := getLayer3SrcDstFromPacket(packet)
			if err != nil {
				return nil, err
			}
			srcPort, dstPort, err := getLayer4SrcPortDstPortFromPacket(packet)
			if err != nil {
				return nil, err
			}
			return []interface{}{
				srcIP,
				dstIP,
				srcPort,
				dstPort,
				trace.PacketMetadata{
					Direction: getPacketDirection(&event),
				},
				getProtoDNS(layer7DNS),
			}, nil
		},
	)
}

func NetPacketDNSRequest() DeriveFunction {
	return deriveSingleEvent(events.NetPacketDNSRequest,
		func(event trace.Event) ([]interface{}, error) {
			packet, err := createPacketFromEvent(&event)
			if err != nil {
				return nil, err
			}
			layer7DNS, err := getLayer7DNSFromPacket(packet)
			if err != nil {
				return nil, nil // regular tcp/ip packet without DNS payload
			}
			srcIP, dstIP, err := getLayer3SrcDstFromPacket(packet)
			if err != nil {
				return nil, err
			}
			srcPort, dstPort, err := getLayer4SrcPortDstPortFromPacket(packet)
			if err != nil {
				return nil, err
			}

			proto, err := getLayer4ProtoFromPacket(packet)
			if err != nil {
				return nil, err
			}
			length, err := getLengthFromPacket(packet)
			if err != nil {
				return nil, err
			}

			meta := getPktMeta(srcIP, dstIP, srcPort, dstPort, proto, length)

			// Convert NetPacketDNS to old DNS Request event

			dns := getProtoDNS(layer7DNS)
			if dns.QR != 0 {
				return nil, nil // not a DNS request
			}

			requests := getDNSQueryFromProtoDNS(dns.Questions)
			if len(requests) != 1 || len(requests) != int(dns.QDCount) {
				logger.Debugw("bad number of requests found")
				return nil, nil
			}

			return []interface{}{
				meta, // TODO: convert to trace.PacketMetadata
				requests,
			}, nil
		},
	)
}

func NetPacketDNSResponse() DeriveFunction {
	return deriveSingleEvent(events.NetPacketDNSResponse,
		func(event trace.Event) ([]interface{}, error) {
			packet, err := createPacketFromEvent(&event)
			if err != nil {
				return nil, err
			}
			layer7DNS, err := getLayer7DNSFromPacket(packet)
			if err != nil {
				return nil, nil // regular tcp/ip packet without DNS payload
			}
			srcIP, dstIP, err := getLayer3SrcDstFromPacket(packet)
			if err != nil {
				return nil, err
			}
			srcPort, dstPort, err := getLayer4SrcPortDstPortFromPacket(packet)
			if err != nil {
				return nil, err
			}

			proto, err := getLayer4ProtoFromPacket(packet)
			if err != nil {
				return nil, err
			}
			length, err := getLengthFromPacket(packet)
			if err != nil {
				return nil, err
			}

			meta := getPktMeta(srcIP, dstIP, srcPort, dstPort, proto, length)

			// Convert NetPacketDNS to old DNS Response event

			dns := getProtoDNS(layer7DNS)
			if dns.QR != 1 {
				return nil, nil // not a DNS response
			}

			requests := getDNSQueryFromProtoDNS(dns.Questions)
			if len(requests) != 1 {
				logger.Debugw("Wrong number of requests found")
				return nil, nil
			}
			responses := getDNSResponseFromProtoDNS(requests[0], dns.Answers)
			if len(responses[0].DnsAnswer) != int(dns.ANCount) {
				logger.Debugw("Could not get all DNS responses")
				return nil, nil
			}

			return []interface{}{
				meta, // TODO: convert to trace.PacketMetadata
				responses,
			}, nil
		},
	)
}

func NetPacketHTTP() DeriveFunction {
	return deriveSingleEvent(events.NetPacketHTTP,
		func(event trace.Event) ([]interface{}, error) {
			packet, err := createPacketFromEvent(&event)
			if err != nil {
				return nil, err
			}
			srcIP, dstIP, err := getLayer3SrcDstFromPacket(packet)
			if err != nil {
				return nil, err
			}
			srcPort, dstPort, err := getLayer4SrcPortDstPortFromPacket(packet)
			if err != nil {
				return nil, err
			}
			var proto *trace.ProtoHTTP
			switch getPacketHTTPDirection(&event) {
			case protoHTTPRequest:
				proto, err = getProtoHTTPFromRequestPacket(packet)
				if err != nil {
					logger.Warnw("attempted to derive net_packet_http event from malformed request packet, event will be skipped", "error", err)
					return nil, nil
				}
			case protoHTTPResponse:
				proto, err = getProtoHTTPFromResponsePacket(packet)
				if err != nil {
					logger.Warnw("attempted to derive net_packet_http event from malformed response packet, event will be skipped", "error", err)
					return nil, nil
				}
			default:
				return nil, errfmt.Errorf("unspecified HTTP packet direction")
			}
			if proto == nil {
				return nil, nil // regular tcp/ip packet without HTTP payload
			}
			return []interface{}{
				srcIP,
				dstIP,
				srcPort,
				dstPort,
				trace.PacketMetadata{
					Direction: getPacketDirection(&event),
				},
				*proto,
			}, nil
		},
	)
}

func NetPacketHTTPRequest() DeriveFunction {
	return deriveSingleEvent(events.NetPacketHTTPRequest,
		func(event trace.Event) ([]interface{}, error) {
			packet, err := createPacketFromEvent(&event)
			if err != nil {
				return nil, err
			}
			srcIP, dstIP, err := getLayer3SrcDstFromPacket(packet)
			if err != nil {
				return nil, err
			}
			srcPort, dstPort, err := getLayer4SrcPortDstPortFromPacket(packet)
			if err != nil {
				return nil, err
			}
			if getPacketHTTPDirection(&event) != protoHTTPRequest {
				return nil, nil
			}
			protoHTTP, err := getProtoHTTPFromRequestPacket(packet)
			if err != nil {
				logger.Warnw("attempted to derive net_packet_http_request event from malformed packet, event will be skipped", "error", err)
				return nil, nil
			}
			if protoHTTP == nil {
				return nil, nil // regular tcp/ip packet without HTTP payload
			}

			// Pick PktMeta (TODO: convert to trace.PacketMetadata)
			proto, err := getLayer4ProtoFromPacket(packet)
			if err != nil {
				return nil, err
			}
			length, err := getLengthFromPacket(packet)
			if err != nil {
				return nil, err
			}
			meta := getPktMeta(srcIP, dstIP, srcPort, dstPort, proto, length)

			return []interface{}{
				meta,
				getProtoHTTPRequestFromHTTP(protoHTTP),
			}, nil
		},
	)
}

func NetPacketHTTPResponse() DeriveFunction {
	return deriveSingleEvent(events.NetPacketHTTPResponse,
		func(event trace.Event) ([]interface{}, error) {
			packet, err := createPacketFromEvent(&event)
			if err != nil {
				return nil, err
			}
			srcIP, dstIP, err := getLayer3SrcDstFromPacket(packet)
			if err != nil {
				return nil, err
			}
			srcPort, dstPort, err := getLayer4SrcPortDstPortFromPacket(packet)
			if err != nil {
				return nil, err
			}
			if getPacketHTTPDirection(&event) != protoHTTPResponse {
				return nil, nil
			}
			protoHTTP, err := getProtoHTTPFromResponsePacket(packet)
			if err != nil {
				logger.Warnw("attempted to derive net_packet_http_response event from malformed packet, event will be skipped", "error", err)
				return nil, nil // malformed packets shouldn't return an error
			}
			if protoHTTP == nil {
				return nil, nil // regular tcp/ip packet without HTTP payload
			}

			// Pick PktMeta (TODO: convert to trace.PacketMetadata)
			proto, err := getLayer4ProtoFromPacket(packet)
			if err != nil {
				return nil, err
			}
			length, err := getLengthFromPacket(packet)
			if err != nil {
				return nil, err
			}
			meta := getPktMeta(srcIP, dstIP, srcPort, dstPort, proto, length)

			return []interface{}{
				meta,
				getProtoHTTPResponseFromHTTP(protoHTTP),
			}, nil
		},
	)
}
