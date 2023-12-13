package derive

import (
	"github.com/aquasecurity/tracee/pkg/dnscache"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

const (
	directionOutgoing = "outgoing"
	directionIncoming = "incoming"
)

func NetFlowTCPBegin(cache *dnscache.DNSCache) DeriveFunction {
	return deriveSingleEvent(events.NetFlowTCPBegin,
		func(event trace.Event) ([]interface{}, error) {
			tcpBegin := event.ReturnValue&flowTCPBegin == flowTCPBegin
			ingress := event.ReturnValue&packetIngress == packetIngress
			egress := event.ReturnValue&packetEgress == packetEgress

			// Sanity check
			if (!ingress && !egress) || (ingress && egress) {
				logger.Debugw("wrong flow direction", "id", event.EventID)
				return nil, nil
			}
			// Return if not a TCP begin flow event
			if !tcpBegin {
				return nil, nil
			}

			// Get the packet from the event
			packet, err := createPacketFromEvent(&event)
			if err != nil {
				return nil, err
			}
			// Sanity check
			proto, _ := getLayer4ProtoFromPacket(packet)
			if proto != IPPROTO_TCP {
				return nil, nil // not an tcp packet
			}
			// Get the packet src and dst IPs
			srcIP, dstIP, err := getLayer3SrcDstFromPacket(packet)
			if err != nil {
				return nil, err
			}
			// Get the packet src and dst ports
			srcPort, dstPort, err := getLayer4SrcPortDstPortFromPacket(packet)
			if err != nil {
				return nil, err
			}

			connectionDirection := ""
			switch {
			case ingress:
				connectionDirection = directionOutgoing // SYN+ACK is incoming, connection is outcoming
			case egress:
				connectionDirection = directionIncoming // SYN+ACK is outgoing, connection is incoming
			}

			// Packet is SYN_ACK, swap src and dst IPs and ports to get connection orientation.
			srcIP, dstIP, srcPort, dstPort = swapSrcDst(srcIP, dstIP, srcPort, dstPort)

			// Pick the src and dst IP addresses domain names from the DNS cache
			srcDomains := getDomainsFromCache(srcIP, cache)
			dstDomains := getDomainsFromCache(dstIP, cache)

			// Return the derived event arguments.
			return []interface{}{
				connectionDirection,
				srcIP,
				dstIP,
				srcPort,
				dstPort,
				srcDomains,
				dstDomains,
			}, nil
		},
	)
}

func NetFlowTCPEnd(cache *dnscache.DNSCache) DeriveFunction {
	return deriveSingleEvent(events.NetFlowTCPEnd,
		func(event trace.Event) ([]interface{}, error) {
			tcpEnd := event.ReturnValue&flowTCPEnd == flowTCPEnd
			ingress := event.ReturnValue&packetIngress == packetIngress
			egress := event.ReturnValue&packetEgress == packetEgress
			srcInitiated := event.ReturnValue&flowSrcInitiator == flowSrcInitiator

			// Sanity check
			if (!ingress && !egress) || (ingress && egress) {
				logger.Debugw("wrong flow direction", "id", event.EventID)
				return nil, nil
			}
			// Return if not a TCP end flow event
			if !tcpEnd {
				return nil, nil
			}

			// Get the packet from the event
			packet, err := createPacketFromEvent(&event)
			if err != nil {
				return nil, err
			}
			// Sanity check
			proto, _ := getLayer4ProtoFromPacket(packet)
			if proto != IPPROTO_TCP {
				return nil, nil // not an tcp packet
			}
			// Get the packet src and dst IPs
			srcIP, dstIP, err := getLayer3SrcDstFromPacket(packet)
			if err != nil {
				return nil, err
			}
			// Get the packet src and dst ports
			srcPort, dstPort, err := getLayer4SrcPortDstPortFromPacket(packet)
			if err != nil {
				return nil, err
			}

			connectionDirection := ""
			if (srcInitiated && ingress) || (!srcInitiated && !ingress) {
				connectionDirection = directionIncoming
			} else {
				connectionDirection = directionOutgoing
			}

			if !srcInitiated {
				// Swap src and dst IPs and ports to get proper flow orientation.
				srcIP, dstIP, srcPort, dstPort = swapSrcDst(srcIP, dstIP, srcPort, dstPort)
			}

			// Pick the src and dst IP addresses domain names from the DNS cache
			srcDomains := getDomainsFromCache(srcIP, cache)
			dstDomains := getDomainsFromCache(dstIP, cache)

			// Return the derived event arguments.
			return []interface{}{
				connectionDirection,
				srcIP,
				dstIP,
				srcPort,
				dstPort,
				srcDomains,
				dstDomains,
			}, nil
		},
	)
}

// func NetFlowUDPBegin(cache *dnscache.DNSCache) DeriveFunction {
// 	return deriveSingleEvent(events.NetFlowUDPBegin,
// 		func(event trace.Event) ([]interface{}, error) {
// 			return nil, nil
// 		},
// 	)
// }

// func NetFlowUDPEnd(cache *dnscache.DNSCache) DeriveFunction {
// 	return deriveSingleEvent(events.NetFlowUDPBegin,
// 		func(event trace.Event) ([]interface{}, error) {
// 			return nil, nil
// 		},
// 	)
// }
