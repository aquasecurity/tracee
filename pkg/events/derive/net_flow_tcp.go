package derive

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/aquasecurity/tracee/pkg/dnscache"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

func NetFlowTCPBegin(cache *dnscache.DNSCache) DeriveFunction {
	return deriveSingleEvent(events.NetFlowTCPBegin, deriveNetFlowTCPBeginArgs(cache))
}

func deriveNetFlowTCPBeginArgs(cache *dnscache.DNSCache) deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		ret := event.ReturnValue

		pktDirection := getPacketDirection(&event)
		ingress := pktDirection == trace.PacketIngress
		egress := pktDirection == trace.PacketEgress

		begin := ret&flowTCPBegin == flowTCPBegin
		end := ret&flowTCPEnd == flowTCPEnd

		ipv4 := ret&familyIpv4 == familyIpv4
		ipv6 := ret&familyIpv6 == familyIpv6

		// Return fast if not the proper event (egress/ingress, begin/end).

		if !begin && !end {
			logger.Debugw("not a TCP flow event", "id", event.EventID)
			return nil, nil
		}
		if !ingress && !egress {
			logger.Debugw("wrong flow direction", "id", event.EventID)
			return nil, nil
		}
		if !ipv4 && !ipv6 {
			logger.Debugw("base layer type not supported", "id", event.EventID)
			return nil, nil
		}

		// Proper event, now parse the packet.

		var srcIP, dstIP net.IP
		var srcPort, dstPort uint16
		var layerType gopacket.LayerType

		payload, err := parsePayloadArg(&event)
		if err != nil {
			return nil, err
		}

		// Event return value encodes layer 3 protocol type.

		if ipv4 {
			layerType = layers.LayerTypeIPv4
		} else if ipv6 {
			layerType = layers.LayerTypeIPv6
		}

		// Parse the packet.

		packet := gopacket.NewPacket(
			payload,
			layerType,
			gopacket.Default,
		)
		if packet == nil {
			return []interface{}{}, parsePacketError()
		}

		layer3 := packet.NetworkLayer()

		switch v := layer3.(type) {
		case (*layers.IPv4):
			srcIP = v.SrcIP
			dstIP = v.DstIP
		case (*layers.IPv6):
			srcIP = v.SrcIP
			dstIP = v.DstIP
		default:
			return nil, nil
		}

		layer4 := packet.TransportLayer()

		switch l4 := layer4.(type) {
		case (*layers.TCP):
			srcPort = uint16(l4.SrcPort)
			dstPort = uint16(l4.DstPort)
		default:
			return nil, notProtoPacketError("TCP")
		}

		connectionDirection := ""

		// Begin means current packet has either SYN or SYN + ACK flags set.
		// The packet src and dst are the connection dst and src respectively.
		if begin {
			if ingress {
				connectionDirection = "outgoing"
			} else {
				connectionDirection = "incoming"
			}
			srcIP, dstIP, srcPort, dstPort = shift(srcIP, dstIP, srcPort, dstPort)
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
	}
}

// shift swaps the source and destination IP addresses and ports.
func shift(s, d net.IP, sp, dp uint16) (net.IP, net.IP, uint16, uint16) {
	return d, s, dp, sp
}

// getDomainsFromCache returns the domain names of an IP address from the DNS cache.
func getDomainsFromCache(ip net.IP, cache *dnscache.DNSCache) []string {
	domains := []string{}
	if cache != nil {
		query, err := cache.Get(ip.String())
		if err != nil {
			switch err {
			case dnscache.ErrDNSRecordNotFound, dnscache.ErrDNSRecordExpired:
				domains = []string{}
			default:
				logger.Debugw("ip lookup error", "ip", ip, "error", err)
				return nil
			}
		} else {
			domains = query.DNSResults()
		}
	}
	return domains
}
