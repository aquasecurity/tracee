package derive

import (
	"fmt"
	"net"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func NetPacketICMPv6() deriveFunction {
	return deriveSingleEvent(events.NetPacketICMPv6, deriveNetPacketICMPv6Args())
}

func deriveNetPacketICMPv6Args() deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		var ok bool
		var payload []byte
		var srcIP net.IP
		var dstIP net.IP

		// sanity checks

		payloadArg := events.GetArg(&event, "payload")
		if payloadArg == nil {
			return nil, fmt.Errorf("no payload ?")
		}
		if payload, ok = payloadArg.Value.([]byte); !ok {
			return nil, fmt.Errorf("non []byte argument ?")
		}
		payloadSize := len(payload)
		if payloadSize < 1 {
			return nil, fmt.Errorf("empty payload ?")
		}

		// initial header type

		if event.ReturnValue != 10 { // AF_INET6
			return nil, nil
		}

		// parse packet

		packet := gopacket.NewPacket(
			payload[4:payloadSize],
			layers.LayerTypeIPv6,
			gopacket.Default,
		)
		if packet == nil {
			return []interface{}{}, fmt.Errorf("could not parse the packet")
		}

		layer3 := packet.NetworkLayer()

		switch v := layer3.(type) {
		case (*layers.IPv6):
			srcIP = v.SrcIP
			dstIP = v.DstIP
		default:
			return nil, nil
		}

		// some people says layer 4 (but icmp is a network layer in practice)

		layer4 := packet.Layer(layers.LayerTypeICMPv6)

		switch l4 := layer4.(type) {
		case (*layers.ICMPv6):
			var icmpv6 trace.ProtoICMPv6

			copyICMPv6ToProtoICMPv6(l4, &icmpv6)

			// TODO: parse subsequent ICMPv6 type layers

			return []interface{}{
				srcIP,
				dstIP,
				icmpv6,
			}, nil
		}

		return nil, fmt.Errorf("not an ICMP packet")
	}
}

//
// ICMPv6 protocol type conversion (from gopacket layer to trace type)
//

func copyICMPv6ToProtoICMPv6(l4 *layers.ICMPv6, proto *trace.ProtoICMPv6) {
	proto.TypeCode = l4.TypeCode.String()
	proto.Checksum = l4.Checksum
}
