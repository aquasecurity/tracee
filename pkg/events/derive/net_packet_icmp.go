package derive

import (
	"fmt"
	"net"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func NetPacketICMP() deriveFunction {
	return deriveSingleEvent(events.NetPacketICMP, deriveNetPacketICMPArgs())
}

func deriveNetPacketICMPArgs() deriveArgsFunction {
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

		if event.ReturnValue != 2 { // AF_INET
			return nil, nil
		}

		// parse packet

		packet := gopacket.NewPacket(
			payload[4:payloadSize],
			layers.LayerTypeIPv4,
			gopacket.Default,
		)
		if packet == nil {
			return []interface{}{}, fmt.Errorf("could not parse the packet")
		}

		layer3 := packet.NetworkLayer()

		switch v := layer3.(type) {
		case (*layers.IPv4):
			srcIP = v.SrcIP
			dstIP = v.DstIP
		default:
			return nil, nil
		}

		// some people says layer 4 (but icmp is a network layer in practice)

		layer4 := packet.Layer(layers.LayerTypeICMPv4)

		switch l4 := layer4.(type) {
		case (*layers.ICMPv4):
			var icmp trace.ProtoICMP

			copyICMPToProtoICMP(l4, &icmp)

			// TODO: parse subsequent ICMP type layers

			return []interface{}{
				srcIP,
				dstIP,
				icmp,
			}, nil
		}

		return nil, fmt.Errorf("not an ICMP packet")
	}
}

//
// ICMP protocol type conversion (from gopacket layer to trace type)
//

func copyICMPToProtoICMP(l4 *layers.ICMPv4, proto *trace.ProtoICMP) {
	proto.TypeCode = l4.TypeCode.String()
	proto.Checksum = l4.Checksum
	proto.Id = l4.Id
	proto.Seq = l4.Seq
}
