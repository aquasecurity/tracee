package derive

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func NetPacketIPv6() deriveFunction {
	return deriveSingleEvent(events.NetPacketIPv6, deriveNetPacketIPv6Args())
}

func deriveNetPacketIPv6Args() deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		var ok bool
		var payload []byte

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

		switch l3 := layer3.(type) {
		case (*layers.IPv6):
			var ipv6 trace.ProtoIPv6
			copyIPv6ToProtoIPv6(l3, &ipv6)

			return []interface{}{
				l3.SrcIP,
				l3.DstIP,
				ipv6,
			}, nil
		}

		return nil, fmt.Errorf("not an IPv6 packet")
	}
}

//
// IPv6 protocol type conversion (from gopacket layer to trace type)
//

func copyIPv6ToProtoIPv6(l3 *layers.IPv6, proto *trace.ProtoIPv6) {
	proto.Version = l3.Version
	proto.DstIP = l3.DstIP
	proto.TrafficClass = l3.TrafficClass
	proto.FlowLabel = l3.FlowLabel
	proto.Length = l3.Length
	proto.NextHeader = l3.NextHeader.String()
	proto.HopLimit = l3.HopLimit
}
