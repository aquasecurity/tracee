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
			return []interface{}{
				l3.Version,
				l3.TrafficClass,
				l3.FlowLabel,
				l3.Length,
				l3.NextHeader,
				l3.HopLimit,
				l3.SrcIP,
				l3.DstIP,
			}, nil
		}

		return nil, fmt.Errorf("not an IPv6 packet")
	}
}
