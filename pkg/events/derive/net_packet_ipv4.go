package derive

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func NetPacketIPv4() deriveFunction {
	return deriveSingleEvent(events.NetPacketIPv4, deriveNetPacketIPv4Args())
}

func deriveNetPacketIPv4Args() deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		var ok bool
		var payload []byte

		// initial header type

		if event.ReturnValue != 2 { // AF_INET
			return nil, nil
		}

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

		switch l3 := layer3.(type) {
		case (*layers.IPv4):
			return []interface{}{
				l3.Version,
				l3.IHL,
				l3.TOS,
				l3.Length,
				l3.Id,
				l3.Flags,
				l3.FragOffset,
				l3.TTL,
				l3.Protocol,
				l3.Checksum,
				l3.SrcIP,
				l3.DstIP,
			}, nil
		}

		return nil, fmt.Errorf("not an IPv4 packet")
	}
}
