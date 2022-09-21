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

func NetPacketIPv6() deriveFunction {
	return deriveSingleEvent(events.NetPacketIPv6, deriveNetPacketIPv6Args())
}

func deriveNetPacketIPv4Args() deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		payloadArg := events.GetArg(&event, "payload")
		if payloadArg == nil {
			return nil, fmt.Errorf("no payload ?")
		}

		if event.ReturnValue != 2 { // discard non IPv4 packets quickly
			return nil, nil
		}

		var ok bool
		var payload []byte

		if payload, ok = payloadArg.Value.([]byte); !ok {
			return nil, fmt.Errorf("non []byte argument ?")
		}

		payloadSize := len(payload)
		if payloadSize < 1 {
			return nil, fmt.Errorf("empty payload ?")
		}

		packet := gopacket.NewPacket(
			payload[4:payloadSize],
			layers.LayerTypeIPv4,
			gopacket.Default,
		)

		if packet == nil {
			return []interface{}{}, fmt.Errorf("could not parse the packet")
		}

		// DEBUG:
		// fmt.Printf("%s", packet.Dump())
		// fmt.Printf("%s", packet.String())

		ipLayer, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if ok {
			return []interface{}{
				ipLayer.Version,
				ipLayer.IHL,
				ipLayer.TOS,
				ipLayer.Length,
				ipLayer.Id,
				ipLayer.Flags,
				ipLayer.FragOffset,
				ipLayer.TTL,
				ipLayer.Protocol,
				ipLayer.Checksum,
				ipLayer.SrcIP,
				ipLayer.DstIP,
			}, nil
		}
		return nil, nil
	}
}

func deriveNetPacketIPv6Args() deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		payloadArg := events.GetArg(&event, "payload")
		if payloadArg == nil {
			return nil, fmt.Errorf("no payload ?")
		}

		if event.ReturnValue != 10 { // discard non IPv6 packets quickly
			return nil, nil
		}

		var ok bool
		var payload []byte

		if payload, ok = payloadArg.Value.([]byte); !ok {
			return nil, fmt.Errorf("non []byte argument ?")
		}

		payloadSize := len(payload)
		if payloadSize < 1 {
			return nil, fmt.Errorf("empty payload ?")
		}

		packet := gopacket.NewPacket(
			payload[4:payloadSize],
			layers.LayerTypeIPv6,
			gopacket.Default,
		)

		if packet == nil {
			return []interface{}{}, fmt.Errorf("could not parse the packet")
		}

		ipv6Layer, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		if ok {
			return []interface{}{
				ipv6Layer.Version,
				ipv6Layer.TrafficClass,
				ipv6Layer.FlowLabel,
				ipv6Layer.Length,
				ipv6Layer.NextHeader,
				ipv6Layer.HopLimit,
				ipv6Layer.SrcIP,
				ipv6Layer.DstIP,
			}, nil
		}
		return nil, nil
	}
}
