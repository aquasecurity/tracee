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
			var ipv4 trace.ProtoIPv4
			copyIPv4ToProtoIPv4(l3, &ipv4)

			return []interface{}{
				l3.SrcIP,
				l3.DstIP,
				ipv4,
			}, nil
		}

		return nil, fmt.Errorf("not an IPv4 packet")
	}
}

//
// IPv4 protocol type conversion (from gopacket layer to trace type)
//

func copyIPv4ToProtoIPv4(l3 *layers.IPv4, proto *trace.ProtoIPv4) {
	proto.Version = l3.Version
	proto.IHL = l3.IHL
	proto.TOS = l3.TOS
	proto.Length = l3.Length
	proto.Id = l3.Id
	proto.Flags = uint8(l3.Flags)
	proto.FragOffset = l3.FragOffset
	proto.TTL = l3.TTL
	proto.Protocol = l3.Protocol.String()
	proto.Checksum = l3.Checksum
	proto.SrcIP = l3.SrcIP
	proto.DstIP = l3.DstIP

	// process all existing IPv4 options (if any)

	for _, i := range l3.Options {
		proto.Options = append(proto.Options,
			trace.ProtoIPv4Option{
				OptionType:   i.OptionType,
				OptionLength: i.OptionLength,
			})
	}
}
