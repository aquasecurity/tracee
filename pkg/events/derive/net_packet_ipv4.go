package derive

import (
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func NetPacketIPv4() DeriveFunction {
	return deriveSingleEvent(events.NetPacketIPv4, deriveNetPacketIPv4Args())
}

func deriveNetPacketIPv4Args() deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		var ok bool
		var payload []byte

		// event retval encodes layer 3 protocol type

		if event.ReturnValue&familyIpv4 != familyIpv4 {
			return nil, nil
		}

		// sanity checks

		payloadArg := events.GetArg(&event, "payload")
		if payloadArg == nil {
			return nil, noPayloadError()
		}
		if payload, ok = payloadArg.Value.([]byte); !ok {
			return nil, nonByteArgError()
		}
		payloadSize := len(payload)
		if payloadSize < 1 {
			return nil, emptyPayloadError()
		}

		// parse packet

		packet := gopacket.NewPacket(
			payload[4:payloadSize], // base event argument is: |sizeof|[]byte|
			layers.LayerTypeIPv4,
			gopacket.Default,
		)
		if packet == nil {
			return []interface{}{}, parsePacketError()
		}

		layer3 := packet.NetworkLayer()

		switch l3 := layer3.(type) {
		case (*layers.IPv4):
			var ipv4 trace.ProtoIPv4
			copyIPv4ToProtoIPv4(l3, &ipv4)

			return []interface{}{
				l3.SrcIP.String(),
				l3.DstIP.String(),
				ipv4,
			}, nil
		}

		return nil, notProtoPacketError("IPv4")
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
	proto.SrcIP = l3.SrcIP.String()
	proto.DstIP = l3.DstIP.String()
	// TODO: IPv4 options if IHL > 5
}
