package derive

import (
	"net"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func NetPacketUDP() DeriveFunction {
	return deriveSingleEvent(events.NetPacketUDP, deriveNetPacketUDPArgs())
}

func deriveNetPacketUDPArgs() deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		var ok bool
		var payload []byte
		var layerType gopacket.LayerType
		var srcIP net.IP
		var dstIP net.IP

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

		// event retval encodes layer 3 protocol type

		if event.ReturnValue&familyIpv4 == familyIpv4 {
			layerType = layers.LayerTypeIPv4
		} else if event.ReturnValue&familyIpv6 == familyIpv6 {
			layerType = layers.LayerTypeIPv6
		} else {
			return nil, nil
		}

		// parse packet

		packet := gopacket.NewPacket(
			payload[4:payloadSize], // base event argument is: |sizeof|[]byte|
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
		case (*layers.UDP):
			var udp trace.ProtoUDP
			copyUDPToProtoUDP(l4, &udp)

			return []interface{}{
				srcIP,
				dstIP,
				udp.SrcPort,
				udp.DstPort,
				udp,
			}, nil
		}

		return nil, notProtoPacketError("UDP")
	}
}

//
// UDP protocol type conversion (from gopacket layer to trace type)
//

func copyUDPToProtoUDP(l4 *layers.UDP, proto *trace.ProtoUDP) {
	proto.SrcPort = uint16(l4.SrcPort)
	proto.DstPort = uint16(l4.DstPort)
	proto.Length = l4.Length
	proto.Checksum = l4.Checksum
}
