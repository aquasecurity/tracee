package derive

import (
	"net"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func NetPacketTCP() DeriveFunction {
	return deriveSingleEvent(events.NetPacketTCP, deriveNetPacketTCPArgs())
}

func deriveNetPacketTCPArgs() deriveArgsFunction {
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
		case (*layers.TCP):
			var tcp trace.ProtoTCP
			copyTCPToProtoTCP(l4, &tcp)

			return []interface{}{
				srcIP,
				dstIP,
				tcp.SrcPort,
				tcp.DstPort,
				tcp,
			}, nil
		}

		return nil, notProtoPacketError("TCP")
	}
}

//
// TCP protocol type conversion (from gopacket layer to trace type)
//

func copyTCPToProtoTCP(l4 *layers.TCP, proto *trace.ProtoTCP) {
	proto.SrcPort = uint16(l4.SrcPort)
	proto.DstPort = uint16(l4.DstPort)
	proto.Seq = l4.Seq
	proto.Ack = l4.Ack
	proto.DataOffset = l4.DataOffset
	proto.FIN = boolToUint8(l4.FIN)
	proto.SYN = boolToUint8(l4.SYN)
	proto.RST = boolToUint8(l4.RST)
	proto.PSH = boolToUint8(l4.PSH)
	proto.ACK = boolToUint8(l4.ACK)
	proto.URG = boolToUint8(l4.URG)
	proto.ECE = boolToUint8(l4.ECE)
	proto.NS = boolToUint8(l4.NS)
	proto.Window = l4.Window
	proto.Checksum = l4.Checksum
	proto.Urgent = l4.Urgent
	// TODO: TCP options
}
