package derive

import (
	"fmt"
	"net"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func NetPacketDNS() deriveFunction {
	return deriveSingleEvent(events.NetPacketDNS, deriveNetPacketDNS())
}

func deriveNetPacketDNS() deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		var ok bool
		var payload []byte
		var layerType gopacket.LayerType
		var srcIP net.IP
		var dstIP net.IP
		var srcPort uint16
		var dstPort uint16

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

		switch event.ReturnValue { // event retval tells layer type
		case 2:
			layerType = layers.LayerTypeIPv4
		case 10:
			layerType = layers.LayerTypeIPv6
		default:
			return nil, nil
		}

		// parse packet

		packet := gopacket.NewPacket(
			payload[4:payloadSize],
			layerType,
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
		case (*layers.IPv6):
			srcIP = v.SrcIP
			dstIP = v.DstIP
		default:
			return nil, nil
		}

		layer4 := packet.TransportLayer()

		switch v := layer4.(type) {
		case (*layers.TCP):
			srcPort = uint16(v.SrcPort)
			dstPort = uint16(v.DstPort)
		case (*layers.UDP):
			srcPort = uint16(v.SrcPort)
			dstPort = uint16(v.DstPort)
		default:
			return nil, nil
		}

		layer7 := packet.ApplicationLayer()

		switch l7 := layer7.(type) {
		case (*layers.DNS):
			// authoritative := v.AA
			// truncation := v.TC
			// recursion_desired := v.RD
			// recursion_available := v.RA
			// response := v.ResponseCode

			return []interface{}{
				srcIP,
				dstIP,
				srcPort,
				dstPort,
				l7.ID,
				l7.QR,
				l7.OpCode,
			}, nil
		default:
			fmt.Printf("%s", packet.String())
		}

		return nil, fmt.Errorf("not a DNS packet")
	}
}
