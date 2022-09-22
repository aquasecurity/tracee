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
			return []interface{}{}, fmt.Errorf("could not parse IP packet")
		}

		icmpLayer, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		if !ok {
			return nil, fmt.Errorf("could not parse ICMPv4 packet")
		}

		ipLayer := packet.Layer(layers.LayerTypeIPv4)

		var srcIP net.IP
		var dstIP net.IP

		switch v := ipLayer.(type) {
		case (*layers.IPv4):
			srcIP = v.SrcIP
			dstIP = v.DstIP
		default:
			return nil, nil
		}

		return []interface{}{
			srcIP,
			dstIP,
			icmpLayer.TypeCode.String(),
			icmpLayer.Checksum,
			icmpLayer.Id,
			icmpLayer.Seq,
		}, nil
	}
}
