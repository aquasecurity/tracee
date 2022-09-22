package derive

import (
	"fmt"
	"net"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func NetPacketUDP() deriveFunction {
	return deriveSingleEvent(events.NetPacketUDP, deriveNetPacketUDPArgs())
}

func deriveNetPacketUDPArgs() deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		payloadArg := events.GetArg(&event, "payload")
		if payloadArg == nil {
			return nil, fmt.Errorf("no payload ?")
		}

		var layerType gopacket.LayerType
		switch event.ReturnValue { // event retval tells layer type
		case 2:
			layerType = layers.LayerTypeIPv4
		case 10:
			layerType = layers.LayerTypeIPv6
		default:
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
			layerType,
			gopacket.Default,
		)

		if packet == nil {
			return []interface{}{}, fmt.Errorf("could not parse IP packet")
		}

		udpLayer, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if !ok {
			return nil, fmt.Errorf("could not parse UDP packet")
		}

		ipLayer := packet.Layer(layerType)

		var srcIP net.IP
		var dstIP net.IP

		switch v := ipLayer.(type) {
		case (*layers.IPv4):
			srcIP = v.SrcIP
			dstIP = v.DstIP
		case (*layers.IPv6):
			srcIP = v.SrcIP
			dstIP = v.DstIP
		}

		return []interface{}{
			srcIP,
			dstIP,
			udpLayer.SrcPort,
			udpLayer.DstPort,
			udpLayer.Length,
			udpLayer.Checksum,
		}, nil
	}
}
