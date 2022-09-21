package derive

import (
	"fmt"
	"net"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func NetPacketTCP() deriveFunction {
	return deriveSingleEvent(events.NetPacketTCP, deriveNetPacketTCPArgs())
}

func deriveNetPacketTCPArgs() deriveArgsFunction {
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

		//fmt.Printf("%s", packet.String())

		tcpLayer, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok {
			return nil, fmt.Errorf("could not parse TCP packet")
		}

		ipLayer := packet.Layer(layerType)

		// TODO: parse TCP and check if it is a valid TCP packet (or else nil,nil)

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

		return []interface{}{ // TCPv4
			srcIP,
			dstIP,
			tcpLayer.SrcPort,
			tcpLayer.DstPort,
			tcpLayer.Seq,
			tcpLayer.Ack,
			tcpLayer.DataOffset,
			tcpLayer.FIN,
			tcpLayer.SYN,
			tcpLayer.RST,
			tcpLayer.PSH,
			tcpLayer.ACK,
			tcpLayer.URG,
			tcpLayer.ECE,
			tcpLayer.CWR,
			tcpLayer.NS,
			tcpLayer.Window,
			tcpLayer.Checksum,
			tcpLayer.Urgent,
		}, nil
	}
}
