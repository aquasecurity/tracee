package derive

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func NewNetPacketIPv4() deriveFunction {
	return deriveSingleEvent(events.NetPacketIPv4, deriveNetPacketIPv4Args())
}

func deriveNetPacketIPv4Args() deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		error01Str := "couldn't find argument name in event %s"
		error01 := fmt.Errorf(error01Str, event.EventName)

		arg0 := events.GetArg(&event, "arg0")
		if arg0 == nil {
			return nil, error01
		}

		arg1 := events.GetArg(&event, "arg1")
		if arg1 == nil {
			return nil, error01
		}

		payloadArg := events.GetArg(&event, "payload")
		if payloadArg == nil {
			return nil, error01
		}

		// TODO: protocol headers sent as payload, derive arguments from it

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
			return nil, fmt.Errorf("received non []byte argument")
		}

		payloadSize := len(payload)
		if payloadSize < 1 {
			return nil, fmt.Errorf("received empty []byte argument")
		}

		// obtaining the packet payload right after event
		packet := gopacket.NewPacket(
			payload[4:payloadSize],
			layerType,
			gopacket.Default,
		)
		if packet == nil {
			return []interface{}{}, fmt.Errorf("could not parse the packet")
		}

		// DEBUG:
		// fmt.Printf("%s", packet.Dump())
		// fmt.Printf("%s", packet.String())

		// IPv4

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
