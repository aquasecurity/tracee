package derive

import (
	"fmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"strings"
)

// helpers for all supported protocol derivations

const (
	familyIpv4 int = 1 << iota
	familyIpv6
	protoHttpRequest
	protoHttpResponse
)

func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func convertArrayOfBytes(given [][]byte) []string {
	var res []string

	for _, i := range given {
		res = append(res, string(i))
	}

	return res
}

func strToLower(given string) string {
	return strings.ToLower(given)
}

//
// Helper Functions
//

type netPair struct {
	srcIP   net.IP
	dstIP   net.IP
	srcPort uint16
	dstPort uint16
	proto   uint8
	length  uint32
}

const (
	IPPROTO_TCP uint8 = 6
	IPPROTO_UDP uint8 = 17
)

// convertNetPairToPktMeta converts the local netPair type, used by this code,
// to PktMeta type, expected by the old dns events, which, for now, we want the
// new network packet simple dns events to be compatible with.
func convertNetPairToPktMeta(net *netPair) *trace.PktMeta {
	return &trace.PktMeta{
		SrcIP:     net.srcIP.String(),
		DstIP:     net.dstIP.String(),
		SrcPort:   net.srcPort,
		DstPort:   net.dstPort,
		Protocol:  net.proto,
		PacketLen: net.length,
		Iface:     "any", // TODO: pick iface from network events
	}
}

func parseUntilLayer7(event *trace.Event, httpNetPair *netPair) (gopacket.ApplicationLayer, error) {
	var ok bool
	var payload []byte
	var layerType gopacket.LayerType

	// sanity checks

	payloadArg := events.GetArg(event, "payload")
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

	// initial header type

	// event retval encodes layer type
	if event.ReturnValue&familyIpv4 == familyIpv4 {
		layerType = layers.LayerTypeIPv4
	} else if event.ReturnValue&familyIpv6 == familyIpv6 {
		layerType = layers.LayerTypeIPv6
	} else {
		return nil, fmt.Errorf("base layer type not supported: %d", event.ReturnValue)
	}

	// parse packet

	packet := gopacket.NewPacket(
		payload[4:payloadSize], // base event argument is: |sizeof|[]byte|
		layerType,
		gopacket.Default,
	)
	if packet == nil {
		return nil, parsePacketError()
	}

	layer3 := packet.NetworkLayer()

	switch v := layer3.(type) {
	case (*layers.IPv4):
		httpNetPair.srcIP = v.SrcIP
		httpNetPair.dstIP = v.DstIP
		httpNetPair.length = uint32(v.Length)
	case (*layers.IPv6):
		httpNetPair.srcIP = v.SrcIP
		httpNetPair.dstIP = v.DstIP
		httpNetPair.length = uint32(v.Length)
	default:
		return nil, fmt.Errorf("layer 3 not supported: %v", layer3)
	}

	layer4 := packet.TransportLayer()

	switch v := layer4.(type) {
	case (*layers.TCP):
		httpNetPair.srcPort = uint16(v.SrcPort)
		httpNetPair.dstPort = uint16(v.DstPort)
		httpNetPair.proto = IPPROTO_TCP
	case (*layers.UDP):
		httpNetPair.srcPort = uint16(v.SrcPort)
		httpNetPair.dstPort = uint16(v.DstPort)
		httpNetPair.proto = IPPROTO_UDP
	default:
		return nil, fmt.Errorf("layer 4 not supported: %v", layer4)
	}

	errorLayer := packet.ErrorLayer()
	if errorLayer != nil {
		return nil, errorLayer.Error()
	}
	layer7 := packet.ApplicationLayer()

	return layer7, nil
}
