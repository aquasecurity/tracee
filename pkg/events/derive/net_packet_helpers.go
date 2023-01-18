package derive

import (
	"fmt"
	"net"
	"strings"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// helpers for all supported protocol derivations

// Event return value (retval) encodes network event related information, such
// as the L3 layer protocol (impossible to know without a L2 header, since
// cgroup_skb programs are L3 only). It might also encode some other
// information, such as L7 flow direction (impossible to know without deriving
// the network event. knowing in advance helps to derive correct event and not
// all possible ones).
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
		Iface:     "any", // TODO: pick iface index from the kernel ?
	}
}

func parseUntilLayer7(event *trace.Event, pair *netPair) (gopacket.ApplicationLayer, error) {
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

	// event retval encodes layer 3 protocol

	if event.ReturnValue&familyIpv4 == familyIpv4 {
		layerType = layers.LayerTypeIPv4
	} else if event.ReturnValue&familyIpv6 == familyIpv6 {
		layerType = layers.LayerTypeIPv6
	} else {
		return nil, fmt.Errorf("base layer type not supported: %d", event.ReturnValue)
	}

	// parse packet with gopacket

	packet := gopacket.NewPacket(
		payload[4:payloadSize], // base event argument is: |sizeof|[]byte|
		layerType,
		gopacket.Default,
	)
	if packet == nil {
		return nil, parsePacketError()
	}

	// network layer

	layer3 := packet.NetworkLayer()

	switch v := layer3.(type) {
	case (*layers.IPv4):
		pair.srcIP = v.SrcIP
		pair.dstIP = v.DstIP
		pair.length = uint32(v.Length)
	case (*layers.IPv6):
		pair.srcIP = v.SrcIP
		pair.dstIP = v.DstIP
		pair.length = uint32(v.Length)
	default:
		return nil, fmt.Errorf("layer 3 not supported: %v", layer3)
	}

	// transport layer

	layer4 := packet.TransportLayer()

	switch v := layer4.(type) {
	case (*layers.TCP):
		pair.srcPort = uint16(v.SrcPort)
		pair.dstPort = uint16(v.DstPort)
		pair.proto = IPPROTO_TCP
	case (*layers.UDP):
		pair.srcPort = uint16(v.SrcPort)
		pair.dstPort = uint16(v.DstPort)
		pair.proto = IPPROTO_UDP
	default:
		return nil, fmt.Errorf("layer 4 not supported: %v", layer4)
	}

	// check partial packet decoding

	errorLayer := packet.ErrorLayer()
	if errorLayer != nil {
		return nil, errorLayer.Error()
	}

	// application layer

	layer7 := packet.ApplicationLayer()

	return layer7, nil
}
