package network_protocols

import (
	"bytes"
	"encoding/binary"
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/pkg/processContext"
	"inet.af/netaddr"
)

type PacketMeta struct {
	PktLen   uint32   `json:"pkt_len"`
	IfIndex  uint32   `json:"if_index"`
	SrcIP    [16]byte `json:"src_ip"`
	DestIP   [16]byte `json:"dest_ip"`
	SrcPort  uint16   `json:"src_port"`
	DestPort uint16   `json:"dest_port"`
	Protocol uint8    `json:"protocol"`
	_        [3]byte  //padding
}

func netPacketProtocolHandler(buffer *bytes.Buffer, evtMeta EventMeta, ctx processContext.ProcessCtx) external.Event {
	var evt external.Event
	packet, err := ParseNetPacketMetaData(buffer)
	if err != nil {
		return evt
	}
	evt = CreateNetEvent(evtMeta, "NetPacket", ctx)
	CreateNetPacketMetaArgs(&evt, packet)
	return evt
}

// parsing the PacketMeta struct from bytes.buffer
func ParseNetPacketMetaData(payload *bytes.Buffer) (PacketMeta, error) {
	var pktMetaData PacketMeta
	err := binary.Read(payload, binary.LittleEndian, &pktMetaData)
	if err != nil {
		return pktMetaData, err
	}
	return pktMetaData, nil
}

//takes the packet metadata and create argument array with that data
func createNetPacketMetadataArg(packet PacketMeta) []external.Argument {
	eventArgs := make([]external.Argument, 0, 0)
	arg := external.PktMeta{}
	if IsIpv6(packet.SrcIP) {
		arg.SrcIP = netaddr.IPFrom16(packet.SrcIP).String()
	} else {
		ip := AssginIpV4(packet.SrcIP)
		arg.SrcIP = netaddr.IPFrom4(ip).String()
	}
	if IsIpv6(packet.DestIP) {
		arg.DestIP = netaddr.IPFrom16(packet.DestIP).String()
	} else {
		ip := AssginIpV4(packet.DestIP)
		arg.DestIP = netaddr.IPFrom4(ip).String()
	}
	arg.SrcPort = packet.SrcPort
	arg.DestPort = packet.DestPort
	arg.Protocol = packet.Protocol
	evtArg := external.Argument{
		ArgMeta: external.ArgMeta{"PacketMetaData", "PacketMeta"},
		Value:   arg,
	}
	eventArgs = append(eventArgs, evtArg)
	return eventArgs
}

func CreateNetPacketMetaArgs(event *external.Event, NetPacket PacketMeta) {
	event.Args = createNetPacketMetadataArg(NetPacket)
	event.ArgsNum = len(event.Args)
}
