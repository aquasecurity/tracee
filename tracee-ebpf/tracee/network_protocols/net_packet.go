package network_protocols

import (
	"bytes"
	"encoding/binary"
	"github.com/aquasecurity/tracee/pkg/external"
	"inet.af/netaddr"
)

// parsing the PacketMeta struct from bytes.buffer
func ParseNetPacketMetaData(payload *bytes.Buffer) (external.PacketMeta, error) {
	var pktMetaData external.PacketMeta
	err := binary.Read(payload, binary.LittleEndian, &pktMetaData)
	if err != nil {
		return pktMetaData, err
	}
	return pktMetaData, nil
}

//takes the packet metadata and create argument array with that data
func createNetPacketMetadataArg(packet external.PacketMeta) []external.Argument {
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

func CreateNetPacketMetaArgs(event *external.Event, NetPacket external.PacketMeta) {
	event.Args = createNetPacketMetadataArg(NetPacket)
	event.ArgsNum = len(event.Args)
}
