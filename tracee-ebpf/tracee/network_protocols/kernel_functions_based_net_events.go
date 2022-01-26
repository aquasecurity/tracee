package network_protocols

import (
	"bytes"
	"encoding/binary"
	"github.com/aquasecurity/tracee/pkg/external"
	"inet.af/netaddr"
)

type FunctionBasedPacket struct {
	LocalIP     [16]byte
	RemoteIP    [16]byte
	LocalPort   uint16
	RemotePort  uint16
	Protocol    uint8
	_           [3]byte //padding
	TcpOldState uint32
	TcpNewState uint32
	_           [4]byte //padding
	SockPtr     uint64
}

// parsing the PacketMeta struct from bytes.buffer
func ParseDebugPacketMetaData(payload *bytes.Buffer) (FunctionBasedPacket, error) {
	var pktMetaData FunctionBasedPacket
	err := binary.Read(payload, binary.LittleEndian, &pktMetaData)
	if err != nil {
		return pktMetaData, err
	}

	return pktMetaData, nil
}

func CreateDebugPacketMetadataArg(event *external.Event, packet FunctionBasedPacket) {
	eventArgs := make([]external.Argument, 0, 0)
	arg := external.PktMeta{}
	if IsIpv6(packet.LocalIP) {
		arg.SrcIP = netaddr.IPFrom16(packet.LocalIP).String()
	} else {
		ip := AssginIpV4(packet.LocalIP)
		arg.SrcIP = netaddr.IPFrom4(ip).String()
	}
	if IsIpv6(packet.RemoteIP) {
		arg.DestIP = netaddr.IPFrom16(packet.RemoteIP).String()
	} else {
		ip := AssginIpV4(packet.RemoteIP)
		arg.DestIP = netaddr.IPFrom4(ip).String()
	}
	arg.SrcPort = packet.LocalPort
	arg.DestPort = packet.RemotePort
	arg.Protocol = packet.Protocol
	evtArg := external.Argument{
		ArgMeta: external.ArgMeta{"DebugPacketMetaData", "PacketMeta"},
		Value:   arg,
	}
	eventArgs = append(eventArgs, evtArg)
	event.Args = eventArgs
	event.ArgsNum = len(eventArgs)
}
