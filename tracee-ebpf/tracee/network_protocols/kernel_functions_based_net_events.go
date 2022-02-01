package network_protocols

import (
	"bytes"
	"encoding/binary"
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/pkg/processContext"
)

// FunctionBasedNetEvents are net events originated from kernel functions (kprobes) rather than from the tc (tc_probes).
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

func FunctionBasedNetEventHandler(buffer *bytes.Buffer, evtMeta EventMeta, ctx processContext.ProcessCtx, eventName string) external.Event {
	var evt external.Event
	functionBasedEventPacket, err := ParseFunctionBasedPacketMetaData(buffer)
	if err != nil {
		return evt
	}
	evt = CreateNetEvent(evtMeta, ctx)
	CreateFunctionBasedPacketMetadataArgs(&evt, functionBasedEventPacket)
	evt.EventName = eventName
	return evt
}

// parsing the PacketMeta struct from bytes.buffer
func ParseFunctionBasedPacketMetaData(payload *bytes.Buffer) (FunctionBasedPacket, error) {
	var pktMetaData FunctionBasedPacket
	err := binary.Read(payload, binary.LittleEndian, &pktMetaData)
	if err != nil {
		return pktMetaData, err
	}

	return pktMetaData, nil
}

func CreateFunctionBasedPacketMetadataArgs(event *external.Event, packet FunctionBasedPacket) {
	eventArgs := make([]external.Argument, 0, 0)
	arg := external.FunctionBasedPacket{}
	arg.LocalIP = parseIP(packet.LocalIP)
	arg.RemoteIP = parseIP(packet.RemoteIP)
	arg.LocalPort = packet.LocalPort
	arg.LocalPort = packet.RemotePort
	arg.Protocol = packet.Protocol
	arg.TcpNewState = packet.TcpNewState
	arg.TcpOldState = packet.TcpOldState
	arg.SockPtr = packet.SockPtr
	evtArg := external.Argument{
		ArgMeta: external.ArgMeta{"FunctionBasedPacket", "external.FunctionBasedPacket"},
		Value:   arg,
	}
	eventArgs = append(eventArgs, evtArg)
	event.Args = eventArgs
	event.ArgsNum = len(eventArgs)
}
