package netproto

import (
	"encoding/binary"
	"fmt"
	"inet.af/netaddr"

	"github.com/aquasecurity/tracee/pkg/procinfo"
	"github.com/aquasecurity/tracee/types/trace"
)

// NetPacketProtocolHandler parse a given a packet bytes buffer to packetMeta and event
func NetPacketProtocolHandler(buffer []byte, evtMeta EventMeta, ctx procinfo.ProcessCtx, eventName string) (trace.Event, error) {
	var evt trace.Event
	packet, err := ParseNetPacketMetaData(buffer)
	if err != nil {
		return evt, err
	}
	evt = CreateNetEvent(evtMeta, ctx, eventName, int(evtMeta.TimeStamp))
	appendPktMetaArg(&evt, packet)
	return evt, nil
}

type EventMeta struct {
	TimeStamp   uint64 `json:"timeStamp"`
	NetEventId  uint32 `json:"netEventId"`
	HostTid     int    `json:"hostTid"`
	ProcessName string `json:"processName"`
}

func CreateNetEvent(eventMeta EventMeta, ctx procinfo.ProcessCtx, eventName string, ts int) trace.Event {
	evt := ctx.GetEventByProcessCtx()
	evt.Timestamp = int(eventMeta.TimeStamp)
	evt.ProcessName = eventMeta.ProcessName
	evt.EventID = int(eventMeta.NetEventId)
	evt.EventName = eventName
	evt.Timestamp = ts
	return evt
}

//takes the packet metadata and create argument array with that data
func appendPktMetaArg(event *trace.Event, NetPacket trace.PktMeta) {
	event.Args = []trace.Argument{trace.Argument{
		ArgMeta: trace.ArgMeta{"metadata", "trace.PktMeta"},
		Value: trace.PktMeta{
			SrcIP:    NetPacket.SrcIP,
			DstIP:    NetPacket.DstIP,
			SrcPort:  NetPacket.SrcPort,
			DstPort:  NetPacket.DstPort,
			Protocol: NetPacket.Protocol,
		},
	}}
	event.ArgsNum = 1
}

// parsing the PacketMeta struct from bytes.buffer
func ParseNetPacketMetaData(payload []byte) (trace.PktMeta, error) {
	var pktMetaData trace.PktMeta
	if len(payload) < 45 {
		return pktMetaData, fmt.Errorf("Payload size too short\n")
	}
	ip := [16]byte{0}
	copy(ip[:], payload[8:24])
	pktMetaData.SrcIP = netaddr.IPFrom16(ip).String()
	copy(ip[:], payload[24:40])
	pktMetaData.DstIP = netaddr.IPFrom16(ip).String()
	pktMetaData.SrcPort = binary.LittleEndian.Uint16(payload[40:42])
	pktMetaData.DstPort = binary.LittleEndian.Uint16(payload[42:44])
	pktMetaData.Protocol = payload[44]
	return pktMetaData, nil
}
