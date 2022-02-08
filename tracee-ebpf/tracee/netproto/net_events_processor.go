package netproto

import (
	"bytes"
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/pkg/procinfo"
)

const (
	NetPacket int32 = iota + 4000
	NetSecurityBind
	NetUdpSendmsg
	NetUdpDisconnect
	NetUdpDestroySock
	NetUdpV6DestroySock
	NetInetSockSetState
	NetTcpConnect
	MaxNetEventID
)

type EventMeta struct {
	TimeStamp   uint64 `json:"timeStamp"`
	NetEventId  int32  `json:"netEventId"`
	HostTid     int    `json:"hostTid"`
	ProcessName string `json:"processName"`
}
type CaptureData struct {
	PacketLen      uint32
	InterfaceIndex uint32
}

func ProcessNetEvent(buffer *bytes.Buffer, evtMeta EventMeta, eventName string, ctx procinfo.ProcessCtx, bootTime uint64) (external.Event, bool, CaptureData) {
	var evt external.Event
	var captureData CaptureData
	switch evtMeta.NetEventId {
	case NetPacket:
		var packet PacketMeta
		evt, packet = netPacketProtocolHandler(buffer, evtMeta, ctx, eventName, bootTime)
		captureData.PacketLen = packet.PktLen
		captureData.InterfaceIndex = packet.IfIndex
		return evt, true, captureData
	}

	return evt, false, captureData
}

func CreateNetEvent(eventMeta EventMeta, ctx procinfo.ProcessCtx) external.Event {
	evt := getEventByProcessCtx(ctx)
	evt.Timestamp = int(eventMeta.TimeStamp)
	evt.ProcessName = eventMeta.ProcessName
	evt.EventID = int(eventMeta.NetEventId)
	evt.ReturnValue = 0
	evt.StackAddresses = nil
	return evt
}

func getEventByProcessCtx(ctx procinfo.ProcessCtx) external.Event {
	var event external.Event
	event.ContainerID = ctx.ContainerID
	event.ProcessID = int(ctx.Pid)
	event.ThreadID = int(ctx.Tid)
	event.ParentProcessID = int(ctx.Ppid)
	event.HostProcessID = int(ctx.HostPid)
	event.HostThreadID = int(ctx.HostTid)
	event.HostParentProcessID = int(ctx.HostPpid)
	event.UserID = int(ctx.Uid)
	event.MountNS = int(ctx.MntId)
	event.PIDNS = int(ctx.PidId)
	return event

}
