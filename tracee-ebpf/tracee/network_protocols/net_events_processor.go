package network_protocols

import (
	"bytes"
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/pkg/processContext"
)

const (
	NetPacket int32 = iota + 1000
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
	TimeStamp   uint64 `json:"time_stamp"`
	NetEventId  int32  `json:"net_event_id"`
	HostTid     int    `json:"host_tid"`
	ProcessName string `json:"process_name"`
}
type CaptueData struct {
	PacketLen      int
	InterfaceIndex uint32
}

func ProcessNetEvent(buffer *bytes.Buffer, evtMeta EventMeta, eventName string, ctx processContext.ProcessCtx) (external.Event, bool, CaptueData) {
	var evt external.Event
	var captureData CaptueData
	switch evtMeta.NetEventId {
	case NetPacket:
		evt = netPacketProtocolHandler(buffer, evtMeta, ctx)

		return evt, false, captureData

	}
	if evtMeta.NetEventId > NetPacket && evtMeta.NetEventId <= NetTcpConnect {
		return FunctionBasedNetEventHandler(buffer, evtMeta, ctx, eventName), false, captureData
	}
	return evt, true, captureData

}

func CreateNetEvent(eventMeta EventMeta, eventName string, ctx processContext.ProcessCtx) external.Event {
	evt := getEventByProcessCtx(ctx)
	evt.Timestamp = int(eventMeta.TimeStamp)
	evt.ProcessName = eventMeta.ProcessName
	evt.EventID = int(eventMeta.NetEventId)
	evt.EventName = eventName
	evt.ReturnValue = 0
	evt.StackAddresses = nil
	return evt
}

func getEventByProcessCtx(ctx processContext.ProcessCtx) external.Event {
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
