package tracee

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/google/gopacket"
	"inet.af/netaddr"
	"time"
)

type EventMeta struct {
	timeStamp   uint64 `json:"time_stamp"`
	netEventId  int32  `json:"net_event_id"`
	hostTid     int    `json:"host_tid"`
	processName string `json:"process_name"`
}

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
type DebugPacket struct {
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

var NetEvents = map[int32]string{
	NetPacket:                "NetPacket",
	DebugNetSecurityBind:     "DebugNetSecurityBind",
	DebugNetUdpSendmsg:       "DebugNetUdpSendmsg",
	DebugNetUdpDisconnect:    "DebugNetUdpDisconnect",
	DebugNetUdpDestroySock:   "DebugNetUdpDestroySock",
	DebugNetUdpV6DestroySock: "DebugNetUdpV6DestroySock",
	DebugNetInetSockSetState: "DebugNetInetSockSetState",
	DebugNetTcpConnect:       "DebugNetTcpConnect",
}

func (t *Tracee) processNetEvents() {
	// Todo: split pcap files by context (tid + comm)
	// Todo: add stats for network packets (in epilog)
	for {
		select {
		case in := <-t.netChannel:
			// Sanity check - timestamp, event id, host tid and processName must exist in all net events
			if len(in) < 32 {
				continue
			}
			evtMeta, dataBuff := parseEventMetaData(in)

			// timeStamp is nanoseconds since system boot time
			timeStampObj := time.Unix(0, int64(evtMeta.timeStamp+t.bootTime))

			ctx, exist := t.processTree.processTreeMap[evtMeta.hostTid]
			if !exist {
				t.handleError(fmt.Errorf("couldn't find the process"))
				continue
			}

			if evtMeta.netEventId == NetPacket {
				packet, err := parseNetPacketMetaData(dataBuff)
				if err != nil {
					t.handleError(fmt.Errorf("couldent parse the packet metadata"))
					continue
				}
				interfaceIndex, ok := t.ngIfacesIndex[int(packet.IfIndex)]
				// now we are only supporting net event tracing only in debug mode.
				// in the feature we will create specific flag for that feature
				if t.config.Debug {
					evt := createNetEvent(int(evtMeta.timeStamp), evtMeta.hostTid, evtMeta.processName, evtMeta.netEventId, "NetPacket", ctx)
					createNetPacketMetaArgs(&evt, packet)
					t.config.ChanEvents <- evt
					t.stats.eventCounter.Increment()
					if ok {
						info := gopacket.CaptureInfo{
							Timestamp:      timeStampObj,
							CaptureLength:  int(packet.PktLen),
							Length:         int(packet.PktLen),
							InterfaceIndex: interfaceIndex,
						}

						err = t.pcapWriter.WritePacket(info, dataBuff.Bytes()[:packet.PktLen])
						if err != nil {
							t.handleError(err)
							continue
						}

						// todo: maybe we should not flush every packet?
						err = t.pcapWriter.Flush()
						if err != nil {
							t.handleError(err)
							continue
						}
					}

				}
			} else if t.config.Debug {
				debugEventPacket, err := parseDebugPacketMetaData(dataBuff)
				if err != nil {
					t.handleError(err)
					continue
				}
				evt := createNetEvent(int(evtMeta.timeStamp), evtMeta.hostTid, evtMeta.processName, evtMeta.netEventId, NetEvents[evtMeta.netEventId], ctx)
				createDebugPacketMetaArgs(&evt, debugEventPacket)
				t.config.ChanEvents <- evt
				t.stats.eventCounter.Increment()
			}

		case lost := <-t.lostNetChannel:
			// When terminating tracee-ebpf the lost channel receives multiple "0 lost events" events.
			// This check prevents those 0 lost events messages to be written to stderr until the bug is fixed:
			// https://github.com/aquasecurity/libbpfgo/issues/122
			if lost > 0 {
				t.stats.lostNtCounter.Increment(int(lost))
				t.config.ChanErrors <- fmt.Errorf("lost %d network events", lost)
			}
		}
	}
}

// parsing the EventMeta struct from byte array and returns bytes.Buffer pointers
// Note: after this function the next data in the packet byte array is the PacketMeta struct so i recommend to call 'parseNetPacketMetaData' after this function had called
func parseEventMetaData(payloadBytes []byte) (EventMeta, *bytes.Buffer) {
	var eventMetaData EventMeta
	eventMetaData.timeStamp = binary.LittleEndian.Uint64(payloadBytes[0:8])
	eventMetaData.netEventId = int32(binary.LittleEndian.Uint32(payloadBytes[8:12]))
	eventMetaData.hostTid = int(binary.LittleEndian.Uint32(payloadBytes[12:16]))
	eventMetaData.processName = string(bytes.TrimRight(payloadBytes[16:32], "\x00"))
	return eventMetaData, bytes.NewBuffer(payloadBytes[32:])

}

// parsing the PacketMeta struct from bytes.buffer
func parseNetPacketMetaData(payload *bytes.Buffer) (PacketMeta, error) {
	var pktMetaData PacketMeta
	err := binary.Read(payload, binary.LittleEndian, &pktMetaData)
	if err != nil {
		return pktMetaData, err
	}
	return pktMetaData, nil
}

// parsing the PacketMeta struct from bytes.buffer
func parseDebugPacketMetaData(payload *bytes.Buffer) (DebugPacket, error) {
	var pktMetaData DebugPacket
	err := binary.Read(payload, binary.LittleEndian, &pktMetaData)
	if err != nil {
		return pktMetaData, err
	}

	return pktMetaData, nil
}

// check if a given Ip as byte array is Ipv6 or Ipv4
func isIpv6(ip [16]byte) bool {
	zeroedPattern := make([]byte, 9, 9)
	if bytes.Compare(ip[:9], zeroedPattern) == 0 {
		return false
	}
	return true
}

func assginIpV4(ip [16]byte) [4]byte {
	var ipV4 [4]byte
	copy(ipV4[:], ip[12:16])
	return ipV4
}

//takes the packet metadata and create argument array with that data
func createNetPacketMetadataArg(packet PacketMeta) []external.Argument {
	eventArgs := make([]external.Argument, 0, 0)
	arg := external.PktMeta{}
	if isIpv6(packet.SrcIP) {
		arg.SrcIP = netaddr.IPFrom16(packet.SrcIP).String()
	} else {
		ip := assginIpV4(packet.SrcIP)
		arg.SrcIP = netaddr.IPFrom4(ip).String()
	}
	if isIpv6(packet.DestIP) {
		arg.DestIP = netaddr.IPFrom16(packet.DestIP).String()
	} else {
		ip := assginIpV4(packet.DestIP)
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

func createDebugPacketMetaffdataArg(packet DebugPacket) []external.Argument {
	eventArgs := make([]external.Argument, 0, 0)
	arg := external.PktMeta{}
	if isIpv6(packet.LocalIP) {
		arg.SrcIP = netaddr.IPFrom16(packet.LocalIP).String()
	} else {
		ip := assginIpV4(packet.LocalIP)
		arg.SrcIP = netaddr.IPFrom4(ip).String()
	}
	if isIpv6(packet.RemoteIP) {
		arg.DestIP = netaddr.IPFrom16(packet.RemoteIP).String()
	} else {
		ip := assginIpV4(packet.RemoteIP)
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
	return eventArgs
}

func getEventByProcessCtx(ctx ProcessCtx) external.Event {
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

func createNetEvent(ts int, hostTid int, processName string, eventId int32, eventName string, ctx ProcessCtx) external.Event {
	evt := getEventByProcessCtx(ctx)
	evt.Timestamp = ts
	evt.ProcessName = processName
	evt.EventID = int(eventId)
	evt.EventName = eventName
	evt.ReturnValue = 0
	evt.StackAddresses = nil
	return evt
}
func createNetPacketMetaArgs(event *external.Event, NetPacket PacketMeta) {
	event.Args = createNetPacketMetadataArg(NetPacket)
	event.ArgsNum = len(event.Args)
}
func createDebugPacketMetaArgs(event *external.Event, NetPacket DebugPacket) {
	event.Args = createDebugPacketMetaffdataArg(NetPacket)
	event.ArgsNum = len(event.Args)
}
