package ebpf

import (
	"bytes"
	gocontext "context"
	"encoding/binary"
	"fmt"
	"inet.af/netaddr"
	"time"

	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/pkg/procinfo"
	"github.com/google/gopacket"
)

type EventMeta struct {
	TimeStamp   uint64 `json:"timeStamp"`
	NetEventId  uint32 `json:"netEventId"`
	HostTid     int    `json:"hostTid"`
	ProcessName string `json:"processName"`
}

type CaptureData struct {
	PacketLen      uint32 `json:"pkt_len"`
	InterfaceIndex uint32 `json:"if_index"`
}

func (t *Tracee) processNetEvents(ctx gocontext.Context) {
	// Todo: split pcap files by context (tid + comm)
	// Todo: add stats for network packets (in epilog)
	for {
		select {
		case in := <-t.netChannel:
			// Sanity check - timestamp, event id, host tid and comm must exist in all net events
			if len(in) < 32 {
				continue
			}

			evtMeta, payloadBytes := parseEventMetaData(in)

			timeStampObj := time.Unix(0, int64(evtMeta.TimeStamp+t.bootTime))

			if t.config.Output.RelativeTime {
				// To get the current ("wall") time, we add the boot time into it.
				evtMeta.TimeStamp -= t.startTime
			} else {
				// timeStamp is nanoseconds since system boot time
				// To get the monotonic time since tracee was started, we have to subtract the start time from the timestamp.
				evtMeta.TimeStamp += t.bootTime
			}

			if evtMeta.NetEventId == NetPacket {
				captureData, err := parseCaptureData(payloadBytes)
				if err != nil {
					t.handleError(err)
					continue
				}
				if err := t.writePacket(captureData, time.Unix(int64(evtMeta.TimeStamp), 0), bytes.NewBuffer(payloadBytes)); err != nil {
					t.handleError(err)
					continue
				}
				if t.config.Debug {
					networkProcess, _ := t.getProcessCtx(int(evtMeta.HostTid))
					evt, err := netPacketProtocolHandler(payloadBytes, evtMeta, networkProcess, "net_packet")
					if err == nil {
						select {
						case t.config.ChanEvents <- evt:
							t.stats.NetEvCount.Increment()
						case <-ctx.Done():
							return
						}
					}
				}

			} else if t.config.Debug {
				var pkt struct {
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
				err := binary.Read(bytes.NewBuffer(payloadBytes), binary.LittleEndian, &pkt)
				if err != nil {
					t.handleError(err)
					continue
				}

				switch evtMeta.NetEventId {
				case DebugNetSecurityBind:
					fmt.Printf("%v  %-16s  %-7d  debug_net/security_socket_bind LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, evtMeta.ProcessName, evtMeta.HostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpSendmsg:
					fmt.Printf("%v  %-16s  %-7d  debug_net/udp_sendmsg          LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, evtMeta.ProcessName, evtMeta.HostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpDisconnect:
					fmt.Printf("%v  %-16s  %-7d  debug_net/__udp_disconnect     LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, evtMeta.ProcessName, evtMeta.HostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpDestroySock:
					fmt.Printf("%v  %-16s  %-7d  debug_net/udp_destroy_sock     LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, evtMeta.ProcessName, evtMeta.HostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpV6DestroySock:
					fmt.Printf("%v  %-16s  %-7d  debug_net/udpv6_destroy_sock   LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, evtMeta.ProcessName, evtMeta.HostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetInetSockSetState:
					fmt.Printf("%v  %-16s  %-7d  debug_net/inet_sock_set_state  LocalIP: %v, LocalPort: %d, RemoteIP: %v, RemotePort: %d, Protocol: %d, OldState: %d, NewState: %d, SockPtr: 0x%x\n",
						timeStampObj,
						evtMeta.ProcessName,
						evtMeta.HostTid,
						netaddr.IPFrom16(pkt.LocalIP),
						pkt.LocalPort,
						netaddr.IPFrom16(pkt.RemoteIP),
						pkt.RemotePort,
						pkt.Protocol,
						pkt.TcpOldState,
						pkt.TcpNewState,
						pkt.SockPtr)
				case DebugNetTcpConnect:
					fmt.Printf("%v  %-16s  %-7d  debug_net/tcp_connect     LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, evtMeta.ProcessName, evtMeta.HostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				}
			}

		case lost := <-t.lostNetChannel:
			// When terminating tracee-ebpf the lost channel receives multiple "0 lost events" events.
			// This check prevents those 0 lost events messages to be written to stderr until the bug is fixed:
			// https://github.com/aquasecurity/libbpfgo/issues/122
			if lost > 0 {
				t.stats.LostNtCount.Increment(int(lost))
				t.config.ChanErrors <- fmt.Errorf("lost %d network events", lost)
			}
		}
	}
}

func (t *Tracee) writePacket(capData CaptureData, timeStamp time.Time, dataBuff *bytes.Buffer) error {
	idx, ok := t.ngIfacesIndex[int(capData.InterfaceIndex)]
	if !ok {
		return fmt.Errorf("cant get the right interface index\n")
	}
	info := gopacket.CaptureInfo{
		Timestamp:      timeStamp,
		CaptureLength:  int(capData.PacketLen),
		Length:         int(capData.PacketLen),
		InterfaceIndex: int(idx),
	}

	err := t.pcapWriter.WritePacket(info, dataBuff.Bytes()[:capData.PacketLen])
	if err != nil {
		return err
	}

	// todo: maybe we should not flush every packet?
	err = t.pcapWriter.Flush()
	if err != nil {
		return err
	}
	return nil
}

// parsing the EventMeta struct from byte array and returns a slice of the rest payload
func parseEventMetaData(payloadBytes []byte) (EventMeta, []byte) {
	var eventMetaData EventMeta
	eventMetaData.TimeStamp = binary.LittleEndian.Uint64(payloadBytes[0:8])
	eventMetaData.NetEventId = binary.LittleEndian.Uint32(payloadBytes[8:12])
	eventMetaData.HostTid = int(binary.LittleEndian.Uint32(payloadBytes[12:16]))
	eventMetaData.ProcessName = string(bytes.TrimRight(payloadBytes[16:32], "\x00"))
	return eventMetaData, payloadBytes[32:]

}

// netPacketProtocolHandler parse a given a packet bytes buffer to packetMeta and event
func netPacketProtocolHandler(buffer []byte, evtMeta EventMeta, ctx procinfo.ProcessCtx, eventName string) (external.Event, error) {
	var evt external.Event
	packet, err := ParseNetPacketMetaData(buffer)
	if err != nil {
		return evt, err
	}
	evt = CreateNetEvent(evtMeta, ctx, eventName, int(evtMeta.TimeStamp))
	appendPktMetaArg(&evt, packet)
	return evt, nil
}

func parseCaptureData(payload []byte) (CaptureData, error) {
	var capData CaptureData
	if len(payload) < 8 {
		return capData, fmt.Errorf("payload too short\n")
	}
	capData.PacketLen = binary.LittleEndian.Uint32(payload[0:4])
	capData.InterfaceIndex = binary.LittleEndian.Uint32(payload[4:8])
	return capData, nil
}

// parsing the PacketMeta struct from bytes.buffer
func ParseNetPacketMetaData(payload []byte) (external.PktMeta, error) {
	var pktMetaData external.PktMeta
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

func CreateNetEvent(eventMeta EventMeta, ctx procinfo.ProcessCtx, eventName string, ts int) external.Event {
	evt := ctx.GetEventByProcessCtx()
	evt.Timestamp = int(eventMeta.TimeStamp)
	evt.ProcessName = eventMeta.ProcessName
	evt.EventID = int(eventMeta.NetEventId)
	evt.EventName = eventName
	evt.Timestamp = ts
	return evt
}

//takes the packet metadata and create argument array with that data
func appendPktMetaArg(event *external.Event, NetPacket external.PktMeta) {
	event.Args = []external.Argument{external.Argument{
		ArgMeta: external.ArgMeta{"metadata", "external.PktMeta"},
		Value: external.PktMeta{
			SrcIP:    NetPacket.SrcIP,
			DstIP:    NetPacket.DstIP,
			SrcPort:  NetPacket.SrcPort,
			DstPort:  NetPacket.DstPort,
			Protocol: NetPacket.Protocol,
		},
	}}
	event.ArgsNum = 1
}
