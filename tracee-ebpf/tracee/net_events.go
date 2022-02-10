package tracee

import (
	"bytes"
	gocontext "context"
	"encoding/binary"
	"fmt"
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/pkg/procinfo"
	"time"

	"github.com/google/gopacket"
)

type EventMeta struct {
	TimeStamp   uint64 `json:"timeStamp"`
	NetEventId  uint32 `json:"netEventId"`
	HostTid     int    `json:"hostTid"`
	ProcessName string `json:"processName"`
}

type CaptureData struct {
	PacketLen      uint32
	InterfaceIndex uint32
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

			evtMeta, dataBuff := parseEventMetaData(in)

			// timeStamp is nanoseconds since system boot time
			timeStampObj := time.Unix(0, int64(evtMeta.TimeStamp+t.bootTime))

			if evtMeta.NetEventId == NetPacket {

				if t.config.Debug {
					var captureData CaptureData
					networkProcess, err := t.getProcessCtx(int(evtMeta.HostTid))
					if err != nil {
						t.handleError(err)
						continue
					}
					evt, packet := netPacketProtocolHandler(dataBuff, evtMeta, networkProcess, "net_packet", t.bootTime)
					captureData.PacketLen = packet.PktLen
					captureData.InterfaceIndex = packet.IfIndex
					if err := t.writePacket(captureData, time.Unix(int64(evtMeta.TimeStamp), 0), dataBuff); err != nil {
						t.handleError(err)
						continue
					}
					select {
					case t.config.ChanEvents <- evt:
						t.stats.eventCounter.Increment()
					case <-ctx.Done():
						return
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
				err := binary.Read(dataBuff, binary.LittleEndian, &pkt)
				if err != nil {
					t.handleError(err)
					continue
				}

				switch evtMeta.NetEventId {
				case DebugNetSecurityBind:
					fmt.Printf("%v  %-16s  %-7d  debug_net/security_socket_bind LocalIP: %s, LocalPort: %d, Protocol: %d\n",
						timeStampObj, evtMeta.ProcessName, evtMeta.HostTid, parseIP(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpSendmsg:
					fmt.Printf("%v  %-16s  %-7d  debug_net/udp_sendmsg          LocalIP: %s, LocalPort: %d, Protocol: %d\n",
						timeStampObj, evtMeta.ProcessName, evtMeta.HostTid, parseIP(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpDisconnect:
					fmt.Printf("%v  %-16s  %-7d  debug_net/__udp_disconnect     LocalIP: %s, LocalPort: %d, Protocol: %d\n",
						timeStampObj, evtMeta.ProcessName, evtMeta.HostTid, parseIP(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpDestroySock:
					fmt.Printf("%v  %-16s  %-7d  debug_net/udp_destroy_sock     LocalIP: %s, LocalPort: %d, Protocol: %d\n",
						timeStampObj, evtMeta.ProcessName, evtMeta.HostTid, parseIP(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpV6DestroySock:
					fmt.Printf("%v  %-16s  %-7d  debug_net/udpv6_destroy_sock   LocalIP: %s, LocalPort: %d, Protocol: %d\n",
						timeStampObj, evtMeta.ProcessName, evtMeta.HostTid, parseIP(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetInetSockSetState:
					fmt.Printf("%v  %-16s  %-7d  debug_net/inet_sock_set_state  LocalIP: %s, LocalPort: %d, RemoteIP: %s, RemotePort: %d, Protocol: %d, OldState: %d, NewState: %d, SockPtr: 0x%x\n",
						timeStampObj,
						evtMeta.ProcessName,
						evtMeta.HostTid,
						parseIP(pkt.LocalIP),
						pkt.LocalPort,
						parseIP(pkt.RemoteIP),
						pkt.RemotePort,
						pkt.Protocol,
						pkt.TcpOldState,
						pkt.TcpNewState,
						pkt.SockPtr)
				case DebugNetTcpConnect:
					fmt.Printf("%v  %-16s  %-7d  debug_net/tcp_connect     LocalIP: %s, LocalPort: %d, Protocol: %d\n",
						timeStampObj, evtMeta.ProcessName, evtMeta.HostTid, parseIP(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
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

// parsing the EventMeta struct from byte array and returns bytes.Buffer pointers
func parseEventMetaData(payloadBytes []byte) (EventMeta, *bytes.Buffer) {
	var eventMetaData EventMeta
	eventMetaData.TimeStamp = binary.LittleEndian.Uint64(payloadBytes[0:8])
	eventMetaData.NetEventId = binary.LittleEndian.Uint32(payloadBytes[8:12])
	eventMetaData.HostTid = int(binary.LittleEndian.Uint32(payloadBytes[12:16]))
	eventMetaData.ProcessName = string(bytes.TrimRight(payloadBytes[16:32], "\x00"))
	return eventMetaData, bytes.NewBuffer(payloadBytes[32:])

}

func netPacketProtocolHandler(buffer *bytes.Buffer, evtMeta EventMeta, ctx procinfo.ProcessCtx, eventName string, bootTime uint64) (external.Event, PacketMeta) {
	var evt external.Event
	packet, err := ParseNetPacketMetaData(buffer)
	if err != nil {
		return evt, packet
	}
	evt = CreateNetEvent(evtMeta, ctx)
	CreateNetPacketMetaArgs(&evt, packet)
	evt.EventName = eventName
	evt.Timestamp = int(evtMeta.TimeStamp + bootTime)
	return evt, packet
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
	arg.SrcIP = parseIP(packet.SrcIP)
	arg.DestIP = parseIP(packet.SrcIP)
	arg.SrcPort = packet.SrcPort
	arg.DestPort = packet.DestPort
	arg.Protocol = packet.Protocol
	evtArg := external.Argument{
		ArgMeta: external.ArgMeta{"metadata", "external.PktMeta"},
		Value:   arg,
	}
	eventArgs = append(eventArgs, evtArg)
	return eventArgs
}

func CreateNetPacketMetaArgs(event *external.Event, NetPacket PacketMeta) {
	event.Args = createNetPacketMetadataArg(NetPacket)
	event.ArgsNum = len(event.Args)
}
