package tracee

import (
	"bytes"
	gocontext "context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/aquasecurity/tracee/tracee-ebpf/tracee/netproto"
	"github.com/google/gopacket"
	"inet.af/netaddr"
)

func (t *Tracee) processNetEvents(ctx gocontext.Context) {
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

			processContext, err := t.getProcessCtx(evtMeta.HostTid)
			if err != nil {
				t.handleError(fmt.Errorf("couldn't find the process: %d", evtMeta.HostTid))
				continue
			}

			eventData, exist := EventsDefinitions[evtMeta.NetEventId]
			if !exist {
				t.handleError(fmt.Errorf("Net eventId didnt found in the map\n"))
				continue
			}
			eventName := eventData.Name
			evt, ShouldCapture, cap := netproto.ProcessNetEvent(dataBuff, evtMeta, eventName, processContext, t.bootTime)
			if ShouldCapture {
				interfaceIndex, ok := t.ngIfacesIndex[int(cap.InterfaceIndex)]
				if ok {
					if err := t.writePacket(cap.PacketLen, time.Unix(int64(evt.Timestamp), 0), interfaceIndex, dataBuff); err != nil {
						t.handleError(err)
						continue
					}
				}
			}
			if evtMeta.NetEventId == netproto.NetPacket {
				//TODO: add support to other network events such as the debug_events
				select {
				case t.config.ChanEvents <- evt:
					t.stats.eventCounter.Increment()
				case <-ctx.Done():
					return
				}

			}
			if evtMeta.NetEventId != netproto.NetPacket {
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
				err = binary.Read(dataBuff, binary.LittleEndian, &pkt)
				if err != nil {
					t.handleError(err)
					continue
				}
				ts := time.Unix(0, int64(evtMeta.TimeStamp+t.bootTime))
				hr, min, sec := ts.Clock()
				switch evtMeta.NetEventId {
				case netproto.NetSecurityBind:
					fmt.Printf("%v:%v:%v  %-16s  %-7d  debug_net/security_socket_bind LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						hr, min, sec, evtMeta.ProcessName, evtMeta.HostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case netproto.NetUdpSendmsg:
					fmt.Printf("%v:%v:%v  %-16s  %-7d  debug_net/udp_sendmsg          LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						hr, min, sec, evtMeta.ProcessName, evtMeta.HostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case netproto.NetUdpDisconnect:
					fmt.Printf("%v:%v:%v  %-16s  %-7d  debug_net/__udp_disconnect     LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						hr, min, sec, evtMeta.ProcessName, evtMeta.HostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case netproto.NetUdpDestroySock:
					fmt.Printf("%v:%v:%v  %-16s  %-7d  debug_net/udp_destroy_sock     LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						hr, min, sec, evtMeta.ProcessName, evtMeta.HostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case netproto.NetUdpV6DestroySock:
					fmt.Printf("%v:%v:%v  %-16s  %-7d  debug_net/udpv6_destroy_sock   LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						hr, min, sec, evtMeta.ProcessName, evtMeta.HostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case netproto.NetInetSockSetState:
					fmt.Printf("%v:%v:%v  %-16s  %-7d  debug_net/inet_sock_set_state  LocalIP: %v, LocalPort: %d, RemoteIP: %v, RemotePort: %d, Protocol: %d, OldState: %d, NewState: %d, SockPtr: 0x%x\n",
						hr,
						min,
						sec,
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
				case netproto.NetTcpConnect:
					fmt.Printf("%v  %-16s  %-7d  debug_net/tcp_connect     LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						ts, evtMeta.ProcessName, evtMeta.HostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				}
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

func (t *Tracee) writePacket(packetLen uint32, timeStamp time.Time, interfaceIndex int, dataBuff *bytes.Buffer) error {
	info := gopacket.CaptureInfo{
		Timestamp:      timeStamp,
		CaptureLength:  int(packetLen),
		Length:         int(packetLen),
		InterfaceIndex: interfaceIndex,
	}

	err := t.pcapWriter.WritePacket(info, dataBuff.Bytes()[:packetLen])
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
func parseEventMetaData(payloadBytes []byte) (netproto.EventMeta, *bytes.Buffer) {
	var eventMetaData netproto.EventMeta
	eventMetaData.TimeStamp = binary.LittleEndian.Uint64(payloadBytes[0:8])
	eventMetaData.NetEventId = int32(binary.LittleEndian.Uint32(payloadBytes[8:12]))
	eventMetaData.HostTid = int(binary.LittleEndian.Uint32(payloadBytes[12:16]))
	eventMetaData.ProcessName = string(bytes.TrimRight(payloadBytes[16:32], "\x00"))
	return eventMetaData, bytes.NewBuffer(payloadBytes[32:])

}
