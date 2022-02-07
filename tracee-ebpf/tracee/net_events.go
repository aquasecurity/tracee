package tracee

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"inet.af/netaddr"
)

type EventMeta struct {
	TimeStamp   uint64 `json:"timeStamp"`
	NetEventId  uint32 `json:"netEventId"`
	HostTid     int    `json:"hostTid"`
	ProcessName string `json:"processName"`
}

func (t *Tracee) processNetEvents() {
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
				var pktLen uint32
				err := binary.Read(dataBuff, binary.LittleEndian, &pktLen)
				if err != nil {
					t.handleError(err)
					continue
				}
				var ifindex uint32
				err = binary.Read(dataBuff, binary.LittleEndian, &ifindex)
				if err != nil {
					t.handleError(err)
					continue
				}
				idx, ok := t.ngIfacesIndex[int(ifindex)]
				if !ok {
					t.handleError(err)
					continue
				}

				if t.config.Debug {
					var pktMeta struct {
						SrcIP    [16]byte
						DestIP   [16]byte
						SrcPort  uint16
						DestPort uint16
						Protocol uint8
						_        [3]byte //padding
					}
					err = binary.Read(dataBuff, binary.LittleEndian, &pktMeta)
					if err != nil {
						t.handleError(err)
						continue
					}
					networkProcess, err := t.getProcessCtx(int(evtMeta.HostTid))
					hr, min, sec := timeStampObj.Clock()
					nsec := uint16(timeStampObj.Nanosecond())

					if err != nil {
						fmt.Printf("%v:%v:%v:%v  %-16s  %-7d  debug_net/packet               Len: %d, SrcIP: %v, SrcPort: %d, DestIP: %v, DestPort: %d, Protocol: %d\n",
							hr,
							min,
							sec,
							nsec,
							evtMeta.ProcessName,
							evtMeta.HostTid,
							pktLen,
							netaddr.IPFrom16(pktMeta.SrcIP),
							pktMeta.SrcPort,
							netaddr.IPFrom16(pktMeta.DestIP),
							pktMeta.DestPort,
							pktMeta.Protocol)
					} else {
						fmt.Printf("%v:%v:%v:%v   %v    %-16s  %v  %v    %d             debug_net/packet              Len: %d, SrcIP: %v, SrcPort: %d, DestIP: %v, DestPort: %d, Protocol: %d\n",
							hr,
							min,
							sec,
							nsec,
							networkProcess.Uid,
							evtMeta.ProcessName,
							networkProcess.Pid,
							networkProcess.Tid,
							0,
							pktLen,
							netaddr.IPFrom16(pktMeta.SrcIP),
							pktMeta.SrcPort,
							netaddr.IPFrom16(pktMeta.DestIP),
							pktMeta.DestPort,
							pktMeta.Protocol)
					}

				}
				if err := t.writePacket(pktLen, time.Unix(int64(evtMeta.TimeStamp), 0), idx, dataBuff); err != nil {
					t.handleError(err)
					continue
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
func parseEventMetaData(payloadBytes []byte) (EventMeta, *bytes.Buffer) {
	var eventMetaData EventMeta
	eventMetaData.TimeStamp = binary.LittleEndian.Uint64(payloadBytes[0:8])
	eventMetaData.NetEventId = binary.LittleEndian.Uint32(payloadBytes[8:12])
	eventMetaData.HostTid = int(binary.LittleEndian.Uint32(payloadBytes[12:16]))
	eventMetaData.ProcessName = string(bytes.TrimRight(payloadBytes[16:32], "\x00"))
	return eventMetaData, bytes.NewBuffer(payloadBytes[32:])

}
