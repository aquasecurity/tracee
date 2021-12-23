package tracee

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"inet.af/netaddr"
	"time"
)

func DnsPaseName(payload []byte) string {
	for idx, val := range payload {
		if int16(val) < 32 && idx != 0 {
			payload[idx] = byte('.')
		}
	}
	return string(payload)
}

//asumme we get the payload as the start of the name and then we parse the name, class , type
func ParseDnsMetaData(payload []byte) ([3]string, int32) {

	queryData := [3]string{"", "Unknown", "Unknown"} //name, type, class
	for idx, val := range payload {
		if val == 0 || val == 0xc0 {
			//fmt.Println(payload[idx:idx+10])

			if val == 0xc0 {
				idx++
			} else if payload[idx+1] == 0xc0 {
				idx += 2
				queryData[0] = "prev"
			} else {
				if idx != 0 {
					queryData[0] = DnsPaseName(payload[1:idx])
				}
			}
			dataTypeB := payload[idx+2]
			dataClassB := payload[idx+4]
			switch dataClassB {
			case 0:
				queryData[2] = "Reserved"
			case 1:
				queryData[2] = "IN"
			case 2:
				queryData[2] = "Unassigned"
			case 3:
				queryData[2] = "CH"
			case 4:
				queryData[2] = "HS"
			}
			switch dataTypeB {
			case 1:
				queryData[1] = "A (IPv4)"

			case 28:
				queryData[1] = "AAAA (IPv6)"
			case 16:
				queryData[1] = "TXT"
			case 33:
				queryData[1] = "SRV (location of service)"
			case 5:
				queryData[1] = "CNAME"
			case 15:
				queryData[1] = "MX"
			case 2:
				queryData[2] = "NS"

			}
			return queryData, int32(idx + 4)
		}

	}
	return queryData, 0
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

			timeStamp := binary.LittleEndian.Uint64(in[0:8])
			netEventId := binary.LittleEndian.Uint32(in[8:12])
			hostTid := binary.LittleEndian.Uint32(in[12:16])
			comm := string(bytes.TrimRight(in[16:32], "\x00"))
			dataBuff := bytes.NewBuffer(in[32:])

			// timeStamp is nanoseconds since system boot time
			timeStampObj := time.Unix(0, int64(timeStamp+t.bootTime))

			if netEventId == NetPacket {
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
					networkProcess, err := t.getProcessCtx(hostTid)
					hr, min, sec := timeStampObj.Clock()
					nsec := timeStampObj.Nanosecond()
					if err != nil {
						fmt.Printf("%v:%v:%v:%v  %-16s  %-7d  debug_net/packet               Len: %d, SrcIP: %v, SrcPort: %d, DestIP: %v, DestPort: %d, Protocol: %d\n",
							hr,
							min,
							sec,
							nsec,
							comm,
							hostTid,
							pktLen,
							netaddr.IPFrom16(pktMeta.SrcIP),
							pktMeta.SrcPort,
							netaddr.IPFrom16(pktMeta.DestIP),
							pktMeta.DestPort,
							pktMeta.Protocol)
					} else {
						fmt.Printf("%v:%v:%v:%v  %v   %-16s  %v  %v    %d             debug_net/packet     %-7d            Len: %d, SrcIP: %v, SrcPort: %d, DestIP: %v, DestPort: %d, Protocol: %d\n",
							hr,
							min,
							sec,
							nsec,
							networkProcess.Uid,
							comm,
							networkProcess.Pid,
							networkProcess.Tid,
							0,
							hostTid,
							pktLen,
							netaddr.IPFrom16(pktMeta.SrcIP),
							pktMeta.SrcPort,
							netaddr.IPFrom16(pktMeta.DestIP),
							pktMeta.DestPort,
							pktMeta.Protocol)
					}

				}

				info := gopacket.CaptureInfo{
					Timestamp:      timeStampObj,
					CaptureLength:  int(pktLen),
					Length:         int(pktLen),
					InterfaceIndex: idx,
				}

				err = t.pcapWriter.WritePacket(info, dataBuff.Bytes()[:pktLen])
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

				switch netEventId {
				case DebugNetSecurityBind:
					fmt.Printf("%v  %-16s  %-7d  debug_net/security_socket_bind LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, comm, hostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpSendmsg:
					fmt.Printf("%v  %-16s  %-7d  debug_net/udp_sendmsg          LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, comm, hostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpDisconnect:
					fmt.Printf("%v  %-16s  %-7d  debug_net/__udp_disconnect     LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, comm, hostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpDestroySock:
					fmt.Printf("%v  %-16s  %-7d  debug_net/udp_destroy_sock     LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, comm, hostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpV6DestroySock:
					fmt.Printf("%v  %-16s  %-7d  debug_net/udpv6_destroy_sock   LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, comm, hostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetInetSockSetState:
					fmt.Printf("%v  %-16s  %-7d  debug_net/inet_sock_set_state  LocalIP: %v, LocalPort: %d, RemoteIP: %v, RemotePort: %d, Protocol: %d, OldState: %d, NewState: %d, SockPtr: 0x%x\n",
						timeStampObj,
						comm,
						hostTid,
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
						timeStampObj, comm, hostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				}
			}

		case lost := <-t.lostNetChannel:
			t.stats.lostNtCounter.Increment(int(lost))
		}
	}
}
