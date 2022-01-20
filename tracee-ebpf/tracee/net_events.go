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

			timeStamp := binary.LittleEndian.Uint64(in[0:8])
			netEventId := int32(binary.LittleEndian.Uint32(in[8:12]))
			hostTid := int(binary.LittleEndian.Uint32(in[12:16]))
			processName := string(bytes.TrimRight(in[16:32], "\x00"))
			dataBuff := bytes.NewBuffer(in[32:])

			// timeStamp is nanoseconds since system boot time
			timeStampObj := time.Unix(0, int64(timeStamp+t.bootTime))

			if netEventId == NetPacket {
				packet, err := parsePacketMetaData(dataBuff)
				if err != nil {
					t.handleError(fmt.Errorf("couldent parse the packet metadata"))
					continue
				}
				interfaceIndex, ok := t.ngIfacesIndex[int(packet.IfIndex)]
				ctx, exist := t.processTree.processTreeMap[hostTid]
				if !exist {
					t.handleError(fmt.Errorf("couldn't find the process"))
					continue
				}
				evt := createNetEvent(int(timeStamp), hostTid, processName, netEventId, "NetPacket", packet, ctx)
				if t.config.Debug {
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
						timeStampObj, processName, hostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpSendmsg:
					fmt.Printf("%v  %-16s  %-7d  debug_net/udp_sendmsg          LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, processName, hostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpDisconnect:
					fmt.Printf("%v  %-16s  %-7d  debug_net/__udp_disconnect     LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, processName, hostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpDestroySock:
					fmt.Printf("%v  %-16s  %-7d  debug_net/udp_destroy_sock     LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, processName, hostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpV6DestroySock:
					fmt.Printf("%v  %-16s  %-7d  debug_net/udpv6_destroy_sock   LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, processName, hostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetInetSockSetState:
					fmt.Printf("%v  %-16s  %-7d  debug_net/inet_sock_set_state  LocalIP: %v, LocalPort: %d, RemoteIP: %v, RemotePort: %d, Protocol: %d, OldState: %d, NewState: %d, SockPtr: 0x%x\n",
						timeStampObj,
						processName,
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
						timeStampObj, processName, hostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
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

// parsing the PacketMeta struct from bytes.buffer
func parsePacketMetaData(payload *bytes.Buffer) (PacketMeta, error) {
	var pktMetaData PacketMeta
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
func createPacketMetadataArg(packet PacketMeta) []external.Argument {
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

func createNetEvent(ts int, hostTid int, processName string, eventId int32, eventName string, pkt PacketMeta, ctx ProcessCtx) external.Event {
	args := createPacketMetadataArg(pkt)
	evt := getEventByProcessCtx(ctx)
	evt.Timestamp = ts
	evt.ProcessName = processName
	evt.EventID = int(eventId)
	evt.EventName = eventName
	evt.Args = args
	evt.ArgsNum = len(args)
	evt.ReturnValue = 0
	evt.StackAddresses = nil
	return evt
}
