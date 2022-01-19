package tracee

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/aquasecurity/tracee/pkg/external"
	"time"

	"github.com/google/gopacket"
	"inet.af/netaddr"
)

type PktMeta struct {
	SrcIP    [16]byte `json:"src_ip"`
	DestIP   [16]byte `json:"dest_ip"`
	SrcPort  uint16   `json:"src_port"`
	DestPort uint16   `json:"dest_port"`
	Protocol uint8    `json:"protocol"`
	_        [3]byte  //padding
}

func (t Tracee) parsePacketMetaData(payload *bytes.Buffer) (PktMeta, uint32, int, error) {
	var pktMetaData PktMeta
	var pktLen uint32

	err := binary.Read(payload, binary.LittleEndian, &pktLen)
	if err != nil {
		return pktMetaData, 0, 0, err
	}
	var ifindex uint32
	err = binary.Read(payload, binary.LittleEndian, &ifindex)
	if err != nil {
		return pktMetaData, 0, 0, err
	}
	interfaceIndex, ok := t.ngIfacesIndex[int(ifindex)]
	if !ok {
		return pktMetaData, 0, 0, err
	}
	err = binary.Read(payload, binary.LittleEndian, &pktMetaData)
	if err != nil {
		return pktMetaData, 0, 0, err
	}
	return pktMetaData, pktLen, interfaceIndex, nil
}

func isIpv6(ip [16]byte) bool {
	zeroedPattern := make([]byte, 9, 9)
	if bytes.Compare(ip[:9], zeroedPattern) == 0 {
		return false
	}
	return true
}

//takes the packet metadata and create argument array with that data
func createPacketMetadataArg(packetmeta PktMeta) []external.Argument {
	eventArgs := make([]external.Argument, 0, 0)
	arg := external.PktMeta{}
	if isIpv6(packetmeta.SrcIP) {
		arg.SrcIP = netaddr.IPFrom16(packetmeta.SrcIP).String()
	} else {
		var ip [4]byte
		copy(ip[:], packetmeta.SrcIP[12:])
		arg.SrcIP = netaddr.IPFrom4(ip).String()
	}
	if isIpv6(packetmeta.DestIP) {
		arg.DestIP = netaddr.IPFrom16(packetmeta.DestIP).String()
	} else {
		var ip [4]byte
		copy(ip[:], packetmeta.SrcIP[12:])
		arg.DestIP = netaddr.IPFrom4(ip).String()
	}
	arg.SrcPort = packetmeta.SrcPort
	arg.DestPort = packetmeta.DestPort
	arg.Protocol = packetmeta.Protocol
	evtArg := external.Argument{
		ArgMeta: external.ArgMeta{"PacketMetaData", "PktMeta"},
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

func createNetEvent(ts int, hostTid int, processName string, eventId int32, eventName string, pkt PktMeta, ctx ProcessCtx) external.Event {
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
				pktMeta, pktLen, interfaceIndex, err := t.parsePacketMetaData(dataBuff)
				if err != nil {
					t.handleError(fmt.Errorf("couldent parse the packet metadata"))
					continue
				}
				ctx, exist := t.processTree.processTreeMap[hostTid]
				if !exist {
					t.handleError(fmt.Errorf("couldn't find the process"))
					continue
				}
				evt := createNetEvent(int(timeStamp), hostTid, processName, netEventId, "NetPacket", pktMeta, ctx)
				if t.config.Debug {
					fmt.Println("IN")
					t.config.ChanEvents <- evt
					t.stats.eventCounter.Increment()

					info := gopacket.CaptureInfo{
						Timestamp:      timeStampObj,
						CaptureLength:  int(pktLen),
						Length:         int(pktLen),
						InterfaceIndex: interfaceIndex,
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
