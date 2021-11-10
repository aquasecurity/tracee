package tracee

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"math"
	"os"
	"path"
	"time"

	"github.com/google/gopacket"
	"inet.af/netaddr"
)

type processPcapId struct {
	hostPid       uint32
	procStartTime uint64
	comm          string
	contID        string
}

func (t *Tracee) getPcapsDirPath() string {
	return path.Join(t.config.Capture.OutputPath, "pcaps")
}

func (t *Tracee) getPcapFilePathWithTime(pcapContext processPcapId, timeStampObj time.Time) string {
	var pcapFileName string
	if t.config.Output.PcapPerProcess {
		pcapFileName = fmt.Sprintf("%s_%d_%d.pcap", pcapContext.comm, pcapContext.hostPid, pcapContext.procStartTime)
	} else if t.config.Output.PcapPerContainer {
		pcapFileName = fmt.Sprintf("%s_%d.pcap", pcapContext.contID, timeStampObj.Unix())
	} else {
		pcapFileName = "dump.pcap"
	}
	return path.Join(t.getPcapsDirPath(), pcapFileName)
}

func (t *Tracee) getPcapFilePath(pcapContext processPcapId) string {
	var pcapFileName string
	if t.config.Output.PcapPerProcess {
		pcapFileName = fmt.Sprintf("%s_%d_%d.pcap", pcapContext.comm, pcapContext.hostPid, pcapContext.procStartTime)
	} else if t.config.Output.PcapPerContainer {
		pcapFileName = fmt.Sprintf("%s.pcap", pcapContext.contID)
	} else {
		pcapFileName = "dump.pcap"
	}
	return path.Join(t.getPcapsDirPath(), pcapFileName)
}

func (t *Tracee) renamePcapFileAtExit(pcapContext processPcapId, timeStamp time.Time) error {
	origPcapFilePath := t.getPcapFilePath(pcapContext)
	newPcapFilePath := t.getPcapFilePathWithTime(pcapContext, timeStamp)

	return os.Rename(origPcapFilePath, newPcapFilePath)
}

func (t *Tracee) createPcapFile(pcapContext processPcapId) error {

	pcapsDirPath := t.getPcapsDirPath()
	err := os.MkdirAll(pcapsDirPath, os.ModePerm)
	if err != nil {
		return fmt.Errorf("error creating pcaps dir: %v", err)
	}

	pcapFilePath := t.getPcapFilePath(pcapContext)
	pcapFile, err := os.OpenFile(pcapFilePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("error creating pcap file: %v", err)
	}

	ngIface := pcapgo.NgInterface{
		Name:       t.config.Capture.NetIfaces[0],
		Comment:    "tracee tc capture",
		Filter:     "",
		LinkType:   layers.LinkTypeEthernet,
		SnapLength: uint32(math.MaxUint16),
	}

	pcapWriter, err := pcapgo.NewNgWriterInterface(pcapFile, ngIface, pcapgo.NgWriterOptions{})
	if err != nil {
		return err
	}

	for _, iface := range t.config.Capture.NetIfaces[1:] {
		ngIface = pcapgo.NgInterface{
			Name:       iface,
			Comment:    "tracee tc capture",
			Filter:     "",
			LinkType:   layers.LinkTypeEthernet,
			SnapLength: uint32(math.MaxUint16),
		}

		_, err := pcapWriter.AddInterface(ngIface)
		if err != nil {
			return err
		}
	}

	// Flush the header
	err = pcapWriter.Flush()
	if err != nil {
		return err
	}
	t.pcapWriters[pcapContext] = pcapWriter

	return nil
}

func (t *Tracee) netExit(pcapContext processPcapId, timeStamp time.Time) {

	delete(t.pcapWriters, pcapContext)
	err := t.renamePcapFileAtExit(pcapContext, timeStamp)
	if err != nil {
		t.handleError(err)
	}
}

func (t *Tracee) getPacketContext(hostTid uint32, procStartTime uint64, comm string, containerId string) processPcapId {
	var packetContext processPcapId
	if t.config.Output.PcapPerProcess {
		packetContext = processPcapId{hostPid: hostTid, comm: comm, procStartTime: procStartTime}
	} else if t.config.Output.PcapPerContainer {
		packetContext = processPcapId{contID: containerId}
	} else {
		packetContext = processPcapId{comm: "dump.pcap"}
	}

	return packetContext
}

func (t *Tracee) processNetEvents() {
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
			// 12:16 is hostTid which is of no use to us here
			hostPid := binary.LittleEndian.Uint32(in[16:20])
			// 20:24 is padding
			procStartTime := binary.LittleEndian.Uint64(in[24:32])
			comm := string(bytes.TrimRight(in[32:48], "\x00"))
			containerId := string(bytes.TrimRight(in[48:64], "\x00"))
			dataBuff := bytes.NewBuffer(in[64:])

			// timeStamp is nanoseconds since system boot time
			timeStampObj := time.Unix(0, int64(timeStamp+t.bootTime))

			packetContext := t.getPacketContext(hostPid, procStartTime, comm, containerId)

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

					fmt.Printf("%v  %-16s  %-7d  debug_net/packet               Len: %d, SrcIP: %v, SrcPort: %d, DestIP: %v, DestPort: %d, Protocol: %d\n",
						timeStampObj,
						comm,
						hostPid,
						pktLen,
						netaddr.IPFrom16(pktMeta.SrcIP),
						pktMeta.SrcPort,
						netaddr.IPFrom16(pktMeta.DestIP),
						pktMeta.DestPort,
						pktMeta.Protocol)
				}

				info := gopacket.CaptureInfo{
					Timestamp:      timeStampObj,
					CaptureLength:  int(pktLen),
					Length:         int(pktLen),
					InterfaceIndex: idx,
				}

				_, pcapWriterExists := t.pcapWriters[packetContext]
				if !pcapWriterExists {
					err = t.createPcapFile(packetContext)
					if err != nil {
						t.handleError(err)
						continue
					}
				}

				err = t.pcapWriters[packetContext].WritePacket(info, dataBuff.Bytes()[:pktLen])
				if err != nil {
					t.handleError(err)
					continue
				}

				// todo: maybe we should not flush every packet?
				err = t.pcapWriters[packetContext].Flush()
				if err != nil {
					t.handleError(err)
					continue
				}
			} else if (netEventId == NetConnectionExit && t.config.Output.PcapPerProcess) || (netEventId == NetContainerExit) {
				_, pcapWriterExists := t.pcapWriters[packetContext]
				if pcapWriterExists {
					go t.netExit(packetContext, timeStampObj)
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
						timeStampObj, comm, hostPid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpSendmsg:
					fmt.Printf("%v  %-16s  %-7d  debug_net/udp_sendmsg          LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, comm, hostPid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpDisconnect:
					fmt.Printf("%v  %-16s  %-7d  debug_net/__udp_disconnect     LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, comm, hostPid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpDestroySock:
					fmt.Printf("%v  %-16s  %-7d  debug_net/udp_destroy_sock     LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, comm, hostPid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpV6DestroySock:
					fmt.Printf("%v  %-16s  %-7d  debug_net/udpv6_destroy_sock   LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, comm, hostPid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetInetSockSetState:
					fmt.Printf("%v  %-16s  %-7d  debug_net/inet_sock_set_state  LocalIP: %v, LocalPort: %d, RemoteIP: %v, RemotePort: %d, Protocol: %d, OldState: %d, NewState: %d, SockPtr: 0x%x\n",
						timeStampObj,
						comm,
						hostPid,
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
						timeStampObj, comm, hostPid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				}
			}
		case lost := <-t.lostNetChannel:
			t.stats.lostNtCounter.Increment(int(lost))
		}
	}
}
