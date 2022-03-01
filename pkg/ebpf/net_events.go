package ebpf

import (
	"bytes"
	gocontext "context"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"path"
	"sync"
	"time"

	"inet.af/netaddr"

	"github.com/aquasecurity/tracee/pkg/procinfo"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
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

type netInfo struct {
	mtx           sync.Mutex
	pcapWriters   map[processPcapId]*pcapgo.NgWriter
	ngIfacesIndex map[int]int
}

func (ni *netInfo) GetPcapWriter(id processPcapId) (*pcapgo.NgWriter, bool) {
	ni.mtx.Lock()
	defer ni.mtx.Unlock()

	writer, exists := ni.pcapWriters[id]
	return writer, exists
}

func (ni *netInfo) SetPcapWriter(id processPcapId, writer *pcapgo.NgWriter) {
	ni.mtx.Lock()
	defer ni.mtx.Unlock()

	ni.pcapWriters[id] = writer
}

func (ni *netInfo) DeletePcapWriter(id processPcapId) {
	ni.mtx.Lock()
	defer ni.mtx.Unlock()

	delete(ni.pcapWriters, id)
}

type processPcapId struct {
	hostPid       uint32
	procStartTime uint64
	comm          string
	contID        string
}

func (t *Tracee) createPcapsDirPath(pcapContext processPcapId) (string, error) {
	pcapsDirPath := path.Join(t.config.Capture.OutputPath, pcapContext.contID)
	err := os.MkdirAll(pcapsDirPath, os.ModePerm)
	if err != nil {
		return "", err
	}

	return pcapsDirPath, nil
}

func (t *Tracee) getPcapFilePath(pcapContext processPcapId) (string, error) {
	pcapsDirPath, err := t.createPcapsDirPath(pcapContext)
	if err != nil {
		return "", err
	}

	var pcapFileName string
	if t.config.Capture.NetPerProcess {
		pcapFileName = fmt.Sprintf("%s_%d_%d.pcap", pcapContext.comm, pcapContext.hostPid, pcapContext.procStartTime)
	} else {
		pcapFileName = "capture.pcap"
	}

	return path.Join(pcapsDirPath, pcapFileName), nil
}

func (t *Tracee) createPcapFile(pcapContext processPcapId) error {
	pcapFilePath, err := t.getPcapFilePath(pcapContext)
	if err != nil {
		return fmt.Errorf("error getting pcap file path: %v", err)
	}

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
	t.netPcap.SetPcapWriter(pcapContext, pcapWriter)

	return nil
}

func (t *Tracee) netExit(pcapContext processPcapId) {
	// wait a second before deleting from the map - because there might be more packets coming in
	time.Sleep(time.Second * 1)
	t.netPcap.DeletePcapWriter(pcapContext)
}

func (t *Tracee) getPcapContext(hostTid uint32) (processPcapId, procinfo.ProcessCtx, error) {
	packetContext := processPcapId{contID: "host"}
	networkThread, err := t.getProcessCtx(hostTid)
	if err != nil {
		return packetContext, procinfo.ProcessCtx{}, fmt.Errorf("unable to get ProcessCtx of hostTid %d to generate pcap context: %v", hostTid, err)
	}
	networkProcess, err := t.getProcessCtx(networkThread.HostPid)
	if err != nil {
		return packetContext, procinfo.ProcessCtx{}, fmt.Errorf("unable to get ProcessCtx of hostTid %d to generate pcap context: %v", networkThread.HostPid, err)
	}

	var contID string
	if networkThread.ContainerID == "" {
		contID = "host"
	} else {
		contID = networkThread.ContainerID
	}

	if t.config.Capture.NetPerProcess {
		packetContext = processPcapId{hostPid: networkProcess.HostPid, comm: networkProcess.Comm, procStartTime: uint64(networkProcess.StartTime), contID: contID}
	} else if t.config.Capture.NetPerContainer {
		packetContext = processPcapId{contID: contID}
	}

	return packetContext, networkThread, nil
}

func (t *Tracee) processNetEvents(ctx gocontext.Context) {
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

			// continue without checking for error, as packetContext will be valid anyway
			packetContext, networkThread, _ := t.getPcapContext(uint32(evtMeta.HostTid))

			if evtMeta.NetEventId == NetPacket {
				captureData, err := parseCaptureData(payloadBytes)
				if err != nil {
					t.handleError(err)
					continue
				}
				if err := t.writePacket(captureData, time.Unix(int64(evtMeta.TimeStamp), 0), packetContext, bytes.NewBuffer(payloadBytes)); err != nil {
					t.handleError(err)
					continue
				}
				if t.config.Debug {
					evt, err := netPacketProtocolHandler(payloadBytes, evtMeta, networkThread, "net_packet")
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

func (t *Tracee) writePacket(capData CaptureData, timeStamp time.Time, packetContext processPcapId, dataBuff *bytes.Buffer) error {
	idx, ok := t.netPcap.ngIfacesIndex[int(capData.InterfaceIndex)]
	if !ok {
		return fmt.Errorf("cannot get the right interface index")
	}

	info := gopacket.CaptureInfo{
		Timestamp:      timeStamp,
		CaptureLength:  int(capData.PacketLen),
		Length:         int(capData.PacketLen),
		InterfaceIndex: int(idx),
	}

	_, pcapWriterExists := t.netPcap.GetPcapWriter(packetContext)
	if !pcapWriterExists {
		err := t.createPcapFile(packetContext)
		if err != nil {
			return err
		}
	}

	writer, _ := t.netPcap.GetPcapWriter(packetContext)
	err := writer.WritePacket(info, dataBuff.Bytes()[:capData.PacketLen])
	if err != nil {
		return err
	}

	// todo: maybe we should not flush every packet?
	err = writer.Flush()
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
func netPacketProtocolHandler(buffer []byte, evtMeta EventMeta, ctx procinfo.ProcessCtx, eventName string) (trace.Event, error) {
	var evt trace.Event
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
		return capData, fmt.Errorf("payload too short")
	}
	capData.PacketLen = binary.LittleEndian.Uint32(payload[0:4])
	capData.InterfaceIndex = binary.LittleEndian.Uint32(payload[4:8])
	return capData, nil
}

// parsing the PacketMeta struct from bytes.buffer
func ParseNetPacketMetaData(payload []byte) (trace.PktMeta, error) {
	var pktMetaData trace.PktMeta
	if len(payload) < 45 {
		return pktMetaData, fmt.Errorf("payload size too short")
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

func CreateNetEvent(eventMeta EventMeta, ctx procinfo.ProcessCtx, eventName string, ts int) trace.Event {
	evt := ctx.GetEventByProcessCtx()
	evt.Timestamp = int(eventMeta.TimeStamp)
	evt.ProcessName = eventMeta.ProcessName
	evt.EventID = int(eventMeta.NetEventId)
	evt.EventName = eventName
	evt.Timestamp = ts
	return evt
}

//takes the packet metadata and create argument array with that data
func appendPktMetaArg(event *trace.Event, NetPacket trace.PktMeta) {
	event.Args = []trace.Argument{
		{
			ArgMeta: trace.ArgMeta{
				Name: "metadata",
				Type: "trace.PktMeta"},
			Value: trace.PktMeta{
				SrcIP:    NetPacket.SrcIP,
				DstIP:    NetPacket.DstIP,
				SrcPort:  NetPacket.SrcPort,
				DstPort:  NetPacket.DstPort,
				Protocol: NetPacket.Protocol,
			},
		},
	}
	event.ArgsNum = 1
}
