package ebpf

import (
	gocontext "context"
	"fmt"
	"math"
	"os"
	"path"
	"sync"
	"time"

	"inet.af/netaddr"

	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/procinfo"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type netPcap struct {
	FileObj *os.File
	Writer  *pcapgo.NgWriter
}

type netInfo struct {
	mtx           sync.Mutex
	pcapWriters   map[processPcapId]netPcap
	ngIfacesIndex map[int]int
}

func (ni *netInfo) GetPcapWriter(id processPcapId) (netPcap, bool) {
	ni.mtx.Lock()
	defer ni.mtx.Unlock()

	writer, exists := ni.pcapWriters[id]
	return writer, exists
}

func (ni *netInfo) SetPcapWriter(id processPcapId, pcap netPcap) {
	ni.mtx.Lock()
	defer ni.mtx.Unlock()

	ni.pcapWriters[id] = pcap
}

func (ni *netInfo) DeletePcapWriter(id processPcapId) {
	// close the pcap file
	pcap, exists := ni.GetPcapWriter(id)
	if exists {
		pcap.Writer.Flush()
		pcap.FileObj.Close()
	}

	ni.mtx.Lock()
	defer ni.mtx.Unlock()

	// delete from map
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
	t.netCapture.SetPcapWriter(pcapContext, netPcap{pcapFile, pcapWriter})

	return nil
}

func (t *Tracee) netExit(pcapContext processPcapId) {
	// wait a second before deleting from the map - because there might be more packets coming in
	time.Sleep(time.Second * 1)
	t.netCapture.DeletePcapWriter(pcapContext)
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

			netDecoder := bufferdecoder.New(in)

			var netEventMetadata bufferdecoder.NetEventMetadata
			err := netDecoder.DecodeNetEventMetadata(&netEventMetadata)
			if err != nil {
				t.handleError(err)
				continue
			}

			timeStampObj := time.Unix(0, int64(netEventMetadata.TimeStamp+t.bootTime))

			if t.config.Output.RelativeTime {
				// To get the current ("wall") time, we add the boot time into it.
				netEventMetadata.TimeStamp -= t.startTime
			} else {
				// timeStamp is nanoseconds since system boot time
				// To get the monotonic time since tracee was started, we have to subtract the start time from the timestamp.
				netEventMetadata.TimeStamp += t.bootTime
			}

			// continue without checking for error, as packetContext will be valid anyway
			packetContext, networkThread, _ := t.getPcapContext(netEventMetadata.HostTid)

			if netEventMetadata.NetEventId == NetPacket {
				var netCaptureData bufferdecoder.NetCaptureData
				err = netDecoder.DecodeNetCaptureData(&netCaptureData)
				if err != nil {
					t.handleError(err)
					continue
				}

				if t.config.Debug {
					evt, err := netPacketProtocolHandler(netDecoder, netEventMetadata, networkThread, "net_packet")
					if err != nil {
						t.handleError(err)
						continue
					}

					// output the event
					select {
					case t.config.ChanEvents <- evt:
						t.stats.NetEvCount.Increment()
					case <-ctx.Done():
						return
					}
				}

				// capture the packet
				packetBytes, err := getPacketBytes(netDecoder, netCaptureData.PacketLength)
				if err != nil {
					t.handleError(err)
					continue
				}
				if err := t.writePacket(netCaptureData, time.Unix(0, int64(netEventMetadata.TimeStamp)), packetContext, packetBytes); err != nil {
					t.handleError(err)
					continue
				}
			} else if t.config.Debug {
				var netDebugEvent bufferdecoder.NetDebugEvent
				err = netDecoder.DecodeNetDebugEvent(&netDebugEvent)
				if err != nil {
					t.handleError(err)
					continue
				}

				switch netEventMetadata.NetEventId {
				case DebugNetSecurityBind:
					fmt.Printf("%v  %-16s  %-7d  debug_net/security_socket_bind LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, netEventMetadata.ProcessName, netEventMetadata.HostTid, netaddr.IPFrom16(netDebugEvent.LocalIP), netDebugEvent.LocalPort, netDebugEvent.Protocol)
				case DebugNetUdpSendmsg:
					fmt.Printf("%v  %-16s  %-7d  debug_net/udp_sendmsg          LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, netEventMetadata.ProcessName, netEventMetadata.HostTid, netaddr.IPFrom16(netDebugEvent.LocalIP), netDebugEvent.LocalPort, netDebugEvent.Protocol)
				case DebugNetUdpDisconnect:
					fmt.Printf("%v  %-16s  %-7d  debug_net/__udp_disconnect     LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, netEventMetadata.ProcessName, netEventMetadata.HostTid, netaddr.IPFrom16(netDebugEvent.LocalIP), netDebugEvent.LocalPort, netDebugEvent.Protocol)
				case DebugNetUdpDestroySock:
					fmt.Printf("%v  %-16s  %-7d  debug_net/udp_destroy_sock     LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, netEventMetadata.ProcessName, netEventMetadata.HostTid, netaddr.IPFrom16(netDebugEvent.LocalIP), netDebugEvent.LocalPort, netDebugEvent.Protocol)
				case DebugNetUdpV6DestroySock:
					fmt.Printf("%v  %-16s  %-7d  debug_net/udpv6_destroy_sock   LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, netEventMetadata.ProcessName, netEventMetadata.HostTid, netaddr.IPFrom16(netDebugEvent.LocalIP), netDebugEvent.LocalPort, netDebugEvent.Protocol)
				case DebugNetInetSockSetState:
					fmt.Printf("%v  %-16s  %-7d  debug_net/inet_sock_set_state  LocalIP: %v, LocalPort: %d, RemoteIP: %v, RemotePort: %d, Protocol: %d, OldState: %d, NewState: %d, SockPtr: 0x%x\n",
						timeStampObj,
						netEventMetadata.ProcessName,
						netEventMetadata.HostTid,
						netaddr.IPFrom16(netDebugEvent.LocalIP),
						netDebugEvent.LocalPort,
						netaddr.IPFrom16(netDebugEvent.RemoteIP),
						netDebugEvent.RemotePort,
						netDebugEvent.Protocol,
						netDebugEvent.TcpOldState,
						netDebugEvent.TcpNewState,
						netDebugEvent.SockPtr)
				case DebugNetTcpConnect:
					fmt.Printf("%v  %-16s  %-7d  debug_net/tcp_connect     LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, netEventMetadata.ProcessName, netEventMetadata.HostTid, netaddr.IPFrom16(netDebugEvent.LocalIP), netDebugEvent.LocalPort, netDebugEvent.Protocol)
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

func (t *Tracee) writePacket(capData bufferdecoder.NetCaptureData, timeStamp time.Time, packetContext processPcapId, packetBytes []byte) error {
	idx, ok := t.netCapture.ngIfacesIndex[int(capData.InterfaceIndex)]
	if !ok {
		return fmt.Errorf("cannot get the right interface index")
	}

	info := gopacket.CaptureInfo{
		Timestamp:      timeStamp,
		CaptureLength:  int(capData.PacketLength),
		Length:         int(capData.PacketLength),
		InterfaceIndex: idx,
	}

	_, pcapWriterExists := t.netCapture.GetPcapWriter(packetContext)
	if !pcapWriterExists {
		err := t.createPcapFile(packetContext)
		if err != nil {
			return err
		}
	}

	pcap, _ := t.netCapture.GetPcapWriter(packetContext)
	err := pcap.Writer.WritePacket(info, packetBytes)
	if err != nil {
		return err
	}

	// todo: maybe we should not flush every packet?
	err = pcap.Writer.Flush()
	if err != nil {
		return err
	}
	return nil
}

func getPacketBytes(netDecoder *bufferdecoder.EbpfDecoder, packetLength uint32) ([]byte, error) {
	packetBytes := make([]byte, packetLength)
	err := netDecoder.DecodeBytes(packetBytes[:], packetLength)
	return packetBytes, err
}

// netPacketProtocolHandler parse a given a packet bytes buffer to packetMeta and event
func netPacketProtocolHandler(netDecoder *bufferdecoder.EbpfDecoder, evtMeta bufferdecoder.NetEventMetadata, ctx procinfo.ProcessCtx, eventName string) (trace.Event, error) {
	var packetEvent bufferdecoder.NetPacketEvent
	err := netDecoder.DecodeNetPacketEvent(&packetEvent)
	if err != nil {
		return trace.Event{}, err
	}

	evt := CreateNetEvent(evtMeta, ctx, eventName)
	appendPktMetaArg(&evt, packetEvent)
	return evt, nil
}

func CreateNetEvent(eventMeta bufferdecoder.NetEventMetadata, ctx procinfo.ProcessCtx, eventName string) trace.Event {
	evt := ctx.GetEventByProcessCtx()
	evt.Timestamp = int(eventMeta.TimeStamp)
	evt.ProcessName = string(eventMeta.ProcessName[:])
	evt.EventID = int(eventMeta.NetEventId)
	evt.EventName = eventName
	return evt
}

//takes the packet metadata and create argument array with that data
func appendPktMetaArg(event *trace.Event, netPacket bufferdecoder.NetPacketEvent) {
	event.Args = []trace.Argument{
		{
			ArgMeta: trace.ArgMeta{
				Name: "metadata",
				Type: "trace.PktMeta"},
			Value: trace.PktMeta{
				SrcIP:    netaddr.IPFrom16(netPacket.SrcIP).String(),
				DstIP:    netaddr.IPFrom16(netPacket.DstIP).String(),
				SrcPort:  netPacket.SrcPort,
				DstPort:  netPacket.DstPort,
				Protocol: netPacket.Protocol,
			},
		},
	}
	event.ArgsNum = 1
}
