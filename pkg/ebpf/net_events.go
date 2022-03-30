package ebpf

import (
	gocontext "context"
	"fmt"
	lru "github.com/hashicorp/golang-lru"
	"math"
	"net"
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

const openPcapsLimit = 512

type netPcap struct {
	FileObj os.File
	Writer  pcapgo.NgWriter
}

type netInfo struct {
	mtx          sync.Mutex
	pcapWriters  *lru.Cache
	ifaces       map[int]*net.Interface
	ifacesConfig map[string]int32
}

func (n *netInfo) hasIface(ifaceName string) bool {
	for _, iface := range n.ifaces {
		if iface.Name == ifaceName {
			return true
		}
	}
	return false
}

func (ni *netInfo) GetPcapWriter(id processPcapId) (netPcap, bool) {
	ni.mtx.Lock()
	defer ni.mtx.Unlock()

	pcap, exists := ni.pcapWriters.Get(id)
	if exists {
		return pcap.(netPcap), exists
	}
	return netPcap{}, exists
}

func (ni *netInfo) AddPcapWriter(id processPcapId, pcap netPcap) {
	ni.mtx.Lock()
	defer ni.mtx.Unlock()

	ni.pcapWriters.Add(id, pcap)
}

func (ni *netInfo) PcapWriterOnEvict(_ interface{}, value interface{}) {
	pcap := value.(netPcap)
	pcap.Writer.Flush()
	pcap.FileObj.Close()
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

func (t *Tracee) createPcapFile(pcapContext processPcapId) (netPcap, error) {
	pcapFilePath, err := t.getPcapFilePath(pcapContext)
	if err != nil {
		return netPcap{}, fmt.Errorf("error getting pcap file path: %v", err)
	}

	pcapFile, err := os.OpenFile(pcapFilePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return netPcap{}, fmt.Errorf("error creating pcap file: %v", err)
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
		return netPcap{}, err
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
			return netPcap{}, err
		}
	}

	// Flush the header
	err = pcapWriter.Flush()
	if err != nil {
		return netPcap{}, err
	}

	pcap := netPcap{*pcapFile, *pcapWriter}
	t.netInfo.AddPcapWriter(pcapContext, pcap)

	return pcap, nil
}

func (t *Tracee) netExit(pcapContext processPcapId) {
	// wait a second before deleting from the map - because there might be more packets coming in
	time.Sleep(time.Second * 1)

	t.netInfo.mtx.Lock()
	defer t.netInfo.mtx.Unlock()
	t.netInfo.pcapWriters.Remove(pcapContext)
}

func (t *Tracee) getHostPcapContext() processPcapId {
	return processPcapId{contID: "host"}
}

func (t *Tracee) getContainerPcapContext(containerId string) processPcapId {
	return processPcapId{contID: containerId}
}

func (t *Tracee) getProcessPcapContext(hostPid uint32, ProcessName string, procStartTime uint64, containerId string) processPcapId {
	return processPcapId{hostPid: hostPid, comm: ProcessName, procStartTime: procStartTime, contID: containerId}
}

func (t *Tracee) getPcapContextFromTid(hostTid uint32) (processPcapId, procinfo.ProcessCtx, error) {
	pcapContext := t.getHostPcapContext()
	networkThread, err := t.getProcessCtx(hostTid)
	if err != nil {
		return pcapContext, procinfo.ProcessCtx{}, fmt.Errorf("unable to get ProcessCtx of hostTid %d to generate pcap context: %v", hostTid, err)
	}

	var contID string
	if networkThread.ContainerID == "" {
		contID = "host"
	} else {
		contID = networkThread.ContainerID
	}

	if t.config.Capture.NetPerProcess {
		networkProcess, err := t.getProcessCtx(networkThread.HostPid)
		if err != nil {
			return pcapContext, procinfo.ProcessCtx{}, fmt.Errorf("unable to get ProcessCtx of hostTid %d to generate pcap context: %v", networkThread.HostPid, err)
		}
		pcapContext = t.getProcessPcapContext(networkProcess.HostPid, networkProcess.Comm, uint64(networkProcess.StartTime), contID)
	} else if t.config.Capture.NetPerContainer {
		pcapContext = t.getContainerPcapContext(contID)
	}

	return pcapContext, networkThread, nil
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
			packetContext, networkThread, _ := t.getPcapContextFromTid(netEventMetadata.HostTid)

			if isNetEvent(netEventMetadata.NetEventId) {
				var netCaptureData bufferdecoder.NetCaptureData
				err = netDecoder.DecodeNetCaptureData(&netCaptureData)
				if err != nil {
					t.handleError(err)
					continue
				}

				ifaceName := t.netInfo.ifaces[int(netCaptureData.ConfigIfaceIndex)].Name
				ifaceIdx, err := t.getTracedIfaceIdx(ifaceName)
				if err == nil && ifaceIdx >= 0 {
					if t.eventsToTrace[netEventMetadata.NetEventId] {
						evt, err := netPacketProtocolHandler(netDecoder, netEventMetadata, networkThread, "net_packet")
						if err != nil {
							t.handleError(err)
							continue
						}
						protocolProcessor(netEventMetadata.NetEventId, &evt, *netDecoder)
						// output the event
						select {
						case t.config.ChanEvents <- evt:
							t.stats.NetEvCount.Increment()
						case <-ctx.Done():
							return
						}
					}
				}

				ifaceIdx, err = t.getCapturedIfaceIdx(ifaceName)
				if ifaceIdx >= 0 && err == nil {
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
	iface, ok := t.netInfo.ifaces[int(capData.ConfigIfaceIndex)]
	if !ok {
		return fmt.Errorf("cannot get the right interface")
	}

	ifaceIdx, err := t.getCapturedIfaceIdx(iface.Name)
	if err != nil {
		return fmt.Errorf("cannot get the right interface idx in the capture ifaces list")
	}
	info := gopacket.CaptureInfo{
		Timestamp:      timeStamp,
		CaptureLength:  int(capData.PacketLength),
		Length:         int(capData.PacketLength),
		InterfaceIndex: ifaceIdx,
	}

	pcap, pcapWriterExists := t.netInfo.GetPcapWriter(packetContext)
	if !pcapWriterExists {
		pcap, err = t.createPcapFile(packetContext)
		if err != nil {
			return err
		}
	}

	err = pcap.Writer.WritePacket(info, packetBytes)
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
	//fmt.Println(packetBytes)
	return packetBytes, err
}

func isNetEvent(eventId int32) bool {
	if eventId >= NetPacket && eventId < MaxNetEventID {
		return true
	}
	return false

}

func protocolProcessor(eventID int32, evt *trace.Event, decoder bufferdecoder.EbpfDecoder) {
	evt.EventName = EventsDefinitions[eventID].Name
	switch eventID {
	case DnsRequest:
		dnsRequestProtocolHandler(decoder, evt)
	case DnsResponse:
		dnsResponseProtocolHandler(decoder, evt)
	}
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

func dnsRequestProtocolHandler(decoder bufferdecoder.EbpfDecoder, evt *trace.Event) error {
	requests := make([]bufferdecoder.DnsQueryData, 0, 0)
	decoder.DecodeDnsQueryArray(&requests)
	appendDnsRequestArgs(evt, &requests)
	return nil
}

// appendDnsRequestArgs parse the given buffer to dns questions and adds it to the event
func appendDnsRequestArgs(event *trace.Event, requests *[]bufferdecoder.DnsQueryData) {
	event.Args = append(event.Args, trace.Argument{
		ArgMeta: trace.ArgMeta{"dns_questions", "[]bufferdecoder.DnsQueryData"},
		Value:   *requests,
	})
	event.ArgsNum++

}

func dnsResponseProtocolHandler(decoder bufferdecoder.EbpfDecoder, evt *trace.Event) error {
	respones := make([]bufferdecoder.DnsResponseData, 0, 0)
	decoder.DecodeDnsResponseData(&respones)
	appendDnsResponseArgs(evt, &respones)
	return nil
}

// appendDnsRequestArgs parse the given buffer to dns questions and adds it to the event
func appendDnsResponseArgs(event *trace.Event, responses *[]bufferdecoder.DnsResponseData) {
	event.Args = append(event.Args, trace.Argument{
		ArgMeta: trace.ArgMeta{"dns_response", "[]bufferdecoder.DnsResponseData"},
		Value:   *responses,
	})
	event.ArgsNum++

}
