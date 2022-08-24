package ebpf

import (
	gocontext "context"
	"fmt"
	"math"
	"net"
	"os"
	"path"
	"sync"
	"time"

	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/derive"
	"github.com/aquasecurity/tracee/pkg/procinfo"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	lru "github.com/hashicorp/golang-lru"
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

func (ni *netInfo) hasIface(ifaceName string) bool {
	for _, iface := range ni.ifaces {
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

// createPcapsDirPath create the pcap output directory and return its relative path in the output directory.
func (t *Tracee) createPcapsDirPath(pcapContext processPcapId) (string, error) {
	err := utils.MkdirAtExist(t.outDir, pcapContext.contID, os.ModePerm)
	if err != nil {
		return "", err
	}

	return pcapContext.contID, nil
}

// getPcapFilePath return the matching relative path of a pcap file for a give pcap context
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

	pcapFile, err := utils.OpenAt(t.outDir, pcapFilePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return netPcap{}, fmt.Errorf("error creating pcap file: %v", err)
	}

	ngIface := pcapgo.NgInterface{
		Name:       t.config.Capture.NetIfaces.Interfaces()[0],
		Comment:    "tracee tc capture",
		Filter:     "",
		LinkType:   layers.LinkTypeEthernet,
		SnapLength: uint32(math.MaxUint16),
	}

	pcapWriter, err := pcapgo.NewNgWriterInterface(pcapFile, ngIface, pcapgo.NgWriterOptions{})
	if err != nil {
		return netPcap{}, err
	}

	for _, iface := range t.config.Capture.NetIfaces.Interfaces()[1:] {
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

				// handle net event trace
				ifaceName := t.netInfo.ifaces[int(netCaptureData.ConfigIfaceIndex)].Name
				ifaceIdx, found := t.getTracedIfaceIdx(ifaceName)
				if found && ifaceIdx >= 0 {
					// this packet should be traced. i.e. output the event if chosen by the user.

					evt, err := protocolProcessor(networkThread, netEventMetadata, netDecoder, ifaceName, netCaptureData.PacketLength)
					if err != nil {
						t.handleError(err)
						continue
					}

					// derive events chosen by the user
					derivatives, errors := derive.DeriveEvent(evt, t.eventDerivations)

					for _, err := range errors {
						t.handleError(err)
					}

					for _, derivative := range derivatives {
						// output derived events
						select {
						case t.config.ChanEvents <- derivative:
							t.stats.NetEvCount.Increment()
						case <-ctx.Done():
							return
						}
					}

					if t.events[netEventMetadata.NetEventId].emit {
						// output origin event
						select {
						case t.config.ChanEvents <- evt:
							t.stats.NetEvCount.Increment()
						case <-ctx.Done():
							return
						}
					}
				}

				// handle packet capture
				ifaceIdx, found = t.getCapturedIfaceIdx(ifaceName)
				if ifaceIdx >= 0 && found {
					// this packet should be captured. i.e. save the packet into pcap.

					packetBytes, err := getPacketBytes(netDecoder, netCaptureData.PacketLength)
					if err != nil {
						t.handleError(err)
						continue
					}
					if err := t.writePacket(netCaptureData, ifaceIdx, time.Unix(0, int64(netEventMetadata.TimeStamp)), packetContext, packetBytes); err != nil {
						t.handleError(err)
						continue
					}
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

func (t *Tracee) writePacket(capData bufferdecoder.NetCaptureData, ifaceIdx int, timeStamp time.Time, packetContext processPcapId, packetBytes []byte) error {
	info := gopacket.CaptureInfo{
		Timestamp:      timeStamp,
		CaptureLength:  int(capData.PacketLength),
		Length:         int(capData.PacketLength),
		InterfaceIndex: ifaceIdx,
	}

	var err error
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
	return packetBytes, err
}

// isNetEvent checks if eventId is in net events IDs range
func isNetEvent(eventId events.ID) bool {
	if eventId >= events.NetPacket && eventId < events.MaxNetID {
		return true
	}
	return false
}
