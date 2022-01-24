package tracee

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/tracee-ebpf/tracee/network_protocols"
	"github.com/google/gopacket"
	"time"
)

type EventMeta struct {
	timeStamp   uint64 `json:"time_stamp"`
	netEventId  int32  `json:"net_event_id"`
	hostTid     int    `json:"host_tid"`
	processName string `json:"process_name"`
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
			evtMeta, dataBuff := parseEventMetaData(in)
			// timeStamp is nanoseconds since system boot time
			timeStampObj := time.Unix(0, int64(evtMeta.timeStamp+t.bootTime))

			processContext, exist := t.processTree.processTreeMap[evtMeta.hostTid]
			if !exist {
				t.handleError(fmt.Errorf("couldn't find the process: %d", evtMeta.hostTid))
				continue
			}

			if evtMeta.netEventId == NetPacket {
				packet, err := network_protocols.ParseNetPacketMetaData(dataBuff)
				if err != nil {
					t.handleError(fmt.Errorf("couldent parse the packet metadata"))
					continue
				}
				interfaceIndex, ok := t.ngIfacesIndex[int(packet.IfIndex)]
				// now we are only supporting net event tracing only in debug mode.
				// in the feature we will create specific flag for that feature
				if t.config.Debug {
					evt := createNetEvent(int(evtMeta.timeStamp), evtMeta.hostTid, evtMeta.processName, evtMeta.netEventId, "NetPacket", processContext)
					network_protocols.CreateNetPacketMetaArgs(&evt, packet)
					t.config.ChanEvents <- evt
					t.stats.eventCounter.Increment()
					if ok {
						if err := t.writePacket(packet.PktLen, timeStampObj, interfaceIndex, dataBuff); err != nil {
							t.handleError(err)
							continue
						}
					}

				}
			} else if t.config.Debug {
				debugEventPacket, err := network_protocols.ParseDebugPacketMetaData(dataBuff)
				if err != nil {
					t.handleError(err)
					continue
				}
				evt := createNetEvent(int(evtMeta.timeStamp), evtMeta.hostTid, evtMeta.processName, evtMeta.netEventId, EventsDefinitions[evtMeta.netEventId].Name, processContext)
				createDebugPacketMetaArgs(&evt, debugEventPacket)
				t.config.ChanEvents <- evt
				t.stats.eventCounter.Increment()
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
// Note: after this function the next data in the packet byte array is the PacketMeta struct so i recommend to call 'parseNetPacketMetaData' after this function had called
func parseEventMetaData(payloadBytes []byte) (EventMeta, *bytes.Buffer) {
	var eventMetaData EventMeta
	eventMetaData.timeStamp = binary.LittleEndian.Uint64(payloadBytes[0:8])
	eventMetaData.netEventId = int32(binary.LittleEndian.Uint32(payloadBytes[8:12]))
	eventMetaData.hostTid = int(binary.LittleEndian.Uint32(payloadBytes[12:16]))
	eventMetaData.processName = string(bytes.TrimRight(payloadBytes[16:32], "\x00"))
	return eventMetaData, bytes.NewBuffer(payloadBytes[32:])

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

func createNetEvent(ts int, hostTid int, processName string, eventId int32, eventName string, ctx ProcessCtx) external.Event {
	evt := getEventByProcessCtx(ctx)
	evt.Timestamp = ts
	evt.ProcessName = processName
	evt.EventID = int(eventId)
	evt.EventName = eventName
	evt.ReturnValue = 0
	evt.StackAddresses = nil
	return evt
}
func createDebugPacketMetaArgs(event *external.Event, NetPacket network_protocols.FunctionBasedPacket) {
	event.Args = network_protocols.CreateDebugPacketMetaffdataArg(NetPacket)
	event.ArgsNum = len(event.Args)
}
