package tracee

import (
	"bytes"
	gocontext "context"
	"encoding/binary"
	"fmt"
	"github.com/aquasecurity/tracee/tracee-ebpf/tracee/network_protocols"
	"github.com/google/gopacket"
	"time"
)

func (t *Tracee) processNetEvents(ctx gocontext.Context) {
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

			processContext, err := t.getProcessCtx(evtMeta.HostTid)
			if err != nil {
				t.handleError(fmt.Errorf("couldn't find the process: %d", evtMeta.HostTid))
				continue
			}

			eventData, exist := EventsDefinitions[evtMeta.NetEventId]
			if !exist {
				t.handleError(fmt.Errorf("Net eventId didnt found in the map\n"))
				continue
			}
			eventName := eventData.Name
			evt, ShouldCapture, cap := network_protocols.ProcessNetEvent(dataBuff, evtMeta, eventName, processContext, t.bootTime)

			if ShouldCapture {
				interfaceIndex, ok := t.ngIfacesIndex[int(cap.InterfaceIndex)]
				if ok {
					if err := t.writePacket(cap.PacketLen, time.Unix(int64(evt.Timestamp), 0), interfaceIndex, dataBuff); err != nil {
						t.handleError(err)
						continue
					}
				}
			}
			select {
			case t.config.ChanEvents <- evt:
				t.stats.eventCounter.Increment()
			case <-ctx.Done():
				return
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
func parseEventMetaData(payloadBytes []byte) (network_protocols.EventMeta, *bytes.Buffer) {
	var eventMetaData network_protocols.EventMeta
	eventMetaData.TimeStamp = binary.LittleEndian.Uint64(payloadBytes[0:8])
	eventMetaData.NetEventId = int32(binary.LittleEndian.Uint32(payloadBytes[8:12]))
	eventMetaData.HostTid = int(binary.LittleEndian.Uint32(payloadBytes[12:16]))
	eventMetaData.ProcessName = string(bytes.TrimRight(payloadBytes[16:32], "\x00"))
	return eventMetaData, bytes.NewBuffer(payloadBytes[32:])

}
