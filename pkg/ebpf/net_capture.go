package ebpf

import (
	gocontext "context"
	"encoding/binary"
	"fmt"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

//
// User chooses through config/cmdline how to capture pcap files:
//
// - single file
// - per process
// - per container
// - per command
//
// and might have more than 1 way enabled simultaneously.
//

const (
	familyIpv4 int = 1 << iota
	familyIpv6
)

func (t *Tracee) processNetCaptureEvents(ctx gocontext.Context) {
	var errChanList []<-chan error

	// source pipeline stage (re-used from regular pipeline)
	eventsChan, errChan := t.decodeEvents(ctx, t.netCapChannel)
	errChanList = append(errChanList, errChan)

	// process events stage (network capture only)
	errChan = t.processNetCapEvents(ctx, eventsChan)
	errChanList = append(errChanList, errChan)

	// pipeline started, wait for completion.
	t.WaitForPipeline(errChanList...)
}

func (t *Tracee) processNetCapEvents(ctx gocontext.Context, in <-chan *trace.Event) <-chan error {
	errc := make(chan error, 1)

	go func() {
		defer close(errc)

		for {
			select {
			case event := <-in:
				t.processNetCapEvent(event)
				t.stats.NetCapCount.Increment()

			case lost := <-t.lostNetCapChannel:
				if lost > 0 {
					// https://github.com/aquasecurity/libbpfgo/issues/122
					t.stats.LostNtCapCount.Increment(lost)
					logger.Warn(fmt.Sprintf("lost %d network capture events", lost))
				}

			case <-ctx.Done():
				return
			}
		}
	}()

	return errc
}

func (t *Tracee) processNetCapEvent(event *trace.Event) {
	eventId := events.ID(event.EventID)

	switch eventId {
	case events.NetPacketCapture:
		var ok bool
		var payload []byte
		var layerType gopacket.LayerType
		// var srcIP net.IP // keep for debug
		// var dstIP net.IP // keep for debug

		// sanity checks

		payloadArg := events.GetArg(event, "payload")
		if payloadArg == nil {
			logger.Debug("network capture: no payload packet")
			return
		}
		if payload, ok = payloadArg.Value.([]byte); !ok {
			logger.Debug("network capture: non []byte argument")
			return
		}
		payloadSize := len(payload)
		if payloadSize < 1 {
			logger.Debug("network capture: empty payload")
			return
		}

		// event retval encodes layer 3 protocol type

		if event.ReturnValue&familyIpv4 == familyIpv4 {
			layerType = layers.LayerTypeIPv4
		} else if event.ReturnValue&familyIpv6 == familyIpv6 {
			layerType = layers.LayerTypeIPv6
		} else {
			logger.Debug("unsupported layer3 protocol")
		}

		// parse packet

		packet := gopacket.NewPacket(
			payload[4:payloadSize], // base event argument is: |sizeof|[]byte|
			layerType,
			gopacket.Default,
		)
		if packet == nil {
			logger.Debug("could not parse packet")
			return
		}

		// NOTE:
		//
		// We're capturing L3 packets only, but pcap needs a L2 header, as we
		// are going to mix IPv4 and IPv6 packets in the same pcap file.
		//
		// The easiest link type is "Null", which emulates a BSD loopback
		// encapsulation (4-byte field differentiating IPv4 and IPv6 packets).
		//
		// So, from now on, instead of having the initial 32-bit as the
		// "sizeof" (the event argument), it will become this "fake L2 header"
		// as if it were the BSD loopback encapsulation header.
		//

		layer3 := packet.NetworkLayer()

		switch layer3.(type) {
		case (*layers.IPv4):
			binary.BigEndian.PutUint32(payload, 2) // L2 header: IPv4 (BSD encap header spec)
			// srcIP = v.SrcIP // keep for debug
			// dstIP = v.DstIP // keep for debug
		case (*layers.IPv6):
			binary.BigEndian.PutUint32(payload, 28) // L2 header: IPv6 (BSD encap header spec)
			// srcIP = v.SrcIP // keep for debug
			// dstIP = v.DstIP // keep for debug
		default:
			return
		}

		// This might be too much, but keep it here for now

		// logger.Debug(
		// 	"capturing network",
		// 	"command", event.ProcessName,
		// 	"srcIP", srcIP,
		// 	"dstIP", dstIP,
		// )

		// capture the packet to all enabled pcap files

		err := t.netCapturePcap.Write(event, payload)
		if err != nil {
			logger.Error("could not write pcap data", "err", err)
		}

	default:
		logger.Debug("network capture: wrong net capture event type")
	}
}
