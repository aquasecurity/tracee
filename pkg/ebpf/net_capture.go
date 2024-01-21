package ebpf

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
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

func (t *Tracee) handleNetCaptureEvents(ctx context.Context) {
	logger.Debugw("Starting handleNetCaptureEvents goroutine")
	defer logger.Debugw("Stopped handleNetCaptureEvents goroutine")

	var errChanList []<-chan error

	// source pipeline stage (re-used from regular pipeline)
	eventsChan, errChan := t.decodeEvents(ctx, t.netCapChannel)
	errChanList = append(errChanList, errChan)

	// process events stage (network capture only)
	errChan = t.processNetCapEvents(ctx, eventsChan)
	errChanList = append(errChanList, errChan)

	// pipeline started, wait for completion.
	if err := t.WaitForPipeline(errChanList...); err != nil {
		logger.Errorw("Pipeline", "error", err)
	}
}

func (t *Tracee) processNetCapEvents(ctx context.Context, in <-chan *trace.Event) <-chan error {
	errc := make(chan error, 1)

	go func() {
		defer close(errc)

		for {
			select {
			case event := <-in:
				// TODO: Support captures pipeline in t.processEvent
				err := t.normalizeEventCtxTimes(event)
				if err != nil {
					t.handleError(err)
					t.eventsPool.Put(event)
					continue
				}
				t.processNetCapEvent(event)
				_ = t.stats.NetCapCount.Increment()
				t.eventsPool.Put(event)

			case lost := <-t.lostNetCapChannel:
				if err := t.stats.LostNtCapCount.Increment(lost); err != nil {
					logger.Errorw("Incrementing lost network events count", "error", err)
				}
				logger.Warnw(fmt.Sprintf("Lost %d network capture events", lost))

			case <-ctx.Done():
				return
			}
		}
	}()

	return errc
}

// processNetCapEvent processes network packets meant to be captured.
//
// TODO: usually networking parsing functions are big, still, this might need
// some refactoring to make it smaller (code reuse might not be a key for the
// refactor).
func (t *Tracee) processNetCapEvent(event *trace.Event) {
	eventId := events.ID(event.EventID)

	switch eventId {
	case events.NetPacketCapture:
		var (
			ok            bool
			payloadLayer3 []byte
			payloadLayer2 []byte
			layerType     gopacket.LayerType
		)

		// sanity checks

		payloadArg := events.GetArg(event, "payload")
		if payloadArg == nil {
			logger.Debugw("Network capture: no payload packet")
			return
		}
		if payloadLayer3, ok = payloadArg.Value.([]byte); !ok {
			logger.Debugw("Network capture: non []byte argument")
			return
		}
		payloadLayer3Size := len(payloadLayer3)
		if payloadLayer3Size < 1 {
			logger.Debugw("Network capture: empty payload")
			return
		}

		// event retval encodes layer 3 protocol type

		if event.ReturnValue&familyIpv4 == familyIpv4 {
			layerType = layers.LayerTypeIPv4
		} else if event.ReturnValue&familyIpv6 == familyIpv6 {
			layerType = layers.LayerTypeIPv6
		} else {
			logger.Debugw("Unsupported layer3 protocol")
		}

		// make room for fake layer 2 header

		layer2Slice := make([]byte, 4)
		payloadLayer2 = append(layer2Slice[:], payloadLayer3...)

		// parse packet

		packet := gopacket.NewPacket(
			payloadLayer2[4:payloadLayer3Size],
			layerType,
			gopacket.Default,
		)
		if packet == nil {
			logger.Debugw("Could not parse packet")
			return
		}

		// amount of bytes the TCP header has based on data offset field

		tcpDoff := func(l4 gopacket.TransportLayer) uint32 {
			var doff uint32
			if v, ok := l4.(*layers.TCP); ok {
				doff = 20                    // TCP header default length is 20 bytes
				if v.DataOffset > uint8(5) { // unless doff is set, then...
					doff = uint32(v.DataOffset) * 4 // doff * 32bit words == tcp header length
				}
			}
			return doff
		}

		// NOTES:
		//
		// 1) Fake Layer 2:
		//
		// Tracee captures L3 packets only, but pcap needs a L2 header, as it
		// mixes IPv4 and IPv6 packets in the same pcap file.
		//
		// The easiest link type is "Null", which emulates a BSD loopback
		// encapsulation (4-byte field differentiating IPv4 and IPv6 packets).
		//
		// So, from now on, instead of having the initial 32-bit as the "sizeof"
		// (the event argument), it will become this "fake L2 header" as if it
		// were the BSD loopback encapsulation header.
		//
		// 2) Fake IP header length Field:
		//
		// Tcpdump, when reading the generated pcap files, will complain about
		// missing packet payload if the IP header says one length and the
		// actual data in the payload is smaller (what happens when tracee
		// pcap-snaplen option is not set to max). The code bellow changes IP
		// length field to the length of the captured data.
		//

		captureLength := t.config.Capture.Net.CaptureLength // after last known header

		// parse packet
		layer3 := packet.NetworkLayer()
		layer4 := packet.TransportLayer()

		ipHeaderLength := uint32(0)  // IP header length is dynamic
		udpHeaderLength := uint32(8) // UDP header length is 8 bytes
		tcpHeaderLength := uint32(0) // TCP header length is dynamic

		// will calculate L4 protocol headers length value
		ipHeaderLengthValue := uint32(0)
		udpHeaderLengthValue := uint32(0)

		switch v := layer3.(type) {
		case (*layers.IPv4):
			// Fake L2 header: IPv4 (BSD encap header spec)
			binary.BigEndian.PutUint32(payloadLayer2, 2) // set value 2 to first 4 bytes (uint32)

			// IP header depends on IHL flag (default: 5 * 4 = 20 bytes)
			ipHeaderLength += uint32(v.IHL) * 4
			ipHeaderLengthValue += ipHeaderLength

			switch v.Protocol {
			case layers.IPProtocolICMPv4:
				// ICMP
				break // always has "headers" only (payload = 0)
			case layers.IPProtocolUDP:
				// UDP
				udpHeaderLengthValue += udpHeaderLength
				ipHeaderLengthValue += udpHeaderLength
			case layers.IPProtocolTCP:
				// TCP
				tcpHeaderLength = tcpDoff(layer4)
				ipHeaderLengthValue += tcpHeaderLength
			}

			// add capture length (length to capture after last known proto header)
			ipHeaderLengthValue += captureLength
			udpHeaderLengthValue += captureLength

			// capture length is bigger than the pkt payload: no need for mangling
			if ipHeaderLengthValue != uint32(len(payloadLayer2[4:])) {
				break
			} // else: mangle the packet (below) due to capture length

			// sanity check for max uint16 size in IP header length field
			if ipHeaderLengthValue >= (1 << 16) {
				ipHeaderLengthValue = (1 << 16) - 1
			}

			// change IPv4 total length field for the correct (new) packet size
			binary.BigEndian.PutUint16(payloadLayer2[6:], uint16(ipHeaderLengthValue))
			// no flags, frag offset OR checksum changes (tcpdump does not complain)

			switch v.Protocol {
			// TCP does not have a length field (uses checksum to verify)
			// no checksum recalculation (tcpdump does not complain)
			case layers.IPProtocolUDP:
				// NOTE: tcpdump might complain when parsing UDP packets that
				//       are meant for a specific L7 protocol, like DNS, for
				//       example, if their port is the protocol port and user
				//       is only capturing "headers". That happens because it
				//       tries to parse the DNS header and, if it does not
				//       exist, it causes an error. To avoid that, one can run
				//       tcpdump -q -r ./file.pcap, so it does not try to parse
				//       upper layers in detail. That is the reason why the
				//       default pcap snaplen is 96b.
				//
				// change UDP header length field for the correct (new) size
				binary.BigEndian.PutUint16(
					payloadLayer2[4+ipHeaderLength+4:],
					uint16(udpHeaderLengthValue),
				)
			}

		case (*layers.IPv6):
			// Fake L2 header: IPv6 (BSD encap header spec)
			binary.BigEndian.PutUint32(payloadLayer2, 28) // set value 28 to first 4 bytes (uint32)

			ipHeaderLength = uint32(40) // IPv6 does not have an IHL field
			ipHeaderLengthValue += ipHeaderLength

			switch v.NextHeader {
			case layers.IPProtocolICMPv6:
				// ICMPv6
				break // always has "headers" only (payload = 0)
			case layers.IPProtocolUDP:
				// UDP
				udpHeaderLengthValue += udpHeaderLength
				ipHeaderLengthValue += udpHeaderLength
			case layers.IPProtocolTCP:
				// TCP
				tcpHeaderLength = tcpDoff(layer4)
				ipHeaderLengthValue += tcpHeaderLength
			}

			// add capture length (length to capture after last known proto header)
			ipHeaderLengthValue += captureLength
			udpHeaderLengthValue += captureLength

			// capture length is bigger than the pkt payload: no need for mangling
			if ipHeaderLengthValue != uint32(len(payloadLayer2[4:])) {
				break
			} // else: mangle the packet (below) due to capture length

			// sanity check for max uint16 size in IP header length field
			if ipHeaderLengthValue >= (1 << 16) {
				ipHeaderLengthValue = (1 << 16) - 1
			}

			// change IPv6 payload length field for the correct (new) packet size
			binary.BigEndian.PutUint16(payloadLayer2[12:], uint16(ipHeaderLengthValue))
			// no flags, frag offset OR checksum changes (tcpdump does not complain)

			switch v.NextHeader {
			// TCP does not have a length field (uses checksum to verify)
			// no checksum recalculation (tcpdump does not complain)
			case layers.IPProtocolUDP:
				// NOTE: same as IPv4 note
				// change UDP header length field for the correct (new) size
				binary.BigEndian.PutUint16(
					payloadLayer2[4+ipHeaderLength+4:],
					uint16(udpHeaderLengthValue),
				)
			}

		default:
			return
		}

		// This might be too much, but keep it here for now

		// logger.Debugw(
		// 	"capturing network",
		// 	"command", event.ProcessName,
		// 	"srcIP", srcIP,
		// 	"dstIP", dstIP,
		// )

		// capture the packet to all enabled pcap files

		err := t.netCapturePcap.Write(event, payloadLayer2)
		if err != nil {
			logger.Errorw("Could not write pcap data", "err", err)
		}

	default:
		logger.Debugw("Network capture: wrong net capture event type")
	}
}
