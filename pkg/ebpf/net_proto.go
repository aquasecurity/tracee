package ebpf

import (
	"bytes"
	"fmt"

	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/procinfo"
	"github.com/aquasecurity/tracee/types/trace"
)

// TODO: deprecated, remove these events and handlers

// protocolHandler is a function prototype for a function that receives a trace.Event pointer as
// argument, a bufferdecoder.EbpfDecoder pointer to a network packet, and may append protocol specific arguments to
// the event.
// It returns an error.
type protocolHandler func(*bufferdecoder.EbpfDecoder, *trace.Event) error

// protocolProcessor calls handlers of the appropriate protocol event
func protocolProcessor(networkThread procinfo.ProcessCtx, evtMeta bufferdecoder.NetEventMetadata, decoder *bufferdecoder.EbpfDecoder, ifaceName string, packetLen uint32) (trace.Event, error) {
	eventDefinition := events.Definitions.Get(evtMeta.NetEventId)

	// create network event without any args
	evt := CreateNetEvent(evtMeta, networkThread, eventDefinition.Name)

	// handle specific protocol data
	err := callProtocolHandler(evtMeta.NetEventId, decoder, &evt, ifaceName, packetLen)

	return evt, err
}

// CreateNetEvent creates and returns event 'eventName'
func CreateNetEvent(eventMeta bufferdecoder.NetEventMetadata, ctx procinfo.ProcessCtx, eventName string) trace.Event {
	evt := ctx.GetEventByProcessCtx()
	evt.Timestamp = int(eventMeta.TimeStamp)
	evt.ProcessName = string(bytes.TrimRight(eventMeta.ProcessName[:], "\x00"))
	evt.EventID = int(eventMeta.NetEventId)
	evt.EventName = eventName
	return evt
}

// callProtocolHandler calls protocol handler
func callProtocolHandler(eventId events.ID, decoder *bufferdecoder.EbpfDecoder, evt *trace.Event, ifaceName string, packetLen uint32) error {
	protocolHandlers := map[events.ID][]protocolHandler{
		events.DnsRequest:  {dnsQueryProtocolHandler},
		events.DnsResponse: {dnsReplyProtocolHandler},
	}

	// call the generic netPacketHandler
	err := netPacketHandler(decoder, evt, ifaceName, packetLen)
	if err != nil {
		return err
	}

	// call the specific protocol handlers
	handlers, handlerExists := protocolHandlers[eventId]
	if handlerExists && len(handlers) == 0 {
		return fmt.Errorf("no protocol handler for event id %d", eventId)
	}
	for _, handler := range handlers {
		err = handler(decoder, evt)
		if err != nil {
			return err
		}
	}

	return nil
}
