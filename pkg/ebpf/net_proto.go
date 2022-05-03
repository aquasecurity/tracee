package ebpf

import (
	"fmt"
	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/procinfo"
	"github.com/aquasecurity/tracee/types/trace"
)

// protocolHandler is a function prototype for a function that receives a trace.Event pointer as
// argument, a bufferdecoder.EbpfDecoder pointer to a network packet, and may append protocol specific arguments to
// the event.
// It returns an error.
type protocolHandler func(*bufferdecoder.EbpfDecoder, *trace.Event) error

// protocolProcessor calls handlers of the appropriate protocol event
func protocolProcessor(networkThread procinfo.ProcessCtx, evtMeta bufferdecoder.NetEventMetadata, decoder *bufferdecoder.EbpfDecoder) (trace.Event, error) {

	// create network event without any args
	evt := CreateNetEvent(evtMeta, networkThread, EventsDefinitions[evtMeta.NetEventId].Name)

	// handle specific protocol data
	err := callProtocolHandler(evtMeta.NetEventId, decoder, &evt)
	return evt, err
}

// CreateNetEvent creates and returns event 'eventName'
func CreateNetEvent(eventMeta bufferdecoder.NetEventMetadata, ctx procinfo.ProcessCtx, eventName string) trace.Event {
	evt := ctx.GetEventByProcessCtx()
	evt.Timestamp = int(eventMeta.TimeStamp)
	evt.ProcessName = string(eventMeta.ProcessName[:])
	evt.EventID = int(eventMeta.NetEventId)
	evt.EventName = eventName
	return evt
}

// callProtocolHandler calls protocol handler
func callProtocolHandler(eventId int32, decoder *bufferdecoder.EbpfDecoder, evt *trace.Event) error {
	protocolHandlers := map[int32][]protocolHandler{
		NetPacket:   {netPacketProtocolHandler},
		DnsRequest:  {netPacketProtocolHandler, dnsQueryProtocolHandler},
		DnsResponse: {netPacketProtocolHandler, dnsReplyProtocolHandler},
	}

	handlers, handlerExists := protocolHandlers[eventId]
	if !handlerExists {
		return fmt.Errorf("no protocol handler for event id %d", eventId)
	}

	var err error
	for _, handler := range handlers {
		err = handler(decoder, evt)
		if err != nil {
			return err
		}
	}

	return nil
}
