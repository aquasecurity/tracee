package ebpf

import (
	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/types/trace"
	"inet.af/netaddr"
)

// netPacketProtocolHandler parse a given a packet bytes buffer to packetMeta and event
func netPacketProtocolHandler(decoder *bufferdecoder.EbpfDecoder, evt *trace.Event) error {
	var packetEvent bufferdecoder.NetPacketEvent
	err := decoder.DecodeNetPacketEvent(&packetEvent)
	if err != nil {
		return err
	}
	appendPktMetadataArg(evt, packetEvent)
	return nil
}

// dnsQueryProtocolHandler decodes DNS queries from packet and appends the DNS argument to the event
func dnsQueryProtocolHandler(decoder *bufferdecoder.EbpfDecoder, evt *trace.Event) error {
	requests := make([]bufferdecoder.DnsQueryData, 0, 0)
	err := decoder.DecodeDnsQueryArray(&requests)
	if err != nil {
		return err
	}
	appendDnsQueryArgs(evt, &requests)
	return nil
}

// dnsReplyProtocolHandler decodes DNS replies from packet and appends the DNS argument to the event
func dnsReplyProtocolHandler(decoder *bufferdecoder.EbpfDecoder, evt *trace.Event) error {
	responses := make([]bufferdecoder.DnsResponseData, 0, 0)
	err := decoder.DecodeDnsRepliesData(&responses)
	if err != nil {
		return err
	}
	appendDnsReplyArgs(evt, &responses)
	return nil
}

// eventAppendArg append argument to event and increase ArgsNum
func eventAppendArg(event *trace.Event, arg trace.Argument) {
	event.Args = append(event.Args, arg)
	event.ArgsNum++
}

// appendPktMetadataArg takes the packet metadata and create argument array with that data
func appendPktMetadataArg(event *trace.Event, netPacket bufferdecoder.NetPacketEvent) {
	metedataArg := trace.Argument{
		ArgMeta: trace.ArgMeta{
			Name: "metadata",
			Type: "trace.PktMeta",
		},
		Value: trace.PktMeta{
			SrcIP:    netaddr.IPFrom16(netPacket.SrcIP).String(),
			DstIP:    netaddr.IPFrom16(netPacket.DstIP).String(),
			SrcPort:  netPacket.SrcPort,
			DstPort:  netPacket.DstPort,
			Protocol: netPacket.Protocol,
		},
	}
	eventAppendArg(event, metedataArg)
}

// appendDnsQueryArgs parse the given buffer to dns queries and adds it to the event
func appendDnsQueryArgs(event *trace.Event, requests *[]bufferdecoder.DnsQueryData) {
	questionArg := trace.Argument{
		ArgMeta: EventsDefinitions[int32(event.EventID)].Params[1],
		Value:   *requests,
	}
	eventAppendArg(event, questionArg)
}

// appendDnsReplyArgs parse the given buffer to dns replies and adds it to the event
func appendDnsReplyArgs(event *trace.Event, responses *[]bufferdecoder.DnsResponseData) {
	responseArg := trace.Argument{
		ArgMeta: EventsDefinitions[int32(event.EventID)].Params[1],
		Value:   *responses,
	}
	eventAppendArg(event, responseArg)
}
