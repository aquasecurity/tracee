package ebpf

import (
	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/types/trace"
	"inet.af/netaddr"
	"net/http"
)

// netPacketHandler parse a given a packet bytes buffer to packetMeta and event
func netPacketHandler(decoder *bufferdecoder.EbpfDecoder, evt *trace.Event, ifaceName string, packetLen uint32) error {
	var packetEvent bufferdecoder.NetPacketEvent
	err := decoder.DecodeNetPacketEvent(&packetEvent)
	if err != nil {
		return err
	}
	appendPktMetadataArg(evt, packetEvent, ifaceName, packetLen)
	return nil
}

// dnsQueryProtocolHandler decodes DNS queries from packet and appends the DNS argument to the event
func dnsQueryProtocolHandler(decoder *bufferdecoder.EbpfDecoder, evt *trace.Event) error {
	requests := make([]bufferdecoder.DnsQueryData, 0)
	err := decoder.DecodeDnsQueryArray(&requests)
	if err != nil {
		return err
	}
	appendDnsQueryArgs(evt, &requests)
	return nil
}

// dnsReplyProtocolHandler decodes DNS replies from packet and appends the DNS argument to the event
func dnsReplyProtocolHandler(decoder *bufferdecoder.EbpfDecoder, evt *trace.Event) error {
	responses := make([]bufferdecoder.DnsResponseData, 0)
	err := decoder.DecodeDnsRepliesData(&responses)
	if err != nil {
		return err
	}
	appendDnsReplyArgs(evt, &responses)
	return nil
}

// httpRequestProtocolHandler decodes an HTTP request from packet and appends the HTTP argument to the event
func httpRequestProtocolHandler(decoder *bufferdecoder.EbpfDecoder, evt *trace.Event) error {
	httpReq := http.Request{}
	err := decoder.DecodeHttpRequestData(&httpReq)
	if err != nil {
		return err
	}
	appendHttpRequestArgs(evt, &httpReq)
	return nil
}

// httpResponseProtocolHandler decodes an HTTP response from packet and appends the HTTP argument to the event
func httpResponseProtocolHandler(decoder *bufferdecoder.EbpfDecoder, evt *trace.Event) error {
	httpRes := http.Response{}
	err := decoder.DecodeHttpResponseData(&httpRes)
	if err != nil {
		return err
	}
	appendHttpResponseArgs(evt, &httpRes)
	return nil
}

// eventAppendArg append argument to event and increase ArgsNum
func eventAppendArg(event *trace.Event, arg trace.Argument) {
	event.Args = append(event.Args, arg)
	event.ArgsNum++
}

// appendPktMetadataArg takes the packet metadata and create argument array with that data
func appendPktMetadataArg(event *trace.Event, netPacket bufferdecoder.NetPacketEvent, ifaceName string, packetLen uint32) {
	metedataArg := trace.Argument{
		ArgMeta: trace.ArgMeta{
			Name: "metadata",
			Type: "trace.PktMeta",
		},
		Value: trace.PktMeta{
			SrcIP:     netaddr.IPFrom16(netPacket.SrcIP).String(),
			DstIP:     netaddr.IPFrom16(netPacket.DstIP).String(),
			SrcPort:   netPacket.SrcPort,
			DstPort:   netPacket.DstPort,
			Protocol:  netPacket.Protocol,
			PacketLen: packetLen,
			Iface:     ifaceName,
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

// appendHttpRequestArgs parses the given http.Request and appends relevant args to the event
func appendHttpRequestArgs(event *trace.Event, httpReq *http.Request) {
	for _, param := range EventsDefinitions[int32(event.EventID)].Params {
		arg := trace.Argument{
			ArgMeta: param,
		}
		switch param.Name {
		case "method":
			arg.Value = httpReq.Method
		case "protocol":
			arg.Value = httpReq.Proto
		case "host":
			arg.Value = httpReq.Host
		case "uri_path":
			arg.Value = httpReq.URL
		case "headers":
			arg.Value = httpReq.Header
		case "content_length":
			arg.Value = httpReq.ContentLength
		default:
			continue
		}
		eventAppendArg(event, arg)
	}
}

// appendHttpResponseArgs parses the given http.Response and appends relevant args to the event
func appendHttpResponseArgs(event *trace.Event, httpRes *http.Response) {
	for _, param := range EventsDefinitions[int32(event.EventID)].Params {
		arg := trace.Argument{
			ArgMeta: param,
		}
		switch param.Name {
		case "status":
			arg.Value = httpRes.Status
		case "status_code":
			arg.Value = httpRes.StatusCode
		case "protocol":
			arg.Value = httpRes.Proto
		case "headers":
			arg.Value = httpRes.Header
		case "content_length":
			arg.Value = httpRes.ContentLength
		default:
			continue
		}
		eventAppendArg(event, arg)
	}
}
