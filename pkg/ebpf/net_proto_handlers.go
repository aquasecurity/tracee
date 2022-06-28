package ebpf

import (
	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
	"inet.af/netaddr"
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
	eventId := events.ID(event.EventID)
	eventDef := events.Definitions.Get(eventId)
	questionArg := trace.Argument{
		ArgMeta: eventDef.Params[1],
		Value:   getTraceDnsQueryDataArrFromDecoded(requests),
	}
	eventAppendArg(event, questionArg)
}

// appendDnsReplyArgs parse the given buffer to dns replies and adds it to the event
func appendDnsReplyArgs(event *trace.Event, responses *[]bufferdecoder.DnsResponseData) {
	eventId := events.ID(event.EventID)
	eventDef := events.Definitions.Get(eventId)
	responseArg := trace.Argument{
		ArgMeta: eventDef.Params[1],
		Value:   getTraceDnsResponseDataFromDecoded(responses),
	}
	eventAppendArg(event, responseArg)
}

// getTraceDnsResponseDataFromDecoded returns []trace.DnsResponseData from *[]bufferdecoder.DnsResponseData
func getTraceDnsResponseDataFromDecoded(decodedResponseData *[]bufferdecoder.DnsResponseData) []trace.DnsResponseData {
	var responseData []trace.DnsResponseData
	for _, decodedResponse := range *decodedResponseData {
		response := trace.DnsResponseData{
			QueryData: getTraceDnsQueryDataFromDecoded(&decodedResponse.QueryData),
			DnsAnswer: getTraceDnsAnswersFromDecoded(&decodedResponse.DnsAnswer),
		}
		responseData = append(responseData, response)
	}

	return responseData
}

// getTraceDnsAnswersFromDecoded returns []trace.DnsAnswer from *[]bufferdecoder.DnsAnswer
func getTraceDnsAnswersFromDecoded(decodedAnswers *[]bufferdecoder.DnsAnswer) []trace.DnsAnswer {
	var answers []trace.DnsAnswer
	for _, decodedAnswer := range *decodedAnswers {
		answer := trace.DnsAnswer{
			Type:   decodedAnswer.Type,
			Ttl:    decodedAnswer.Ttl,
			Answer: decodedAnswer.Answer,
		}
		answers = append(answers, answer)
	}

	return answers
}

// getTraceDnsQueryDataArrFromDecoded returns []trace.DnsQueryData from *[]bufferdecoder.DnsQueryData
func getTraceDnsQueryDataArrFromDecoded(decodedQueryDataArr *[]bufferdecoder.DnsQueryData) []trace.DnsQueryData {
	var queryData []trace.DnsQueryData
	for _, decodedqueryData := range *decodedQueryDataArr {
		queryData = append(queryData, getTraceDnsQueryDataFromDecoded(&decodedqueryData))
	}

	return queryData
}

// getTraceDnsQueryDataFromDecoded returns trace.DnsQueryData from *bufferdecoder.DnsQueryData
func getTraceDnsQueryDataFromDecoded(decodedQueryData *bufferdecoder.DnsQueryData) trace.DnsQueryData {
	queryData := trace.DnsQueryData{
		Query:      decodedQueryData.Query,
		QueryType:  decodedQueryData.QueryType,
		QueryClass: decodedQueryData.QueryClass,
	}

	return queryData
}
