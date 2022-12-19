package derive

import (
	"fmt"
	"net"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

//
// NetPacketDNS
//

func NetPacketDNS() deriveFunction {
	return deriveSingleEvent(events.NetPacketDNS, deriveDNS())
}

func deriveDNS() deriveArgsFunction {
	return deriveDNSEvents
}

func deriveDNSEvents(event trace.Event) ([]interface{}, error) {
	net, dns, err := eventToProtoDNS(&event)
	if err != nil {
		return nil, err
	}
	if dns == nil {
		return nil, nil // connection related packets
	}
	if net == nil {
		return nil, parsePacketError()
	}

	return []interface{}{
		net.srcIP,
		net.dstIP,
		net.srcPort,
		net.dstPort,
		dns,
	}, nil
}

//
// NetPacketDNSRequest
//

func NetPacketDNSRequest() deriveFunction {
	return deriveSingleEvent(events.NetPacketDNSRequest, deriveDNSRequest())
}

func deriveDNSRequest() deriveArgsFunction {
	return deriveDNSRequestEvents
}

func deriveDNSRequestEvents(event trace.Event) ([]interface{}, error) {
	net, dns, err := eventToProtoDNS(&event)
	if err != nil {
		return nil, err
	}
	if dns == nil {
		return nil, nil // connection related packets
	}
	if net == nil {
		return nil, err
	}

	// discover if it is a request or response

	if dns.QR != 0 {
		return nil, nil // not a dns request
	}

	// NOTE: temporary, not to brake existing signatures using old DNS events.
	// TODO: change DNS events arguments at will after removing old DNS events.

	meta := convertNetPairToPktMeta(net)
	requests := convertProtoDNSQuestionToDnsRequest(dns.Questions)

	// NOTE: No DNS server does more than 1 question per query, but spec allows.

	if len(requests) != int(dns.QDCount) { // number of questions to expect
		return nil, fmt.Errorf("could not get all requests")
	}

	return []interface{}{
		*meta,
		requests,
	}, nil
}

//
// NetPacketDNSResponse
//

func NetPacketDNSResponse() deriveFunction {
	return deriveSingleEvent(events.NetPacketDNSResponse, deriveDNSResponse())
}

func deriveDNSResponse() deriveArgsFunction {
	return deriveDNSResponseEvents
}

func deriveDNSResponseEvents(event trace.Event) ([]interface{}, error) {
	net, dns, err := eventToProtoDNS(&event)
	if err != nil {
		return nil, err
	}
	if dns == nil {
		return nil, nil // connection related packets
	}
	if net == nil {
		return nil, err
	}

	// discover if it is a request or response

	if dns.QR != 1 {
		return nil, nil // not a dns response
	}

	// NOTE: temporary, not to brake existing signatures using old DNS events.
	// TODO: change DNS events arguments at will after removing old DNS events.

	meta := convertNetPairToPktMeta(net)

	// NOTE: No DNS server does more than 1 question per query, but spec allows.
	//       Unfortunately there is no way to tell which answer comes from
	//       which question, so we support only single question DNS responses.

	requests := convertProtoDNSQuestionToDnsRequest(dns.Questions)
	if len(requests) > 1 {
		return nil, fmt.Errorf("response with more than 1 question")
	}

	responses := convertProtoDNSResourceRecordToDnsResponse(requests[0], dns.Answers)
	if len(responses[0].DnsAnswer) != int(dns.ANCount) { // number of responses to expect
		return nil, fmt.Errorf("could not get all responses")
	}

	return []interface{}{
		*meta,
		responses,
	}, nil
}

//
// Helper Functions
//

type netPair struct {
	srcIP   net.IP
	dstIP   net.IP
	srcPort uint16
	dstPort uint16
	proto   uint8
	length  uint32
}

const (
	IPPROTO_TCP uint8 = 6
	IPPROTO_UDP uint8 = 17
)

// eventToProtoDNS turns a trace event into a ProtoDNS type, a type used by the
// new network code for DNS events
func eventToProtoDNS(event *trace.Event) (*netPair, *trace.ProtoDNS, error) {
	var ok bool
	var payload []byte
	var layerType gopacket.LayerType
	var net netPair

	// sanity checks

	payloadArg := events.GetArg(event, "payload")
	if payloadArg == nil {
		return nil, nil, noPayloadError()
	}
	if payload, ok = payloadArg.Value.([]byte); !ok {
		return nil, nil, nonByteArgError()
	}
	payloadSize := len(payload)
	if payloadSize < 1 {
		return nil, nil, emptyPayloadError()
	}

	// initial header type

	switch event.ReturnValue { // event retval tells layer type
	case AF_INET:
		layerType = layers.LayerTypeIPv4
	case AF_INET6:
		layerType = layers.LayerTypeIPv6
	default:
		return nil, nil, nil
	}

	// parse packet

	packet := gopacket.NewPacket(
		payload[4:payloadSize], // base event argument is: |sizeof|[]byte|
		layerType,
		gopacket.Default,
	)
	if packet == nil {
		return nil, nil, parsePacketError()
	}

	layer3 := packet.NetworkLayer()

	switch v := layer3.(type) {
	case (*layers.IPv4):
		net.srcIP = v.SrcIP
		net.dstIP = v.DstIP
		net.length = uint32(v.Length)
	case (*layers.IPv6):
		net.srcIP = v.SrcIP
		net.dstIP = v.DstIP
		net.length = uint32(v.Length)
	default:
		return nil, nil, nil
	}

	layer4 := packet.TransportLayer()

	switch v := layer4.(type) {
	case (*layers.TCP):
		net.srcPort = uint16(v.SrcPort)
		net.dstPort = uint16(v.DstPort)
		net.proto = IPPROTO_TCP
	case (*layers.UDP):
		net.srcPort = uint16(v.SrcPort)
		net.dstPort = uint16(v.DstPort)
		net.proto = IPPROTO_UDP
	default:
		return nil, nil, nil
	}

	layer7 := packet.ApplicationLayer()

	switch l7 := layer7.(type) {
	case (*layers.DNS):
		var dns trace.ProtoDNS
		copyDNSToProtoDNS(l7, &dns)
		return &net, &dns, nil
	default:
		if net.srcPort != 53 && net.dstPort != 53 {
			return &net, nil, notProtoPacketError("DNS") // TCP packets (connection related), no event
		}
	}

	return &net, nil, nil
}

// convertNetPairToPktMeta converts the local netPair type, used by this code,
// to PktMeta type, expected by the old dns events, which, for now, we want the
// new network packet simple dns events to be compatible with.
func convertNetPairToPktMeta(net *netPair) *trace.PktMeta {
	return &trace.PktMeta{
		SrcIP:     net.srcIP.String(),
		DstIP:     net.dstIP.String(),
		SrcPort:   net.srcPort,
		DstPort:   net.dstPort,
		Protocol:  net.proto,
		PacketLen: net.length,
		Iface:     "any", // TODO: pick iface from network events
	}
}

// convertProtoDNSQuestionToDnsRequest converts the network packet dns event
// type, ProtoDNSQuestion, to type expected by old dns events, which, for now,
// we want the new network packet simple dns events to be compatible with.
func convertProtoDNSQuestionToDnsRequest(
	questions []trace.ProtoDNSQuestion,
) []trace.DnsQueryData {

	var requests []trace.DnsQueryData

	for _, question := range questions {
		requests = append(requests, trace.DnsQueryData{
			Query:      question.Name,
			QueryType:  question.Type,
			QueryClass: question.Class,
		})
	}

	return requests
}

// convertProtoDNSResourceRecordToDnsResponse converts the network packet dns
// event type, ProtoDNSResourceRecord, used by DNS answers packet field, to type
// expected by old dns events, which, for now, we want the new network packet
// simple dns events to be compatible with.
func convertProtoDNSResourceRecordToDnsResponse(
	dnsQueryData trace.DnsQueryData,
	dnsResourceRecord []trace.ProtoDNSResourceRecord,
) []trace.DnsResponseData {

	var dnsAnswers []trace.DnsAnswer

	for _, record := range dnsResourceRecord {
		var dnsAnswer trace.DnsAnswer

		switch record.Type {
		case "A":
			dnsAnswer.Answer = record.IP
		case "AAAA":
			dnsAnswer.Answer = record.IP
		case "NS":
			dnsAnswer.Answer = record.NS
		case "CNAME":
			dnsAnswer.Answer = record.CNAME
		case "PTR":
			dnsAnswer.Answer = record.PTR
		case "MX":
			dnsAnswer.Answer = record.MX.Name
		case "TXT":
			dnsAnswer.Answer = record.TXT
		default:
			dnsAnswer.Answer = "not implemented"
		}

		dnsAnswer.Type = record.Type
		dnsAnswer.Ttl = record.TTL
		dnsAnswers = append(dnsAnswers, dnsAnswer)
	}

	return []trace.DnsResponseData{
		{
			QueryData: dnsQueryData,
			DnsAnswer: dnsAnswers,
		},
	}
}

//
// DNS protocol type conversion (from gopacket layer to trace type)
//

func copyDNSToProtoDNS(l7 *layers.DNS, proto *trace.ProtoDNS) {
	proto.ID = l7.ID
	proto.QR = boolToUint8(l7.QR)
	proto.OpCode = strToLower(l7.OpCode.String())

	proto.AA = boolToUint8(l7.AA)
	proto.TC = boolToUint8(l7.TC)
	proto.RD = boolToUint8(l7.RD)
	proto.RA = boolToUint8(l7.RA)
	proto.Z = l7.Z

	proto.ResponseCode = strToLower(l7.ResponseCode.String())
	proto.QDCount = l7.QDCount
	proto.ANCount = l7.ANCount
	proto.NSCount = l7.NSCount
	proto.ARCount = l7.ARCount

	// process all existing questions (if any)
	proto.Questions = make([]trace.ProtoDNSQuestion, len(l7.Questions))
	for i, j := range l7.Questions {
		proto.Questions[i] = trace.ProtoDNSQuestion{
			Name:  string(j.Name),
			Type:  j.Type.String(),
			Class: j.Class.String(),
		}
	}

	// process all existing answers (if any)
	proto.Answers = make([]trace.ProtoDNSResourceRecord, len(l7.Answers))
	for i, j := range l7.Answers {
		proto.Answers[i] = newProtoDNSResourceRecord(j)
	}

	// process all existing authorities (if any)
	proto.Authorities = make([]trace.ProtoDNSResourceRecord, len(l7.Authorities))
	for i, j := range l7.Authorities {
		proto.Authorities[i] = newProtoDNSResourceRecord(j)
	}

	// process all existing additionals (if any)
	proto.Additionals = make([]trace.ProtoDNSResourceRecord, len(l7.Additionals))
	for i, j := range l7.Additionals {
		proto.Additionals[i] = newProtoDNSResourceRecord(j)
	}
}

func newProtoDNSResourceRecord(j layers.DNSResourceRecord) trace.ProtoDNSResourceRecord {
	var ip string

	if j.IP != nil {
		ip = j.IP.String()
	}

	r := trace.ProtoDNSResourceRecord{
		Name:  string(j.Name),
		Type:  j.Type.String(),
		Class: j.Class.String(),
		TTL:   j.TTL,
		IP:    ip,
		NS:    string(j.NS),
		CNAME: string(j.CNAME),
		PTR:   string(j.PTR),
		TXTs:  convertArrayOfBytes(j.TXTs),
		SOA: trace.ProtoDNSSOA{
			MName:   string(j.SOA.MName),
			RName:   string(j.SOA.RName),
			Serial:  j.SOA.Serial,
			Refresh: j.SOA.Refresh,
			Retry:   j.SOA.Retry,
			Expire:  j.SOA.Expire,
			Minimum: j.SOA.Minimum,
		},
		SRV: trace.ProtoDNSSRV{
			Priority: j.SRV.Priority,
			Weight:   j.SRV.Weight,
			Port:     j.SRV.Port,
			Name:     string(j.SRV.Name),
		},
		MX: trace.ProtoDNSMX{
			Preference: j.MX.Preference,
			Name:       string(j.MX.Name),
		},
		OPT: convertArrayOfDNSOPT(j.OPT),
		URI: trace.ProtoDNSURI{
			Priority: j.URI.Priority,
			Weight:   j.URI.Weight,
			Target:   string(j.URI.Target),
		},
		TXT: string(j.TXT),
	}

	return r
}

// helpers

func convertArrayOfDNSOPT(given []layers.DNSOPT) []trace.ProtoDNSOPT {
	res := make([]trace.ProtoDNSOPT, len(given))

	for i, j := range given {
		res[i] = trace.ProtoDNSOPT{
			Code: j.Code.String(),
			Data: string(j.Data),
		}
	}

	return res
}
