package derive

import (
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"

	"github.com/google/gopacket/layers"
)

//
// NetPacketDNS
//

func NetPacketDNS() DeriveFunction {
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

func NetPacketDNSRequest() DeriveFunction {
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

	if len(requests) != 1 || len(requests) != int(dns.QDCount) {
		logger.Debug("wrong number of requests found")
		return nil, nil
	}

	return []interface{}{
		*meta,
		requests,
	}, nil
}

//
// NetPacketDNSResponse
//

func NetPacketDNSResponse() DeriveFunction {
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

	var requests []trace.DnsQueryData
	var responses []trace.DnsResponseData

	requests = convertProtoDNSQuestionToDnsRequest(dns.Questions)
	if len(requests) != 1 {
		logger.Debug("wrong number of requests found")
		return nil, nil
	}

	responses = convertProtoDNSResourceRecordToDnsResponse(requests[0], dns.Answers)
	if len(responses[0].DnsAnswer) != int(dns.ANCount) { // number of responses to expect
		logger.Debug("could not get all DNS responses")
		return nil, nil
	}

	return []interface{}{
		*meta,
		responses,
	}, nil
}

// eventToProtoDNS turns a trace event into a ProtoDNS type, a type used by the
// new network code for DNS events
func eventToProtoDNS(event *trace.Event) (*netPair, *trace.ProtoDNS, error) {
	var DnsNetPair netPair

	layer7, err := parseUntilLayer7(event, &DnsNetPair)
	if err != nil {
		return nil, nil, err
	}

	switch l7 := layer7.(type) {
	case (*layers.DNS):
		var dns trace.ProtoDNS
		copyDNSToProtoDNS(l7, &dns)
		return &DnsNetPair, &dns, nil
	default:
		if DnsNetPair.srcPort != 53 && DnsNetPair.dstPort != 53 {
			// TCP packets (connection related), no event
			return &DnsNetPair, nil, notProtoPacketError("DNS")
		}
	}

	return &DnsNetPair, nil, nil
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
