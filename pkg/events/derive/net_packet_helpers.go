package derive

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/aquasecurity/tracee/pkg/dnscache"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

// Event return value (retval) encodes network event information, such as:
//
// 0. L3 protocol (IPv4/IPv6)
// 1. packet flow direction (ingress/egress)
// 2. HTTP request/response direction
// 3. TCP Flow begin/end

const (
	familyIPv4 int = 1 << iota
	familyIPv6
	protoHTTPRequest
	protoHTTPResponse
	packetIngress
	packetEgress
	flowTCPBegin
	flowTCPEnd
	flowUDPBegin
	flowUDPEnd
	flowSrcInitiator
)

const httpMinLen int = 7 // longest http command is "DELETE "

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

//
// Helpers
//

func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// convertArrayOfBytes converts a [][]byte to a []string.
func convertArrayOfBytes(given [][]byte) []string {
	res := make([]string, 0, len(given))

	for _, i := range given {
		res = append(res, string(i))
	}

	return res
}

func strToLower(given string) string {
	return strings.ToLower(given)
}

// parsePayloadArg returns the packet payload from the event.
func parsePayloadArg(event *trace.Event) ([]byte, error) {
	payloadArg := events.GetArg(event, "payload")
	if payloadArg == nil {
		return nil, noPayloadError()
	}
	payload, ok := payloadArg.Value.([]byte)
	if !ok {
		return nil, nonByteArgError()
	}
	payloadSize := len(payload)
	if payloadSize < 1 {
		return nil, emptyPayloadError()
	}
	return payload, nil
}

// getNetPair returns the network pair from the event.
// TODO: convert to trace.packetMetadata{}
func getPktMeta(srcIP, dstIP net.IP, srcPort, dstPort uint16, proto uint8, length uint32) trace.PktMeta {
	return trace.PktMeta{
		SrcIP:     srcIP.String(),
		DstIP:     dstIP.String(),
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  proto,
		PacketLen: length,
		Iface:     "any", // TODO: pick iface index from the kernel ?
	}
}

// swapSrcDst swaps the source and destination IP addresses and ports.
func swapSrcDst(s, d net.IP, sp, dp uint16) (net.IP, net.IP, uint16, uint16) {
	return d, s, dp, sp
}

// getPacketDirection returns the packet direction from the event.
func getPacketDirection(event *trace.Event) trace.PacketDirection {
	switch {
	case event.ReturnValue&packetIngress == packetIngress:
		return trace.PacketIngress
	case event.ReturnValue&packetEgress == packetEgress:
		return trace.PacketEgress
	}
	return trace.InvalidPacketDirection
}

// getPacketHTTPDirection returns the packet HTTP direction from the event.
func getPacketHTTPDirection(event *trace.Event) int {
	switch {
	case event.ReturnValue&protoHTTPRequest == protoHTTPRequest:
		return protoHTTPRequest
	case event.ReturnValue&protoHTTPResponse == protoHTTPResponse:
		return protoHTTPResponse
	}
	return 0
}

// createPacketFromEvent creates a gopacket.Packet from the event.
func createPacketFromEvent(event *trace.Event) (gopacket.Packet, error) {
	payload, err := parsePayloadArg(event)
	if err != nil {
		return nil, err
	}
	layer3TypeFlag, err := getLayer3TypeFlagFromEvent(event)
	if err != nil {
		return nil, err
	}
	layer3Type, err := getLayer3TypeFromFlag(layer3TypeFlag)
	if err != nil {
		return nil, err
	}

	packet := gopacket.NewPacket(
		payload,
		layer3Type,
		gopacket.Default,
	)
	if packet == nil {
		return nil, parsePacketError()
	}

	return packet, nil
}

// getDomainsFromCache returns the domain names of an IP address from the DNS cache.
func getDomainsFromCache(ip net.IP, cache *dnscache.DNSCache) []string {
	domains := []string{}
	if cache != nil {
		query, err := cache.Get(ip.String())
		if err != nil {
			switch err {
			case dnscache.ErrDNSRecordNotFound, dnscache.ErrDNSRecordExpired:
				domains = []string{}
			default:
				logger.Debugw("ip lookup error", "ip", ip, "error", err)
				return nil
			}
		} else {
			domains = query.DNSResults()
		}
	}
	return domains
}

//
// Layer 3 (Network Layer)
//

// getLayer3FromPacket returns the layer 3 protocol from the packet.
func getLayer3FromPacket(packet gopacket.Packet) (gopacket.NetworkLayer, error) {
	layer3 := packet.NetworkLayer()
	switch layer3.(type) {
	case (*layers.IPv4):
	case (*layers.IPv6):
	default:
		return nil, fmt.Errorf("wrong layer 3 protocol type")
	}
	return layer3, nil
}

// getLayer3IPv4FromPacket returns the IPv4 layer 3 from the packet.
func getLayer3IPv4FromPacket(packet gopacket.Packet) (*layers.IPv4, error) {
	layer3, err := getLayer3FromPacket(packet)
	if err != nil {
		return nil, err
	}
	ipv4, ok := layer3.(*layers.IPv4)
	if !ok {
		return nil, fmt.Errorf("wrong layer 3 protocol type")
	}
	return ipv4, nil
}

// getLayer3IPv6FromPacket returns the IPv6 layer 3 from the packet.
func getLayer3IPv6FromPacket(packet gopacket.Packet) (*layers.IPv6, error) {
	layer3, err := getLayer3FromPacket(packet)
	if err != nil {
		return nil, err
	}
	ipv6, ok := layer3.(*layers.IPv6)
	if !ok {
		return nil, fmt.Errorf("wrong layer 3 protocol type")
	}
	return ipv6, nil
}

// getSrcDstFromLayer3 returns the source and destination IP addresses from the layer 3.
func getSrcDstFromLayer3(layer3 gopacket.NetworkLayer) (net.IP, net.IP, error) {
	switch v := layer3.(type) {
	case (*layers.IPv4):
		return v.SrcIP, v.DstIP, nil
	case (*layers.IPv6):
		return v.SrcIP, v.DstIP, nil
	}
	return nil, nil, fmt.Errorf("wrong layer 3 protocol type")
}

// getLayer3SrcDstFromPacket returns the source and destination IP addresses from the packet.
func getLayer3SrcDstFromPacket(packet gopacket.Packet) (net.IP, net.IP, error) {
	layer3, err := getLayer3FromPacket(packet)
	if err != nil {
		return nil, nil, err
	}
	return getSrcDstFromLayer3(layer3)
}

// getLayer3TypeFromFlag returns the layer 3 protocol type from a given flag.
func getLayer3TypeFromFlag(layer3TypeFlag int) (gopacket.LayerType, error) {
	switch layer3TypeFlag {
	case familyIPv4:
		return layers.LayerTypeIPv4, nil
	case familyIPv6:
		return layers.LayerTypeIPv6, nil
	}
	return 0, fmt.Errorf("wrong layer 3 type")
}

// getLayer3TypeFlagFromEvent returns the layer 3 protocol type from a given event.
func getLayer3TypeFlagFromEvent(event *trace.Event) (int, error) {
	switch {
	case event.ReturnValue&familyIPv4 == familyIPv4:
		return familyIPv4, nil
	case event.ReturnValue&familyIPv6 == familyIPv6:
		return familyIPv6, nil
	}
	return 0, fmt.Errorf("wrong layer 3 ret value flag")
}

// getLengthFromPacket returns the packet length from a given packet.
func getLengthFromPacket(packet gopacket.Packet) (uint32, error) {
	layer3, err := getLayer3FromPacket(packet)
	if err != nil {
		return 0, err
	}
	switch v := layer3.(type) {
	case (*layers.IPv4):
		return uint32(v.Length), nil
	case (*layers.IPv6):
		return uint32(v.Length), nil
	}
	return 0, fmt.Errorf("wrong layer 3 protocol type")
}

//
// Layer 4 (Transport Layer)
//

// getLayer4FromPacket returns the layer 4 protocol from the packet.
func getLayer4FromPacket(packet gopacket.Packet) (gopacket.TransportLayer, error) {
	layer4 := packet.TransportLayer()
	switch layer4.(type) {
	case (*layers.TCP):
	case (*layers.UDP):
	default:
		return nil, fmt.Errorf("wrong layer 4 protocol type")
	}
	return layer4, nil
}

// getLayer4TCPFromPacket returns the TCP layer 4 from the packet.
func getLayer4TCPFromPacket(packet gopacket.Packet) (*layers.TCP, error) {
	layer4, err := getLayer4FromPacket(packet)
	if err != nil {
		return nil, err
	}
	tcp, ok := layer4.(*layers.TCP)
	if !ok {
		return nil, fmt.Errorf("wrong layer 4 protocol type")
	}
	return tcp, nil
}

// getLayer4UDPFromPacket returns the UDP layer 4 from the packet.
func getLayer4UDPFromPacket(packet gopacket.Packet) (*layers.UDP, error) {
	layer4, err := getLayer4FromPacket(packet)
	if err != nil {
		return nil, err
	}
	udp, ok := layer4.(*layers.UDP)
	if !ok {
		return nil, fmt.Errorf("wrong layer 4 protocol type")
	}
	return udp, nil
}

// getLayer4ProtoFromPacket returns the layer 4 protocol type from the packet.
func getLayer4ProtoFromPacket(packet gopacket.Packet) (uint8, error) {
	layer4, err := getLayer4FromPacket(packet)
	if err != nil {
		return 0, err
	}
	switch layer4.(type) {
	case (*layers.TCP):
		return IPPROTO_TCP, nil
	case (*layers.UDP):
		return IPPROTO_UDP, nil
	}
	return 0, fmt.Errorf("wrong layer 4 protocol type")
}

// getLayer4SrcPortDstPortFromPacket returns the source and destination ports from the packet.
func getLayer4SrcPortDstPortFromPacket(packet gopacket.Packet) (uint16, uint16, error) {
	layer4, err := getLayer4FromPacket(packet)
	if err != nil {
		return 0, 0, err
	}
	switch v := layer4.(type) {
	case (*layers.TCP):
		return uint16(v.SrcPort), uint16(v.DstPort), nil
	case (*layers.UDP):
		return uint16(v.SrcPort), uint16(v.DstPort), nil
	}
	return 0, 0, fmt.Errorf("wrong layer 4 protocol type")
}

//
// Special Layer (Some consider it as Layer 4, others Layer 3)
//

// getLayerICMPFromPacket returns the ICMP layer from the packet.
func getLayerICMPFromPacket(packet gopacket.Packet) (*layers.ICMPv4, error) {
	// ICMP might be considered Layer 3 (per OSI) or Layer 4 (per TCP/IP).
	layer := packet.Layer(layers.LayerTypeICMPv4)
	if layer == nil {
		return nil, fmt.Errorf("wrong layer protocol type")
	}
	icmp, ok := layer.(*layers.ICMPv4)
	if !ok {
		return nil, fmt.Errorf("wrong layer protocol type")
	}
	return icmp, nil
}

// getLayerICMPv6FromPacket returns the ICMPv6 layer from the packet.
func getLayerICMPv6FromPacket(packet gopacket.Packet) (*layers.ICMPv6, error) {
	// ICMP might be considered Layer 3 (per OSI) or Layer 4 (per TCP/IP).
	layer := packet.Layer(layers.LayerTypeICMPv6)
	if layer == nil {
		return nil, fmt.Errorf("wrong layer protocol type")
	}
	icmp, ok := layer.(*layers.ICMPv6)
	if !ok {
		return nil, fmt.Errorf("wrong layer protocol type")
	}
	return icmp, nil
}

//
// Layer 7 (Application Layer)
//

func getLayer7DNSFromPacket(packet gopacket.Packet) (*layers.DNS, error) {
	layer7, err := getLayer7FromPacket(packet)
	if err != nil {
		return nil, err
	}
	switch l7 := layer7.(type) {
	case (*layers.DNS):
		return l7, nil
	}
	return nil, fmt.Errorf("wrong layer 7 protocol type")
}

// getLayer7FromPacket returns the layer 7 protocol from the packet.
func getLayer7FromPacket(packet gopacket.Packet) (gopacket.ApplicationLayer, error) {
	layer7 := packet.ApplicationLayer()
	if layer7 == nil {
		return nil, fmt.Errorf("wrong layer 7 protocol type")
	}
	return layer7, nil
}

//
// Proto Types (tracee/types/trace)
//

// getProtoIPv4 returns the ProtoIPv4 from the IPv4.
func getProtoIPv4(ipv4 *layers.IPv4) trace.ProtoIPv4 {
	// TODO: IPv4 options if IHL > 5
	return trace.ProtoIPv4{
		Version:    ipv4.Version,
		IHL:        ipv4.IHL,
		TOS:        ipv4.TOS,
		Length:     ipv4.Length,
		Id:         ipv4.Id,
		Flags:      uint8(ipv4.Flags),
		FragOffset: ipv4.FragOffset,
		TTL:        ipv4.TTL,
		Protocol:   ipv4.Protocol.String(),
		Checksum:   ipv4.Checksum,
		SrcIP:      ipv4.SrcIP.String(),
		DstIP:      ipv4.DstIP.String(),
	}
}

// getProtoIPv6 returns the ProtoIPv6 from the IPv6.
func getProtoIPv6(ipv6 *layers.IPv6) trace.ProtoIPv6 {
	return trace.ProtoIPv6{
		Version:      ipv6.Version,
		TrafficClass: ipv6.TrafficClass,
		FlowLabel:    ipv6.FlowLabel,
		Length:       ipv6.Length,
		NextHeader:   ipv6.NextHeader.String(),
		HopLimit:     ipv6.HopLimit,
		SrcIP:        ipv6.SrcIP.String(),
		DstIP:        ipv6.DstIP.String(),
	}
}

// getProtoTCP returns the ProtoTCP from the TCP.
func getProtoTCP(tcp *layers.TCP) trace.ProtoTCP {
	return trace.ProtoTCP{
		SrcPort:    uint16(tcp.SrcPort),
		DstPort:    uint16(tcp.DstPort),
		Seq:        tcp.Seq,
		Ack:        tcp.Ack,
		DataOffset: tcp.DataOffset,
		FIN:        boolToUint8(tcp.FIN),
		SYN:        boolToUint8(tcp.SYN),
		RST:        boolToUint8(tcp.RST),
		PSH:        boolToUint8(tcp.PSH),
		ACK:        boolToUint8(tcp.ACK),
		URG:        boolToUint8(tcp.URG),
		ECE:        boolToUint8(tcp.ECE),
		NS:         boolToUint8(tcp.NS),
		Window:     tcp.Window,
		Checksum:   tcp.Checksum,
		Urgent:     tcp.Urgent,
		// TODO: TCP options
	}
}

// getProtoUDP returns the ProtoUDP from the UDP.
func getProtoUDP(udp *layers.UDP) trace.ProtoUDP {
	return trace.ProtoUDP{
		SrcPort:  uint16(udp.SrcPort),
		DstPort:  uint16(udp.DstPort),
		Length:   udp.Length,
		Checksum: udp.Checksum,
	}
}

// getProtoICMP returns the ProtoICMP from the ICMP.
func getProtoICMP(icmp *layers.ICMPv4) trace.ProtoICMP {
	return trace.ProtoICMP{
		TypeCode: icmp.TypeCode.String(),
		Checksum: icmp.Checksum,
		Id:       icmp.Id,
		Seq:      icmp.Seq,
	}
}

// getProtoICMPv6 returns the ProtoICMPv6 from the ICMPv6.
func getProtoICMPv6(icmpv6 *layers.ICMPv6) trace.ProtoICMPv6 {
	return trace.ProtoICMPv6{
		TypeCode: icmpv6.TypeCode.String(),
		Checksum: icmpv6.Checksum,
	}
}

// getProtoDNS returns the ProtoDNS from the DNS.
func getProtoDNS(dns *layers.DNS) trace.ProtoDNS {
	proto := trace.ProtoDNS{
		ID:           dns.ID,
		QR:           boolToUint8(dns.QR),
		OpCode:       strToLower(dns.OpCode.String()),
		AA:           boolToUint8(dns.AA),
		TC:           boolToUint8(dns.TC),
		RD:           boolToUint8(dns.RD),
		RA:           boolToUint8(dns.RA),
		Z:            dns.Z,
		ResponseCode: strToLower(dns.ResponseCode.String()),
		QDCount:      dns.QDCount,
		ANCount:      dns.ANCount,
		NSCount:      dns.NSCount,
		ARCount:      dns.ARCount,
	}

	// Process all existing questions (if any).
	proto.Questions = make([]trace.ProtoDNSQuestion, 0, len(dns.Questions))
	proto.Answers = make([]trace.ProtoDNSResourceRecord, 0, len(dns.Answers))
	proto.Authorities = make([]trace.ProtoDNSResourceRecord, 0, len(dns.Authorities))
	proto.Additionals = make([]trace.ProtoDNSResourceRecord, 0, len(dns.Additionals))

	for _, question := range dns.Questions {
		proto.Questions = append(proto.Questions, getProtoDNSQuestion(question))
	}

	for _, answer := range dns.Answers {
		proto.Answers = append(proto.Answers, getProtoDNSResourceRecord(answer))
	}

	for _, auth := range dns.Authorities {
		proto.Authorities = append(proto.Authorities, getProtoDNSResourceRecord(auth))
	}

	for _, add := range dns.Additionals {
		proto.Additionals = append(proto.Additionals, getProtoDNSResourceRecord(add))
	}

	return proto
}

// getProtoDNSQuestion returns the ProtoDNSQuestion from the DNSQuestion.
func getProtoDNSQuestion(question layers.DNSQuestion) trace.ProtoDNSQuestion {
	return trace.ProtoDNSQuestion{
		Name:  string(question.Name),
		Type:  question.Type.String(),
		Class: question.Class.String(),
	}
}

// getProtoDNSResourceRecord returns the ProtoDNSResourceRecord from the DNSResourceRecord.
func getProtoDNSResourceRecord(record layers.DNSResourceRecord) trace.ProtoDNSResourceRecord {
	var ip string

	if record.IP != nil {
		ip = record.IP.String()
	}

	return trace.ProtoDNSResourceRecord{
		Name:  string(record.Name),
		Type:  record.Type.String(),
		Class: record.Class.String(),
		TTL:   record.TTL,
		IP:    ip,
		NS:    string(record.NS),
		CNAME: string(record.CNAME),
		PTR:   string(record.PTR),
		TXTs:  convertArrayOfBytes(record.TXTs),
		SOA: trace.ProtoDNSSOA{
			MName:   string(record.SOA.MName),
			RName:   string(record.SOA.RName),
			Serial:  record.SOA.Serial,
			Refresh: record.SOA.Refresh,
			Retry:   record.SOA.Retry,
			Expire:  record.SOA.Expire,
			Minimum: record.SOA.Minimum,
		},
		SRV: trace.ProtoDNSSRV{
			Priority: record.SRV.Priority,
			Weight:   record.SRV.Weight,
			Port:     record.SRV.Port,
			Name:     string(record.SRV.Name),
		},
		MX: trace.ProtoDNSMX{
			Preference: record.MX.Preference,
			Name:       string(record.MX.Name),
		},
		OPT: getDNSOPT(record.OPT),
		URI: trace.ProtoDNSURI{
			Priority: record.URI.Priority,
			Weight:   record.URI.Weight,
			Target:   string(record.URI.Target),
		},
		TXT: string(record.TXT),
	}
}

// getDNSOPT returns the ProtoDNSOPT from the DNSOPT.
func getDNSOPT(opt []layers.DNSOPT) []trace.ProtoDNSOPT {
	res := make([]trace.ProtoDNSOPT, 0, len(opt))

	for _, j := range opt {
		res = append(res,
			trace.ProtoDNSOPT{
				Code: j.Code.String(),
				Data: string(j.Data),
			},
		)
	}

	return res
}

// getProtoHTTPFromRequestPacket returns the ProtoHTTP from the HTTP request packet.
func getProtoHTTPFromRequestPacket(packet gopacket.Packet) (*trace.ProtoHTTP, error) {
	layer7, err := getLayer7FromPacket(packet)
	if err != nil {
		return nil, err
	}

	layer7Payload := layer7.Payload()

	if len(layer7Payload) < httpMinLen {
		return nil, nil // regular tcp/ip packet without HTTP payload
	}

	reader := bufio.NewReader(bytes.NewReader(layer7Payload))

	request, err := http.ReadRequest(reader)
	if err != nil {
		return nil, err
	}

	return &trace.ProtoHTTP{
		Direction:     "request",
		Method:        request.Method,
		Protocol:      request.Proto,
		Host:          request.Host,
		URIPath:       request.URL.Path,
		Headers:       request.Header,
		ContentLength: request.ContentLength,
	}, nil
}

// getProtoHTTPFromResponsePacket returns the ProtoHTTP from the HTTP response packet.
func getProtoHTTPFromResponsePacket(packet gopacket.Packet) (*trace.ProtoHTTP, error) {
	layer7, err := getLayer7FromPacket(packet)
	if err != nil {
		return nil, err
	}

	layer7Payload := layer7.Payload()

	if len(layer7Payload) < httpMinLen {
		return nil, nil // regular tcp/ip packet without HTTP payload
	}

	reader := bufio.NewReader(bytes.NewReader(layer7Payload))

	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		return nil, err
	}

	return &trace.ProtoHTTP{
		Direction:     "response",
		Status:        response.Status,
		StatusCode:    response.StatusCode,
		Protocol:      response.Proto,
		Headers:       response.Header,
		ContentLength: response.ContentLength,
	}, nil
}

// getProtoHTTPRequestFromHTTP returns the ProtoHTTPRequest from the ProtoHTTP.
func getProtoHTTPRequestFromHTTP(proto *trace.ProtoHTTP) trace.ProtoHTTPRequest {
	return trace.ProtoHTTPRequest{
		Method:        proto.Method,
		Protocol:      proto.Protocol,
		Host:          proto.Host,
		URIPath:       proto.URIPath,
		Headers:       proto.Headers,
		ContentLength: proto.ContentLength,
	}
}

// getProtoHTTPResponseFromHTTP returns the ProtoHTTPResponse from the ProtoHTTP.
func getProtoHTTPResponseFromHTTP(proto *trace.ProtoHTTP) trace.ProtoHTTPResponse {
	return trace.ProtoHTTPResponse{
		Status:        proto.Status,
		StatusCode:    proto.StatusCode,
		Protocol:      proto.Protocol,
		Headers:       proto.Headers,
		ContentLength: proto.ContentLength,
	}
}

// getDNSQueryFromProtoDNS converts a NetPacketDNS to a DnsQueryData.
func getDNSQueryFromProtoDNS(questions []trace.ProtoDNSQuestion) []trace.DnsQueryData {
	requests := make([]trace.DnsQueryData, 0, len(questions))

	for _, question := range questions {
		requests = append(requests,
			trace.DnsQueryData{
				Query:      question.Name,
				QueryType:  question.Type,
				QueryClass: question.Class,
			},
		)
	}

	return requests
}

// getDNSResponseFromProtoDNS converts a NetPacketDNS to a DnsResponseData.
func getDNSResponseFromProtoDNS(query trace.DnsQueryData, answers []trace.ProtoDNSResourceRecord) []trace.DnsResponseData {
	dnsAnswers := make([]trace.DnsAnswer, 0, len(answers))

	for _, answer := range answers {
		var dnsAnswer trace.DnsAnswer

		switch answer.Type {
		case "A":
			dnsAnswer.Answer = answer.IP
		case "AAAA":
			dnsAnswer.Answer = answer.IP
		case "NS":
			dnsAnswer.Answer = answer.NS
		case "CNAME":
			dnsAnswer.Answer = answer.CNAME
		case "PTR":
			dnsAnswer.Answer = answer.PTR
		case "MX":
			dnsAnswer.Answer = answer.MX.Name
		case "TXT":
			dnsAnswer.Answer = answer.TXT
		default:
			dnsAnswer.Answer = "not implemented"
		}

		dnsAnswer.Type = answer.Type
		dnsAnswer.Ttl = answer.TTL

		dnsAnswers = append(dnsAnswers, dnsAnswer)
	}

	return []trace.DnsResponseData{
		{
			QueryData: query,
			DnsAnswer: dnsAnswers,
		},
	}
}
