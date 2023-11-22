// Package trace defines the public types exported through the EBPF code and produced outwards from tracee-ebpf
package trace

import (
	"net/http"
)

type PktMeta struct {
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   uint16 `json:"src_port"`
	DstPort   uint16 `json:"dst_port"`
	Protocol  uint8  `json:"protocol"`
	PacketLen uint32 `json:"packet_len"`
	Iface     string `json:"iface"` // TODO: currently it is always "any"
}

type DnsQueryData struct {
	Query      string `json:"query"`
	QueryType  string `json:"query_type"`
	QueryClass string `json:"query_class"`
}

type DnsAnswer struct {
	Type   string `json:"answer_type"`
	Ttl    uint32 `json:"ttl"`
	Answer string `json:"answer"`
}

type DnsResponseData struct {
	QueryData DnsQueryData `json:"query_data"`
	DnsAnswer []DnsAnswer  `json:"dns_answer"`
}

//
// Network Protocol Event Types
//

// Metadata

type PacketDirection uint8

const (
	InvalidPacketDirection PacketDirection = iota
	PacketIngress
	PacketEgress
)

func (dir *PacketDirection) String() string {
	switch *dir {
	case PacketEgress:
		return "egress"
	case PacketIngress:
		return "ingress"
	default:
		return "invalid"
	}
}

// TODO: move all ip and port arguments from packet events here
// This can be done once this struct is filterable. In  order to filter structs
// the move to the new event structure (from protobuf) will need to be done (see issue #2870).
// Once it is done, cel-go filtering can be added for struct fields.
type PacketMetadata struct {
	Direction PacketDirection `json:"direction"`
}

// IPv4

type ProtoIPv4 struct {
	Version    uint8  `json:"version"`
	IHL        uint8  `json:"IHL"`
	TOS        uint8  `json:"TOS"`
	Length     uint16 `json:"length"`
	Id         uint16 `json:"id"`
	Flags      uint8  `json:"flags"`
	FragOffset uint16 `json:"fragOffset"`
	TTL        uint8  `json:"TTL"`
	Protocol   string `json:"protocol"`
	Checksum   uint16 `json:"checksum"`
	SrcIP      string `json:"srcIP"`
	DstIP      string `json:"dstIP"`
	// TODO: Options []ProtoIPv4Option (IHL > 5)
}

// IPv6

type ProtoIPv6 struct {
	Version      uint8  `json:"version"`
	TrafficClass uint8  `json:"trafficClass"`
	FlowLabel    uint32 `json:"flowLabel"`
	Length       uint16 `json:"length"`
	NextHeader   string `json:"nextHeader"`
	HopLimit     uint8  `json:"hopLimit"`
	SrcIP        string `json:"srcIP"`
	DstIP        string `json:"dstIP"`
}

// TCP

type ProtoTCP struct {
	SrcPort    uint16 `json:"srcPort"`
	DstPort    uint16 `json:"dstPort"`
	Seq        uint32 `json:"seq"`
	Ack        uint32 `json:"ack"`
	DataOffset uint8  `json:"dataOffset"`
	FIN        uint8  `json:"FIN"`
	SYN        uint8  `json:"SYN"`
	RST        uint8  `json:"RST"`
	PSH        uint8  `json:"PSH"`
	ACK        uint8  `json:"ACK"`
	URG        uint8  `json:"URG"`
	ECE        uint8  `json:"ECE"`
	CWR        uint8  `json:"CWR"`
	NS         uint8  `json:"NS"`
	Window     uint16 `json:"window"`
	Checksum   uint16 `json:"checksum"`
	Urgent     uint16 `json:"urgent"`
	// TODO: Options []ProtoTCPOption
}

// UDP

type ProtoUDP struct {
	SrcPort  uint16 `json:"srcPort"`
	DstPort  uint16 `json:"dstPort"`
	Length   uint16 `json:"length"`
	Checksum uint16 `json:"checksum"`
}

// ICMP

type ProtoICMP struct {
	TypeCode string `json:"typeCode"`
	Checksum uint16 `json:"checksum"`
	Id       uint16 `json:"id"`
	Seq      uint16 `json:"seq"`
}

// ICMPv6

type ProtoICMPv6 struct {
	TypeCode string `json:"typeCode"`
	Checksum uint16 `json:"checksum"`
}

// DNS

type ProtoDNS struct {
	ID           uint16                   `json:"ID"`
	QR           uint8                    `json:"QR"`
	OpCode       string                   `json:"opCode"`
	AA           uint8                    `json:"AA"`
	TC           uint8                    `json:"TC"`
	RD           uint8                    `json:"RD"`
	RA           uint8                    `json:"RA"`
	Z            uint8                    `json:"Z"`
	ResponseCode string                   `json:"responseCode"`
	QDCount      uint16                   `json:"QDCount"`
	ANCount      uint16                   `json:"ANCount"`
	NSCount      uint16                   `json:"NSCount"`
	ARCount      uint16                   `json:"ARCount"`
	Questions    []ProtoDNSQuestion       `json:"questions"`
	Answers      []ProtoDNSResourceRecord `json:"answers"`
	Authorities  []ProtoDNSResourceRecord `json:"authorities"`
	Additionals  []ProtoDNSResourceRecord `json:"additionals"`
}

type ProtoDNSQuestion struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
}

type ProtoDNSResourceRecord struct {
	Name  string        `json:"name"`
	Type  string        `json:"type"`
	Class string        `json:"class"`
	TTL   uint32        `json:"TTL"`
	IP    string        `json:"IP"`
	NS    string        `json:"NS"`
	CNAME string        `json:"CNAME"`
	PTR   string        `json:"PTR"`
	TXTs  []string      `json:"TXTs"`
	SOA   ProtoDNSSOA   `json:"SOA"`
	SRV   ProtoDNSSRV   `json:"SRV"`
	MX    ProtoDNSMX    `json:"MX"`
	OPT   []ProtoDNSOPT `json:"OPT"`
	URI   ProtoDNSURI   `json:"URI"`
	TXT   string        `json:"TXT"`
}

type ProtoDNSSOA struct {
	MName   string `json:"MName"`
	RName   string `json:"RName"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minimum uint32 `json:"minimum"`
}

type ProtoDNSSRV struct {
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Port     uint16 `json:"port"`
	Name     string `json:"name"`
}

type ProtoDNSMX struct {
	Preference uint16 `json:"preference"`
	Name       string `json:"name"`
}

type ProtoDNSURI struct {
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Target   string `json:"target"`
}

type ProtoDNSOPT struct {
	Code string `json:"code"`
	Data string `json:"data"`
}

type ProtoHTTP struct {
	Direction     string      `json:"direction"`
	Method        string      `json:"method"`
	Protocol      string      `json:"protocol"`
	Host          string      `json:"host"`
	URIPath       string      `json:"uri_path"`
	Status        string      `json:"status"`
	StatusCode    int         `json:"status_code"`
	Headers       http.Header `json:"headers"`
	ContentLength int64       `json:"content_length"`
}

type ProtoHTTPRequest struct {
	Method        string      `json:"method"`
	Protocol      string      `json:"protocol"`
	Host          string      `json:"host"`
	URIPath       string      `json:"uri_path"`
	Headers       http.Header `json:"headers"`
	ContentLength int64       `json:"content_length"`
}

type ProtoHTTPResponse struct {
	Status        string      `json:"status"`
	StatusCode    int         `json:"status_code"`
	Protocol      string      `json:"protocol"`
	Headers       http.Header `json:"headers"`
	ContentLength int64       `json:"content_length"`
}
