// Package trace defines the public types exported through the EBPF code and produced outwards from tracee-ebpf
package trace

type PktMeta struct {
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   uint16 `json:"src_port"`
	DstPort   uint16 `json:"dst_port"`
	Protocol  uint8  `json:"protocol"`
	PacketLen uint32 `json:"packet_len"`
	Iface     string `json:"iface"`
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
