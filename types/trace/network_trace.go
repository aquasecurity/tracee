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
