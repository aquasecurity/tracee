package external

type PktMeta struct {
	SrcIP    string `json:"src_ip"`
	DestIP   string `json:"dest_ip"`
	SrcPort  uint16 `json:"src_port"`
	DestPort uint16 `json:"dest_port"`
	Protocol uint8  `json:"protocol"`
}
