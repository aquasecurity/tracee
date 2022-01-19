package external

//for supporting networking events in tracee rules
type PktMeta struct {
	SrcIP    string `json:"srcIP"`
	DestIP   string `json:"destIP"`
	SrcPort  uint16 `json:"srcPort"`
	DestPort uint16 `json:"destPort"`
	Protocol uint8  `json:"protocol"`
}
