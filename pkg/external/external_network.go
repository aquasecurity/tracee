package external

//for supporting networking events in tracee rules
type PktMeta struct {
	SrcIP    string `json:"srcIP"`
	DestIP   string `json:"destIP"`
	SrcPort  uint16 `json:"srcPort"`
	DestPort uint16 `json:"destPort"`
	Protocol uint8  `json:"protocol"`
}

type FunctionBasedPacket struct {
	LocalIP     string `json:"localIP"`
	RemoteIP    string `json:"remoteIP"`
	LocalPort   uint16 `json:"localPort"`
	RemotePort  uint16 `json:"remotePort"`
	Protocol    uint8  `json:"protocol"`
	TcpOldState uint32 `json:"tcpOldState"`
	TcpNewState uint32 `json:"tcpNewState"`
	SockPtr     uint64 `json:"sockPtr"`
}

type DnsQueryData struct {
	Query      string `json:"query"`
	QueryType  string `json:"queryType"`
	QueryClass string `json:"queryClass"`
}
