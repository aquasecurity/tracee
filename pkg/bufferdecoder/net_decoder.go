package bufferdecoder

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type NetEventMetadata struct {
	TimeStamp   uint64   `json:"timeStamp"`
	NetEventId  int32    `json:"netEventId"`
	HostTid     uint32   `json:"hostTid"`
	ProcessName [16]byte `json:"processName"`
}

func (NetEventMetadata) GetSizeBytes() uint32 {
	return 32
}

//DecodeNetEventMetadata parsing the NetEventMetadata struct from byte array
func (decoder *EbpfDecoder) DecodeNetEventMetadata(eventMetaData *NetEventMetadata) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < int(eventMetaData.GetSizeBytes()) {
		return fmt.Errorf("can't read NetEventMetadata from buffer: buffer too short")
	}
	eventMetaData.TimeStamp = binary.LittleEndian.Uint64(decoder.buffer[offset : offset+8])
	eventMetaData.NetEventId = int32(binary.LittleEndian.Uint32(decoder.buffer[offset+8 : offset+12]))
	eventMetaData.HostTid = binary.LittleEndian.Uint32(decoder.buffer[offset+12 : offset+16])
	copy(eventMetaData.ProcessName[:], bytes.TrimRight(decoder.buffer[offset+16:offset+32], "\x00"))

	decoder.cursor += int(eventMetaData.GetSizeBytes())
	return nil
}

type NetCaptureData struct {
	PacketLength     uint32 `json:"pktLen"`
	ConfigIfaceIndex uint32 `json:"ifIndex"`
}

func (NetCaptureData) GetSizeBytes() uint32 {
	return 8
}

//DecodeNetCaptureData parsing the NetCaptureData struct from byte array
func (decoder *EbpfDecoder) DecodeNetCaptureData(netCaptureData *NetCaptureData) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < int(netCaptureData.GetSizeBytes()) {
		return fmt.Errorf("can't read NetCaptureData from buffer: buffer too short")
	}
	netCaptureData.PacketLength = binary.LittleEndian.Uint32(decoder.buffer[offset : offset+4])
	netCaptureData.ConfigIfaceIndex = binary.LittleEndian.Uint32(decoder.buffer[offset+4 : offset+8])

	decoder.cursor += int(netCaptureData.GetSizeBytes())
	return nil
}

type NetPacketEvent struct {
	SrcIP    [16]byte
	DstIP    [16]byte
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	_        [3]byte //padding
}

func (NetPacketEvent) GetSizeBytes() uint32 {
	return 40
}

//DecodeNetPacketEvent parsing the NetPacketEvent struct from byte array
func (decoder *EbpfDecoder) DecodeNetPacketEvent(netPacketEvent *NetPacketEvent) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < int(netPacketEvent.GetSizeBytes()) {
		return fmt.Errorf("can't read NetPacketEvent from buffer: buffer too short")
	}
	copy(netPacketEvent.SrcIP[:], decoder.buffer[offset:offset+16])
	copy(netPacketEvent.DstIP[:], decoder.buffer[offset+16:offset+32])
	netPacketEvent.SrcPort = binary.LittleEndian.Uint16(decoder.buffer[offset+32 : offset+34])
	netPacketEvent.DstPort = binary.LittleEndian.Uint16(decoder.buffer[offset+34 : offset+36])
	netPacketEvent.Protocol = decoder.buffer[offset+36]

	decoder.cursor += int(netPacketEvent.GetSizeBytes())
	return nil
}

type NetDebugEvent struct {
	LocalIP     [16]byte
	RemoteIP    [16]byte
	LocalPort   uint16
	RemotePort  uint16
	Protocol    uint8
	_           [3]byte //padding
	TcpOldState uint32
	TcpNewState uint32
	_           [4]byte //padding
	SockPtr     uint64
}

func (NetDebugEvent) GetSizeBytes() uint32 {
	return 60
}

//DecodeNetDebugEvent parsing the NetDebugEvent struct from byte array
func (decoder *EbpfDecoder) DecodeNetDebugEvent(netDebugEvent *NetDebugEvent) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < int(netDebugEvent.GetSizeBytes()) {
		return fmt.Errorf("can't read NetDebugEvent from buffer: buffer too short")
	}
	copy(netDebugEvent.LocalIP[:], decoder.buffer[offset:offset+16])
	copy(netDebugEvent.RemoteIP[:], decoder.buffer[offset+16:offset+32])
	netDebugEvent.LocalPort = binary.LittleEndian.Uint16(decoder.buffer[offset+32 : offset+34])
	netDebugEvent.RemotePort = binary.LittleEndian.Uint16(decoder.buffer[offset+34 : offset+36])
	netDebugEvent.Protocol = decoder.buffer[offset+36]
	netDebugEvent.TcpOldState = binary.LittleEndian.Uint32(decoder.buffer[offset+40 : offset+44])
	netDebugEvent.TcpNewState = binary.LittleEndian.Uint32(decoder.buffer[offset+44 : offset+48])
	netDebugEvent.SockPtr = binary.LittleEndian.Uint64(decoder.buffer[offset+52 : offset+60])

	decoder.cursor += int(netDebugEvent.GetSizeBytes())
	return nil
}

type DnsQueryData struct {
	Query      string `json:"query"`
	QueryType  string `json:"queryType"`
	QueryClass string `json:"queryClass"`
}

// parseDnsQuestion parse dns request to DnsQueryData
func parseDnsQuestion(question layers.DNSQuestion) DnsQueryData {
	var request DnsQueryData
	request.Query = string(question.Name)
	request.QueryType = question.Type.String()
	request.QueryClass = fmt.Sprint("", question.Class)
	return request
}

func (decoder *EbpfDecoder) DecodeDnsQueryArray(questions *[]DnsQueryData) error {
	offset := decoder.cursor
	packet := gopacket.NewPacket(decoder.buffer[offset:], layers.LayerTypeEthernet, gopacket.Default)
	if packet == nil {
		return fmt.Errorf("couldnt parse the packet")
	}
	dnsLayer, ok := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
	if !ok {
		return fmt.Errorf("couldnt find the dns layer")
	}
	for _, question := range dnsLayer.Questions {
		*questions = append(*questions, parseDnsQuestion(question))
	}
	return nil
}

type DnsAnswer struct {
	Type   string `json:"answerType"`
	Ttl    uint32 `json:"ttl"`
	Answer string `json:"answer"`
}

type DnsResponseData struct {
	QueryData DnsQueryData `json:"queryData"`
	DnsAnswer []DnsAnswer  `json:"dnsAnswer"`
}

func (decoder *EbpfDecoder) DecodeDnsResponseData(responses *[]DnsResponseData) error {
	offset := decoder.cursor
	packet := gopacket.NewPacket(decoder.buffer[offset:], layers.LayerTypeEthernet, gopacket.Default)
	if packet == nil {
		return fmt.Errorf("couldnt find udp layer1")
	}
	dnsLayer := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
	if dnsLayer == nil {
		return fmt.Errorf("couldnt find dns layer")
	}

	for _, question := range dnsLayer.Questions {
		response := DnsResponseData{}
		response.QueryData = parseDnsQuestion(question)
		if int(dnsLayer.ANCount) > 0 {
			for _, answer := range dnsLayer.Answers {
				ans := DnsAnswer{Type: answer.Type.String(), Ttl: answer.TTL}
				switch answer.Type {
				case layers.DNSTypeA, layers.DNSTypeAAAA:
					ans.Answer = answer.IP.String()
				case layers.DNSTypePTR:
					ans.Answer = string(answer.PTR)
				case layers.DNSTypeCNAME:
					ans.Answer = string(answer.CNAME)
				case layers.DNSTypeNS:
					ans.Answer = string(answer.NS)
				}
				response.DnsAnswer = append(response.DnsAnswer, ans)
			}
		}
		*responses = append(*responses, response)
	}
	return nil
}
