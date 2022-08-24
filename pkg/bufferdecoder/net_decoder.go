package bufferdecoder

import (
	"encoding/binary"
	"fmt"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type NetEventMetadata struct {
	TimeStamp   uint64    `json:"timeStamp"`
	NetEventId  events.ID `json:"netEventId"` //int32
	HostTid     uint32    `json:"hostTid"`
	ProcessName [16]byte  `json:"processName"`
}

func (NetEventMetadata) GetSizeBytes() uint32 {
	return 32
}

// DecodeNetEventMetadata parsing the NetEventMetadata struct from byte array
func (decoder *EbpfDecoder) DecodeNetEventMetadata(eventMetaData *NetEventMetadata) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < int(eventMetaData.GetSizeBytes()) {
		return fmt.Errorf("can't read NetEventMetadata from buffer: buffer too short")
	}
	eventMetaData.TimeStamp = binary.LittleEndian.Uint64(decoder.buffer[offset : offset+8])
	eventMetaData.NetEventId = events.ID(binary.LittleEndian.Uint32(decoder.buffer[offset+8 : offset+12]))
	eventMetaData.HostTid = binary.LittleEndian.Uint32(decoder.buffer[offset+12 : offset+16])
	copy(eventMetaData.ProcessName[:], decoder.buffer[offset+16:offset+32])

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

// DecodeNetCaptureData parsing the NetCaptureData struct from byte array
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

// DecodeNetPacketEvent parsing the NetPacketEvent struct from byte array
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

// getDnsLayerFromBytes creates a packet from packetBytes and returns DNS layer
func getDnsLayerFromBytes(packetBytes []byte) (*layers.DNS, error) {
	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeEthernet, gopacket.Default)
	if packet == nil {
		return nil, fmt.Errorf("couldn't parse the packet")
	}
	dnsLayer, ok := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
	if !ok {
		return nil, fmt.Errorf("couldn't find the DNS layer in packet")
	}
	return dnsLayer, nil
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

// DecodeDnsQueryArray gets DNS layer from packet and parses DNS questions from it
func (decoder *EbpfDecoder) DecodeDnsQueryArray(questions *[]DnsQueryData) error {
	dnsLayer, err := getDnsLayerFromBytes(decoder.buffer[decoder.cursor:])
	if err != nil {
		return err
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

// DecodeDnsRepliesData gets DNS layer from packet and parses DNS replies from it
func (decoder *EbpfDecoder) DecodeDnsRepliesData(responses *[]DnsResponseData) error {
	dnsLayer, err := getDnsLayerFromBytes(decoder.buffer[decoder.cursor:])
	if err != nil {
		return err
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
