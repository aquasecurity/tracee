package bufferdecoder

import (
	"encoding/binary"
	"fmt"
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
	copy(eventMetaData.ProcessName[:], decoder.buffer[offset+16:offset+32])

	decoder.cursor += int(eventMetaData.GetSizeBytes())
	return nil
}

type NetCaptureData struct {
	PacketLength     uint32 `json:"pkt_len"`
	ConfigIfaceIndex uint32 `json:"if_index"`
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
