package helpers

import (
	"fmt"
	"strings"
	"syscall"

	"github.com/aquasecurity/tracee/types/trace"
)

// IsFileWrite returns whether the passed file permissions string contains
// o_wronly or o_rdwr
func IsFileWrite(flags int) bool {
	accessMode := uint64(flags) & syscall.O_ACCMODE
	if accessMode == syscall.O_WRONLY || accessMode == syscall.O_RDWR {
		return true
	}
	return false
}

// IsFileRead returns whether the passed file permissions string contains
// o_rdonly or o_rdwr
func IsFileRead(flags int) bool {
	accessMode := uint64(flags) & syscall.O_ACCMODE
	if accessMode == syscall.O_RDONLY || accessMode == syscall.O_RDWR {
		return true
	}
	return false
}

// IsMemoryPath checks if a given file path is located under "memfd", "/run/shm/" or "/dev/shm/".
func IsMemoryPath(pathname string) bool {
	if strings.HasPrefix(pathname, "memfd:") || strings.HasPrefix(pathname, "/run/shm/") ||
		strings.HasPrefix(pathname, "/dev/shm/") {
		return true
	}

	return false
}

// IsElf checks if the file starts with an ELF magic.
func IsElf(bytesArray []byte) bool {
	if len(bytesArray) >= 4 {
		if bytesArray[0] == 127 && bytesArray[1] == 69 && bytesArray[2] == 76 && bytesArray[3] == 70 {
			return true
		}
	}

	return false
}

func GetFamilyFromRawAddr(addr map[string]string) (string, error) {
	family, exists := addr["sa_family"]
	if !exists {
		return "", fmt.Errorf("family not found in address")
	}

	return family, nil
}

func IsInternetFamily(addr map[string]string) (bool, error) {
	family, err := GetFamilyFromRawAddr(addr)
	if err != nil {
		return false, err
	}

	if family == "AF_INET" || family == "AF_INET6" {
		return true, nil
	}

	return false, nil
}

func IsUnixFamily(addr map[string]string) (bool, error) {
	family, err := GetFamilyFromRawAddr(addr)
	if err != nil {
		return false, err
	}

	if family == "AF_UNIX" {
		return true, nil
	}

	return false, nil
}

func GetIPFromRawAddr(addr map[string]string) (string, error) {
	family, err := GetFamilyFromRawAddr(addr)
	if err != nil {
		return "", err
	}

	ip := ""
	var exists bool

	switch family {
	case "AF_INET":
		ip, exists = addr["sin_addr"]
		if !exists {
			return "", fmt.Errorf("ip not found in address")
		}
	case "AF_INET6":
		ip, exists = addr["sin6_addr"]
		if !exists {
			return "", fmt.Errorf("ip not found in address")
		}
	default:
		return "", fmt.Errorf("address family not supported")
	}

	return ip, nil
}

func GetPortFromRawAddr(addr map[string]string) (string, error) {
	family, err := GetFamilyFromRawAddr(addr)
	if err != nil {
		return "", err
	}

	port := ""
	var exists bool

	switch family {
	case "AF_INET":
		port, exists = addr["sin_port"]
		if !exists {
			return "", fmt.Errorf("port not found in address")
		}
	case "AF_INET6":
		port, exists = addr["sin6_port"]
		if !exists {
			return "", fmt.Errorf("port not found in address")
		}
	default:
		return "", fmt.Errorf("address family not supported")
	}

	return port, nil
}

func GetPathFromRawAddr(addr map[string]string) (string, error) {
	family, err := GetFamilyFromRawAddr(addr)
	if err != nil {
		return "", err
	}

	path := ""
	var exists bool

	switch family {
	case "AF_UNIX":
		path, exists = addr["sun_path"]
		if !exists {
			return "", fmt.Errorf("path not found in address")
		}
	default:
		return "", fmt.Errorf("address family not supported")
	}

	return path, nil
}

//
// Network Protocol Event Types
//

// GetPacketMetadata converts json to PacketMetadata
func GetPacketMetadata(
	event trace.Event,
	argName string) (
	trace.PacketMetadata,
	error) {
	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return trace.PacketMetadata{}, err
	}

	argPacketMetadata, ok := arg.Value.(trace.PacketMetadata)
	if ok {
		return argPacketMetadata, nil
	}

	return trace.PacketMetadata{}, fmt.Errorf("packet metadata: type error (should be trace.PacketMetadata, is %T)", arg.Value)
}

// GetProtoIPv4ByName converts json to ProtoIPv4
func GetProtoIPv4ByName(
	event trace.Event,
	argName string) (
	trace.ProtoIPv4,
	error) {
	//
	// Current ProtoIPv4 type considered:
	//
	// type ProtoIPv4 struct {
	// 	Version    uint8             `json:"version"`
	// 	IHL        uint8             `json:"IHL"`
	// 	TOS        uint8             `json:"TOS"`
	// 	Length     uint16            `json:"length"`
	// 	Id         uint16            `json:"id"`
	// 	Flags      uint8             `json:"flags"`
	// 	FragOffset uint16            `json:"fragOffset"`
	// 	TTL        uint8             `json:"TTL"`
	// 	Protocol   string            `json:"protocol"`
	// 	Checksum   uint16            `json:"checksum"`
	// 	SrcIP      net.IP            `json:"srcIP"`
	// 	DstIP      net.IP            `json:"dstIP"`
	// }
	//

	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return trace.ProtoIPv4{}, err
	}

	argProtoIPv4, ok := arg.Value.(trace.ProtoIPv4)
	if ok {
		return argProtoIPv4, nil
	}

	return trace.ProtoIPv4{}, fmt.Errorf("protocol IPv4: type error (should be trace.ProtoIPv4, is %T)", arg.Value)
}

// GetProtoIPv6ByName converts json to ProtoIPv6
func GetProtoIPv6ByName(
	event trace.Event,
	argName string) (
	trace.ProtoIPv6,
	error) {
	//
	// Current ProtoIPv6 type considered:
	//
	// type ProtoIPv6 struct {
	// 	Version      uint8  `json:"version"`
	// 	TrafficClass uint8  `json:"trafficClass"`
	// 	FlowLabel    uint32 `json:"flowLabel"`
	// 	Length       uint16 `json:"length"`
	// 	NextHeader   string `json:"nextHeader"`
	// 	HopLimit     uint8  `json:"hopLimit"`
	// 	SrcIP        string `json:"srcIP"`
	// 	DstIP        string `json:"dstIP"`
	// }

	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return trace.ProtoIPv6{}, err
	}

	argProtoIPv6, ok := arg.Value.(trace.ProtoIPv6)
	if ok {
		return argProtoIPv6, nil
	}

	return trace.ProtoIPv6{}, fmt.Errorf("protocol IPv6: type error (should be trace.ProtoIPv6, is %T)", arg.Value)
}

// GetProtoUDPByName converts json to ProtoUDP
func GetProtoUDPByName(
	event trace.Event, argName string) (
	trace.ProtoUDP, error) {
	//
	// Current ProtoUDP type considered:
	//
	// type ProtoUDP struct {
	// 	SrcPort  uint16 `json:"srcPort"`
	// 	DstPort  uint16 `json:"dstPort"`
	// 	Length   uint16 `json:"length"`
	// 	Checksum uint16 `json:"checksum"`
	// }

	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return trace.ProtoUDP{}, err
	}

	argProtoUDP, ok := arg.Value.(trace.ProtoUDP)
	if ok {
		return argProtoUDP, nil
	}

	return trace.ProtoUDP{}, fmt.Errorf("protocol UDP: type error (should be trace.ProtoUDP, is %T)", arg.Value)
}

// GetProtoTCPByName converts json to ProtoTCP
func GetProtoTCPByName(
	event trace.Event, argName string) (
	trace.ProtoTCP, error) {
	//
	// Current ProtoTCP type considered:
	//
	// type ProtoTCP struct {
	// SrcPort    uint16 `json:"srcPort"`
	// DstPort    uint16 `json:"dstPort"`
	// Seq        uint32 `json:"seq"`
	// Ack        uint32 `json:"ack"`
	// DataOffset uint8  `json:"dataOffset"`
	// FIN        uint8  `json:"FIN"`
	// SYN        uint8  `json:"SYN"`
	// RST        uint8  `json:"RST"`
	// PSH        uint8  `json:"PSH"`
	// ACK        uint8  `json:"ACK"`
	// URG        uint8  `json:"URG"`
	// ECE        uint8  `json:"ECE"`
	// CWR        uint8  `json:"CWR"`
	// NS         uint8  `json:"NS"`
	// Window     uint16 `json:"window"`
	// Checksum   uint16 `json:"checksum"`
	// Urgent     uint16 `json:"urgent"`
	// }

	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return trace.ProtoTCP{}, err
	}

	argProtoTCP, ok := arg.Value.(trace.ProtoTCP)
	if ok {
		return argProtoTCP, nil
	}

	return trace.ProtoTCP{}, fmt.Errorf("protocol TCP: type error (should be trace.ProtoTCP, is %T)", arg.Value)
}

// GetProtoICMPByName converts json to ProtoICMP
func GetProtoICMPByName(
	event trace.Event, argName string) (
	trace.ProtoICMP, error) {
	//
	// Current ProtoICMP type considered:
	//
	// type ProtoICMP struct {
	// 	TypeCode string `json:"typeCode"`
	// 	Checksum uint16 `json:"checksum"`
	// 	Id       uint16 `json:"id"`
	// 	Seq      uint16 `json:"seq"`
	// }

	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return trace.ProtoICMP{}, err
	}

	argProtoICMP, ok := arg.Value.(trace.ProtoICMP)
	if ok {
		return argProtoICMP, nil
	}

	return trace.ProtoICMP{}, fmt.Errorf("protocol ICMP: type error (should be trace.ProtoICMP, is %T)", arg.Value)
}

// GetProtoICMPv6ByName converts json to ProtoICMPv6
func GetProtoICMPv6ByName(
	event trace.Event,
	argName string) (
	trace.ProtoICMPv6,
	error) {
	//
	// Current ProtoICMPv6 type considered:
	//
	// type ProtoICMPv6 struct {
	// 	TypeCode string `json:"typeCode"`
	// 	Checksum uint16 `json:"checksum"`
	// }

	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return trace.ProtoICMPv6{}, err
	}

	argProtoICMPv6, ok := arg.Value.(trace.ProtoICMPv6)
	if ok {
		return argProtoICMPv6, nil
	}

	return trace.ProtoICMPv6{}, fmt.Errorf("protocol ICMPv6: type error (should be trace.ProtoICMPv6, is %T)", arg.Value)
}

// GetProtoDNSByName converts json to ProtoDNS
func GetProtoDNSByName(
	event trace.Event,
	argName string,
) (
	trace.ProtoDNS, error,
) {
	//
	// Current ProtoDNS type considered:
	//
	// type ProtoDNS struct {
	// 	ID           uint16                   `json:"ID"`
	// 	QR           uint8                    `json:"QR"`
	// 	OpCode       string                   `json:"opCode"`
	// 	AA           uint8                    `json:"AA"`
	// 	TC           uint8                    `json:"TC"`
	// 	RD           uint8                    `json:"RD"`
	// 	RA           uint8                    `json:"RA"`
	// 	Z            uint8                    `json:"Z"`
	// 	ResponseCode string                   `json:"responseCode"`
	// 	QDCount      uint16                   `json:"QDCount"`
	// 	ANCount      uint16                   `json:"ANCount"`
	// 	NSCount      uint16                   `json:"NSCount"`
	// 	ARCount      uint16                   `json:"ARCount"`
	// 	Questions    []ProtoDNSQuestion       `json:"questions"`
	// 	Answers      []ProtoDNSResourceRecord `json:"answers"`
	// 	Authorities  []ProtoDNSResourceRecord `json:"authorities"`
	// 	Additionals  []ProtoDNSResourceRecord `json:"additionals"`
	// }

	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return trace.ProtoDNS{}, err
	}

	argProtoDNS, ok := arg.Value.(trace.ProtoDNS)
	if ok {
		return argProtoDNS, nil
	}

	return trace.ProtoDNS{}, fmt.Errorf("protocol DNS: type error (should be trace.ProtoDNS, is %T)", arg.Value)
}

func GetProtoHTTPByName(
	event trace.Event,
	argName string,
) (
	trace.ProtoHTTP, error,
) {
	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return trace.ProtoHTTP{}, err
	}

	argProtoHTTP, ok := arg.Value.(trace.ProtoHTTP)
	if ok {
		return argProtoHTTP, nil
	}

	return trace.ProtoHTTP{}, fmt.Errorf("protocol HTTP: type error (should be trace.ProtoHTTP, is %T)", arg.Value)
}

func GetProtoHTTPRequestByName(
	event trace.Event,
	argName string,
) (
	trace.ProtoHTTPRequest, error,
) {
	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return trace.ProtoHTTPRequest{}, err
	}

	argProtoHTTPRequest, ok := arg.Value.(trace.ProtoHTTPRequest)
	if ok {
		return argProtoHTTPRequest, nil
	}

	return trace.ProtoHTTPRequest{}, fmt.Errorf("protocol HTTP (request): type error (should be trace.ProtoHTTPRequest, is %T)", arg.Value)
}

func GetProtoHTTPResponseByName(
	event trace.Event,
	argName string,
) (
	trace.ProtoHTTPResponse, error,
) {
	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return trace.ProtoHTTPResponse{}, err
	}

	argProtoHTTPResponse, ok := arg.Value.(trace.ProtoHTTPResponse)
	if ok {
		return argProtoHTTPResponse, nil
	}

	return trace.ProtoHTTPResponse{}, fmt.Errorf("protocol HTTP (response): type error (should be trace.ProtoHTTPResponse, is %T)", arg.Value)
}
