package helpers

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/types/trace"
)

// IsFileWrite returns whether the passed file permissions string contains
// o_wronly or o_rdwr
func IsFileWrite(flags string) bool {
	flagsLow := strings.ToLower(flags)
	if strings.Contains(flagsLow, "o_wronly") || strings.Contains(flagsLow, "o_rdwr") {
		return true
	}
	return false
}

// IsFileRead returns whether the passed file permissions string contains
// o_rdonly or o_rdwr
func IsFileRead(flags string) bool {
	flagsLow := strings.ToLower(flags)
	if strings.Contains(flagsLow, "o_rdonly") || strings.Contains(flagsLow, "o_rdwr") {
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
	var ipv4 trace.ProtoIPv4

	arg, err := GetTraceeArgumentByName(event, argName)
	if err != nil {
		return trace.ProtoIPv4{}, err
	}

	argProtoIPv4, ok := arg.Value.(trace.ProtoIPv4)
	if ok {
		return argProtoIPv4, nil
	}

	argProtoIPv4Map, ok := arg.Value.(map[string]interface{})
	if !ok {
		return trace.ProtoIPv4{}, fmt.Errorf("ProtoIPv4: wrong types received")
	}

	uint8Types := map[string]uint8{"version": 0, "IHL": 0, "TOS": 0, "flags": 0, "TTL": 0}

	for key := range uint8Types {
		val, ok := argProtoIPv4Map[key].(json.Number)
		if !ok {
			return ipv4, fmt.Errorf("ProtoIPv4: error in argument %v", argName)
		}

		val64, err := val.Int64()
		if err != nil {
			return ipv4, err
		}

		uint8Types[key] = uint8(val64)
	}

	uint16Types := map[string]uint16{"length": 0, "id": 0, "fragOffset": 0, "checksum": 0}

	for key := range uint16Types {
		val, ok := argProtoIPv4Map[key].(json.Number)
		if !ok {
			return ipv4, fmt.Errorf("ProtoIPv4: error in argument %v", argName)
		}

		val64, err := val.Int64()
		if err != nil {
			return ipv4, err
		}

		uint16Types[key] = uint16(val64)
	}

	stringTypes := map[string]string{"protocol": "", "srcIP": "", "dstIP": ""}

	for key := range stringTypes {
		val, ok := argProtoIPv4Map[key].(string)
		if !ok {
			return ipv4, fmt.Errorf("ProtoIPv4: error in argument %v", argName)
		}

		stringTypes[key] = val
	}

	return trace.ProtoIPv4{
		Version:    uint8Types["version"],
		IHL:        uint8Types["IHL"],
		TOS:        uint8Types["TOS"],
		Length:     uint16Types["length"],
		Id:         uint16Types["id"],
		Flags:      uint8Types["flags"],
		FragOffset: uint16Types["fragOffset"],
		TTL:        uint8Types["TTL"],
		Protocol:   stringTypes["protocol"],
		Checksum:   uint16Types["checksum"],
		SrcIP:      stringTypes["srcIP"],
		DstIP:      stringTypes["dstIP"],
	}, nil
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

	var ipv4 trace.ProtoIPv6

	arg, err := GetTraceeArgumentByName(event, argName)
	if err != nil {
		return trace.ProtoIPv6{}, err
	}

	argProtoIPv6, ok := arg.Value.(trace.ProtoIPv6)
	if ok {
		return argProtoIPv6, nil
	}

	argProtoIPv6Map, ok := arg.Value.(map[string]interface{})
	if !ok {
		return trace.ProtoIPv6{}, fmt.Errorf("ProtoIPv6: wrong types received")
	}

	uint8Types := map[string]uint8{"version": 0, "trafficClass": 0, "hopLimit": 0}

	for key := range uint8Types {
		val, ok := argProtoIPv6Map[key].(json.Number)
		if !ok {
			return ipv4, fmt.Errorf("ProtoIPv6: error in argument %v", argName)
		}

		val64, err := val.Int64()
		if err != nil {
			return ipv4, err
		}

		uint8Types[key] = uint8(val64)
	}

	uint16Types := map[string]uint16{"length": 0}

	for key := range uint16Types {
		val, ok := argProtoIPv6Map[key].(json.Number)
		if !ok {
			return ipv4, fmt.Errorf("ProtoIPv6: error in argument %v", argName)
		}

		val64, err := val.Int64()
		if err != nil {
			return ipv4, err
		}

		uint16Types[key] = uint16(val64)
	}

	uint32Types := map[string]uint32{"flowLabel": 0}

	for key := range uint32Types {
		val, ok := argProtoIPv6Map[key].(json.Number)
		if !ok {
			return ipv4, fmt.Errorf("ProtoIPv6: error in argument %v", argName)
		}

		val64, err := val.Int64()
		if err != nil {
			return ipv4, err
		}

		uint32Types[key] = uint32(val64)
	}

	stringTypes := map[string]string{"nextHeader": "", "srcIP": "", "dstIP": ""}

	for key := range stringTypes {
		val, ok := argProtoIPv6Map[key].(string)
		if !ok {
			return ipv4, fmt.Errorf("ProtoIPv6: error in argument %v", argName)
		}

		stringTypes[key] = val
	}

	return trace.ProtoIPv6{
		Version:      uint8Types["version"],
		TrafficClass: uint8Types["trafficClass"],
		FlowLabel:    uint32Types["flowLabel"],
		Length:       uint16Types["length"],
		NextHeader:   stringTypes["nextHeader"],
		HopLimit:     uint8Types["hopLimit"],
		SrcIP:        stringTypes["srcIP"],
		DstIP:        stringTypes["dstIP"],
	}, nil
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

	var icmp trace.ProtoUDP

	arg, err := GetTraceeArgumentByName(event, argName)
	if err != nil {
		return trace.ProtoUDP{}, err
	}

	argProtoUDP, ok := arg.Value.(trace.ProtoUDP)
	if ok {
		return argProtoUDP, nil
	}

	argProtoUDPMap, ok := arg.Value.(map[string]interface{})
	if !ok {
		return trace.ProtoUDP{}, fmt.Errorf("ProtoUDP: wrong types received")
	}

	uint16Types := map[string]uint16{"srcPort": 0, "dstPort": 0, "length": 0, "checksum": 0}

	for key := range uint16Types {
		val, ok := argProtoUDPMap[key].(json.Number)
		if !ok {
			return icmp, fmt.Errorf("ProtoUDP: error in argument %v", argName)
		}

		val64, err := val.Int64()
		if err != nil {
			return icmp, err
		}

		uint16Types[key] = uint16(val64)
	}

	return trace.ProtoUDP{
		SrcPort:  uint16Types["srcPort"],
		DstPort:  uint16Types["dstPort"],
		Length:   uint16Types["length"],
		Checksum: uint16Types["checksum"],
	}, nil
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

	var icmp trace.ProtoTCP

	arg, err := GetTraceeArgumentByName(event, argName)
	if err != nil {
		return trace.ProtoTCP{}, err
	}

	argProtoTCP, ok := arg.Value.(trace.ProtoTCP)
	if ok {
		return argProtoTCP, nil
	}

	argProtoTCPMap, ok := arg.Value.(map[string]interface{})
	if !ok {
		return trace.ProtoTCP{}, fmt.Errorf("ProtoTCP: wrong types received")
	}

	uint8Types := map[string]uint8{
		"dataOffset": 0,
		"FIN":        0,
		"SYN":        0,
		"RST":        0,
		"PSH":        0,
		"ACK":        0,
		"URG":        0,
		"ECE":        0,
		"CWR":        0,
		"NS":         0,
	}

	for key := range uint8Types {
		val, ok := argProtoTCPMap[key].(json.Number)
		if !ok {
			return icmp, fmt.Errorf("ProtoTCP: error in argument %v", argName)
		}

		val64, err := val.Int64()
		if err != nil {
			return icmp, err
		}

		uint8Types[key] = uint8(val64)
	}

	uint16Types := map[string]uint16{
		"srcPort":  0,
		"dstPort":  0,
		"window":   0,
		"checksum": 0,
		"urgent":   0,
	}

	for key := range uint16Types {
		val, ok := argProtoTCPMap[key].(json.Number)
		if !ok {
			return icmp, fmt.Errorf("ProtoTCP: error in argument %v", argName)
		}

		val64, err := val.Int64()
		if err != nil {
			return icmp, err
		}

		uint16Types[key] = uint16(val64)
	}

	uint32Types := map[string]uint32{
		"seq": 0,
		"ack": 0,
	}

	for key := range uint32Types {
		val, ok := argProtoTCPMap[key].(json.Number)
		if !ok {
			return icmp, fmt.Errorf("ProtoTCP: error in argument %v", argName)
		}

		val64, err := val.Int64()
		if err != nil {
			return icmp, err
		}

		uint32Types[key] = uint32(val64)
	}

	return trace.ProtoTCP{
		SrcPort:    uint16Types["srcPort"],
		DstPort:    uint16Types["dstPort"],
		Seq:        uint32Types["seq"],
		Ack:        uint32Types["ack"],
		DataOffset: uint8Types["dataOffset"],
		FIN:        uint8Types["FIN"],
		SYN:        uint8Types["SYN"],
		RST:        uint8Types["RST"],
		PSH:        uint8Types["PSH"],
		ACK:        uint8Types["ACK"],
		URG:        uint8Types["URG"],
		ECE:        uint8Types["ECE"],
		CWR:        uint8Types["CWR"],
		NS:         uint8Types["NS"],
		Window:     uint16Types["window"],
		Checksum:   uint16Types["checksum"],
		Urgent:     uint16Types["urgent"],
	}, nil
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

	var icmp trace.ProtoICMP

	arg, err := GetTraceeArgumentByName(event, argName)
	if err != nil {
		return trace.ProtoICMP{}, err
	}

	argProtoICMP, ok := arg.Value.(trace.ProtoICMP)
	if ok {
		return argProtoICMP, nil
	}

	argProtoICMPMap, ok := arg.Value.(map[string]interface{})
	if !ok {
		return trace.ProtoICMP{}, fmt.Errorf("ProtoICMP: wrong types received")
	}

	uint16Types := map[string]uint16{"checksum": 0, "id": 0, "seq": 0}

	for key := range uint16Types {
		val, ok := argProtoICMPMap[key].(json.Number)
		if !ok {
			return icmp, fmt.Errorf("ProtoICMP: error in argument %v", argName)
		}

		val64, err := val.Int64()
		if err != nil {
			return icmp, err
		}

		uint16Types[key] = uint16(val64)
	}

	typeCode, ok := argProtoICMPMap["typeCode"].(string)
	if !ok {
		return icmp, fmt.Errorf("ProtoICMP: error in argument %v", argName)
	}

	return trace.ProtoICMP{
		TypeCode: typeCode,
		Checksum: uint16Types["checksum"],
		Id:       uint16Types["id"],
		Seq:      uint16Types["seq"],
	}, nil
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

	var icmpv6 trace.ProtoICMPv6

	arg, err := GetTraceeArgumentByName(event, argName)
	if err != nil {
		return trace.ProtoICMPv6{}, err
	}

	argProtoICMPv6, ok := arg.Value.(trace.ProtoICMPv6)
	if ok {
		return argProtoICMPv6, nil
	}

	argProtoICMPv6Map, ok := arg.Value.(map[string]interface{})
	if !ok {
		return trace.ProtoICMPv6{}, fmt.Errorf("ProtoICMPv6: wrong types received")
	}

	uint16Types := map[string]uint16{"checksum": 0}

	for key := range uint16Types {
		val, ok := argProtoICMPv6Map[key].(json.Number)
		if !ok {
			return icmpv6, fmt.Errorf("ProtoICMPv6: error in argument %v", argName)
		}

		val64, err := val.Int64()
		if err != nil {
			return icmpv6, err
		}

		uint16Types[key] = uint16(val64)
	}

	typeCode, ok := argProtoICMPv6Map["typeCode"].(string)
	if !ok {
		return icmpv6, fmt.Errorf("ProtoICMPv6: error in argument %v", argName)
	}

	return trace.ProtoICMPv6{
		TypeCode: typeCode,
		Checksum: uint16Types["checksum"],
	}, nil
}
