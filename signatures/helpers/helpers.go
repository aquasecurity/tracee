package helpers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
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

	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return trace.ProtoIPv4{}, err
	}

	argProtoIPv4, ok := arg.Value.(trace.ProtoIPv4)
	if ok {
		return argProtoIPv4, nil
	}

	argProtoIPv4Map, ok := arg.Value.(map[string]interface{})
	if !ok {
		return trace.ProtoIPv4{}, fmt.Errorf("protocol IPv4: wrong types received")
	}

	uint8Types := map[string]uint8{"version": 0, "IHL": 0, "TOS": 0, "flags": 0, "TTL": 0}

	for key := range uint8Types {
		val, ok := argProtoIPv4Map[key].(json.Number)
		if !ok {
			return ipv4, fmt.Errorf("protocol IPv4: error in argument %v", argName)
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
			return ipv4, fmt.Errorf("protocol IPv4: error in argument %v", argName)
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
			return ipv4, fmt.Errorf("protocol IPv4: error in argument %v", argName)
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

	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return trace.ProtoIPv6{}, err
	}

	argProtoIPv6, ok := arg.Value.(trace.ProtoIPv6)
	if ok {
		return argProtoIPv6, nil
	}

	argProtoIPv6Map, ok := arg.Value.(map[string]interface{})
	if !ok {
		return trace.ProtoIPv6{}, fmt.Errorf("protocol IPv6: wrong types received")
	}

	uint8Types := map[string]uint8{"version": 0, "trafficClass": 0, "hopLimit": 0}

	for key := range uint8Types {
		val, ok := argProtoIPv6Map[key].(json.Number)
		if !ok {
			return ipv4, fmt.Errorf("protocol IPv6: error in argument %v", argName)
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
			return ipv4, fmt.Errorf("protocol IPv6: error in argument %v", argName)
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
			return ipv4, fmt.Errorf("protocol IPv6: error in argument %v", argName)
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
			return ipv4, fmt.Errorf("protocol IPv6: error in argument %v", argName)
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

	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return trace.ProtoUDP{}, err
	}

	argProtoUDP, ok := arg.Value.(trace.ProtoUDP)
	if ok {
		return argProtoUDP, nil
	}

	argProtoUDPMap, ok := arg.Value.(map[string]interface{})
	if !ok {
		return trace.ProtoUDP{}, fmt.Errorf("protocol UDP: wrong types received")
	}

	uint16Types := map[string]uint16{"srcPort": 0, "dstPort": 0, "length": 0, "checksum": 0}

	for key := range uint16Types {
		val, ok := argProtoUDPMap[key].(json.Number)
		if !ok {
			return icmp, fmt.Errorf("protocol UDP: error in argument %v", argName)
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

	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return trace.ProtoTCP{}, err
	}

	argProtoTCP, ok := arg.Value.(trace.ProtoTCP)
	if ok {
		return argProtoTCP, nil
	}

	argProtoTCPMap, ok := arg.Value.(map[string]interface{})
	if !ok {
		return trace.ProtoTCP{}, fmt.Errorf("protocol TCP: wrong types received")
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
			return icmp, fmt.Errorf("protocol TCP: error in argument %v", argName)
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
			return icmp, fmt.Errorf("protocol TCP: error in argument %v", argName)
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
			return icmp, fmt.Errorf("protocol TCP: error in argument %v", argName)
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

	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return trace.ProtoICMP{}, err
	}

	argProtoICMP, ok := arg.Value.(trace.ProtoICMP)
	if ok {
		return argProtoICMP, nil
	}

	argProtoICMPMap, ok := arg.Value.(map[string]interface{})
	if !ok {
		return trace.ProtoICMP{}, fmt.Errorf("protocol ICMP: wrong types received")
	}

	uint16Types := map[string]uint16{"checksum": 0, "id": 0, "seq": 0}

	for key := range uint16Types {
		val, ok := argProtoICMPMap[key].(json.Number)
		if !ok {
			return icmp, fmt.Errorf("protocol ICMP: error in argument %v", argName)
		}

		val64, err := val.Int64()
		if err != nil {
			return icmp, err
		}

		uint16Types[key] = uint16(val64)
	}

	typeCode, ok := argProtoICMPMap["typeCode"].(string)
	if !ok {
		return icmp, fmt.Errorf("protocol ICMP: error in argument %v", argName)
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

	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return trace.ProtoICMPv6{}, err
	}

	argProtoICMPv6, ok := arg.Value.(trace.ProtoICMPv6)
	if ok {
		return argProtoICMPv6, nil
	}

	argProtoICMPv6Map, ok := arg.Value.(map[string]interface{})
	if !ok {
		return trace.ProtoICMPv6{}, fmt.Errorf("protocol ICMPv6: wrong types received")
	}

	uint16Types := map[string]uint16{"checksum": 0}

	for key := range uint16Types {
		val, ok := argProtoICMPv6Map[key].(json.Number)
		if !ok {
			return icmpv6, fmt.Errorf("protocol ICMPv6: error in argument %v", argName)
		}

		val64, err := val.Int64()
		if err != nil {
			return icmpv6, err
		}

		uint16Types[key] = uint16(val64)
	}

	typeCode, ok := argProtoICMPv6Map["typeCode"].(string)
	if !ok {
		return icmpv6, fmt.Errorf("protocol ICMPv6: error in argument %v", argName)
	}

	return trace.ProtoICMPv6{
		TypeCode: typeCode,
		Checksum: uint16Types["checksum"],
	}, nil
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
	//
	var dns trace.ProtoDNS

	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return trace.ProtoDNS{}, err
	}

	// if type is already correct, return right away
	argProtoDNS, ok := arg.Value.(trace.ProtoDNS)
	if ok {
		return argProtoDNS, nil
	}

	// if type comes from json, deal with it
	argProtoDNSMap, ok := arg.Value.(map[string]interface{})
	if !ok {
		return trace.ProtoDNS{}, fmt.Errorf("protocol DNS: type error")
	}

	// uint8 conversion
	uint8Types := map[string]uint8{
		"QR": 0,
		"AA": 0,
		"TC": 0,
		"RD": 0,
		"RA": 0,
		"Z":  0,
	}
	for key := range uint8Types {
		val, ok := argProtoDNSMap[key].(json.Number)
		if !ok {
			return dns, fmt.Errorf("protocol DNS: type error for key %v", key)
		}
		val64, err := val.Int64()
		if err != nil {
			return dns, fmt.Errorf("protocol DNS: error in key %v: %v", key, err)
		}
		uint8Types[key] = uint8(val64)
	}

	// uint16 conversion
	uint16Types := map[string]uint16{
		"ID":      0,
		"QDCount": 0,
		"ANCount": 0,
		"NSCount": 0,
		"ARCount": 0,
	}
	for key := range uint16Types {
		val, ok := argProtoDNSMap[key].(json.Number)
		if !ok {
			return dns, fmt.Errorf("protocol DNS: type error for key %v", key)
		}
		val64, err := val.Int64()
		if err != nil {
			return dns, fmt.Errorf("protocol DNS: error in key %v: %v", key, err)
		}
		uint16Types[key] = uint16(val64)
	}

	// string conversion
	stringTypes := map[string]string{
		"opCode":       "",
		"responseCode": "",
	}
	for key := range stringTypes {
		val, ok := argProtoDNSMap[key].(string)
		if !ok {
			return dns, fmt.Errorf("protocol DNS: type error for key %v", key)
		}
		stringTypes[key] = val
	}

	// questions conversion
	qu, ok := argProtoDNSMap["questions"].([]interface{})
	if !ok {
		return dns, fmt.Errorf("protocol DNS: type error for key %v", "questions")
	}
	dnsQuestions, err := GetProtoDNSQuestion(qu)
	if err != nil {
		return dns, err
	}

	// answers conversion
	an, ok := argProtoDNSMap["answers"].([]interface{})
	if !ok {
		return dns, fmt.Errorf("protocol DNS: type error for key %v", "answers")
	}
	dnsAnswers, err := GetProtoDNSResourceRecord(an)
	if err != nil {
		return dns, err
	}

	// authorities conversion
	au, ok := argProtoDNSMap["authorities"].([]interface{})
	if !ok {
		return dns, fmt.Errorf("protocol DNS: type error for key %v", "authorities")
	}
	dnsAuthorities, err := GetProtoDNSResourceRecord(au)
	if err != nil {
		return dns, err
	}

	// additionals conversion
	ad, ok := argProtoDNSMap["additionals"].([]interface{})
	if !ok {
		return dns, fmt.Errorf("protocol DNS: type error for key %v", "additionals")
	}
	dnsAdditionals, err := GetProtoDNSResourceRecord(ad)
	if err != nil {
		return dns, err
	}

	return trace.ProtoDNS{
		ID:           uint16Types["ID"],
		QR:           uint8Types["QR"],
		OpCode:       stringTypes["opCode"],
		AA:           uint8Types["AA"],
		TC:           uint8Types["TC"],
		RD:           uint8Types["RD"],
		RA:           uint8Types["RA"],
		Z:            uint8Types["Z"],
		ResponseCode: stringTypes["responseCode"],
		QDCount:      uint16Types["QDCount"],
		ANCount:      uint16Types["ANCount"],
		NSCount:      uint16Types["NSCount"],
		ARCount:      uint16Types["ARCount"],
		Questions:    dnsQuestions,
		Answers:      dnsAnswers,
		Authorities:  dnsAuthorities,
		Additionals:  dnsAdditionals,
	}, nil
}

// GetProtoDNSQuestion converts json to ProtoDNSQuestion
func GetProtoDNSQuestion(
	arg []interface{},
) (
	[]trace.ProtoDNSQuestion,
	error,
) {
	//
	// Current ProtoDNSQuestion type considered:
	//
	// type ProtoDNSQuestion struct {
	// 	Name  string `json:"name"`
	// 	Type  string `json:"type"`
	// 	Class string `json:"class"`
	// }
	var dnsQuestions []trace.ProtoDNSQuestion

	for _, value := range arg {
		val, ok := value.(map[string]interface{})
		if !ok {
			return dnsQuestions, fmt.Errorf("protocol DNSQuestion: type error")
		}

		// string conversion
		stringTypes := map[string]string{
			"name":  "",
			"type":  "",
			"class": "",
		}
		for key := range stringTypes {
			v, ok := val[key].(string)
			if !ok {
				return dnsQuestions, fmt.Errorf("protocol DNS: type error for key %v", key)
			}
			stringTypes[key] = v
		}

		dnsQuestions = append(dnsQuestions,
			trace.ProtoDNSQuestion{
				Name:  stringTypes["name"],
				Type:  stringTypes["type"],
				Class: stringTypes["class"],
			})
	}

	return dnsQuestions, nil
}

// GetProtoDNSResourceRecord converts json to ProtoDNSResourceRecord
func GetProtoDNSResourceRecord(
	arg []interface{},
) (
	[]trace.ProtoDNSResourceRecord,
	error,
) {
	//
	// Current ProtoDNSResourceRecord type considered:
	//
	// type ProtoDNSResourceRecord struct {
	// 	Name  string        `json:"name"`
	// 	Type  string        `json:"type"`
	// 	Class string        `json:"class"`
	// 	TTL   uint32        `json:"TTL"`
	// 	IP    string        `json:"IP"`
	// 	NS    string        `json:"NS"`
	// 	CNAME string        `json:"CNAME"`
	// 	PTR   string        `json:"PTR"`
	// 	TXTs  []string      `json:"TXTs"`
	// 	SOA   ProtoDNSSOA   `json:"SOA"`
	// 	SRV   ProtoDNSSRV   `json:"SRV"`
	// 	MX    ProtoDNSMX    `json:"MX"`
	// 	OPT   []ProtoDNSOPT `json:"OPT"`
	// 	URI   ProtoDNSURI   `json:"URI"`
	// 	TXT   string        `json:"TXT"`
	// }
	var err error
	var dnsResourceRecords []trace.ProtoDNSResourceRecord

	for _, value := range arg {

		val, ok := value.(map[string]interface{})
		if !ok {
			return dnsResourceRecords, fmt.Errorf("protocol DNSResourceRecord: type error")
		}

		// string conversion
		stringTypes := map[string]string{
			"name":  "",
			"type":  "",
			"class": "",
			"IP":    "",
			"NS":    "",
			"CNAME": "",
			"PTR":   "",
			"TXT":   "",
		}
		for key := range stringTypes {
			v, ok := val[key].(string)
			if !ok {
				return dnsResourceRecords, fmt.Errorf("protocol DNS: type error for key %v", key)
			}
			stringTypes[key] = v
		}

		// uint32 conversion
		uint32Types := map[string]uint32{
			"TTL": 0,
		}
		for key := range uint32Types {
			val, ok := val[key].(json.Number)
			if !ok {
				return dnsResourceRecords, fmt.Errorf("protocol DNS: type error for key %v", key)
			}
			val64, err := val.Int64()
			if err != nil {
				return dnsResourceRecords, fmt.Errorf("protocol DNS: error in key %v: %v", key, err)
			}
			uint32Types[key] = uint32(val64)
		}

		var soa trace.ProtoDNSSOA
		var srv trace.ProtoDNSSRV
		var mx trace.ProtoDNSMX
		var uri trace.ProtoDNSURI
		var opt []trace.ProtoDNSOPT
		var txts []string

		for k, v := range val {
			if v == nil {
				continue
			}

			switch v := v.(type) {
			case string, json.Number:
				continue
			case map[string]interface{}:
				switch k {
				case "SOA":
					soa, err = GetProtoDNSSOA(v)
					if err != nil {
						return dnsResourceRecords, fmt.Errorf("protocol DNSResourceRecord: SOA error: %v", err)
					}
				case "SRV":
					srv, err = GetProtoDNSSRV(v)
					if err != nil {
						return dnsResourceRecords, fmt.Errorf("protocol DNSResourceRecord: SRV error: %v", err)
					}
				case "MX":
					mx, err = GetProtoDNSMX(v)
					if err != nil {
						return dnsResourceRecords, fmt.Errorf("protocol DNSResourceRecord: MX error: %v", err)
					}
				case "URI":
					uri, err = GetProtoDNSURI(v)
					if err != nil {
						return dnsResourceRecords, fmt.Errorf("protocol DNSResourceRecord: URI error: %v", err)
					}
				}
			case []interface{}:
				switch k {
				case "TXTs":
					txts, err = GetProtoDNSTXTs(v)
					if err != nil {
						return dnsResourceRecords, fmt.Errorf("protocol DNSResourceRecord: TXTs error: %v", err)
					}
				case "OPT":
					opt, err = GetProtoDNSOPT(v)
					if err != nil {
						return dnsResourceRecords, fmt.Errorf("protocol DNSResourceRecord: OPT error: %v", err)
					}
				}
			default:
				return dnsResourceRecords, fmt.Errorf("protocol DNSResourceRecord: error in key %v, type %v not implemented", k, reflect.TypeOf(v))
			}
		}

		dnsResourceRecords = append(dnsResourceRecords,
			trace.ProtoDNSResourceRecord{
				Name:  stringTypes["name"],
				Type:  stringTypes["type"],
				Class: stringTypes["class"],
				TTL:   uint32Types["TTL"],
				IP:    stringTypes["IP"],
				NS:    stringTypes["NS"],
				CNAME: stringTypes["CNAME"],
				PTR:   stringTypes["PTR"],
				TXTs:  txts,
				SOA:   soa,
				SRV:   srv,
				MX:    mx,
				OPT:   opt,
				URI:   uri,
				TXT:   stringTypes["TXT"],
			})
	}

	return dnsResourceRecords, nil
}

// GetProtoDNSSOA converts json to ProtoDNSSOA
func GetProtoDNSSOA(
	arg map[string]interface{},
) (
	trace.ProtoDNSSOA,
	error,
) {
	//
	// Current ProtoDNSSOA type considered:
	//
	// type ProtoDNSSOA struct {
	// 	MName   string `json:"MName"`
	// 	RName   string `json:"RName"`
	// 	Serial  uint32 `json:"serial"`
	// 	Refresh uint32 `json:"refresh"`
	// 	Retry   uint32 `json:"retry"`
	// 	Expire  uint32 `json:"expire"`
	// 	Minimum uint32 `json:"minimum"`
	// }
	var dnsSOA trace.ProtoDNSSOA

	// string conversion
	stringTypes := map[string]string{
		"MName": "",
		"RName": "",
	}
	for key := range stringTypes {
		val, ok := arg[key].(string)
		if !ok {
			return dnsSOA, fmt.Errorf("protocol DNSSOA: type error for key %v", key)
		}
		stringTypes[key] = val
	}

	// uint32 conversion
	uint32Types := map[string]uint32{
		"serial":  0,
		"refresh": 0,
		"retry":   0,
		"expire":  0,
		"minimum": 0,
	}
	for key := range uint32Types {
		val, ok := arg[key].(json.Number)
		if !ok {
			return dnsSOA, fmt.Errorf("protocol DNSSOA: type error for key %v", key)
		}
		val64, err := val.Int64()
		if err != nil {
			return dnsSOA, fmt.Errorf("protocol DNSNSOA: error in key %v: %v", key, err)
		}
		uint32Types[key] = uint32(val64)
	}

	return trace.ProtoDNSSOA{
		MName:   stringTypes["MName"],
		RName:   stringTypes["RName"],
		Serial:  uint32Types["serial"],
		Refresh: uint32Types["refresh"],
		Retry:   uint32Types["retry"],
		Expire:  uint32Types["expire"],
		Minimum: uint32Types["minimum"],
	}, nil
}

// GetProtoDNSSRV converts json to ProtoDNSSRV
func GetProtoDNSSRV(
	arg map[string]interface{},
) (
	trace.ProtoDNSSRV,
	error,
) {
	//
	// Current ProtoDNSSRV type considered:
	//
	// type ProtoDNSSRV struct {
	// 	Priority uint16 `json:"priority"`
	// 	Weight   uint16 `json:"weight"`
	// 	Port     uint16 `json:"port"`
	// 	Name     string `json:"name"`
	// }
	var dnsSRV trace.ProtoDNSSRV

	// string conversion
	stringTypes := map[string]string{
		"name": "",
	}
	for key := range stringTypes {
		val, ok := arg[key].(string)
		if !ok {
			return dnsSRV, fmt.Errorf("protocol DNSSRV: type error for key %v", key)
		}
		stringTypes[key] = val
	}

	// uint16 conversion
	uint16Types := map[string]uint16{
		"priority": 0,
		"weight":   0,
		"port":     0,
	}
	for key := range uint16Types {
		val, ok := arg[key].(json.Number)
		if !ok {
			return dnsSRV, fmt.Errorf("protocol DNSSRV: type error for key %v", key)
		}
		val64, err := val.Int64()
		if err != nil {
			return dnsSRV, fmt.Errorf("protocol DNSNSRV: error in key %v: %v", key, err)
		}
		uint16Types[key] = uint16(val64)
	}

	return trace.ProtoDNSSRV{
		Priority: uint16Types["priority"],
		Weight:   uint16Types["weight"],
		Port:     uint16Types["port"],
		Name:     stringTypes["name"],
	}, nil
}

// GetProtoDNSMX converts json to ProtoDNSMX
func GetProtoDNSMX(
	arg map[string]interface{},
) (
	trace.ProtoDNSMX,
	error,
) {
	//
	// Current ProtoDNSMX type considered:
	//
	// type ProtoDNSMX struct {
	// 	Preference uint16 `json:"preference"`
	// 	Name       string `json:"name"`
	// }
	var dnsMX trace.ProtoDNSMX

	// string conversion
	stringTypes := map[string]string{
		"name": "",
	}
	for key := range stringTypes {
		val, ok := arg[key].(string)
		if !ok {
			return dnsMX, fmt.Errorf("protocol DNSMX: type error for key %v", key)
		}
		stringTypes[key] = val
	}

	// uint16 conversion
	uint16Types := map[string]uint16{
		"preference": 0,
	}

	for key := range uint16Types {
		val, ok := arg[key].(json.Number)
		if !ok {
			return dnsMX, fmt.Errorf("protocol DNSMX: type error for key %v", key)
		}
		val64, err := val.Int64()
		if err != nil {
			return dnsMX, fmt.Errorf("protocol DNSNMX: error in key %v: %v", key, err)
		}
		uint16Types[key] = uint16(val64)
	}

	return trace.ProtoDNSMX{
		Preference: uint16Types["preference"],
		Name:       stringTypes["name"],
	}, nil
}

// GetProtoDNSURI converts json to ProtoDNSURI
func GetProtoDNSURI(
	arg map[string]interface{},
) (
	trace.ProtoDNSURI,
	error,
) {
	//
	// Current ProtoDNSURI type considered:
	//
	// type ProtoDNSURI struct {
	// 	Priority uint16 `json:"priority"`
	// 	Weight   uint16 `json:"weight"`
	// 	Target   string `json:"target"`
	// }
	var dnsURI trace.ProtoDNSURI

	// string conversion
	stringTypes := map[string]string{
		"target": "",
	}
	for key := range stringTypes {
		val, ok := arg[key].(string)
		if !ok {
			return dnsURI, fmt.Errorf("protocol DNSURI: type error for key %v", key)
		}
		stringTypes[key] = val
	}

	// uint16 conversion
	uint16Types := map[string]uint16{
		"priority": 0,
		"weight":   0,
	}
	for key := range uint16Types {
		val, ok := arg[key].(json.Number)
		if !ok {
			return dnsURI, fmt.Errorf("protocol DNSURI: type error for key %v", key)
		}
		val64, err := val.Int64()
		if err != nil {
			return dnsURI, fmt.Errorf("protocol DNSURI: error in key %v: %v", key, err)
		}
		uint16Types[key] = uint16(val64)
	}

	return trace.ProtoDNSURI{
		Priority: uint16Types["priority"],
		Weight:   uint16Types["weight"],
		Target:   stringTypes["target"],
	}, nil
}

func GetProtoDNSTXTs(
	arg []interface{},
) (
	[]string,
	error,
) {
	var DNSTXTs []string

	for _, v := range arg {
		val, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("protocol DNSTXTs: type error")
		}
		DNSTXTs = append(DNSTXTs, val)
	}

	return DNSTXTs, nil
}

// GetProtoDNSOPT converts json to ProtoDNSOPT
func GetProtoDNSOPT(
	arg []interface{},
) (
	[]trace.ProtoDNSOPT,
	error,
) {
	//
	// Current ProtoDNSOPT type considered:
	//
	// type ProtoDNSOPT struct {
	// 	Code string `json:"code"`
	// 	Data string `json:"data"`
	// }
	var dnsOPTs []trace.ProtoDNSOPT

	// TODO: implement DNSOPT (DNS protocol extension by RFC 6891)
	// NOTE: couldn't find a domain example to query OPT from

	return dnsOPTs, nil
}

func GetProtoHTTPByName(
	event trace.Event,
	argName string,
) (
	trace.ProtoHTTP, error,
) {
	var httpProto trace.ProtoHTTP

	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return trace.ProtoHTTP{}, err
	}

	// if type is already correct, return right away
	argProtoHTTP, ok := arg.Value.(trace.ProtoHTTP)
	if ok {
		return argProtoHTTP, nil
	}

	// if type comes from json, deal with it
	argProtoHTTPMap, ok := arg.Value.(map[string]interface{})
	if !ok {
		return trace.ProtoHTTP{}, fmt.Errorf("protocol HTTP: type error")
	}

	// string conversion
	stringTypes := map[string]string{
		"direction": "",
		"method":    "",
		"protocol":  "",
		"host":      "",
		"uri_path":  "",
		"status":    "",
	}
	for key := range stringTypes {
		val, ok := argProtoHTTPMap[key]
		if !ok {
			return httpProto, fmt.Errorf("protocol HTTP: type error for key %v", key)
		}
		stringTypes[key] = val.(string)
	}

	// int conversion
	intTypes := map[string]int{
		"status_code": 0,
	}
	for key := range intTypes {
		val, ok := argProtoHTTPMap[key]
		if !ok {
			return httpProto, fmt.Errorf("protocol HTTP: type error for key %v", key)
		}
		int64Val, err := val.(json.Number).Int64()
		if err != nil {
			return httpProto, fmt.Errorf("protocol HTTP: type error for key %v: %s", key, err)
		}
		intTypes[key] = int(int64Val)
	}

	// int64 conversion
	int64Types := map[string]int64{
		"content_length": 0,
	}
	for key := range int64Types {
		val, ok := argProtoHTTPMap[key]
		if !ok {
			return httpProto, fmt.Errorf("protocol HTTP: type error for key %v", key)
		}
		int64Val, err := val.(json.Number).Int64()
		if err != nil {
			return httpProto, fmt.Errorf("protocol HTTP: type error for key %v: %s", key, err)
		}
		int64Types[key] = int64Val
	}

	// headers conversion
	headersVal, ok := argProtoHTTPMap["headers"]
	if !ok {
		return httpProto, fmt.Errorf("protocol HTTP: type error for key %v", "headers")
	}
	headers := make(http.Header)
	for headerKey, headerValInterface := range headersVal.(map[string]interface{}) {
		var headerVals []string
		for _, headerValInterfaceElem := range headerValInterface.([]interface{}) {
			headerVals = append(headerVals, headerValInterfaceElem.(string))
		}
		headers[headerKey] = headerVals
	}

	return trace.ProtoHTTP{
		Direction:     stringTypes["direction"],
		Method:        stringTypes["method"],
		Protocol:      stringTypes["protocol"],
		Host:          stringTypes["host"],
		URIPath:       stringTypes["uri_path"],
		Status:        stringTypes["status"],
		StatusCode:    intTypes["status_code"],
		Headers:       headers,
		ContentLength: int64Types["content_length"],
	}, nil
}
