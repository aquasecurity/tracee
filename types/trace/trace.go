// Package trace defines the public types exported through the EBPF code and produced outwards from tracee-ebpf
package trace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/types/protocol"
)

// Event is a single result of an ebpf event process. It is used as a payload later delivered to tracee-rules.
type Event struct {
	Timestamp             int          `json:"timestamp"`
	ThreadStartTime       int          `json:"threadStartTime"`
	ProcessorID           int          `json:"processorId"`
	ProcessID             int          `json:"processId"`
	CgroupID              uint         `json:"cgroupId"`
	ThreadID              int          `json:"threadId"`
	ParentProcessID       int          `json:"parentProcessId"`
	HostProcessID         int          `json:"hostProcessId"`
	HostThreadID          int          `json:"hostThreadId"`
	HostParentProcessID   int          `json:"hostParentProcessId"`
	UserID                int          `json:"userId"`
	MountNS               int          `json:"mountNamespace"`
	PIDNS                 int          `json:"pidNamespace"`
	ProcessName           string       `json:"processName"`
	Executable            File         `json:"executable"`
	HostName              string       `json:"hostName"`
	ContainerID           string       `json:"containerId"`
	Container             Container    `json:"container,omitempty"`
	Kubernetes            Kubernetes   `json:"kubernetes,omitempty"`
	EventID               int          `json:"eventId,string"`
	EventName             string       `json:"eventName"`
	PoliciesVersion       uint16       `json:"-"`
	MatchedPoliciesKernel uint64       `json:"-"`
	MatchedPoliciesUser   uint64       `json:"-"`
	MatchedPolicies       []string     `json:"matchedPolicies,omitempty"`
	ArgsNum               int          `json:"argsNum"`
	ReturnValue           int          `json:"returnValue"`
	Syscall               string       `json:"syscall"`
	StackAddresses        []uint64     `json:"stackAddresses"`
	ContextFlags          ContextFlags `json:"contextFlags"`
	ThreadEntityId        uint32       `json:"threadEntityId"`  // thread task unique identifier (*)
	ProcessEntityId       uint32       `json:"processEntityId"` // process unique identifier (*)
	ParentEntityId        uint32       `json:"parentEntityId"`  // parent process unique identifier (*)
	Args                  []Argument   `json:"args"`            // args are ordered according their appearance in the original event
	Metadata              *Metadata    `json:"metadata,omitempty"`
}

// (*) For an OS task to be uniquely identified, tracee builds a hash consisting of:
//
// u64: task start time (from event context)
// u32: task thread id (from event context)
//
// murmur([]byte) where slice of bytes is a concatenation (not a sum) of the 2 values above.

type Container struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	ImageName   string `json:"image,omitempty"`
	ImageDigest string `json:"imageDigest,omitempty"`
}

type Kubernetes struct {
	PodName      string `json:"podName,omitempty"`
	PodNamespace string `json:"podNamespace,omitempty"`
	PodUID       string `json:"podUID,omitempty"`
	PodSandbox   bool   `json:"podSandbox,omitempty"`
}

// Metadata is a struct that holds metadata about an event
type Metadata struct {
	Version     string
	Description string
	Tags        []string
	Properties  map[string]interface{}
}

// ContextFlags are flags representing event context
type ContextFlags struct {
	ContainerStarted bool `json:"containerStarted"`
	IsCompat         bool `json:"isCompat"`
}

type File struct {
	Path string `json:"path"`
}

// EventOrigin is where a trace.Event occured, it can either be from the host machine or from a container
type EventOrigin string

const (
	ContainerOrigin     EventOrigin = "container"      // Events originated from within a container, starting with the entry-point execution
	HostOrigin          EventOrigin = "host"           // Events originated from the host
	ContainerInitOrigin EventOrigin = "container-init" // Events originated from within container, before entry-point execution
)

// Origin derive the EventOrigin of a trace.Event
func (e Event) Origin() EventOrigin {
	if e.ContextFlags.ContainerStarted {
		return ContainerOrigin
	}
	if e.Container.ID != "" {
		return ContainerInitOrigin
	}
	return HostOrigin
}

const (
	EventSource = "tracee"
)

// Converts a trace.Event into a protocol.Event that the rules engine can consume
func (e Event) ToProtocol() protocol.Event {
	return protocol.Event{
		Headers: protocol.EventHeaders{
			Selector: protocol.Selector{
				Name:   e.EventName,
				Origin: string(e.Origin()),
				Source: "tracee",
			},
		},
		Payload: e,
	}
}

// Argument holds the information for one argument
type Argument struct {
	ArgMeta
	Value interface{} `json:"value"`
}

// ArgMeta describes an argument
type ArgMeta struct {
	Name string `json:"name"`
	Type string `json:"type"`

	// Zero contains the zero value for Argument.Value.
	// It is automatically initialized based on ArgMeta.Type when the Core DefinitionGroup is initialized.
	Zero interface{} `json:"-"`
}

// UnmarshalJSON implements the json.Unmarshaler interface.
// All the values in this function should be supported in finding.go in the `getCType` function and vice versa.
func (arg *Argument) UnmarshalJSON(b []byte) error {
	type argument Argument // alias Argument so we can unmarshal it within the unmarshaler implementation
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode((*argument)(arg)); err != nil {
		return err
	}
	if arg.Value == nil {
		return nil
	}
	if num, isNum := arg.Value.(json.Number); isNum {
		if strings.HasSuffix(arg.Type, "*") {
			tmp, err := strconv.ParseUint(num.String(), 10, 64)
			if err != nil {
				return err
			}
			arg.Value = uint64(tmp)
			return nil
		}
		switch arg.Type {
		case "int", "pid_t", "uid_t", "gid_t", "mqd_t", "clockid_t", "const clockid_t", "key_t", "key_serial_t", "timer_t", "landlock_rule_type":
			tmp, err := strconv.ParseInt(num.String(), 10, 32)
			if err != nil {
				return err
			}
			arg.Value = int32(tmp)
		case "long":
			tmp, err := num.Int64()
			if err != nil {
				return err
			}
			arg.Value = tmp
		case "unsigned int", "u32", "mode_t", "dev_t":
			tmp, err := strconv.ParseUint(num.String(), 10, 32)
			if err != nil {
				return err
			}
			arg.Value = uint32(tmp)
		case "unsigned long", "u64", "off_t", "size_t":
			tmp, err := strconv.ParseUint(num.String(), 10, 64)
			if err != nil {
				return err
			}
			arg.Value = uint64(tmp)
		case "float":
			tmp, err := strconv.ParseFloat(num.String(), 32)
			if err != nil {
				return err
			}
			arg.Value = float32(tmp)
		case "float64", "double":
			tmp, err := num.Float64()
			if err != nil {
				return err
			}
			arg.Value = tmp
		case "unsigned short", "old_uid_t", "old_gid_t", "umode_t", "u16", "uint16":
			tmp, err := strconv.ParseUint(num.String(), 10, 16)
			if err != nil {
				return err
			}
			arg.Value = uint16(tmp)
		case "int8":
			tmp, err := strconv.ParseInt(num.String(), 10, 8)
			if err != nil {
				return err
			}
			arg.Value = int8(tmp)
		case "u8", "uint8":
			tmp, err := strconv.ParseUint(num.String(), 10, 8)
			if err != nil {
				return err
			}
			arg.Value = uint8(tmp)
		default:
			return fmt.Errorf("unrecognized argument type %s of argument %s", arg.Type, arg.Name)
		}
	}

	var err error

	switch arg.Type {
	case "const char*const*", "const char**":
		if arg.Value != nil {
			argValue, ok := arg.Value.([]interface{})
			if !ok {
				return fmt.Errorf("const char*const*: type error")
			}
			arg.Value = jsonConvertToStringSlice(argValue)
		} else {
			arg.Value = []string{}
		}
	case "trace.ProtoIPv4":
		var argProtoIPv4 ProtoIPv4
		if arg.Value != nil {
			protoIPv4Map, ok := arg.Value.(map[string]interface{})
			if !ok {
				return fmt.Errorf("protocol IPv4: type error")
			}
			argProtoIPv4, err = jsonConvertToProtoIPv4Arg(protoIPv4Map)
			if err != nil {
				return err
			}
		}

		arg.Value = argProtoIPv4
	case "trace.ProtoIPv6":
		var argProtoIPv6 ProtoIPv6
		if arg.Value != nil {
			protoIPv6Map, ok := arg.Value.(map[string]interface{})
			if !ok {
				return fmt.Errorf("protocol IPv6: type error")
			}
			argProtoIPv6, err = jsonConvertToProtoIPv6Arg(protoIPv6Map)
			if err != nil {
				return err
			}
		}

		arg.Value = argProtoIPv6
	case "trace.ProtoTCP":
		var argProtoTCP ProtoTCP
		if arg.Value != nil {
			protoTCPMap, ok := arg.Value.(map[string]interface{})
			if !ok {
				return fmt.Errorf("protocol TCP: type error")
			}
			argProtoTCP, err = jsonConvertToProtoTCPArg(protoTCPMap)
			if err != nil {
				return err
			}
		}

		arg.Value = argProtoTCP
	case "trace.ProtoUDP":
		var argProtoUDP ProtoUDP
		if arg.Value != nil {
			protoUDPMap, ok := arg.Value.(map[string]interface{})
			if !ok {
				return fmt.Errorf("protocol UDP: type error")
			}
			argProtoUDP, err = jsonConvertToProtoUDPArg(protoUDPMap)
			if err != nil {
				return err
			}
		}

		arg.Value = argProtoUDP
	case "trace.ProtoICMP":
		var argProtoICMP ProtoICMP
		if arg.Value != nil {
			protoICMPMap, ok := arg.Value.(map[string]interface{})
			if !ok {
				return fmt.Errorf("protocol ICMP: type error")
			}
			argProtoICMP, err = jsonConvertToProtoICMPArg(protoICMPMap)
			if err != nil {
				return err
			}
		}

		arg.Value = argProtoICMP
	case "trace.ProtoICMPv6":
		var argProtoICMPv6 ProtoICMPv6
		if arg.Value != nil {
			protoICMPv6Map, ok := arg.Value.(map[string]interface{})
			if !ok {
				return fmt.Errorf("protocol ICMPv6: type error")
			}
			argProtoICMPv6, err = jsonConvertToProtoICMPv6Arg(protoICMPv6Map)
			if err != nil {
				return err
			}
		}

		arg.Value = argProtoICMPv6
	case "trace.PktMeta":
		var argPktMeta PktMeta
		if arg.Value != nil {
			argPktMetaMap, ok := arg.Value.(map[string]interface{})
			if !ok {
				return fmt.Errorf("PktMeta: type error")
			}
			argPktMeta, err = jsonConvertToPktMetaArg(argPktMetaMap)
			if err != nil {
				return err
			}
		}

		arg.Value = argPktMeta
	case "trace.ProtoDNS":
		var argProtoDNS ProtoDNS
		if arg.Value != nil {
			argProtoDnsMap, ok := arg.Value.(map[string]interface{})
			if !ok {
				return fmt.Errorf("protocol DNS: type error")
			}
			argProtoDNS, err = jsonConvertToProtoDNSArg(argProtoDnsMap)
			if err != nil {
				return err
			}
		}

		arg.Value = argProtoDNS
	case "[]trace.DnsQueryData":
		var dnsQuries []DnsQueryData
		if arg.Value != nil {
			argDnsQueryDataSlice, ok := arg.Value.([]interface{})
			if !ok {
				return fmt.Errorf("protocol Dns Query Data: type error")
			}

			for _, dnsQueryDataElem := range argDnsQueryDataSlice {
				argDnsQueryDataMap, ok := dnsQueryDataElem.(map[string]interface{})
				if !ok {
					return fmt.Errorf("protocol Dns Query Data: type error")
				}

				dnsQuery, err := jsonConvertToDnsQuertDataType(argDnsQueryDataMap)
				if err != nil {
					return err
				}

				dnsQuries = append(dnsQuries, dnsQuery)
			}
		}

		arg.Value = dnsQuries
	case "[]trace.DnsResponseData":
		var dnsResponses []DnsResponseData
		if arg.Value != nil {
			argDnsResponseDataSlice, ok := arg.Value.([]interface{})
			if !ok {
				return fmt.Errorf("protocol Dns Response Data: type error")
			}

			for _, dnsResponseDataElem := range argDnsResponseDataSlice {
				dnsResponseDataMap, ok := dnsResponseDataElem.(map[string]interface{})
				if !ok {
					return fmt.Errorf("protocol Dns Response Data: type error")
				}

				dnsResponseData, err := jsonConvertToDnsResponseDataType(dnsResponseDataMap)
				if err != nil {
					return err
				}

				dnsResponses = append(dnsResponses, dnsResponseData)
			}
		}

		arg.Value = dnsResponses
	case "trace.ProtoHTTP":
		var argProtoHTTP ProtoHTTP
		if arg.Value != nil {
			argProtoHTTPMap, ok := arg.Value.(map[string]interface{})
			if !ok {
				return fmt.Errorf("protocol HTTP: type error")
			}
			argProtoHTTP, err = jsonConvertToProtoHTTPArg(argProtoHTTPMap)
			if err != nil {
				return err
			}
		}

		arg.Value = argProtoHTTP
	case "trace.ProtoHTTPRequest":
		var argProtoHTTPRequest ProtoHTTPRequest
		if arg.Value != nil {
			argProtoHTTPRequestMap, ok := arg.Value.(map[string]interface{})
			if !ok {
				return fmt.Errorf("protocol HTTP Request: type error")
			}
			argProtoHTTPRequest, err = jsonConvertToProtoHTTPRequestArg(argProtoHTTPRequestMap)
			if err != nil {
				return err
			}
		}

		arg.Value = argProtoHTTPRequest
	case "trace.ProtoHTTPResponse":
		var argProtoHTTPResponse ProtoHTTPResponse
		if arg.Value != nil {
			argProtoHTTPResponseMap, ok := arg.Value.(map[string]interface{})
			if !ok {
				return fmt.Errorf("protocol HTTP Response: type error")
			}
			argProtoHTTPResponse, err = jsonConvertToProtoHTTPResponseArg(argProtoHTTPResponseMap)
			if err != nil {
				return err
			}
		}

		arg.Value = argProtoHTTPResponse
	case "trace.PacketMetadata":
		var argPacketMetadata PacketMetadata
		if arg.Value != nil {
			argPacketMetadataMap, ok := arg.Value.(map[string]interface{})
			if !ok {
				return fmt.Errorf("packet metadata: type error")
			}
			if err != nil {
				return err
			}
			argPacketMetadata, err = jsonConvertToPacketMetadata(argPacketMetadataMap)
			if err != nil {
				return err
			}
		}

		arg.Value = argPacketMetadata
	}

	return nil
}

func jsonConvertToProtoIPv4Arg(argMap map[string]interface{}) (ProtoIPv4, error) {
	// string conversion
	stringTypes := map[string]string{
		"protocol": "",
		"srcIP":    "",
		"dstIP":    "",
	}
	stringTypes, err := jsonConvertToStringTypes(argMap, stringTypes)
	if err != nil {
		return ProtoIPv4{}, err
	}

	// uint8 conversion
	uint8Types := map[string]uint8{
		"version": 0,
		"IHL":     0,
		"TOS":     0,
		"flags":   0,
		"TTL":     0,
	}
	uint8Types, err = jsonConvertToUint8Types(argMap, uint8Types)
	if err != nil {
		return ProtoIPv4{}, err
	}

	// uint16 conversion
	uint16Types := map[string]uint16{
		"length":     0,
		"id":         0,
		"fragOffset": 0,
		"checksum":   0,
	}
	uint16Types, err = jsonConvertToUint16Types(argMap, uint16Types)
	if err != nil {
		return ProtoIPv4{}, err
	}

	return ProtoIPv4{
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

func jsonConvertToProtoIPv6Arg(argMap map[string]interface{}) (ProtoIPv6, error) {
	stringTypes := map[string]string{
		"nextHeader": "",
		"srcIP":      "",
		"dstIP":      "",
	}
	stringTypes, err := jsonConvertToStringTypes(argMap, stringTypes)
	if err != nil {
		return ProtoIPv6{}, err
	}

	// uint8 conversion
	uint8Types := map[string]uint8{
		"version":      0,
		"trafficClass": 0,
		"hopLimit":     0,
	}
	uint8Types, err = jsonConvertToUint8Types(argMap, uint8Types)
	if err != nil {
		return ProtoIPv6{}, err
	}

	// uint16 conversion
	uint16Types := map[string]uint16{
		"length": 0,
	}
	uint16Types, err = jsonConvertToUint16Types(argMap, uint16Types)
	if err != nil {
		return ProtoIPv6{}, err
	}

	// uint32 conversion
	uint32Types := map[string]uint32{
		"flowLabel": 0,
	}
	uint32Types, err = jsonConvertToUint32Types(argMap, uint32Types)
	if err != nil {
		return ProtoIPv6{}, err
	}

	return ProtoIPv6{
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

func jsonConvertToProtoTCPArg(argMap map[string]interface{}) (ProtoTCP, error) {
	// uint8 conversion
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
	uint8Types, err := jsonConvertToUint8Types(argMap, uint8Types)
	if err != nil {
		return ProtoTCP{}, err
	}

	// uint16 conversion
	uint16Types := map[string]uint16{
		"srcPort":  0,
		"dstPort":  0,
		"window":   0,
		"checksum": 0,
		"urgent":   0,
	}
	uint16Types, err = jsonConvertToUint16Types(argMap, uint16Types)
	if err != nil {
		return ProtoTCP{}, err
	}

	// uint32 conversion
	uint32Types := map[string]uint32{
		"seq": 0,
		"ack": 0,
	}
	uint32Types, err = jsonConvertToUint32Types(argMap, uint32Types)
	if err != nil {
		return ProtoTCP{}, err
	}

	return ProtoTCP{
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

func jsonConvertToProtoUDPArg(argMap map[string]interface{}) (ProtoUDP, error) {
	// uint16 conversion
	uint16Types := map[string]uint16{
		"srcPort":  0,
		"dstPort":  0,
		"length":   0,
		"checksum": 0,
	}
	uint16Types, err := jsonConvertToUint16Types(argMap, uint16Types)
	if err != nil {
		return ProtoUDP{}, err
	}

	return ProtoUDP{
		SrcPort:  uint16Types["srcPort"],
		DstPort:  uint16Types["dstPort"],
		Length:   uint16Types["length"],
		Checksum: uint16Types["checksum"],
	}, nil
}

func jsonConvertToProtoICMPArg(argMap map[string]interface{}) (ProtoICMP, error) {
	// string conversion
	stringTypes := map[string]string{
		"typeCode": "",
	}
	stringTypes, err := jsonConvertToStringTypes(argMap, stringTypes)
	if err != nil {
		return ProtoICMP{}, err
	}

	// uint16 conversion
	uint16Types := map[string]uint16{
		"checksum": 0,
		"id":       0,
		"seq":      0,
	}
	uint16Types, err = jsonConvertToUint16Types(argMap, uint16Types)
	if err != nil {
		return ProtoICMP{}, err
	}

	return ProtoICMP{
		TypeCode: stringTypes["typeCode"],
		Checksum: uint16Types["checksum"],
		Id:       uint16Types["id"],
		Seq:      uint16Types["seq"],
	}, nil
}

func jsonConvertToProtoICMPv6Arg(argMap map[string]interface{}) (ProtoICMPv6, error) {
	// string conversion
	stringTypes := map[string]string{
		"typeCode": "",
	}
	stringTypes, err := jsonConvertToStringTypes(argMap, stringTypes)
	if err != nil {
		return ProtoICMPv6{}, err
	}

	// uint16 conversion
	uint16Types := map[string]uint16{
		"checksum": 0,
	}
	uint16Types, err = jsonConvertToUint16Types(argMap, uint16Types)
	if err != nil {
		return ProtoICMPv6{}, err
	}

	return ProtoICMPv6{
		TypeCode: stringTypes["typeCode"],
		Checksum: uint16Types["checksum"],
	}, nil
}

func jsonConvertToProtoDNSArg(argMap map[string]interface{}) (ProtoDNS, error) {
	// uint8 conversion
	uint8Types := map[string]uint8{
		"QR": 0,
		"AA": 0,
		"TC": 0,
		"RD": 0,
		"RA": 0,
		"Z":  0,
	}
	uint8Types, err := jsonConvertToUint8Types(argMap, uint8Types)
	if err != nil {
		return ProtoDNS{}, err
	}

	// uint16 conversion
	uint16Types := map[string]uint16{
		"ID":      0,
		"QDCount": 0,
		"ANCount": 0,
		"NSCount": 0,
		"ARCount": 0,
	}
	uint16Types, err = jsonConvertToUint16Types(argMap, uint16Types)
	if err != nil {
		return ProtoDNS{}, err
	}

	// string conversion
	stringTypes := map[string]string{
		"opCode":       "",
		"responseCode": "",
	}
	stringTypes, err = jsonConvertToStringTypes(argMap, stringTypes)
	if err != nil {
		return ProtoDNS{}, err
	}

	// questions conversion
	questions, exists := argMap["questions"]
	if !exists {
		return ProtoDNS{}, fmt.Errorf("questions not found in ProtoDNS arg")
	}

	var dnsQuestions []ProtoDNSQuestion
	if questions != nil {
		questionsSlice, ok := questions.([]interface{})
		if !ok {
			return ProtoDNS{}, fmt.Errorf("questions from ProtoDNS: type error")
		}

		for _, questionsElem := range questionsSlice {
			questionsElemMap, ok := questionsElem.(map[string]interface{})
			if !ok {
				return ProtoDNS{}, fmt.Errorf("questions from ProtoDNS: type error")
			}

			question, err := jsonConvertToProtoDNSQuestionType(questionsElemMap)
			if err != nil {
				return ProtoDNS{}, err
			}

			dnsQuestions = append(dnsQuestions, question)
		}
	}

	// answers conversion
	answers, exists := argMap["answers"]
	if !exists {
		return ProtoDNS{}, fmt.Errorf("answers not found in ProtoDNS arg")
	}

	var dnsAnswers []ProtoDNSResourceRecord
	if answers != nil {
		answersSlice, ok := answers.([]interface{})
		if !ok {
			return ProtoDNS{}, fmt.Errorf("answers from ProtoDNS: type error")
		}

		for _, answersElem := range answersSlice {
			answersElemMap, ok := answersElem.(map[string]interface{})
			if !ok {
				return ProtoDNS{}, fmt.Errorf("answers from ProtoDNS: type error")
			}

			answer, err := jsonConvertToProtoDNSResourceRecordType(answersElemMap)
			if err != nil {
				return ProtoDNS{}, err
			}

			dnsAnswers = append(dnsAnswers, answer)
		}
	}

	// authorities conversion
	authorities, exists := argMap["authorities"]
	if !exists {
		return ProtoDNS{}, fmt.Errorf("authorities not found in ProtoDNS arg")
	}

	var dnsAuthorities []ProtoDNSResourceRecord
	if authorities != nil {
		authoritiesSlice, ok := authorities.([]interface{})
		if !ok {
			return ProtoDNS{}, fmt.Errorf("authorities from ProtoDNS: type error")
		}

		for _, authoritiesElem := range authoritiesSlice {
			authoritiesElemMap, ok := authoritiesElem.(map[string]interface{})
			if !ok {
				return ProtoDNS{}, fmt.Errorf("authorities from ProtoDNS: type error")
			}

			authority, err := jsonConvertToProtoDNSResourceRecordType(authoritiesElemMap)
			if err != nil {
				return ProtoDNS{}, err
			}

			dnsAuthorities = append(dnsAuthorities, authority)
		}
	}

	// additionals conversion
	additionals, exists := argMap["additionals"]
	if !exists {
		return ProtoDNS{}, fmt.Errorf("additionals not found in ProtoDNS arg")
	}

	var dnsAdditionals []ProtoDNSResourceRecord
	if additionals != nil {
		additionalsSlice, ok := additionals.([]interface{})
		if !ok {
			return ProtoDNS{}, fmt.Errorf("additionals from ProtoDNS: type error")
		}

		for _, additionalsElem := range additionalsSlice {
			additionalsElemMap, ok := additionalsElem.(map[string]interface{})
			if !ok {
				return ProtoDNS{}, fmt.Errorf("additionals from ProtoDNS: type error")
			}

			additional, err := jsonConvertToProtoDNSResourceRecordType(additionalsElemMap)
			if err != nil {
				return ProtoDNS{}, err
			}

			dnsAdditionals = append(dnsAdditionals, additional)
		}
	}

	return ProtoDNS{
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

func jsonConvertToProtoDNSQuestionType(argMap map[string]interface{}) (ProtoDNSQuestion, error) {
	// string conversion
	stringTypes := map[string]string{
		"name":  "",
		"type":  "",
		"class": "",
	}
	stringTypes, err := jsonConvertToStringTypes(argMap, stringTypes)
	if err != nil {
		return ProtoDNSQuestion{}, err
	}

	return ProtoDNSQuestion{
		Name:  stringTypes["name"],
		Type:  stringTypes["type"],
		Class: stringTypes["class"],
	}, nil
}

func jsonConvertToProtoDNSResourceRecordType(argMap map[string]interface{}) (ProtoDNSResourceRecord, error) {
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
	stringTypes, err := jsonConvertToStringTypes(argMap, stringTypes)
	if err != nil {
		return ProtoDNSResourceRecord{}, err
	}

	// uint32 conversion
	uint32Types := map[string]uint32{
		"TTL": 0,
	}
	uint32Types, err = jsonConvertToUint32Types(argMap, uint32Types)
	if err != nil {
		return ProtoDNSResourceRecord{}, err
	}

	// []string conversion
	txts, exists := argMap["TXTs"]
	if !exists {
		return ProtoDNSResourceRecord{}, fmt.Errorf("TXTs not found in ProtoDNSResourceRecord arg")
	}

	var txtsValue []string
	if txts != nil {
		txtsInterfaceSlice, ok := txts.([]interface{})
		if !ok {
			return ProtoDNSResourceRecord{}, fmt.Errorf("TXTs from ProtoDNSResourceRecord: type error")
		}

		txtsValue = jsonConvertToStringSlice(txtsInterfaceSlice)
		if err != nil {
			return ProtoDNSResourceRecord{}, err
		}
	}

	// SOA conversion
	soa, exists := argMap["SOA"]
	if !exists {
		return ProtoDNSResourceRecord{}, fmt.Errorf("SOA not found in ProtoDNSResourceRecord arg")
	}

	var protoDNSSOA ProtoDNSSOA
	if soa != nil {
		soaMap, ok := soa.(map[string]interface{})
		if !ok {
			return ProtoDNSResourceRecord{}, fmt.Errorf("SOA from ProtoDNSResourceRecord: type error")
		}

		protoDNSSOA, err = jsonConvertToProtoDNSSOAType(soaMap)
		if err != nil {
			return ProtoDNSResourceRecord{}, err
		}
	}

	// SRV conversion
	srv, exists := argMap["SRV"]
	if !exists {
		return ProtoDNSResourceRecord{}, fmt.Errorf("SRV not found in ProtoDNSResourceRecord arg")
	}

	var protoDNSSRV ProtoDNSSRV
	if srv != nil {
		srvMap, ok := srv.(map[string]interface{})
		if !ok {
			return ProtoDNSResourceRecord{}, fmt.Errorf("SRV from ProtoDNSResourceRecord: type error")
		}

		protoDNSSRV, err = jsonConvertToProtoDNSSRVType(srvMap)
		if err != nil {
			return ProtoDNSResourceRecord{}, err
		}
	}

	// MX conversion
	mx, exists := argMap["MX"]
	if !exists {
		return ProtoDNSResourceRecord{}, fmt.Errorf("MX not found in ProtoDNSResourceRecord arg")
	}

	var protoDNSMX ProtoDNSMX
	if mx != nil {
		mxMap, ok := mx.(map[string]interface{})
		if !ok {
			return ProtoDNSResourceRecord{}, fmt.Errorf("MX from ProtoDNSResourceRecord: type error")
		}

		protoDNSMX, err = jsonConvertToProtoDNSMXType(mxMap)
		if err != nil {
			return ProtoDNSResourceRecord{}, err
		}
	}

	// OPT conversion
	opt, exists := argMap["OPT"]
	if !exists {
		return ProtoDNSResourceRecord{}, fmt.Errorf("OPT not found in ProtoDNSResourceRecord arg")
	}

	var dnsOpts []ProtoDNSOPT
	if opt != nil {
		optSlice, ok := opt.([]interface{})
		if !ok {
			return ProtoDNSResourceRecord{}, fmt.Errorf("OPT from ProtoDNSResourceRecord: type error")
		}

		for _, optElem := range optSlice {
			optElemMap, ok := optElem.(map[string]interface{})
			if !ok {
				return ProtoDNSResourceRecord{}, fmt.Errorf("OPT from ProtoDNSResourceRecord: type error")
			}

			dnsOpt, err := jsonConvertToProtoDNSOPTType(optElemMap)
			if err != nil {
				return ProtoDNSResourceRecord{}, err
			}

			dnsOpts = append(dnsOpts, dnsOpt)
		}
	}

	// URI conversion
	uri, exists := argMap["URI"]
	if !exists {
		return ProtoDNSResourceRecord{}, fmt.Errorf("URI not found in ProtoDNSResourceRecord arg")
	}

	var protoDNSURI ProtoDNSURI
	if uri != nil {
		uriMap, ok := uri.(map[string]interface{})
		if !ok {
			return ProtoDNSResourceRecord{}, fmt.Errorf("URI from ProtoDNSResourceRecord: type error")
		}

		protoDNSURI, err = jsonConvertToProtoDNSURIType(uriMap)
		if err != nil {
			return ProtoDNSResourceRecord{}, err
		}
	}

	return ProtoDNSResourceRecord{
		Name:  stringTypes["name"],
		Type:  stringTypes["type"],
		Class: stringTypes["class"],
		TTL:   uint32Types["TTL"],
		IP:    stringTypes["IP"],
		NS:    stringTypes["NS"],
		CNAME: stringTypes["CNAME"],
		PTR:   stringTypes["PTR"],
		TXTs:  txtsValue,
		SOA:   protoDNSSOA,
		SRV:   protoDNSSRV,
		MX:    protoDNSMX,
		OPT:   dnsOpts,
		URI:   protoDNSURI,
		TXT:   stringTypes["TXT"],
	}, nil
}

func jsonConvertToProtoDNSSOAType(argMap map[string]interface{}) (ProtoDNSSOA, error) {
	// string conversion
	stringTypes := map[string]string{
		"MName": "",
		"RName": "",
	}
	stringTypes, err := jsonConvertToStringTypes(argMap, stringTypes)
	if err != nil {
		return ProtoDNSSOA{}, err
	}

	// uint32 conversion
	uint32Types := map[string]uint32{
		"serial":  0,
		"refresh": 0,
		"retry":   0,
		"expire":  0,
		"minimum": 0,
	}
	uint32Types, err = jsonConvertToUint32Types(argMap, uint32Types)
	if err != nil {
		return ProtoDNSSOA{}, err
	}

	return ProtoDNSSOA{
		MName:   stringTypes["MName"],
		RName:   stringTypes["RName"],
		Serial:  uint32Types["serial"],
		Refresh: uint32Types["refresh"],
		Retry:   uint32Types["retry"],
		Expire:  uint32Types["expire"],
		Minimum: uint32Types["minimum"],
	}, nil
}

func jsonConvertToProtoDNSSRVType(argMap map[string]interface{}) (ProtoDNSSRV, error) {
	// string conversion
	stringTypes := map[string]string{
		"name": "",
	}
	stringTypes, err := jsonConvertToStringTypes(argMap, stringTypes)
	if err != nil {
		return ProtoDNSSRV{}, err
	}

	// uint16 conversion
	uint16Types := map[string]uint16{
		"priority": 0,
		"weight":   0,
		"port":     0,
	}
	uint16Types, err = jsonConvertToUint16Types(argMap, uint16Types)
	if err != nil {
		return ProtoDNSSRV{}, err
	}

	return ProtoDNSSRV{
		Priority: uint16Types["priority"],
		Weight:   uint16Types["weight"],
		Port:     uint16Types["port"],
		Name:     stringTypes["name"],
	}, nil
}

func jsonConvertToProtoDNSMXType(argMap map[string]interface{}) (ProtoDNSMX, error) {
	// string conversion
	stringTypes := map[string]string{
		"name": "",
	}
	stringTypes, err := jsonConvertToStringTypes(argMap, stringTypes)
	if err != nil {
		return ProtoDNSMX{}, err
	}

	// uint16 conversion
	uint16Types := map[string]uint16{
		"preference": 0,
	}
	uint16Types, err = jsonConvertToUint16Types(argMap, uint16Types)
	if err != nil {
		return ProtoDNSMX{}, err
	}

	return ProtoDNSMX{
		Preference: uint16Types["preference"],
		Name:       stringTypes["name"],
	}, nil
}

func jsonConvertToProtoDNSOPTType(argMap map[string]interface{}) (ProtoDNSOPT, error) {
	// string conversion
	stringTypes := map[string]string{
		"code": "",
		"data": "",
	}
	stringTypes, err := jsonConvertToStringTypes(argMap, stringTypes)
	if err != nil {
		return ProtoDNSOPT{}, err
	}

	return ProtoDNSOPT{
		Code: stringTypes["code"],
		Data: stringTypes["data"],
	}, nil
}

func jsonConvertToProtoDNSURIType(argMap map[string]interface{}) (ProtoDNSURI, error) {
	// string conversion
	stringTypes := map[string]string{
		"target": "",
	}
	stringTypes, err := jsonConvertToStringTypes(argMap, stringTypes)
	if err != nil {
		return ProtoDNSURI{}, err
	}

	// uint16 conversion
	uint16Types := map[string]uint16{
		"priority": 0,
		"weight":   0,
	}
	uint16Types, err = jsonConvertToUint16Types(argMap, uint16Types)
	if err != nil {
		return ProtoDNSURI{}, err
	}

	return ProtoDNSURI{
		Priority: uint16Types["priority"],
		Weight:   uint16Types["weight"],
		Target:   stringTypes["target"],
	}, nil
}

func jsonConvertToPktMetaArg(argMap map[string]interface{}) (PktMeta, error) {
	// string conversion
	stringTypes := map[string]string{
		"src_ip": "",
		"dst_ip": "",
		"iface":  "",
	}
	stringTypes, err := jsonConvertToStringTypes(argMap, stringTypes)
	if err != nil {
		return PktMeta{}, err
	}

	// uint16 conversion
	uint16Types := map[string]uint16{
		"src_port": 0,
		"dst_port": 0,
	}
	uint16Types, err = jsonConvertToUint16Types(argMap, uint16Types)
	if err != nil {
		return PktMeta{}, err
	}

	// uint8 conversion
	uint8Types := map[string]uint8{
		"protocol": 0,
	}
	uint8Types, err = jsonConvertToUint8Types(argMap, uint8Types)
	if err != nil {
		return PktMeta{}, err
	}

	// uint32 conversion
	uint32Types := map[string]uint32{
		"packet_len": 0,
	}
	uint32Types, err = jsonConvertToUint32Types(argMap, uint32Types)
	if err != nil {
		return PktMeta{}, err
	}

	return PktMeta{
		SrcIP:     stringTypes["src_ip"],
		DstIP:     stringTypes["dst_ip"],
		SrcPort:   uint16Types["src_port"],
		DstPort:   uint16Types["dst_port"],
		Protocol:  uint8Types["protocol"],
		PacketLen: uint32Types["packet_len"],
		Iface:     stringTypes["iface"],
	}, nil
}

func jsonConvertToDnsResponseDataType(argMap map[string]interface{}) (DnsResponseData, error) {
	// convert query_data

	queryData, exists := argMap["query_data"]
	if !exists {
		return DnsResponseData{}, fmt.Errorf("query_data not found in DnsResponseData arg")
	}

	var dnsQuery DnsQueryData
	if queryData != nil {
		queryDataMap, ok := queryData.(map[string]interface{})
		if !ok {
			return DnsResponseData{}, fmt.Errorf("query_data from DnsResponseData: type error")
		}

		var err error
		dnsQuery, err = jsonConvertToDnsQuertDataType(queryDataMap)
		if err != nil {
			return DnsResponseData{}, err
		}
	}

	// convert dns_answer

	dnsAnswer, exists := argMap["dns_answer"]
	if !exists {
		return DnsResponseData{}, fmt.Errorf("dns_answer not found in DnsResponseData arg")
	}

	var dnsAnswers []DnsAnswer
	if dnsAnswer != nil {
		dnsAnswerSlice, ok := dnsAnswer.([]interface{})
		if !ok {
			return DnsResponseData{}, fmt.Errorf("dns_answer from DnsResponseData: type error")
		}

		for _, dnsAnswerElem := range dnsAnswerSlice {
			dnsAnswerElemMap, ok := dnsAnswerElem.(map[string]interface{})
			if !ok {
				return DnsResponseData{}, fmt.Errorf("dns_answer from DnsResponseData: type error")
			}

			dnsAns, err := jsonConvertToDnsAnswerType(dnsAnswerElemMap)
			if err != nil {
				return DnsResponseData{}, err
			}

			dnsAnswers = append(dnsAnswers, dnsAns)
		}
	}

	return DnsResponseData{
		QueryData: dnsQuery,
		DnsAnswer: dnsAnswers,
	}, nil
}

func jsonConvertToDnsQuertDataType(argMap map[string]interface{}) (DnsQueryData, error) {
	// string conversion
	stringTypes := map[string]string{
		"query":       "",
		"query_type":  "",
		"query_class": "",
	}
	stringTypes, err := jsonConvertToStringTypes(argMap, stringTypes)
	if err != nil {
		return DnsQueryData{}, err
	}

	return DnsQueryData{
		Query:      stringTypes["query"],
		QueryType:  stringTypes["query_type"],
		QueryClass: stringTypes["query_class"],
	}, nil
}

func jsonConvertToDnsAnswerType(argMap map[string]interface{}) (DnsAnswer, error) {
	// string conversion
	dnsAnswerStringTypes := map[string]string{
		"answer_type": "",
		"answer":      "",
	}
	dnsAnswerStringTypes, err := jsonConvertToStringTypes(argMap, dnsAnswerStringTypes)
	if err != nil {
		return DnsAnswer{}, err
	}

	// uint32 conversion
	dnsAnswerUint32Types := map[string]uint32{
		"ttl": 0,
	}
	dnsAnswerUint32Types, err = jsonConvertToUint32Types(argMap, dnsAnswerUint32Types)
	if err != nil {
		return DnsAnswer{}, err
	}

	return DnsAnswer{
		Type:   dnsAnswerStringTypes["answer_type"],
		Ttl:    dnsAnswerUint32Types["ttl"],
		Answer: dnsAnswerStringTypes["answer"],
	}, nil
}

func jsonConvertToProtoHTTPArg(argMap map[string]interface{}) (ProtoHTTP, error) {
	// string conversion
	stringTypes := map[string]string{
		"direction": "",
		"method":    "",
		"protocol":  "",
		"host":      "",
		"uri_path":  "",
		"status":    "",
	}
	stringTypes, err := jsonConvertToStringTypes(argMap, stringTypes)
	if err != nil {
		return ProtoHTTP{}, err
	}

	// int conversion
	intTypes := map[string]int{
		"status_code": 0,
	}
	intTypes, err = jsonConvertToIntTypes(argMap, intTypes)
	if err != nil {
		return ProtoHTTP{}, err
	}

	// int64 conversion
	int64Types := map[string]int64{
		"content_length": 0,
	}
	int64Types, err = jsonConvertToInt64Types(argMap, int64Types)
	if err != nil {
		return ProtoHTTP{}, err
	}

	// headers conversion
	headerTypes := map[string]http.Header{
		"headers": {},
	}
	headerTypes, err = jsonConvertToHttpHeaderTypes(argMap, headerTypes)
	if err != nil {
		return ProtoHTTP{}, err
	}

	return ProtoHTTP{
		Direction:     stringTypes["direction"],
		Method:        stringTypes["method"],
		Protocol:      stringTypes["protocol"],
		Host:          stringTypes["host"],
		URIPath:       stringTypes["uri_path"],
		Status:        stringTypes["status"],
		StatusCode:    intTypes["status_code"],
		Headers:       headerTypes["headers"],
		ContentLength: int64Types["content_length"],
	}, nil
}

func jsonConvertToProtoHTTPRequestArg(argMap map[string]interface{}) (ProtoHTTPRequest, error) {
	// string conversion
	stringTypes := map[string]string{
		"method":   "",
		"protocol": "",
		"host":     "",
		"uri_path": "",
	}
	stringTypes, err := jsonConvertToStringTypes(argMap, stringTypes)
	if err != nil {
		return ProtoHTTPRequest{}, err
	}

	// int64 conversion
	int64Types := map[string]int64{
		"content_length": 0,
	}
	int64Types, err = jsonConvertToInt64Types(argMap, int64Types)
	if err != nil {
		return ProtoHTTPRequest{}, err
	}

	// headers conversion
	headerTypes := map[string]http.Header{
		"headers": {},
	}
	headerTypes, err = jsonConvertToHttpHeaderTypes(argMap, headerTypes)
	if err != nil {
		return ProtoHTTPRequest{}, err
	}

	return ProtoHTTPRequest{
		Method:        stringTypes["method"],
		Protocol:      stringTypes["protocol"],
		Host:          stringTypes["host"],
		URIPath:       stringTypes["uri_path"],
		Headers:       headerTypes["headers"],
		ContentLength: int64Types["content_length"],
	}, nil
}

func jsonConvertToProtoHTTPResponseArg(argMap map[string]interface{}) (ProtoHTTPResponse, error) {
	// string conversion
	stringTypes := map[string]string{
		"status":   "",
		"protocol": "",
	}
	stringTypes, err := jsonConvertToStringTypes(argMap, stringTypes)
	if err != nil {
		return ProtoHTTPResponse{}, err
	}

	// int conversion
	intTypes := map[string]int{
		"status_code": 0,
	}
	intTypes, err = jsonConvertToIntTypes(argMap, intTypes)
	if err != nil {
		return ProtoHTTPResponse{}, err
	}

	// int64 conversion
	int64Types := map[string]int64{
		"content_length": 0,
	}
	int64Types, err = jsonConvertToInt64Types(argMap, int64Types)
	if err != nil {
		return ProtoHTTPResponse{}, err
	}

	// headers conversion
	headerTypes := map[string]http.Header{
		"headers": {},
	}
	headerTypes, err = jsonConvertToHttpHeaderTypes(argMap, headerTypes)
	if err != nil {
		return ProtoHTTPResponse{}, err
	}

	return ProtoHTTPResponse{
		Status:        stringTypes["status"],
		StatusCode:    intTypes["status_code"],
		Protocol:      stringTypes["protocol"],
		Headers:       headerTypes["headers"],
		ContentLength: int64Types["content_length"],
	}, nil
}

func jsonConvertToPacketMetadata(argMap map[string]interface{}) (PacketMetadata, error) {
	uint8Types := map[string]uint8{
		"direction": 0,
	}
	jsonConvertToUint8Types(argMap, uint8Types)
	return PacketMetadata{
		Direction: PacketDirection(uint8Types["direction"]),
	}, nil
}

func jsonConvertToStringTypes(argMap map[string]interface{}, stringTypes map[string]string) (map[string]string, error) {
	for key := range stringTypes {
		val, ok := argMap[key]
		if !ok {
			return stringTypes, fmt.Errorf("key not found in argMap %s", key)
		}

		var valString string
		if val != nil {
			valString, ok = val.(string)
			if !ok {
				return stringTypes, fmt.Errorf("couldn't convert key to string %s", key)
			}
		}

		stringTypes[key] = valString
	}

	return stringTypes, nil
}

func jsonConvertToStringSlice(interfaceSlice []interface{}) []string {
	stringSlice := make([]string, len(interfaceSlice))
	for i, v := range interfaceSlice {
		stringSlice[i] = fmt.Sprint(v)
	}
	return stringSlice
}

func jsonConvertToIntTypes(argMap map[string]interface{}, intTypes map[string]int) (map[string]int, error) {
	for key := range intTypes {
		val, ok := argMap[key]
		if !ok {
			return intTypes, fmt.Errorf("key not found in argMap %s", key)
		}

		var int64Val int64
		if val != nil {
			valJsonNum, ok := val.(json.Number)
			if !ok {
				return intTypes, fmt.Errorf("couldn't convert key to int %s", key)
			}

			var err error
			int64Val, err = valJsonNum.Int64()
			if err != nil {
				return intTypes, err
			}
		}

		intTypes[key] = int(int64Val)
	}

	return intTypes, nil
}

func jsonConvertToUint8Types(argMap map[string]interface{}, uint8Types map[string]uint8) (map[string]uint8, error) {
	for key := range uint8Types {
		val, ok := argMap[key]
		if !ok {
			return uint8Types, fmt.Errorf("key not found in argMap %s", key)
		}

		var int64Val int64
		if val != nil {
			valJsonNum, ok := val.(json.Number)
			if !ok {
				return uint8Types, fmt.Errorf("couldn't convert key to uint8 %s", key)
			}

			var err error
			int64Val, err = valJsonNum.Int64()
			if err != nil {
				return uint8Types, err
			}
		}

		uint8Types[key] = uint8(int64Val)
	}

	return uint8Types, nil
}

func jsonConvertToUint16Types(argMap map[string]interface{}, uint16Types map[string]uint16) (map[string]uint16, error) {
	for key := range uint16Types {
		val, ok := argMap[key]
		if !ok {
			return uint16Types, fmt.Errorf("key not found in argMap %s", key)
		}

		var int64Val int64
		if val != nil {
			valJsonNum, ok := val.(json.Number)
			if !ok {
				return uint16Types, fmt.Errorf("couldn't convert key to uint16 %s", key)
			}

			var err error
			int64Val, err = valJsonNum.Int64()
			if err != nil {
				return uint16Types, err
			}
		}

		uint16Types[key] = uint16(int64Val)
	}

	return uint16Types, nil
}

func jsonConvertToUint32Types(argMap map[string]interface{}, uint32Types map[string]uint32) (map[string]uint32, error) {
	for key := range uint32Types {
		val, ok := argMap[key]
		if !ok {
			return uint32Types, fmt.Errorf("key not found in argMap %s", key)
		}

		var int64Val int64
		if val != nil {
			valJsonNum, ok := val.(json.Number)
			if !ok {
				return uint32Types, fmt.Errorf("couldn't convert key to uint32 %s", key)
			}

			var err error
			int64Val, err = valJsonNum.Int64()
			if err != nil {
				return uint32Types, err
			}
		}

		uint32Types[key] = uint32(int64Val)
	}

	return uint32Types, nil
}

func jsonConvertToUintTypes(argMap map[string]interface{}, uintTypes map[string]uint) (map[string]uint, error) {
	for key := range uintTypes {
		val, ok := argMap[key]
		if !ok {
			return uintTypes, fmt.Errorf("key not found in argMap %s", key)
		}

		var int64Val int64
		if val != nil {
			valJsonNum, ok := val.(json.Number)
			if !ok {
				return uintTypes, fmt.Errorf("couldn't convert key to uint8 %s", key)
			}

			var err error
			int64Val, err = valJsonNum.Int64()
			if err != nil {
				return uintTypes, err
			}
		}

		uintTypes[key] = uint(int64Val)
	}

	return uintTypes, nil
}

func jsonConvertToInt64Types(argMap map[string]interface{}, int64Types map[string]int64) (map[string]int64, error) {
	for key := range int64Types {
		val, ok := argMap[key]
		if !ok {
			return int64Types, fmt.Errorf("key not found in argMap %s", key)
		}

		var int64Val int64
		if val != nil {
			valJsonNum, ok := val.(json.Number)
			if !ok {
				return int64Types, fmt.Errorf("couldn't convert key to int64 %s", key)
			}

			var err error
			int64Val, err = valJsonNum.Int64()
			if err != nil {
				return int64Types, err
			}
		}

		int64Types[key] = int64Val
	}

	return int64Types, nil
}

func jsonConvertToHttpHeaderTypes(argMap map[string]interface{}, httpHeaderTypes map[string]http.Header) (map[string]http.Header, error) {
	for key := range httpHeaderTypes {
		val, ok := argMap[key]
		if !ok {
			return httpHeaderTypes, fmt.Errorf("key not found in argMap %s", key)
		}

		if val != nil {
			headerMap, ok := val.(map[string]interface{})
			if !ok {
				return httpHeaderTypes, fmt.Errorf("couldn't convert key to http.Header %s", key)
			}

			for headerKey, headerValInterface := range headerMap {
				headerValInterfaceSlice, ok := headerValInterface.([]interface{})
				if !ok {
					return httpHeaderTypes, fmt.Errorf("couldn't convert key to http.Header %s", key)
				}

				var headerVals []string
				for _, headerValInterfaceElem := range headerValInterfaceSlice {
					headerVals = append(headerVals, headerValInterfaceElem.(string))
				}
				httpHeaderTypes[key][headerKey] = headerVals
			}
		}
	}

	return httpHeaderTypes, nil
}

// SlimCred struct is a slim version of the kernel's cred struct
// it is used to unmarshal binary data and therefore should match (bit by bit) to the `slim_cred_t` struct in the ebpf code.
// ANY CHANGE TO THIS STRUCT WILL BE REQUIRED ALSO TO bufferdecoder.SlimCred
type SlimCred struct {
	Uid            uint32 /* real UID of the task */
	Gid            uint32 /* real GID of the task */
	Suid           uint32 /* saved UID of the task */
	Sgid           uint32 /* saved GID of the task */
	Euid           uint32 /* effective UID of the task */
	Egid           uint32 /* effective GID of the task */
	Fsuid          uint32 /* UID for VFS ops */
	Fsgid          uint32 /* GID for VFS ops */
	UserNamespace  uint32 /* User Namespace of the of the event */
	SecureBits     uint32 /* SUID-less security management */
	CapInheritable uint64 /* caps our children can inherit */
	CapPermitted   uint64 /* caps we're permitted */
	CapEffective   uint64 /* caps we can actually use */
	CapBounding    uint64 /* capability bounding set */
	CapAmbient     uint64 /* Ambient capability set */
}

type HookedSymbolData struct {
	SymbolName  string
	ModuleOwner string
}

type HiddenKernelModule struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

// MemProtAlert is an enum of possible messages that can be sent by an event to pass some extra information about the event.
type MemProtAlert uint32

const (
	ProtAlertUnknown MemProtAlert = iota
	ProtAlertMmapWX
	ProtAlertMprotectToX
	ProtAlertMprotectXToWX
	ProtAlertMprotectWXToX
	ProtAlertLast
)

func (alert MemProtAlert) String() string {
	switch alert {
	case ProtAlertMmapWX:
		return "Mmaped region with W+E permissions!"
	case ProtAlertMprotectToX:
		return "Protection changed to Executable!"
	case ProtAlertMprotectXToWX:
		return "Protection changed from E to W+E!"
	case ProtAlertMprotectWXToX:
		return "Protection changed from W to E!"
	default:
		return "Unknown alert"
	}
}

type KernelReadType int

const (
	KernelReadUnknown KernelReadType = iota
	KernelReadFirmware
	KernelReadKernelModule
	KernelReadKExecImage
	KernelReadKExecInitRAMFS
	KernelReadSecurityPolicy
	KernelReadx509Certificate
)

func (readType KernelReadType) String() string {
	switch readType {
	case KernelReadUnknown:
		return "unknown"
	case KernelReadFirmware:
		return "firmware"
	case KernelReadKernelModule:
		return "kernel-module"
	case KernelReadKExecImage:
		return "kexec-image"
	case KernelReadKExecInitRAMFS:
		return "kexec-initramfs"
	case KernelReadSecurityPolicy:
		return "security-policy"
	case KernelReadx509Certificate:
		return "x509-certificate"
	}
	return "unknown"
}
