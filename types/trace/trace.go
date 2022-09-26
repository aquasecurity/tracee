// Package trace defines the public types exported through the EBPF code and produced outwards from tracee-ebpf
package trace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/aquasecurity/tracee/types/protocol"
)

// Event is a single result of an ebpf event process. It is used as a payload later delivered to tracee-rules.
type Event struct {
	Timestamp           int          `json:"timestamp"`
	ThreadStartTime     int          `json:"threadStartTime"`
	ProcessorID         int          `json:"processorId"`
	ProcessID           int          `json:"processId"`
	CgroupID            uint         `json:"cgroupId"`
	ThreadID            int          `json:"threadId"`
	ParentProcessID     int          `json:"parentProcessId"`
	HostProcessID       int          `json:"hostProcessId"`
	HostThreadID        int          `json:"hostThreadId"`
	HostParentProcessID int          `json:"hostParentProcessId"`
	UserID              int          `json:"userId"`
	MountNS             int          `json:"mountNamespace"`
	PIDNS               int          `json:"pidNamespace"`
	ProcessName         string       `json:"processName"`
	HostName            string       `json:"hostName"`
	ContainerID         string       `json:"containerId"`
	ContainerImage      string       `json:"containerImage"`
	ContainerName       string       `json:"containerName"`
	PodName             string       `json:"podName"`
	PodNamespace        string       `json:"podNamespace"`
	PodUID              string       `json:"podUID"`
	EventID             int          `json:"eventId,string"`
	EventName           string       `json:"eventName"`
	ArgsNum             int          `json:"argsNum"`
	ReturnValue         int          `json:"returnValue"`
	StackAddresses      []uint64     `json:"stackAddresses"`
	ContextFlags        ContextFlags `json:"contextFlags"`
	Args                []Argument   `json:"args"` //Arguments are ordered according their appearance in the original event
}

// ContextFlags are flags representing event context
type ContextFlags struct {
	ContainerStarted bool `json:"containerStarted"`
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
	if e.ContainerID != "" {
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
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (arg *Argument) UnmarshalJSON(b []byte) error {
	type argument Argument //alias Argument so we can unmarshal it within the unmarshaler implementation
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode((*argument)(arg)); err != nil {
		return err
	}
	if arg.Value == nil {
		return nil
	}
	if num, isNum := arg.Value.(json.Number); isNum {
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
		case "char", "u8":
			tmp, err := strconv.ParseUint(num.String(), 10, 8)
			if err != nil {
				return err
			}
			arg.Value = uint8(tmp)
		case "unsigned short", "u16", "old_uid_t", "old_gid_t", "umode_t":
			tmp, err := strconv.ParseUint(num.String(), 10, 16)
			if err != nil {
				return err
			}
			arg.Value = uint16(tmp)
		case "unsigned int", "u32", "mode_t", "dev_t":
			tmp, err := strconv.ParseUint(num.String(), 10, 32)
			if err != nil {
				return err
			}
			arg.Value = uint32(tmp)
		case "unsigned long", "u64", "off_t", "size_t", "void*", "const void*":
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
		case "float64":
			tmp, err := num.Float64()
			if err != nil {
				return err
			}
			arg.Value = tmp
		default:
			return fmt.Errorf("unrecognized argument type")
		}
	}
	if arg.Type == "const char*const*" || arg.Type == "const char**" {
		argValue := arg.Value.([]interface{})
		tmp := make([]string, len(argValue))
		for i, v := range argValue {
			tmp[i] = fmt.Sprint(v)
		}
		arg.Value = tmp
	}
	return nil
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
		return "Protection changed from W+E to E!"
	default:
		return "Unknown alert"
	}
}

//
// Network Protocol Event Types
//

// IPv4

type ProtoIPv4 struct {
	Version    uint8             `json:"Version"`
	IHL        uint8             `json:"IHL"`
	TOS        uint8             `json:"TOS"`
	Length     uint16            `json:"Length"`
	Id         uint16            `json:"Id"`
	Flags      uint8             `json:"Flags"`
	FragOffset uint16            `json:"FragOffset"`
	TTL        uint8             `json:"TTL"`
	Protocol   string            `json:"Protocol"`
	Checksum   uint16            `json:"Checksum"`
	SrcIP      net.IP            `json:"SrcIP"`
	DstIP      net.IP            `json:"DstIP"`
	Options    []ProtoIPv4Option `json:"Options"`
}

type ProtoIPv4Flag struct {
	OptionType   uint8 `json:"OptionType"`
	OptionLength uint8 `json:"OptionLength"`
}

type ProtoIPv4Option struct {
	OptionType   uint8 `json:"OptionType"`
	OptionLength uint8 `json:"OptionLength"`
}

// IPv6

type ProtoIPv6 struct {
	Version      uint8  `json:"Version"`
	TrafficClass uint8  `json:"TrafficClass"`
	FlowLabel    uint32 `json:"FlowLabel"`
	Length       uint16 `json:"Length"`
	NextHeader   string `json:"NextHeader"`
	HopLimit     uint8  `json:"HopLimit"`
	SrcIP        net.IP `json:"SrcIP"`
	DstIP        net.IP `json:"DstIP"`
}

// TCP

type ProtoTCP struct {
	SrcPort    uint16           `json:"SrcPort"`
	DstPort    uint16           `json:"DstPort"`
	Seq        uint32           `json:"Seq"`
	Ack        uint32           `json:"Ack"`
	DataOffset uint8            `json:"DataOffset"`
	FIN        uint8            `json:"FIN"`
	SYN        uint8            `json:"SYN"`
	RST        uint8            `json:"RST"`
	PSH        uint8            `json:"PSH"`
	ACK        uint8            `json:"ACK"`
	URG        uint8            `json:"URG"`
	ECE        uint8            `json:"ECE"`
	CWR        uint8            `json:"CWR"`
	NS         uint8            `json:"NS"`
	Window     uint16           `json:"Window"`
	Checksum   uint16           `json:"Checksum"`
	Urgent     uint16           `json:"Urgent"`
	Options    []ProtoTCPOption `json:"Options"`
}

type ProtoTCPOption struct {
	OptionType   string `json:"OptionType"`
	OptionLength uint8  `json:"OptionLength"`
}

// UDP

type ProtoUDP struct {
	SrcPort  uint16 `json:"SrcPort"`
	DstPort  uint16 `json:"DstPort"`
	Length   uint16 `json:"Length"`
	Checksum uint16 `json:"Checksum"`
}

// ICMP

type ProtoICMP struct {
	TypeCode string `json:"TypeCode"`
	Checksum uint16 `json:"Checksum"`
	Id       uint16 `json:"Id"`
	Seq      uint16 `json:"Seq"`
}

// ICMPv6

type ProtoICMPv6 struct {
	TypeCode string `json:"TypeCode"`
	Checksum uint16 `json:"Checksum"`
}

// DNS

type ProtoDNS struct {
	ID           uint16                   `json:"ID"`
	QR           uint8                    `json:"QR"`
	OpCode       string                   `json:"OpCode"`
	AA           uint8                    `json:"AA"`
	TC           uint8                    `json:"TC"`
	RD           uint8                    `json:"RD"`
	RA           uint8                    `json:"RA"`
	Z            uint8                    `json:"Z"`
	ResponseCode string                   `json:"ResponseCode"`
	QDCount      uint16                   `json:"QDCount"`
	ANCount      uint16                   `json:"ANCount"`
	NSCount      uint16                   `json:"NSCount"`
	ARCount      uint16                   `json:"ARCount"`
	Questions    []ProtoDNSQuestion       `json:"Questions"`
	Answers      []ProtoDNSResourceRecord `json:"Answers"`
	Authorities  []ProtoDNSResourceRecord `json:"Authorities"`
	Additionals  []ProtoDNSResourceRecord `json:"Additionals"`
}

type ProtoDNSQuestion struct {
	Name  string `json:"Name"`
	Type  string `json:"Type"`
	Class string `json:"Class"`
}

type ProtoDNSResourceRecord struct {
	Name  string        `json:"Name"`
	Type  string        `json:"Type"`
	Class string        `json:"Class"`
	TTL   uint32        `json:"TTL"`
	IP    string        `json:"IP"`
	NS    string        `json:"NS"`
	CNAME string        `json:"CNAME"`
	PTR   string        `json:"PTR"`
	TXTs  []string      `json:"TXTs"`
	SOA   ProtoDNSSOA   `json:"SOA"`
	SRV   ProtoDNSSRV   `json:"SRV"`
	MX    ProtoDNSMX    `json:"MX"`
	OPT   []ProtoDNSOPT `json:"OPT"`
	URI   ProtoDNSURI   `json:"URI"`
	TXT   string        `json:"TXT"`
}

type ProtoDNSSOA struct {
	MName   string `json:"MName"`
	RName   string `json:"RName"`
	Serial  uint32 `json:"Serial"`
	Refresh uint32 `json:"Refresh"`
	Retry   uint32 `json:"Retry"`
	Expire  uint32 `json:"Expire"`
	Minimum uint32 `json:"Minimum"`
}

type ProtoDNSSRV struct {
	Priority uint16 `json:"Priority"`
	Weight   uint16 `json:"Weight"`
	Port     uint16 `json:"Port"`
	Name     string `json:"Name"`
}

type ProtoDNSMX struct {
	Preference uint16 `json:"Preference"`
	Name       string `json:"Name"`
}

type ProtoDNSURI struct {
	Priority uint16 `json:"Priority"`
	Weight   uint16 `json:"Weight"`
	Target   string `json:"Target"`
}

type ProtoDNSOPT struct {
	Code string `json:"Code"`
	Data string `json:"Data"`
}
