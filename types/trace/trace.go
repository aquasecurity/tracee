// Package trace defines the public types exported through the EBPF code and produced outwards from tracee-ebpf
package trace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

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
		case "float64":
			tmp, err := num.Float64()
			if err != nil {
				return err
			}
			arg.Value = tmp
		case "unsigned short", "old_uid_t", "old_gid_t", "umode_t":
			tmp, err := strconv.ParseUint(num.String(), 10, 16)
			if err != nil {
				return err
			}
			arg.Value = uint16(tmp)
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
