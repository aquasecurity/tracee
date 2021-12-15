package external

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

// Event is a user facing data structure representing a single event
type Event struct {
	Timestamp           int        `json:"timestamp"`
	ProcessID           int        `json:"processId"`
	ThreadID            int        `json:"threadId"`
	ParentProcessID     int        `json:"parentProcessId"`
	HostProcessID       int        `json:"hostProcessId"`
	HostThreadID        int        `json:"hostThreadId"`
	HostParentProcessID int        `json:"hostParentProcessId"`
	UserID              int        `json:"userId"`
	MountNS             int        `json:"mountNamespace"`
	PIDNS               int        `json:"pidNamespace"`
	ProcessName         string     `json:"processName"`
	HostName            string     `json:"hostName"`
	ContainerID         string     `json:"containerId"`
	EventID             int        `json:"eventId,string"`
	EventName           string     `json:"eventName"`
	ArgsNum             int        `json:"argsNum"`
	ReturnValue         int        `json:"returnValue"`
	StackAddresses      []uint64   `json:"stackAddresses"`
	Args                []Argument `json:"args"` //Arguments are ordered according their appearance in the original event
}

type Stats struct {
	EventCount  int
	ErrorCount  int
	LostEvCount int
	LostWrCount int
	LostNtCount int
}

// ToUnstructured returns a JSON compatible map with string, float, int, bool,
// []interface{}, or map[string]interface{} children.
//
// It allows this Event to be manipulated generically. For example, it can be
// used as a parsed input with OPA SDK to avoid relatively expensive JSON
// encoding round trip.
func (e Event) ToUnstructured() (map[string]interface{}, error) {
	var argsRef interface{}

	if e.Args != nil {
		args := make([]interface{}, len(e.Args))
		for i, arg := range e.Args {
			value, err := jsonRoundTripArgumentValue(arg.Value)
			if err != nil {
				return nil, fmt.Errorf("marshalling arg %s with value %v: %w", arg.Name, arg.Value, err)
			}
			args[i] = map[string]interface{}{
				"name":  arg.Name,
				"type":  arg.Type,
				"value": value,
			}
		}
		argsRef = args
	}

	var stackAddressesRef interface{}
	if e.StackAddresses != nil {
		// stackAddresses can be ignored in the context of tracee-rules
		stackAddressesRef = make([]interface{}, len(e.StackAddresses))
	}

	return map[string]interface{}{
		"timestamp":           json.Number(strconv.Itoa(e.Timestamp)),
		"processId":           json.Number(strconv.Itoa(e.ProcessID)),
		"threadId":            json.Number(strconv.Itoa(e.ThreadID)),
		"parentProcessId":     json.Number(strconv.Itoa(e.ParentProcessID)),
		"hostProcessId":       json.Number(strconv.Itoa(e.HostProcessID)),
		"hostThreadId":        json.Number(strconv.Itoa(e.HostThreadID)),
		"hostParentProcessId": json.Number(strconv.Itoa(e.HostParentProcessID)),
		"userId":              json.Number(strconv.Itoa(e.UserID)),
		"mountNamespace":      json.Number(strconv.Itoa(e.MountNS)),
		"pidNamespace":        json.Number(strconv.Itoa(e.PIDNS)),
		"processName":         e.ProcessName,
		"hostName":            e.HostName,
		"containerId":         e.ContainerID,
		"eventId":             strconv.Itoa(e.EventID),
		"eventName":           e.EventName,
		"argsNum":             json.Number(strconv.Itoa(e.ArgsNum)),
		"returnValue":         json.Number(strconv.Itoa(e.ReturnValue)),
		"args":                argsRef,
		"stackAddresses":      stackAddressesRef,
	}, nil
}

func jsonRoundTripArgumentValue(v interface{}) (interface{}, error) {
	m, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(m)

	var u interface{}
	d := json.NewDecoder(buf)
	d.UseNumber()
	err = d.Decode(&u)
	if err != nil {
		return nil, err
	}
	return u, nil
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

// Message is an enum of possible messages that can be sent by an event to pass some extra information about the event.
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
