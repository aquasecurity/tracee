package external

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

// Event is a user facing data structure representing a single event
type Event struct {
	Timestamp           float64    `json:"timestamp"`
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
	EventID             int        `json:"eventId,string"`
	EventName           string     `json:"eventName"`
	ArgsNum             int        `json:"argsNum"`
	ReturnValue         int        `json:"returnValue"`
	StackAddresses      []uint64   `json:"stackAddresses"`
	Args                []Argument `json:"args"` //Arguments are ordered according their appearance in the original event
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

// UnmarshalJSON implements the encoding/json.Unmershaler interface
func (arg *Argument) UnmarshalJSON(b []byte) error {
	type argument Argument //alias Argument so we can unmarshal it within the unmarshaler implementation
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode((*argument)(arg)); err != nil {
		return err
	}
	if num, isNum := arg.Value.(json.Number); isNum {
		switch arg.Type {
		case "int", "pid_t", "uid_t", "gid_t", "mqd_t", "clockid_t", "const clockid_t", "key_t", "key_serial_t", "timer_t":
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

	return nil
}
