package sigengine

import (
	"encoding/gob"
	"fmt"
	"io"
	"os"
	"time"
)

type TraceeInputSource struct {
	file *os.File
	dec  *gob.Decoder
}

// GetEvent returns an event, with a slice of (optional) filter results for the event
func (t *TraceeInputSource) GetEvent() (Event, []bool, error) {
	var event TraceeEvent

	// todo: we currently don't know if tracee is in the middle of a write.
	// trying to decode an incomplete event will cause errors (only happens in "online" mode)
	for {
		err := t.dec.Decode(&event)
		if err != nil {
			if err != io.EOF {
				return Event{}, nil, fmt.Errorf("Error while decoding event: %v\n", err)
			} else {
				time.Sleep(100 * time.Millisecond)
			}
		} else {
			break
		}
	}

	return Event{Type: "tracee", Name: event.EventName, Data: event}, nil, nil
}

func (t *TraceeInputSource) Close() {
	t.file.Close()
}

// TraceeEvent represents an event from Tracee, and should match Event struct of Tracee
type TraceeEvent struct {
	Timestamp           float64
	ProcessID           int
	ThreadID            int
	ParentProcessID     int
	HostProcessID       int
	HostThreadID        int
	HostParentProcessID int
	UserID              int
	MountNS             int
	PIDNS               int
	ProcessName         string
	HostName            string
	EventID             int
	EventName           string
	ArgsNum             int
	ReturnValue         int
	Args                []TraceeArgument
}

type TraceeArgument struct {
	Name  string
	Value interface{}
}

// New creates a new TraceeInputSource instance
// evFilters are filters that will be evaluated before returning an event
func NewTraceeIS(inFilePath string, evFilters []EventFilter) (*TraceeInputSource, error) {
	fi, err := os.Stat(inFilePath)
	if err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("Invalid Tracee input file path: %s", inFilePath)
	}

	file, err := os.Open(inFilePath)
	if err != nil {
		return nil, fmt.Errorf("Failed to open tracee input file path: %s", inFilePath)
	}
	dec := gob.NewDecoder(file)

	// todo: use filters

	// create TraceeInputSource
	s := &TraceeInputSource{
		file: file,
		dec:  dec,
	}

	return s, nil
}
