package tracee

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
)

type eventPrinter interface {
	// Preamble prints something before event printing begins (one time)
	Preamble()
	// Epilogue prints something after event printing ends (one time)
	Epilogue(stats statsStore)
	// Print prints a single event
	Print(event Event)
	// Error prints a single error
	Error(err error)
}

func newEventPrinter(kind string, out io.Writer, err io.Writer) eventPrinter {
	var res eventPrinter
	switch kind {
	case "table":
		res = &tableEventPrinter{
			out:     out,
			err:     err,
			verbose: false,
		}
	case "table-verbose":
		res = &tableEventPrinter{
			out:     out,
			err:     err,
			verbose: true,
		}
	case "json":
		res = &jsonEventPrinter{
			out: out,
			err: err,
		}
	case "gob":
		res = &gobEventPrinter{
			out: gob.NewEncoder(out),
			err: gob.NewEncoder(err),
		}
	}
	return res
}

// Event is a user facing data structure representing a single event
type Event struct {
	Timestamp       float64       `json:"timestamp"`
	ProcessID       int           `json:"processId"`
	ThreadID        int           `json:"threadId"`
	ParentProcessID int           `json:"parentProcessId"`
	UserID          int           `json:"userId"`
	MountNS         int           `json:"mountNamespace"`
	PIDNS           int           `json:"pidNamespace"`
	ProcessName     string        `json:"processName"`
	HostName        string        `json:"hostName"`
	EventID         int           `json:"eventId,string"`
	EventName       string        `json:"eventName"`
	ArgsNum         int           `json:"argsNum"`
	ReturnValue     int           `json:"returnValue"`
	ArgsNames       []string      `json:"argsNames"`
	Args            []interface{} `json:"args"`
}

func newEvent(ctx context, argsNames []string, args []interface{}) (Event, error) {
	e := Event{
		Timestamp:       float64(ctx.Ts) / 1000000.0,
		ProcessID:       int(ctx.Pid),
		ThreadID:        int(ctx.Tid),
		ParentProcessID: int(ctx.Ppid),
		UserID:          int(ctx.Uid),
		MountNS:         int(ctx.MntID),
		PIDNS:           int(ctx.PidID),
		ProcessName:     string(bytes.TrimRight(ctx.Comm[:], string(0))),
		HostName:        string(bytes.TrimRight(ctx.UtsName[:], string(0))),
		EventID:         int(ctx.EventID),
		EventName:       EventsIDToEvent[int32(ctx.EventID)].Name,
		ArgsNum:         int(ctx.Argnum),
		ReturnValue:     int(ctx.Retval),
		ArgsNames:       argsNames,
		Args:            args,
	}
	return e, nil
}

type tableEventPrinter struct {
	tracee  *Tracee
	out     io.Writer
	err     io.Writer
	verbose bool
}

func (p tableEventPrinter) Init() {}

func (p tableEventPrinter) Preamble() {
	if p.verbose {
		fmt.Fprintf(p.out, "%-14s %-16s %-12s %-12s %-6s %-16s %-6s %-6s %-6s %-16s %-20s %s", "TIME(s)", "UTS_NAME", "MNT_NS", "PID_NS", "UID", "COMM", "PID", "TID", "PPID", "RET", "EVENT", "ARGS")
	} else {
		fmt.Fprintf(p.out, "%-14s %-16s %-6s %-16s %-6s %-6s %-6s %-16s %-20s %s", "TIME(s)", "UTS_NAME", "UID", "COMM", "PID", "TID", "PPID", "RET", "EVENT", "ARGS")
	}
	fmt.Fprintln(p.out)
}

func (p tableEventPrinter) Print(event Event) {
	if p.verbose {
		fmt.Fprintf(p.out, "%-14f %-16s %-12d %-12d %-6d %-16s %-6d %-6d %-6d %-16d %-20s ", event.Timestamp, event.HostName, event.MountNS, event.PIDNS, event.UserID, event.ProcessName, event.ProcessID, event.ThreadID, event.ParentProcessID, event.ReturnValue, event.EventName)
	} else {
		fmt.Fprintf(p.out, "%-14f %-16s %-6d %-16s %-6d %-6d %-6d %-16d %-20s ", event.Timestamp, event.HostName, event.UserID, event.ProcessName, event.ProcessID, event.ThreadID, event.ParentProcessID, event.ReturnValue, event.EventName)
	}
	for i, value := range event.Args {
		fmt.Fprintf(p.out, "%s: %v ", event.ArgsNames[i], value)
	}
	fmt.Fprintln(p.out)
}

func (p tableEventPrinter) Error(err error) {
	fmt.Fprintf(p.err, "%v", err)
}

func (p tableEventPrinter) Epilogue(stats statsStore) {
	fmt.Println()
	fmt.Fprintf(p.out, "End of events stream\n")
	fmt.Fprintf(p.out, "Stats: %+v\n", stats)
	fmt.Fprintf(p.out, "Tracee is closing...\n")
}

type jsonEventPrinter struct {
	out io.Writer
	err io.Writer
}

func (p jsonEventPrinter) Init() {}

func (p jsonEventPrinter) Preamble() {}

func (p jsonEventPrinter) Print(event Event) {
	eBytes, err := json.Marshal(event)
	if err != nil {
		p.Error(err)
	}
	fmt.Fprintln(p.out, string(eBytes))
}

func (p jsonEventPrinter) Error(e error) {
	eBytes, err := json.Marshal(e)
	if err != nil {
		return
	}
	fmt.Fprintln(p.err, string(eBytes))
}

func (p jsonEventPrinter) Epilogue(stats statsStore) {}

type gobEventPrinter struct {
	out *gob.Encoder
	err *gob.Encoder
}

func (p *gobEventPrinter) Init() {
}

func (p *gobEventPrinter) Preamble() {}

func (p *gobEventPrinter) Print(event Event) {
	err := p.out.Encode(event)
	if err != nil {
		p.Error(err)
	}
}

func (p *gobEventPrinter) Error(e error) {
	_ = p.err.Encode(e)
}

func (p *gobEventPrinter) Epilogue(stats statsStore) {}
