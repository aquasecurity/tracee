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
			out: out,
			err: err,
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
	ParentProcessID int           `json:"parentProcessid"`
	UserID          int           `json:"userId"`
	MountNS         int           `json:"mountNS"`
	PIDNS           int           `json:"pidNS"`
	ProcessName     string        `json:"processName"`
	HostName        string        `json:"hostName"`
	EventID         int           `json:"eventId,string"`
	EventName       string        `json:"eventName"`
	ArgsNum         int           `json:"argsNum"`
	ReturnValue     int           `json:"returnValue"`
	Args            []interface{} `json:"args"`
}

func newEvent(ctx context, args []interface{}) (Event, error) {
	e := Event{
		Timestamp:       float64(ctx.Ts) / 1000000.0,
		ProcessID:       int(ctx.Pid),
		ThreadID:        int(ctx.Tid),
		ParentProcessID: int(ctx.Ppid),
		UserID:          int(ctx.Uid),
		MountNS:         int(ctx.Mnt_id),
		PIDNS:           int(ctx.Pid_id),
		ProcessName:     string(bytes.TrimRight(ctx.Comm[:], string(0))),
		HostName:        string(bytes.TrimRight(ctx.Uts_name[:], string(0))),
		EventID:         int(ctx.Event_id),
		EventName:       EventsIDToEvent[int32(ctx.Event_id)].Name,
		ArgsNum:         int(ctx.Argnum),
		ReturnValue:     int(ctx.Retval),
		Args:            args,
	}
	return e, nil
}

type tableEventPrinter struct {
	tracee *Tracee
	out    io.Writer
	err    io.Writer
}

func (p tableEventPrinter) Init() {}

func (p tableEventPrinter) Preamble() {
	fmt.Fprintf(p.out, "%-14s %-16s %-12s %-12s %-6s %-16s %-16s %-6s %-6s %-6s %-12s %s", "TIME(s)", "UTS_NAME", "MNT_NS", "PID_NS", "UID", "EVENT", "COMM", "PID", "TID", "PPID", "RET", "ARGS")
	fmt.Fprintln(p.out)
}

func (p tableEventPrinter) Print(event Event) {
	fmt.Fprintf(p.out, "%-14f %-16s %-12d %-12d %-6d %-16s %-16s %-6d %-6d %-6d %-12d", event.Timestamp, event.HostName, event.MountNS, event.PIDNS, event.UserID, event.EventName, event.ProcessName, event.ProcessID, event.ThreadID, event.ParentProcessID, event.ReturnValue)
	for _, value := range event.Args {
		fmt.Fprintf(p.out, "%v ", value)
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
