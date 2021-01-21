package tracee

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/template"

	"github.com/aquasecurity/tracee/tracee/external"
)

type eventPrinter interface {
	// Init serves as the initializer method for every event Printer type
	Init() error
	// Preamble prints something before event printing begins (one time)
	Preamble()
	// Epilogue prints something after event printing ends (one time)
	Epilogue(stats statsStore)
	// Print prints a single event
	Print(event external.Event)
	// Error prints a single error
	Error(err error)
	// dispose of resources
	Close()
}

var eotEvent external.Event = external.Event{EventName: string(rune(4))}

func newEventPrinter(kind string, containerMode bool, eot bool, out io.WriteCloser, err io.WriteCloser) (eventPrinter, error) {
	var res eventPrinter
	var initError error
	switch {
	case kind == "table":
		res = &tableEventPrinter{
			out:           out,
			err:           err,
			verbose:       false,
			containerMode: containerMode,
		}
	case kind == "table-verbose":
		res = &tableEventPrinter{
			out:           out,
			err:           err,
			verbose:       true,
			containerMode: containerMode,
		}
	case kind == "json":
		res = &jsonEventPrinter{
			eot: eot,
			out: out,
			err: err,
		}
	case kind == "gob":
		res = &gobEventPrinter{
			eot: eot,
			out: out,
			err: err,
		}
	case strings.HasPrefix(kind, "gotemplate="):
		res = &templateEventPrinter{
			eot:           eot,
			out:           out,
			err:           err,
			containerMode: containerMode,
			templatePath:  strings.Split(kind, "=")[1],
		}
	}
	initError = res.Init()
	if initError != nil {
		return nil, initError
	}
	return res, nil
}

func newEvent(ctx context, argMetas []external.ArgMeta, args []interface{}, StackAddresses []uint64) (external.Event, error) {
	e := external.Event{
		Timestamp:           float64(ctx.Ts) / 1000000.0,
		ProcessID:           int(ctx.Pid),
		ThreadID:            int(ctx.Tid),
		ParentProcessID:     int(ctx.Ppid),
		HostProcessID:       int(ctx.HostPid),
		HostThreadID:        int(ctx.HostTid),
		HostParentProcessID: int(ctx.HostPpid),
		UserID:              int(ctx.Uid),
		MountNS:             int(ctx.MntID),
		PIDNS:               int(ctx.PidID),
		ProcessName:         string(bytes.TrimRight(ctx.Comm[:], "\x00")),
		HostName:            string(bytes.TrimRight(ctx.UtsName[:], "\x00")),
		EventID:             int(ctx.EventID),
		EventName:           EventsIDToEvent[int32(ctx.EventID)].Name,
		ArgsNum:             int(ctx.Argnum),
		ReturnValue:         int(ctx.Retval),
		Args:                make([]external.Argument, 0, len(args)),
		StackAddresses:      StackAddresses,
	}
	for i, arg := range args {
		e.Args = append(e.Args, external.Argument{
			ArgMeta: argMetas[i],
			Value:   arg,
		})
	}
	return e, nil
}

type tableEventPrinter struct {
	tracee        *Tracee
	out           io.WriteCloser
	err           io.WriteCloser
	verbose       bool
	containerMode bool
}

func (p tableEventPrinter) Init() error { return nil }

func (p tableEventPrinter) Preamble() {
	if p.verbose {
		if p.containerMode {
			fmt.Fprintf(p.out, "%-14s %-16s %-12s %-12s %-6s %-16s %-15s %-15s %-15s %-16s %-20s %s", "TIME(s)", "UTS_NAME", "MNT_NS", "PID_NS", "UID", "COMM", "PID/host", "TID/host", "PPID/host", "RET", "EVENT", "ARGS")
		} else {
			fmt.Fprintf(p.out, "%-14s %-16s %-12s %-12s %-6s %-16s %-7s %-7s %-7s %-16s %-20s %s", "TIME(s)", "UTS_NAME", "MNT_NS", "PID_NS", "UID", "COMM", "PID", "TID", "PPID", "RET", "EVENT", "ARGS")
		}
	} else {
		if p.containerMode {
			fmt.Fprintf(p.out, "%-14s %-16s %-6s %-16s %-15s %-15s %-16s %-20s %s", "TIME(s)", "UTS_NAME", "UID", "COMM", "PID/host", "TID/host", "RET", "EVENT", "ARGS")
		} else {
			fmt.Fprintf(p.out, "%-14s %-6s %-16s %-7s %-7s %-16s %-20s %s", "TIME(s)", "UID", "COMM", "PID", "TID", "RET", "EVENT", "ARGS")
		}
	}
	fmt.Fprintln(p.out)
}

func (p tableEventPrinter) Print(event external.Event) {
	if p.verbose {
		if p.containerMode {
			fmt.Fprintf(p.out, "%-14f %-16s %-12d %-12d %-6d %-16s %-7d/%-7d %-7d/%-7d %-7d/%-7d %-16d %-20s ", event.Timestamp, event.HostName, event.MountNS, event.PIDNS, event.UserID, event.ProcessName, event.ProcessID, event.HostProcessID, event.ThreadID, event.HostThreadID, event.ParentProcessID, event.ParentProcessID, event.ReturnValue, event.EventName)
		} else {
			fmt.Fprintf(p.out, "%-14f %-16s %-12d %-12d %-6d %-16s %-7d %-7d %-7d %-16d %-20s ", event.Timestamp, event.HostName, event.MountNS, event.PIDNS, event.UserID, event.ProcessName, event.ProcessID, event.ThreadID, event.ParentProcessID, event.ReturnValue, event.EventName)
		}
	} else {
		if p.containerMode {
			fmt.Fprintf(p.out, "%-14f %-16s %-6d %-16s %-7d/%-7d %-7d/%-7d %-16d %-20s ", event.Timestamp, event.HostName, event.UserID, event.ProcessName, event.ProcessID, event.HostProcessID, event.ThreadID, event.HostThreadID, event.ReturnValue, event.EventName)
		} else {
			fmt.Fprintf(p.out, "%-14f %-6d %-16s %-7d %-7d %-16d %-20s ", event.Timestamp, event.UserID, event.ProcessName, event.ProcessID, event.ThreadID, event.ReturnValue, event.EventName)
		}
	}
	for i, arg := range event.Args {
		if i == 0 {
			fmt.Fprintf(p.out, "%s: %v", arg.Name, arg.Value)
		} else {
			fmt.Fprintf(p.out, ", %s: %v", arg.Name, arg.Value)
		}
	}
	fmt.Fprintln(p.out)
}

func (p tableEventPrinter) Error(err error) {
	fmt.Fprintf(p.err, "%v\n", err)
}

func (p tableEventPrinter) Epilogue(stats statsStore) {
	fmt.Println()
	fmt.Fprintf(p.out, "End of events stream\n")
	fmt.Fprintf(p.out, "Stats: %+v\n", stats)
}

func (p tableEventPrinter) Close() {
	p.out.Close()
	p.err.Close()
}

type templateEventPrinter struct {
	tracee        *Tracee
	out           io.WriteCloser
	err           io.WriteCloser
	containerMode bool
	templatePath  string
	templateObj   **template.Template
	eot           bool
}

func (p *templateEventPrinter) Init() error {
	tmplPath := p.templatePath
	if tmplPath != "" {
		tmpl, err := template.ParseFiles(tmplPath)
		if err != nil {
			return err
		}
		p.templateObj = &tmpl
	} else {
		return errors.New("Please specify a gotemplate for event-based output")
	}
	return nil
}

func (p templateEventPrinter) Preamble() {}

func (p templateEventPrinter) Error(err error) {
	fmt.Fprintf(p.err, "%v", err)
}

func (p templateEventPrinter) Print(event external.Event) {
	if p.templateObj != nil {
		err := (*p.templateObj).Execute(p.out, event)
		if err != nil {
			p.Error(err)
		}
	} else {
		fmt.Fprintf(p.out, "Template Obj is nil")
	}
}

func (p templateEventPrinter) Epilogue(stats statsStore) {
	if p.eot {
		p.Print(eotEvent)
	}
}

func (p templateEventPrinter) Close() {
	p.out.Close()
	p.err.Close()
}

type jsonEventPrinter struct {
	out io.WriteCloser
	err io.WriteCloser
	eot bool
}

func (p jsonEventPrinter) Init() error { return nil }

func (p jsonEventPrinter) Preamble() {}

func (p jsonEventPrinter) Print(event external.Event) {
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

func (p jsonEventPrinter) Epilogue(stats statsStore) {
	if p.eot {
		p.Print(eotEvent)
	}
}

func (p jsonEventPrinter) Close() {
	p.out.Close()
	p.err.Close()
}

// gobEventPrinter is printing events using golang's builtin Gob serializer
// an additional event is added at the end to signal end of transmission
// this event can be identified by it's "EventName" which will be the ASCII "End Of Transmission" character
type gobEventPrinter struct {
	out    io.WriteCloser
	err    io.WriteCloser
	outEnc *gob.Encoder
	errEnc *gob.Encoder
	eot    bool
}

func (p *gobEventPrinter) Init() error {
	p.outEnc = gob.NewEncoder(p.out)
	p.errEnc = gob.NewEncoder(p.err)
	return nil
}

func (p *gobEventPrinter) Preamble() {}

func (p *gobEventPrinter) Print(event external.Event) {
	err := p.outEnc.Encode(event)
	if err != nil {
		p.Error(err)
	}
}

func (p *gobEventPrinter) Error(e error) {
	_ = p.errEnc.Encode(e)
}

func (p *gobEventPrinter) Epilogue(stats statsStore) {
	if p.eot {
		p.Print(eotEvent)
	}
}

func (p gobEventPrinter) Close() {
	p.out.Close()
	p.err.Close()
}
