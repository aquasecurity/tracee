package main

import (
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/template"
	"time"

	"github.com/aquasecurity/tracee/pkg/external"
)

type eventPrinter interface {
	// Init serves as the initializer method for every event Printer type
	Init() error
	// Preamble prints something before event printing begins (one time)
	Preamble()
	// Epilogue prints something after event printing ends (one time)
	Epilogue(stats external.Stats)
	// Print prints a single event
	Print(event external.Event)
	// Error prints a single error
	Error(err error)
	// dispose of resources
	Close()
}

func newEventPrinter(kind string, containerMode bool, relativeTS bool, out io.WriteCloser, err io.WriteCloser) (eventPrinter, error) {
	var res eventPrinter
	var initError error
	switch {
	case kind == "ignore":
		res = &ignoreEventPrinter{
			err: err,
		}
	case kind == "table":
		res = &tableEventPrinter{
			out:           out,
			err:           err,
			verbose:       false,
			containerMode: containerMode,
			relativeTS:    relativeTS,
		}
	case kind == "table-verbose":
		res = &tableEventPrinter{
			out:           out,
			err:           err,
			verbose:       true,
			containerMode: containerMode,
			relativeTS:    relativeTS,
		}
	case kind == "json":
		res = &jsonEventPrinter{
			out: out,
			err: err,
		}
	case kind == "gob":
		res = &gobEventPrinter{
			out: out,
			err: err,
		}
	case strings.HasPrefix(kind, "gotemplate="):
		res = &templateEventPrinter{
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

type tableEventPrinter struct {
	out           io.WriteCloser
	err           io.WriteCloser
	verbose       bool
	containerMode bool
	relativeTS    bool
}

func (p tableEventPrinter) Init() error { return nil }

func (p tableEventPrinter) Preamble() {
	if p.verbose {
		if p.containerMode {
			fmt.Fprintf(p.out, "%-16s %-16s %-13s %-12s %-12s %-6s %-16s %-15s %-15s %-15s %-16s %-20s %s", "TIME", "UTS_NAME", "CONTAINER_ID", "MNT_NS", "PID_NS", "UID", "COMM", "PID/host", "TID/host", "PPID/host", "RET", "EVENT", "ARGS")
		} else {
			fmt.Fprintf(p.out, "%-16s %-16s %-13s %-12s %-12s %-6s %-16s %-7s %-7s %-7s %-16s %-20s %s", "TIME", "UTS_NAME", "CONTAINER_ID", "MNT_NS", "PID_NS", "UID", "COMM", "PID", "TID", "PPID", "RET", "EVENT", "ARGS")
		}
	} else {
		if p.containerMode {
			fmt.Fprintf(p.out, "%-16s %-13s %-6s %-16s %-15s %-15s %-16s %-20s %s", "TIME", "CONTAINER_ID", "UID", "COMM", "PID/host", "TID/host", "RET", "EVENT", "ARGS")
		} else {
			fmt.Fprintf(p.out, "%-16s %-6s %-16s %-7s %-7s %-16s %-20s %s", "TIME", "UID", "COMM", "PID", "TID", "RET", "EVENT", "ARGS")
		}
	}
	fmt.Fprintln(p.out)
}

func (p tableEventPrinter) Print(event external.Event) {
	ut := time.Unix(0, int64(event.Timestamp))
	if p.relativeTS {
		ut = ut.UTC()
	}
	timestamp := fmt.Sprintf("%02d:%02d:%02d:%06d", ut.Hour(), ut.Minute(), ut.Second(), ut.Nanosecond()/1000)

	containerId := event.ContainerID
	if len(containerId) > 12 {
		containerId = containerId[:12]
	}

	if p.verbose {
		if p.containerMode {
			fmt.Fprintf(p.out, "%-16s %-16s %-13s %-12d %-12d %-6d %-16s %-7d/%-7d %-7d/%-7d %-7d/%-7d %-16d %-20s ", timestamp, event.HostName, containerId, event.MountNS, event.PIDNS, event.UserID, event.ProcessName, event.ProcessID, event.HostProcessID, event.ThreadID, event.HostThreadID, event.ParentProcessID, event.ParentProcessID, event.ReturnValue, event.EventName)
		} else {
			fmt.Fprintf(p.out, "%-16s %-16s %-13s %-12d %-12d %-6d %-16s %-7d %-7d %-7d %-16d %-20s ", timestamp, event.HostName, containerId, event.MountNS, event.PIDNS, event.UserID, event.ProcessName, event.ProcessID, event.ThreadID, event.ParentProcessID, event.ReturnValue, event.EventName)
		}
	} else {
		if p.containerMode {
			fmt.Fprintf(p.out, "%-16s %-13s %-6d %-16s %-7d/%-7d %-7d/%-7d %-16d %-20s ", timestamp, containerId, event.UserID, event.ProcessName, event.ProcessID, event.HostProcessID, event.ThreadID, event.HostThreadID, event.ReturnValue, event.EventName)
		} else {
			fmt.Fprintf(p.out, "%-16s %-6d %-16s %-7d %-7d %-16d %-20s ", timestamp, event.UserID, event.ProcessName, event.ProcessID, event.ThreadID, event.ReturnValue, event.EventName)
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

func (p tableEventPrinter) Epilogue(stats external.Stats) {
	fmt.Println()
	fmt.Fprintf(p.out, "End of events stream\n")
	fmt.Fprintf(p.out, "Stats: %+v\n", stats)
}

func (p tableEventPrinter) Close() {
}

type templateEventPrinter struct {
	out           io.WriteCloser
	err           io.WriteCloser
	containerMode bool
	templatePath  string
	templateObj   **template.Template
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
	fmt.Fprintf(p.err, "%v\n", err)
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

func (p templateEventPrinter) Epilogue(stats external.Stats) {}

func (p templateEventPrinter) Close() {
}

type jsonEventPrinter struct {
	out io.WriteCloser
	err io.WriteCloser
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

func (p jsonEventPrinter) Error(err error) {
	fmt.Fprintf(p.err, "%v\n", err)
}

func (p jsonEventPrinter) Epilogue(stats external.Stats) {}

func (p jsonEventPrinter) Close() {
}

// gobEventPrinter is printing events using golang's builtin Gob serializer
type gobEventPrinter struct {
	out    io.WriteCloser
	err    io.WriteCloser
	outEnc *gob.Encoder
}

func (p *gobEventPrinter) Init() error {
	p.outEnc = gob.NewEncoder(p.out)
	gob.Register(external.Event{})
	gob.Register(external.SlimCred{})
	gob.Register(make(map[string]string))
	return nil
}

func (p *gobEventPrinter) Preamble() {}

func (p *gobEventPrinter) Print(event external.Event) {
	err := p.outEnc.Encode(event)
	if err != nil {
		p.Error(err)
	}
}

func (p *gobEventPrinter) Error(err error) {
	fmt.Fprintf(p.err, "%v\n", err)
}

func (p *gobEventPrinter) Epilogue(stats external.Stats) {}

func (p gobEventPrinter) Close() {
}

// ignoreEventPrinter ignores events
type ignoreEventPrinter struct {
	err io.WriteCloser
}

func (p *ignoreEventPrinter) Init() error {
	return nil
}

func (p *ignoreEventPrinter) Preamble() {}

func (p *ignoreEventPrinter) Print(event external.Event) {}

func (p *ignoreEventPrinter) Error(err error) {
	fmt.Fprintf(p.err, "%v\n", err)
}

func (p *ignoreEventPrinter) Epilogue(stats external.Stats) {}

func (p ignoreEventPrinter) Close() {}
