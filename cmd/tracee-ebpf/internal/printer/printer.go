package printer

import (
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/template"
	"time"

	"github.com/aquasecurity/tracee/pkg/metrics"
	"github.com/aquasecurity/tracee/types/trace"
)

type EventPrinter interface {
	// Init serves as the initializer method for every event Printer type
	Init() error
	// Preamble prints something before event printing begins (one time)
	Preamble()
	// Epilogue prints something after event printing ends (one time)
	Epilogue(stats metrics.Stats)
	// Print prints a single event
	Print(event trace.Event)
	// Error prints a single error
	Error(err error)
	// dispose of resources
	Close()
}

type Config struct {
	Kind          string
	OutPath       string
	OutFile       io.WriteCloser
	ErrPath       string
	ErrFile       io.WriteCloser
	ContainerMode bool
	RelativeTS    bool
}

func New(config Config) (EventPrinter, error) {
	var res EventPrinter
	kind := config.Kind

	if config.OutFile == nil {
		return res, fmt.Errorf("out file is not set")
	}
	if config.ErrFile == nil {
		return res, fmt.Errorf("err file is not set")
	}

	switch {
	case kind == "ignore":
		res = &ignoreEventPrinter{
			err: config.ErrFile,
		}
	case kind == "table":
		res = &tableEventPrinter{
			out:           config.OutFile,
			err:           config.ErrFile,
			verbose:       false,
			containerMode: config.ContainerMode,
			relativeTS:    config.RelativeTS,
		}
	case kind == "table-verbose":
		res = &tableEventPrinter{
			out:           config.OutFile,
			err:           config.ErrFile,
			verbose:       true,
			containerMode: config.ContainerMode,
			relativeTS:    config.RelativeTS,
		}
	case kind == "json":
		res = &jsonEventPrinter{
			out: config.OutFile,
			err: config.ErrFile,
		}
	case kind == "gob":
		res = &gobEventPrinter{
			out: config.OutFile,
			err: config.ErrFile,
		}
	case strings.HasPrefix(kind, "gotemplate="):
		res = &templateEventPrinter{
			out:           config.OutFile,
			err:           config.ErrFile,
			containerMode: config.ContainerMode,
			templatePath:  strings.Split(kind, "=")[1],
		}
	}
	err := res.Init()
	if err != nil {
		return nil, err
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

func (p tableEventPrinter) Print(event trace.Event) {
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
			fmt.Fprintf(p.out, "%-16s %-16s %-13s %-12d %-12d %-6d %-16s %-7d/%-7d %-7d/%-7d %-7d/%-7d %-16d %-20s ", timestamp, event.HostName, containerId, event.MountNS, event.PIDNS, event.UserID, event.ProcessName, event.ProcessID, event.HostProcessID, event.ThreadID, event.HostThreadID, event.ParentProcessID, event.HostParentProcessID, event.ReturnValue, event.EventName)
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

func (p tableEventPrinter) Epilogue(stats metrics.Stats) {
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
		return errors.New("please specify a gotemplate for event-based output")
	}
	return nil
}

func (p templateEventPrinter) Preamble() {}

func (p templateEventPrinter) Error(err error) {
	fmt.Fprintf(p.err, "%v\n", err)
}

func (p templateEventPrinter) Print(event trace.Event) {
	if p.templateObj != nil {
		err := (*p.templateObj).Execute(p.out, event)
		if err != nil {
			p.Error(err)
		}
	} else {
		fmt.Fprintf(p.out, "Template Obj is nil")
	}
}

func (p templateEventPrinter) Epilogue(stats metrics.Stats) {}

func (p templateEventPrinter) Close() {
}

type jsonEventPrinter struct {
	out io.WriteCloser
	err io.WriteCloser
}

func (p jsonEventPrinter) Init() error { return nil }

func (p jsonEventPrinter) Preamble() {}

func (p jsonEventPrinter) Print(event trace.Event) {
	eBytes, err := json.Marshal(event)
	if err != nil {
		p.Error(err)
	}
	fmt.Fprintln(p.out, string(eBytes))
}

func (p jsonEventPrinter) Error(err error) {
	fmt.Fprintf(p.err, "%v\n", err)
}

func (p jsonEventPrinter) Epilogue(stats metrics.Stats) {}

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
	gob.Register(trace.Event{})
	gob.Register(trace.SlimCred{})
	gob.Register(make(map[string]string))
	gob.Register(trace.PktMeta{})
	gob.Register([]trace.HookedSymbolData{})
	gob.Register(map[string]trace.HookedSymbolData{})
	gob.Register([]trace.DnsQueryData{})
	gob.Register([]trace.DnsResponseData{})
	return nil
}

func (p *gobEventPrinter) Preamble() {}

func (p *gobEventPrinter) Print(event trace.Event) {
	err := p.outEnc.Encode(event)
	if err != nil {
		p.Error(err)
	}
}

func (p *gobEventPrinter) Error(err error) {
	fmt.Fprintf(p.err, "%v\n", err)
}

func (p *gobEventPrinter) Epilogue(stats metrics.Stats) {}

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

func (p *ignoreEventPrinter) Print(event trace.Event) {}

func (p *ignoreEventPrinter) Error(err error) {
	fmt.Fprintf(p.err, "%v\n", err)
}

func (p *ignoreEventPrinter) Epilogue(stats metrics.Stats) {}

func (p ignoreEventPrinter) Close() {}
