package streamers

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/aquasecurity/tracee/tracee-ebpf/engine/config"
	"github.com/aquasecurity/tracee/tracee-ebpf/engine/consts"
	"github.com/aquasecurity/tracee/tracee-ebpf/engine/event"
	"github.com/aquasecurity/tracee/tracee-ebpf/engine/stats"
)

type Streamer interface {
	// TODO too many functions
	Stream(*event.Event)
	Close()
	Preamble()
	Epilogue(stats.Store)
	Error(error)
	Init() error
	SetId(uint64)
	Id() uint64
}

type tableEventPrinter struct {
	out           io.WriteCloser
	err           io.WriteCloser
	verbose       bool
	containerMode bool
	id            uint64
}

type templateEventPrinter struct {
	out           io.WriteCloser
	err           io.WriteCloser
	containerMode bool
	templatePath  string
	templateObj   **template.Template
	id            uint64
}

type jsonEventPrinter struct {
	out io.WriteCloser
	err io.WriteCloser
	id  uint64
}

// gobEventPrinter is printing events using golang's builtin Gob serializer
type gobEventPrinter struct {
	out    io.WriteCloser
	err    io.WriteCloser
	outEnc *gob.Encoder
	errEnc *gob.Encoder
	id     uint64
}

func (p *templateEventPrinter) SetId(id uint64) {
	p.id = id
}
func (p *templateEventPrinter) Id() uint64 {
	return p.id
}
func (p *tableEventPrinter) SetId(id uint64) {
	p.id = id
}
func (p *tableEventPrinter) Id() uint64 {
	return p.id
}
func (p *jsonEventPrinter) SetId(id uint64) {
	p.id = id
}
func (p *jsonEventPrinter) Id() uint64 {
	return p.id
}
func (p *gobEventPrinter) SetId(id uint64) {
	p.id = id
}
func (p *gobEventPrinter) Id() uint64 {
	return p.id
}
func NewIOStreamer(cfg config.Config) (Streamer, error) {
	format := cfg.Output.Format
	outputPath := cfg.Output.OutPath
	errPath := cfg.Output.ErrPath
	containerMode := (cfg.Filter.ContFilter.Enabled && cfg.Filter.ContFilter.Value) ||
		(cfg.Filter.NewContFilter.Enabled && cfg.Filter.NewContFilter.Value)
	var err error
	outf := os.Stdout
	if outputPath != "" {
		dir := filepath.Dir(outputPath)
		os.MkdirAll(dir, 0755)
		os.Remove(outputPath)
		outf, err = os.Create(outputPath)
		if err != nil {
			return nil, err
		}
	}
	errf := os.Stderr
	if errPath != "" {
		dir := filepath.Dir(errPath)
		os.MkdirAll(dir, 0755)
		os.Remove(errPath)
		errf, err = os.Create(errPath)
		if err != nil {
			return nil, err
		}
	}
	printObj, err := newEventPrinter(format, containerMode, outf, errf)
	if err != nil {
		return nil, err
	}
	return printObj, nil
}

func newEventPrinter(kind string, containerMode bool, out io.WriteCloser, err io.WriteCloser) (Streamer, error) {
	var res Streamer
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

func NewEvent(ctx consts.Context, argMetas []event.ArgMeta, args []interface{}, StackAddresses []uint64) (event.Event, error) {
	e := event.Event{
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
		EventName:           consts.EventsIDToEvent[int32(ctx.EventID)].Name,
		ArgsNum:             int(ctx.Argnum),
		ReturnValue:         int(ctx.Retval),
		Args:                make([]event.Argument, 0, len(args)),
		StackAddresses:      StackAddresses,
	}
	for i, arg := range args {
		e.Args = append(e.Args, event.Argument{
			ArgMeta: argMetas[i],
			Value:   arg,
		})
	}
	return e, nil
}
func (p *tableEventPrinter) Init() error {
	return nil
}

func (p *tableEventPrinter) Preamble() {
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

func (p *tableEventPrinter) Stream(event *event.Event) {
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

func (p *tableEventPrinter) Error(err error) {
	fmt.Fprintf(p.err, "%v\n", err)
}

func (p *tableEventPrinter) Epilogue(stats stats.Store) {
	fmt.Println()
	fmt.Fprintf(p.out, "End of events stream\n")
	fmt.Fprintf(p.out, "stats: %+v\n", stats)
}

func (p *tableEventPrinter) Close() {}
func (p *jsonEventPrinter) Init() error {
	return nil
}

func (p *jsonEventPrinter) Preamble() {}

func (p *jsonEventPrinter) Stream(event *event.Event) {
	eBytes, err := json.Marshal(event)
	if err != nil {
		p.Error(err)
	}
	fmt.Fprintln(p.out, string(eBytes))
}

func (p *jsonEventPrinter) Error(e error) {
	eBytes, err := json.Marshal(e)
	if err != nil {
		return
	}
	fmt.Fprintln(p.err, string(eBytes))
}

func (p *jsonEventPrinter) Epilogue(stats stats.Store) {}

func (p *jsonEventPrinter) Close() {
}
func (p *gobEventPrinter) Init() error {
	p.outEnc = gob.NewEncoder(p.out)
	p.errEnc = gob.NewEncoder(p.err)
	return nil
}

func (p *gobEventPrinter) Preamble() {}

func (p *gobEventPrinter) Stream(event *event.Event) {
	err := p.outEnc.Encode(event)
	if err != nil {
		p.Error(err)
	}
}

func (p *gobEventPrinter) Error(e error) {
	_ = p.errEnc.Encode(e)
}

func (p *gobEventPrinter) Epilogue(stats stats.Store) {}

func (p gobEventPrinter) Close() {}

func (p *templateEventPrinter) Preamble() {}

func (p *templateEventPrinter) Error(err error) {
	fmt.Fprintf(p.err, "%v", err)
}

func (p *templateEventPrinter) Stream(event *event.Event) {
	if p.templateObj != nil {
		err := (*p.templateObj).Execute(p.out, event)
		if err != nil {
			p.Error(err)
		}
	} else {
		fmt.Fprintf(p.out, "Template Obj is nil")
	}
}

func (p *templateEventPrinter) Epilogue(stats stats.Store) {}

func (p *templateEventPrinter) Close() {}
