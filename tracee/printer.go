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
)

type eventPrinter interface {
	// Init serves as the initializer method for every event Printer type
	Init() error
	// Preamble prints something before event printing begins (one time)
	Preamble()
	// Epilogue prints something after event printing ends (one time)
	Epilogue(stats statsStore)
	// Print prints a single event
	Print(event Event)
	// Error prints a single error
	Error(err error)
}

func newEventPrinter(kind string, containerMode bool, out io.Writer, err io.Writer) (eventPrinter, error) {
	var res eventPrinter
	var initError error
	switch {
	case kind == "table":
		res = &tableEventPrinter{
			out:           out,
			err:           err,
			containerMode: containerMode,
			fields: nil,
		}
	case kind == "json":
		res = &jsonEventPrinter{
			out: out,
			err: err,
		}
	case kind == "gob":
		res = &gobEventPrinter{
			out: gob.NewEncoder(out),
			err: gob.NewEncoder(err),
		}
	case strings.HasPrefix(kind, "table="):
		res = &tableEventPrinter{
			out:           out,
			err:           err,
			containerMode: containerMode,
			fields: strings.Split(strings.Split(kind, "=")[1], ","),
		}
	case strings.HasPrefix(kind, "go-template="):
		res = &templateEventPrinter{
			out:           out,
			err:           err,
			containerMode: containerMode,
			templatePath: strings.Split(kind, "=")[1],
		}
	}
	initError = res.Init()
	if initError != nil {
		return nil, initError
	}
	return res, nil
}

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
	Args                []Argument `json:"args"` //Arguments are ordered according their appearance in the original event
}

// Argument holds the information for one argument
type Argument struct {
	Name  string      `json:"name"`
	Value interface{} `json:"value"`
}

func newEvent(ctx context, argsNames []string, args []interface{}) (Event, error) {
	e := Event{
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
		ProcessName:         string(bytes.TrimRight(ctx.Comm[:], string(0))),
		HostName:            string(bytes.TrimRight(ctx.UtsName[:], string(0))),
		EventID:             int(ctx.EventID),
		EventName:           EventsIDToEvent[int32(ctx.EventID)].Name,
		ArgsNum:             int(ctx.Argnum),
		ReturnValue:         int(ctx.Retval),
		Args:                make([]Argument, 0, len(args)),
	}
	for i, arg := range args {
		e.Args = append(e.Args, Argument{
			Name:  argsNames[i],
			Value: arg,
		})
	}
	return e, nil
}

type tableEventPrinter struct {
	tracee        *Tracee
	out           io.Writer
	err           io.Writer
	fields        []string
	fieldTemplate **template.Template
	containerMode bool
}


func (p *tableEventPrinter) Init() (error) { 
	if p.fields != nil {
		var buffer bytes.Buffer
		for _, field := range p.fields {
			switch strings.TrimSpace(field) {
				case "ts": fallthrough
			    case "timestamp": fallthrough
				case "Timestamp":  buffer.WriteString(fmt.Sprintf("%-14s ","{{.Timestamp}}"))
				case "pid": fallthrough
				case "processId": fallthrough
				case "ProcessID":  buffer.WriteString(fmt.Sprintf("%-15s ","{{.ProcessID}} "))
				case "tid": fallthrough
				case "threadId": fallthrough
				case "ThreadID": buffer.WriteString(fmt.Sprintf("%-15s ","{{.ThreadID}} "))
				case "ppid": fallthrough
				case "parentProcessId": fallthrough
				case "ParentProcessID": buffer.WriteString(fmt.Sprintf("%-15s ","{{.ParentProcessID}} "))
				case "hostpid": fallthrough
				case "hostProcessId": fallthrough
				case "HostProcessID": buffer.WriteString(fmt.Sprintf("%-15s ","{{.HostProcessID}} "))
				case "hosttid": fallthrough
				case "hostThreadId": fallthrough
				case "HostThreadID": buffer.WriteString(fmt.Sprintf("%-15s ","{{.HostThreadID}} "))
				case "hostppid": fallthrough
				case "hostParentProcessId": fallthrough
				case "HostParentProcessID": buffer.WriteString(fmt.Sprintf("%-15s ","{{.HostParentProcessID}} "))
				case "uid": fallthrough
				case "userId": fallthrough
				case "UserID": buffer.WriteString(fmt.Sprintf("%-6s ","{{.UserID}} "))
				case "mountNamespace": fallthrough
				case "mountns": fallthrough
				case "MountNS": buffer.WriteString(fmt.Sprintf("%-14s ","{{.MountNS}} "))
				case "pidns": fallthrough
				case "pidNamespace": fallthrough
				case "PIDNS": buffer.WriteString(fmt.Sprintf("%-14s ","{{.PIDNS}} "))
				case "procname": fallthrough
				case "processName": fallthrough
				case "ProcessName": buffer.WriteString(fmt.Sprintf("%-14s ","{{.ProcessName}} "))
				case "hostName": fallthrough
				case "HostName": buffer.WriteString(fmt.Sprintf("%-14s ","{{.HostName}} "))
				case "eventId": fallthrough
				case "EventID": buffer.WriteString(fmt.Sprintf("%-6s ","{{.EventID}} "))
				case "eventName": fallthrough
				case "EventName": buffer.WriteString(fmt.Sprintf("%-20s ","{{.EventName}} "))
				case "argsNum": fallthrough
				case "ArgsNum": buffer.WriteString(fmt.Sprintf("%-20s ","{{.ArgsNum}} "))
				case "returnValue": fallthrough
				case "ReturnValue": buffer.WriteString(fmt.Sprintf("%-20s ","{{.ReturnValue}} "))
				case "args": fallthrough
				case "Args": buffer.WriteString(fmt.Sprintf("%s ","{{.Args}} "))
			}
		}
		bufString := buffer.String()
		tmpl, err := template.New("table").Parse(bufString)
		if err != nil {
			return err
		}
		p.fieldTemplate = &tmpl
	}
	return nil 
}

func (p tableEventPrinter) Preamble() {
	if p.fields != nil {
		fmt.Fprintf(p.out, strings.Join(p.fields, "  "))
	} else {
		if p.containerMode {
			fmt.Fprintf(p.out, "%-14s %-6s %-16s %-15s %-15s %-16s %-20s %s", "TIME(s)", "UID", "COMM", "PID/host", "TID/host", "RET", "EVENT", "ARGS")
		} else {
			fmt.Fprintf(p.out, "%-14s %-6s %-16s %-7s %-7s %-16s %-20s %s", "TIME(s)", "UID", "COMM", "PID", "TID", "RET", "EVENT", "ARGS")
		}
	}
	fmt.Fprintln(p.out)
}

func (p tableEventPrinter) Print(event Event) {
	if p.fields != nil {
		err := (*p.fieldTemplate).Execute(p.out, event)
		if err != nil {
			p.Error(err)
		}
	} else {
		if p.containerMode {
			fmt.Fprintf(p.out, "%-14f %-6d %-16s %-7d/%-7d %-7d/%-7d %-16d %-20s ", event.Timestamp, event.UserID, event.ProcessName, event.ProcessID, event.HostProcessID, event.ThreadID, event.HostThreadID, event.ReturnValue, event.EventName)
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


type templateEventPrinter struct {
	tracee        *Tracee
	out           io.Writer
	err           io.Writer
	containerMode bool
	templatePath  string
	templateObj   **template.Template
}

func (p *templateEventPrinter) Init() (error) {
	tmplPath := p.templatePath
	if tmplPath != "" {
		tmpl, err := template.ParseFiles(tmplPath)
		if err != nil {
			return err
		}
		p.templateObj = &tmpl
	} else {
		return errors.New("Please specify a go-template for event-based output")
	}
	return nil
}

func (p templateEventPrinter) Preamble() {}

func (p templateEventPrinter) Error(err error) {
	fmt.Fprintf(p.err, "%v", err)
}


func (p templateEventPrinter) Print(event Event) {
	if p.templateObj != nil {
		err := (*p.templateObj).Execute(p.out, event)
		if err != nil {
			p.Error(err)
		}
	} else {
		fmt.Fprintf(p.out, "Template Obj is nil")
	}	
}

func (p templateEventPrinter) Epilogue(stats statsStore) {}

type jsonEventPrinter struct {
	out io.Writer
	err io.Writer
}

func (p jsonEventPrinter) Init() (error) { return nil }

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

func (p *gobEventPrinter) Init() (error) { return nil }

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
