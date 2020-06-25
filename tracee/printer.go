package tracee

import (
	"encoding/json"
	"fmt"
	"io"
)

type eventPrinter interface {
	// Preamble prints something before event printing begins (one time)
	Preamble()
	// Epilogue prints something after event printing ends (one time)
	Epilogue()
	// Print prints a single event
	Print(ctx context, args []interface{})
}

type tableEventPrinter struct {
	tracee *Tracee
	out    io.Writer
}

func (p tableEventPrinter) Preamble() {
	fmt.Fprintf(p.out, "%-14s %-16s %-12s %-12s %-6s %-16s %-16s %-6s %-6s %-6s %-12s %s", "TIME(s)", "UTS_NAME", "MNT_NS", "PID_NS", "UID", "EVENT", "COMM", "PID", "TID", "PPID", "RET", "ARGS")
	fmt.Fprintln(p.out)
}

func (p tableEventPrinter) Print(ctx context, args []interface{}) {
	fmt.Fprintf(p.out, "%-14f %-16s %-12d %-12d %-6d %-16s %-16s %-6d %-6d %-6d %-12d", float64(ctx.Ts)/1000000.0, ctx.UtsName, ctx.MntId, ctx.PidId, ctx.Uid, EventsIDToName[ctx.Eventid], ctx.Comm, ctx.Pid, ctx.Tid, ctx.Ppid, ctx.Retval)
	for _, value := range args {
		fmt.Fprintf(p.out, "%v ", value)
	}
	fmt.Fprintln(p.out)
}

func (p tableEventPrinter) Epilogue() {
	fmt.Fprintf(p.out, "\nEnd of events stream\n")
	fmt.Fprintf(p.out, "Total events: %d, Lost events: %d, Lost file writes: %d, Unexpected errors: %d", p.tracee.eventCounter, p.tracee.lostEvCounter, p.tracee.lostWrCounter, p.tracee.errorCounter)
	fmt.Fprintf(p.out, "\nReleasing resources...\n")
}

type jsonEventPrinter struct {
	out io.Writer
}

// printableEvent holds all event data relevent for printing
type printableEvent struct {
	Ts float64 `json:"time"`
	context
	EventName string            `json:"api"`
	Args      map[string]string `json:"arguments"`
}

func (p jsonEventPrinter) Preamble() {}

func (p jsonEventPrinter) Print(ctx context, args []interface{}) {
	argmap := make(map[string]string, len(args))
	for i, a := range args {
		argmap[fmt.Sprintf("p%d", i)] = fmt.Sprintf("%v", a)
	}
	e := printableEvent{context: ctx, EventName: EventsIDToName[ctx.Eventid], Args: argmap}
	e.Ts = float64(e.context.Ts) / 1000000.0
	eBytes, err := json.Marshal(e)
	if err != nil {
		fmt.Fprintf(p.out, "error printing event: %v\n", err)
	}
	fmt.Fprintf(p.out, "%s", string(eBytes))
	fmt.Fprintln(p.out)
}

func (p jsonEventPrinter) Epilogue() {}
