package tracee

import (
	"encoding/json"
	"fmt"
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
}

func (p tableEventPrinter) Preamble() {
	fmt.Printf("%-14s %-16s %-12s %-12s %-6s %-16s %-16s %-6s %-6s %-6s %-12s %s", "TIME(s)", "UTS_NAME", "MNT_NS", "PID_NS", "UID", "EVENT", "COMM", "PID", "TID", "PPID", "RET", "ARGS")
	fmt.Println()
}

func (p tableEventPrinter) Print(ctx context, args []interface{}) {
	fmt.Printf("%-14f %-16s %-12d %-12d %-6d %-16s %-16s %-6d %-6d %-6d %-12d", float64(ctx.Ts)/1000000, ctx.UtsName, ctx.MntId, ctx.PidId, ctx.Uid, EventsIDToName[ctx.Eventid], ctx.Comm, ctx.Pid, ctx.Tid, ctx.Ppid, ctx.Retval)
	fmt.Printf("%v", args)
	fmt.Println()
}

func (p tableEventPrinter) Epilogue() {
	fmt.Printf("\nEnd of events stream\n")
	fmt.Printf("Total events: %d, Lost events: %d, Lost file writes: %d, Unexpected errors: %d", p.tracee.eventCounter, p.tracee.lostEvCounter, p.tracee.lostWrCounter, p.tracee.errorCounter)
	fmt.Printf("\nReleasing resources...\n")
}

type jsonEventPrinter struct{}

// printableEvent holds all event data relevent for printing
type printableEvent struct {
	Ts float64                  `json:"time"`
	contextNoTs
	EventName string            `json:"api"`
	Args      map[string]string `json:"arguments"`
}

func (p jsonEventPrinter) Preamble() {}

func (p jsonEventPrinter) Print(ctx context, args []interface{}) {
	argmap := make(map[string]string, len(args))
	for i, a := range args {
		argmap[fmt.Sprintf("p%d", i)] = fmt.Sprintf("%v", a)
	}
	e := printableEvent{Ts: float64(ctx.Ts), contextNoTs: ctx.contextNoTs, EventName: EventsIDToName[ctx.Eventid], Args: argmap}
	e.Ts = e.Ts / 1000000
	eBytes, err := json.Marshal(e)
	if err != nil {
		fmt.Printf("error printing event: %v\n", err)
	}
	fmt.Printf("%s", string(eBytes))
	fmt.Println()
}

func (p jsonEventPrinter) Epilogue() {}
