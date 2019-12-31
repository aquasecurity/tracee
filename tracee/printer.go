package tracee

import (
	"fmt"
	"encoding/json"
)


type eventPrinter interface{
	// Preamble prints something before event printing begins (one time)
	Preamble()
	// Epilogue prints something after event printing ends (one time)
	Epilogue()
	// Print prints a single event
	Print(ctx context, args []interface{})
}

type tableEventPrinter struct{}

func (p tableEventPrinter) Preamble() {
	fmt.Printf("%-14s %-16s %-12s %-12s %-6s %-16s %-16s %-6s %-6s %-6s %-12s %s", "TIME(s)", "UTS_NAME", "MNT_NS", "PID_NS", "UID", "EVENT", "COMM", "PID", "TID", "PPID", "RET", "ARGS")
	fmt.Println()
}

func (p tableEventPrinter) Print(ctx context, args []interface{}) {
	fmt.Printf("%-14d %-16s %-12d %-12d %-6d %-16s %-16s %-6d %-6d %-6d %-12d", ctx.Ts / 1000000, ctx.UtsName, ctx.MntId, ctx.PidId, ctx.Uid, getEventName(ctx.Eventid), ctx.Comm, ctx.Pid, ctx.Tid, ctx.Ppid, ctx.Retval)
	fmt.Printf("%v", args)
	fmt.Println()
}

func (p tableEventPrinter) Epilogue() {}

type jsonEventPrinter struct{}

// printableEvent holds all event data relevent for printing
type printableEvent struct {
	context
	EventName string `json:"eventName"`
	Args []interface{} `json:"args"`
}

func (p jsonEventPrinter) Preamble() {}

func (p jsonEventPrinter) Print(ctx context, args []interface{}) {
	e := printableEvent{context: ctx, EventName: getEventName(ctx.Eventid), Args: args,}
	eBytes, err := json.Marshal(e)
	if err != nil {
		fmt.Printf("error printing event: %v\n", err)
	}
	fmt.Printf("%s",string(eBytes))
	fmt.Println()
}

func (p jsonEventPrinter) Epilogue() {}

// getEventName returns a the name of the event for printing, specified by it's id
func getEventName(eid uint32) string{
	name := "undefined"
	if (int(eid) < len(eventNames)) { // TODO: off by one? cast error?
		name = eventNames[eid]
	}
	return name
}