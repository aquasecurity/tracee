package derive

import (
	"fmt"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/types/trace"
)

// ExecFailedGenerator is the object which implement the ProcessExecuteFailed event derivation
type ExecFailedGenerator struct {
	baseEvents *lru.Cache[int, *trace.Event]
	deriveBase deriveBase
}

// InitProcessExecuteFailedGenerator initialize a new generator for the ProcessExecuteFailed event.
func InitProcessExecuteFailedGenerator() (*ExecFailedGenerator, error) {
	// The cache is only between mid-execution to its end, so we only need cache of about 1 per core.
	// For now, we assume that the current value is sufficient
	const executionEventsCacheSize = 16

	executeFieldsCache, err := lru.New[int, *trace.Event](executionEventsCacheSize)
	if err != nil {
		return nil, err
	}
	return &ExecFailedGenerator{
		baseEvents: executeFieldsCache,
		deriveBase: makeDeriveBase(events.ProcessExecuteFailed),
	}, nil
}

// ProcessExecuteFailed return the DeriveFunction for the "process_execute_failed" event.
func (gen *ExecFailedGenerator) ProcessExecuteFailed() DeriveFunction {
	return func(event trace.Event) ([]trace.Event, []error) {
		var errs []error
		var derivedEvents []trace.Event
		derivedEvent, err := gen.deriveEvent(&event)
		if err != nil {
			errs = append(errs, err)
		}
		if derivedEvent != nil {
			derivedEvents = append(derivedEvents, *derivedEvent)
		}
		return derivedEvents, errs
	}
}

// execEndInfo stores information about the end of process execution operation.
type execEndInfo struct {
	returnCode int
	timestamp  int
	args       []trace.Argument
}

// deriveEvent is the main logic, which will try to derive the event from the given event.
func (gen *ExecFailedGenerator) deriveEvent(event *trace.Event) (
	*trace.Event, error,
) {
	switch events.ID(event.EventID) {
	case events.ProcessExecuteFailedInternal:
		return gen.handleExecBaseEvent(event)
	case events.ExecuteFinished:
		return gen.handleExecFinished(event)
	default:
		return nil, fmt.Errorf("unsupported event %s", event.EventName)
	}
}

// handleExecFinished will add info on top of base event unless events came out of order. Sends an event in any case.
// Should be simplified once events reach from kernel-space to user-space are ordered!
func (gen *ExecFailedGenerator) handleExecFinished(event *trace.Event) (*trace.Event, error) {
	defer gen.baseEvents.Remove(event.HostProcessID)
	execInfo := execEndInfo{
		returnCode: event.ReturnValue,
		timestamp:  event.Timestamp,
		args:       event.Args,
	}
	if !isFailedExec(execInfo.returnCode) {
		return nil, nil
	}

	e := event
	securityExecEvent, ok := gen.baseEvents.Get(event.HostProcessID)
	if ok {
		e = securityExecEvent // There is a base event to use, use it!
	}
	return gen.generateEvent(e, execInfo)
}

// handleExecBaseEvent will derive the event if the event parts were received, else will cache
// the base event for future use
func (gen *ExecFailedGenerator) handleExecBaseEvent(event *trace.Event) (*trace.Event, error) {
	// We don't have the execution end info - cache current event and wait for it to be received
	// This is the expected flow, as the execution finished event come chronology after
	gen.baseEvents.Add(event.HostProcessID, event)
	return nil, nil
}

// generateEvent create the ProcessExecuteFailed event from its parts
func (gen *ExecFailedGenerator) generateEvent(
	baseEvent *trace.Event,
	execInfo execEndInfo,
) (*trace.Event, error) {
	newEvent := *baseEvent
	newEvent.Timestamp = execInfo.timestamp
	newEvent.EventID = gen.deriveBase.ID
	newEvent.EventName = gen.deriveBase.Name
	newEvent.ReturnValue = execInfo.returnCode

	// fill userspace argv and envp from execute_finished event
	newEvent.Args[parse.ArgIndex(newEvent.Args, "argv")] = execInfo.args[parse.ArgIndex(execInfo.args, "argv")]
	newEvent.Args[parse.ArgIndex(newEvent.Args, "envp")] = execInfo.args[parse.ArgIndex(execInfo.args, "envp")]

	return &newEvent, nil
}

func isFailedExec(returnCode int) bool {
	return returnCode < 0
}
