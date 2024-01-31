package derive

import (
	"fmt"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

func ProcessExecuteFailed() DeriveFunction {
	gen, err := newProcessExecuteFailedGeneratorSingleton()
	if err != nil {
		logger.Errorw("failed to init derive function for ProcessExecuteFiled", "error", err)
		return nil
	}
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
}

// execFailedGenerator is the object which implement the ProcessExecuteFailed event derivation
type execFailedGenerator struct {
	execEndInfo *lru.Cache[int, execEndInfo]
	baseEvents  *lru.Cache[int, *trace.Event]
	deriveBase  deriveBase
}

// newProcessExecuteFailedGenerator initialize a new generator for the ProcessExecuteFailed event.
func newProcessExecuteFailedGenerator() (*execFailedGenerator, error) {
	executeProcsCache, err := lru.New[int, execEndInfo](100)
	if err != nil {
		return nil, err
	}
	executeParamsCache, err := lru.New[int, *trace.Event](100)
	if err != nil {
		return nil, err
	}
	return &execFailedGenerator{
		execEndInfo: executeProcsCache,
		baseEvents:  executeParamsCache,
		deriveBase:  makeDeriveBase(events.ProcessExecuteFailed),
	}, nil
}

var (
	executeFailedGenSingleton *execFailedGenerator
	executeFailedGenOnce      sync.Once
)

// newProcessExecuteFailedGeneratorSingleton will return the singleton instance of the generator
func newProcessExecuteFailedGeneratorSingleton() (*execFailedGenerator, error) {
	var err error
	executeFailedGenOnce.Do(
		func() {
			executeFailedGenSingleton, err = newProcessExecuteFailedGenerator()
		},
	)
	return executeFailedGenSingleton, err
}

// deriveEvent is the main logic, which will try to derive the event from the given event.
func (gen *execFailedGenerator) deriveEvent(event *trace.Event) (
	*trace.Event, error,
) {
	switch events.ID(event.EventID) {
	case events.SecurityBprmCredsForExec:
		return gen.handleExecBaseEvent(event)
	case events.ExecuteFinished:
		return gen.handleExecFinished(event)
	default:
		return nil, fmt.Errorf("unsupported event %s", event.EventName)
	}
}

// handleExecFinished will derive the event if all the event parts were received.
// Else it will cache the finished exec info for future use.
func (gen *execFailedGenerator) handleExecFinished(event *trace.Event) (*trace.Event, error) {
	execInfo := execEndInfo{
		returnCode: event.ReturnValue,
		timestamp:  event.Timestamp,
	}
	securityExecEvent, ok := gen.baseEvents.Get(event.HostProcessID)
	if ok {
		gen.execEndInfo.Remove(event.HostProcessID)
		if !isFailedExec(execInfo.returnCode) {
			return nil, nil
		}
		return gen.generateEvent(securityExecEvent, execInfo)
	}
	gen.execEndInfo.Add(event.HostProcessID, execInfo)
	return nil, nil
}

// handleExecBaseEvent will derive the event if the event parts were received, else will cache
// the base event for future use
func (gen *execFailedGenerator) handleExecBaseEvent(event *trace.Event) (*trace.Event, error) {
	execInfo, ok := gen.execEndInfo.Get(event.HostProcessID)
	// We don't have the execution end info - cache current event and wait for it to be received
	// This is the expected flow, as the execution finished event come chronology after
	if !ok {
		gen.baseEvents.Add(event.HostProcessID, event)
		return nil, nil
	}
	gen.execEndInfo.Remove(event.HostProcessID)
	if !isFailedExec(execInfo.returnCode) {
		return nil, nil
	}
	return gen.generateEvent(event, execInfo)
}

// generateEvent create the ProcessExecuteFailed event from its parts
func (gen *execFailedGenerator) generateEvent(
	baseEvent *trace.Event,
	execInfo execEndInfo,
) (*trace.Event, error) {
	newEvent := *baseEvent
	newEvent.Timestamp = execInfo.timestamp
	newEvent.EventID = gen.deriveBase.ID
	newEvent.EventName = gen.deriveBase.Name
	newEvent.ReturnValue = execInfo.returnCode
	return &newEvent, nil
}

func isFailedExec(returnCode int) bool {
	return returnCode < 0
}
