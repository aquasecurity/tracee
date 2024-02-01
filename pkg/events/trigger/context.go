package trigger

import (
	"fmt"
	"sync"

	"github.com/aquasecurity/tracee/pkg/counter"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

const ContextArgName = "caller_context_id"

// Context is an interface for a struct used to store the triggering events context.
type Context interface {
	Store(trace.Event) uint64               // store an invoke context
	Load(uint64) (trace.Event, bool)        // loads an invoked event context
	Apply(trace.Event) (trace.Event, error) // apply an invoked event context (implicitly gets the event)
}

type context struct {
	store   map[uint64]trace.Event
	mutex   *sync.Mutex
	counter counter.Counter
}

// NewContext creates a new context store.
func NewContext() *context {
	return &context{
		store:   make(map[uint64]trace.Event),
		mutex:   &sync.Mutex{},
		counter: counter.NewCounter(0),
	}
}

// Store stores an event in the context store.
func (store *context) Store(event trace.Event) uint64 {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	id, err := store.counter.IncrementValueAndRead(1)
	if err != nil {
		logger.Debugw("failed to increase context counter", "error", err)
	}

	store.store[id] = event

	return id
}

// Load loads an event from the context store.
func (store *context) Load(id uint64) (trace.Event, bool) {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	contextEvent, ok := store.store[id]
	if !ok {
		return trace.Event{}, false
	}

	delete(store.store, id)

	return contextEvent, true
}

// Apply applies an event from the context store to the given event.
func (store *context) Apply(event trace.Event) (trace.Event, error) {
	contextID, err := parse.ArgVal[uint64](event.Args, ContextArgName)
	if err != nil {
		return trace.Event{}, errfmt.Errorf("error parsing caller_context_id arg: %v", err)
	}
	invoking, ok := store.Load(contextID)
	if !ok {
		return trace.Event{}, NoEventContextError(contextID)
	}

	// Apply the invoking event data on top of the argument event. This is done in the opposite
	// "direction" because we only need the uint64, name, etc., from the argument event.

	// same logic as derive.newEvent
	invoking.EventName = event.EventName
	invoking.EventID = event.EventID
	invoking.ReturnValue = 0
	invoking.Args = make([]trace.Argument, len(event.Args))
	invoking.PoliciesVersion = event.PoliciesVersion
	invoking.MatchedPoliciesKernel = event.MatchedPoliciesKernel
	invoking.MatchedPoliciesUser = event.MatchedPoliciesUser
	copied := copy(invoking.Args, event.Args)
	if copied != len(event.Args) {
		return trace.Event{}, errfmt.Errorf("failed to apply event's args")
	}
	invoking.ArgsNum = len(invoking.Args)

	return invoking, nil
}

func NoEventContextError(id uint64) error {
	return fmt.Errorf("no event context with id %d", id)
}
