package trigger

import (
	"sync"

	"github.com/aquasecurity/tracee/pkg/counter"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/types/trace"
)

const ContextArgName = "caller_context_id"

type Context interface {
	Store(trace.Event) uint64               // store an invoke context
	Get(uint64) (trace.Event, bool)         // get an invoked event context
	Apply(trace.Event) (trace.Event, error) // apply an invoked event context (implicitly gets the event)
}

// context is a struct used to store the triggering events context
type context struct {
	store   map[uint64]trace.Event
	mutex   sync.RWMutex
	counter counter.Counter
}

func NewContext() *context {
	return &context{
		store:   make(map[uint64]trace.Event),
		mutex:   sync.RWMutex{},
		counter: counter.NewCounter(1),
	}
}

func (store *context) Store(event trace.Event) uint64 {
	id := uint64(store.counter.Read())
	_ = store.counter.Increment()
	store.mutex.Lock()
	store.store[id] = event
	store.mutex.Unlock()
	return id
}

func (store *context) Get(id uint64) (trace.Event, bool) {
	store.mutex.RLock()
	contextEvent, ok := store.store[id]
	store.mutex.RUnlock()
	if !ok {
		return trace.Event{}, false
	}
	store.mutex.Lock()
	delete(store.store, id)
	store.mutex.Unlock()
	return contextEvent, true
}

func (store *context) Apply(event trace.Event) (trace.Event, error) {
	contextID, err := parse.ArgVal[uint64](&event, ContextArgName)
	if err != nil {
		return trace.Event{}, errfmt.Errorf("error parsing caller_context_id arg: %v", err)
	}
	invoking, ok := store.Get(contextID)
	if !ok {
		return trace.Event{}, NoEventContextError(contextID)
	}

	// apply the invoking event data on top of the argument event
	// this is done in the opposite "direction" because we only need the uint64, name etc. from the
	// argument event.

	// same logic as derive.newEvent
	invoking.EventName = event.EventName
	invoking.EventID = event.EventID
	invoking.ReturnValue = 0
	invoking.Args = make([]trace.Argument, len(event.Args))
	invoking.MatchedPolicies = event.MatchedPolicies
	copied := copy(invoking.Args, event.Args)
	if copied != len(event.Args) {
		return trace.Event{}, errfmt.Errorf("failed to apply event's args")
	}
	invoking.ArgsNum = event.ArgsNum

	return invoking, nil
}
