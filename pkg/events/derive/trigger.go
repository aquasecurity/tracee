package derive

import (
	"fmt"
	"github.com/aquasecurity/tracee/pkg/counter"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/types/trace"
	"sync"
)

// Context is a struct used to store the triggering events' context
type context struct {
	Map     map[uint64]trace.Event
	Mutex   sync.RWMutex
	Counter counter.Counter
}

var invokedContext = context{make(map[uint64]trace.Event), sync.RWMutex{}, counter.Counter(1)}

func StoreEventContext(event trace.Event) uint64 {
	// Initial event - no need to save
	if event.Timestamp == 0 {
		return 0
	}
	eventHandle := uint64(invokedContext.Counter.Read())
	invokedContext.Counter.Increment(1)
	invokedContext.Mutex.Lock()
	invokedContext.Map[eventHandle] = event
	invokedContext.Mutex.Unlock()
	return eventHandle
}

func GetEventContext(eventHandle uint64) (trace.Event, error) {
	invokedContext.Mutex.RLock()
	contextEvent, ok := invokedContext.Map[eventHandle]
	invokedContext.Mutex.RUnlock()
	if !ok {
		return trace.Event{}, fmt.Errorf("caller_context_id arg not in context map")
	}
	delete(invokedContext.Map, eventHandle)
	return contextEvent, nil
}

// withInvokingContext is used to create the derived event with the triggering event context
// compared to withOriginalContext which is used to create the derived event with the event skeleton provided
func withInvokingContext(event *trace.Event) (trace.Event, error) {
	eventHandle, err := parse.ArgUint64Val(event, "caller_context_id")
	if err != nil {
		return trace.Event{}, fmt.Errorf("error parsing caller_context_id arg: %v", err)
	}
	if eventHandle > 0 {
		return GetEventContext(eventHandle)
	} else {
		return *event, nil
	}
}
