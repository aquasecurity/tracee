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
	contextMapID := uint64(invokedContext.Counter.Read())
	invokedContext.Counter.Increment(1)
	invokedContext.Mutex.Lock()
	invokedContext.Map[contextMapID] = event
	invokedContext.Mutex.Unlock()
	return contextMapID
}

func GetEventContext(contextID uint64) (trace.Event, error) {
	invokedContext.Mutex.RLock()
	contextEvent, ok := invokedContext.Map[contextID]
	invokedContext.Mutex.RUnlock()
	if !ok {
		return trace.Event{}, fmt.Errorf("caller_context_id arg not in context map")
	}
	// Remove from map to avoid memory leak
	delete(invokedContext.Map, contextID)
	return contextEvent, nil
}

func withInvokingContext(event *trace.Event) (trace.Event, error) {
	contextID, err := parse.ArgUint64Val(event, "caller_context_id")
	if err != nil {
		return trace.Event{}, fmt.Errorf("error parsing caller_context_id arg: %v", err)
	}
	if contextID > 0 {
		return GetEventContext(contextID)
	} else {
		return *event, nil
	}
}
