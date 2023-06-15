package events

import (
	"sync"
	"sync/atomic"

	"github.com/aquasecurity/tracee/types/trace"
)

//
// Event
//

// Event is a struct describing an event configuration
type Event struct {
	id           *atomic.Uint32
	id32Bit      *atomic.Uint32
	name         string
	docPath      string
	strMutex     *sync.RWMutex
	internal     *atomic.Bool
	syscall      *atomic.Bool
	dependencies *atomic.Pointer[Dependencies]
	sets         map[string]struct{}
	setsMutex    *sync.RWMutex
	params       []trace.ArgMeta
	paramsMutex  *sync.RWMutex
}

// NewEvent creates a new Event with all its fields set.
func NewEvent(
	id ID,
	id32Bit ID,
	name string,
	docPath string,
	internal bool,
	syscall bool,
	sets []string,
	deps *Dependencies,
	params []trace.ArgMeta,
) *Event {
	event := &Event{
		id:           &atomic.Uint32{},
		id32Bit:      &atomic.Uint32{},
		name:         "",
		docPath:      "",
		internal:     &atomic.Bool{},
		syscall:      &atomic.Bool{},
		sets:         make(map[string]struct{}),
		dependencies: &atomic.Pointer[Dependencies]{},
		params:       []trace.ArgMeta{},
		strMutex:     &sync.RWMutex{},
		setsMutex:    &sync.RWMutex{},
		paramsMutex:  &sync.RWMutex{},
	}

	event.id.Store(uint32(id))
	event.id32Bit.Store(uint32(id32Bit))
	event.name = name
	event.docPath = docPath
	event.internal.Store(internal)
	event.syscall.Store(syscall)
	event.dependencies.Store(deps)
	event.params = params

	for _, s := range sets {
		event.sets[s] = struct{}{}
	}

	return event
}

//
// IDs
//

// SetID does not make sense for Event (immutable).

// GetID returns the ID of the event (thread-safe).
func (e *Event) GetID() ID {
	return ID(e.id32Bit.Load())
}

// SetID32Bit sets the 32-bit ID of the event (thread-safe).
func (e *Event) SetID32Bit(id32bit ID) {
	e.id32Bit.Store(uint32(id32bit))
}

// GetID32Bit returns the 32-bit ID of the event (thread-safe).
func (e *Event) GetID32Bit() ID {
	return ID(e.id32Bit.Load())
}

//
// Name and DocPath (Strings)
//

// SetName sets the name of the event (thread-safe).
func (e *Event) SetName(name string) {
	e.strMutex.Lock()
	defer e.strMutex.Unlock()
	e.name = name
}

// GetName returns the name of the event (thread-safe).
func (e *Event) GetName() string {
	e.strMutex.RLock()
	defer e.strMutex.RUnlock()
	return e.name
}

// SetDocPath sets the documentation path of the event (thread-safe).
func (e *Event) SetDocPath(docPath string) {
	e.strMutex.Lock()
	defer e.strMutex.Unlock()
	e.docPath = docPath
}

// GetDocPath returns the documentation path of the event (thread-safe).
func (e *Event) GetDocPath() string {
	e.strMutex.RLock()
	defer e.strMutex.RUnlock()
	return e.docPath
}

//
// Internal or Sycall (Boolean)
//

// SetInternal sets the internal flag of the event to true (thread-safe).
func (e *Event) SetInternal() {
	e.internal.Store(true)
}

// SetNoIternal sets the internal flag of the event to false (thread-safe).
func (e *Event) SetNotInternal() {
	e.internal.Store(false)
}

// IsInternal returns true if the event is internal (thread-safe).
func (e *Event) IsInternal() bool {
	return e.internal.Load()
}

// SetSyscall sets the syscall flag of the event to true (thread-safe).
func (e *Event) SetSyscall() {
	e.syscall.Store(true)
}

// SetNoSyscall sets the syscall flag of the event to false (thread-safe).
func (e *Event) SetNotSyscall() {
	e.syscall.Store(false)
}

// IsSyscall returns true if the event is a syscall (thread-safe).
func (e *Event) IsSyscall() bool {
	return e.syscall.Load()
}

//
// Dependencies
//

// SetDependencies sets the dependencies of the event (thread-safe).
func (e *Event) SetDependencies(dependencies *Dependencies) {
	e.dependencies.Store(dependencies)
}

// GetDependencies returns the dependencies of the event (thread-safe).
func (e *Event) GetDependencies() *Dependencies {
	return e.dependencies.Load()
}

//
// Sets
//

// SetSets sets the sets of the event (thread-safe).
func (e *Event) SetSets(sets []string) {
	e.setsMutex.Lock()
	defer e.setsMutex.Unlock()

	// delete all existing sets
	for s := range e.sets {
		delete(e.sets, s)
	}

	for _, s := range sets {
		e.sets[s] = struct{}{}
	}
}

// GetSets returns the sets of the event (thread-safe).
func (e *Event) GetSets() []string {
	e.setsMutex.RLock()
	defer e.setsMutex.RUnlock()

	sets := make([]string, 0, len(e.sets))

	for s := range e.sets {
		sets = append(sets, s)
	}

	return sets
}

// AddSet adds a set to the event (thread-safe).
func (e *Event) AddSet(set string) {
	e.AddSets([]string{set})
}

// AddSets adds multiple sets to the event (thread-safe).
func (e *Event) AddSets(sets []string) {
	e.setsMutex.Lock()
	defer e.setsMutex.Unlock()

	for _, s := range sets {
		e.sets[s] = struct{}{}
	}
}

// RemoveSet removes a set from the event (thread-safe).
func (e *Event) RemoveSet(set string) {
	e.RemoveSets([]string{set})
}

// RemoveSets removes multiple sets from the event (thread-safe).
func (e *Event) RemoveSets(sets []string) {
	e.setsMutex.Lock()
	defer e.setsMutex.Unlock()

	for _, s := range sets {
		delete(e.sets, s)
	}
}

//
// Params
//

// SetParams sets the params of the event (thread-safe).
func (e *Event) SetParams(params []trace.ArgMeta) {
	e.paramsMutex.Lock()
	defer e.paramsMutex.Unlock()
	e.params = params
}

// GetParams returns the params of the event (thread-safe).
func (e *Event) GetParams() []trace.ArgMeta {
	e.paramsMutex.RLock()
	defer e.paramsMutex.RUnlock()
	return e.params
}

//
// Others
//

// IsASignatureEvent returns true if the event is a signature event (thread-safe).
func (e *Event) IsASignatureEvent() bool {
	sets := e.GetSets()

	// analyze sets without holding a lock
	for _, s := range sets {
		if s == "signatures" {
			return true
		}
	}

	return false
}
