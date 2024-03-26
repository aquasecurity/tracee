package policy

import (
	"github.com/aquasecurity/tracee/pkg/events"
)

// EventStates defines an interface for accessing the states of a single event in a read-only manner.
type EventStates interface {
	// GetSubmit returns the submit state of the event.
	GetSubmit() uint64

	// GetEmit returns the emit state of the event.
	GetEmit() uint64

	// ShouldSubmit returns true if the event is marked to be submitted.
	ShouldSubmit() bool

	// ShouldEmit returns true if the event is marked to be emitted.
	ShouldEmit() bool
}

// EventsStates defines an interface for accessing a collection of event states in a read-only manner.
// It allows for querying individual events or collections of events.
type EventsStates interface {
	// Get returns the event states of the given event ID.
	Get(events.ID) EventStates

	// GetOk returns the event states of the given event ID and a boolean indicating if the event ID exists.
	GetOk(events.ID) (EventStates, bool)

	// GetAll returns a map of all event states.
	GetAll() map[events.ID]EventStates

	// GetAllSubmittable returns a map of all event IDs that are marked as submittable.
	GetAllSubmittable() map[events.ID]struct{}

	// GetAllEmittable returns a map of all event IDs that are marked as emittable.
	GetAllEmittable() map[events.ID]struct{}

	// GetAllCancelled returns a map of all event IDs that are marked as cancelled.
	GetAllCancelled() map[events.ID]struct{}
}

// ATTENTION!
// The eventStates and eventsStates are managed by the Policies struct, all of
// which are made available through the read-only interfaces EventStates and
// EventsStates. This arrangement ensures safe access to these types from
// multiple goroutines without the necessity for additional locking mechanisms.

//
// eventStates
//

// eventStates describes the states of an event.
type eventStates struct {
	submit uint64 // should be submitted to userspace (by policies bitmap)
	emit   uint64 // should be emitted to the user (by policies bitmap)
}

// eventStatesOption is a function that sets an option on an eventStates.
type eventStatesOption func(*eventStates)

// eventStatesWithSubmit sets the submit value.
func eventStatesWithSubmit(submit uint64) eventStatesOption {
	return func(es *eventStates) {
		es.submit = submit
	}
}

// eventStatesWithEmit sets the emit value.
func eventStatesWithEmit(emit uint64) eventStatesOption {
	return func(es *eventStates) {
		es.emit = emit
	}
}

// newEventStates creates a new eventStates with the given options.
func newEventStates(options ...eventStatesOption) eventStates {
	// default values
	es := eventStates{
		submit: 0,
		emit:   0,
	}

	// apply options
	for _, option := range options {
		option(&es)
	}

	return es
}

// eventStates implements the EventStates interface.

func (es eventStates) GetSubmit() uint64 {
	return es.submit
}

func (es eventStates) GetEmit() uint64 {
	return es.emit
}

func (es eventStates) ShouldSubmit() bool {
	return es.submit > 0
}

func (es eventStates) ShouldEmit() bool {
	return es.emit > 0
}

//
// eventsStates
//

// eventsStates is a struct describing a collection of eventStates.
type eventsStates struct {
	states    map[events.ID]eventStates
	cancelled map[events.ID]struct{}
}

// newEventsStates creates a new eventsStates.
func newEventsStates() *eventsStates {
	return &eventsStates{
		states:    make(map[events.ID]eventStates),
		cancelled: make(map[events.ID]struct{}),
	}
}

// set sets the event's states.
func (es *eventsStates) set(id events.ID, states EventStates) {
	es.states[id] = states.(eventStates)
}

// cancelEvent cancels an event and updates the cancelled events list.
func (es *eventsStates) cancelEvent(id events.ID) {
	delete(es.states, id)
	es.cancelled[id] = struct{}{}
}

// cancelEventAndAllDeps cancels an event and all its dependencies.
func (es *eventsStates) cancelEventAndAllDeps(id events.ID) {
	es.cancelEvent(id)

	evtDef := events.Core.GetDefinitionByID(id)
	for _, evtDepID := range evtDef.GetDependencies().GetIDs() {
		es.cancelEventAndAllDeps(evtDepID)
	}
}

// eventsStates implements the EventsStates interface.

func (es *eventsStates) Get(id events.ID) EventStates {
	return es.getAll()[id]
}

func (es *eventsStates) GetOk(id events.ID) (EventStates, bool) {
	states, ok := es.getAll()[id]
	return states, ok
}

// getAll returns all event states.
func (es *eventsStates) getAll() map[events.ID]eventStates {
	return es.states
}

func (es *eventsStates) GetAll() map[events.ID]EventStates {
	all := make(map[events.ID]EventStates, len(es.getAll()))

	for id, states := range es.getAll() {
		all[id] = states
	}

	// return a copy to prevent modification of the original map
	return all
}

func (es *eventsStates) GetAllSubmittable() map[events.ID]struct{} {
	submittable := make(map[events.ID]struct{}, len(es.getAll()))

	for id, states := range es.getAll() {
		if states.ShouldSubmit() {
			submittable[id] = struct{}{}
		}
	}

	// return a copy to prevent modification of the original map
	return submittable
}

func (es *eventsStates) GetAllEmittable() map[events.ID]struct{} {
	emittable := make(map[events.ID]struct{}, len(es.getAll()))

	for id, states := range es.getAll() {
		if states.ShouldEmit() {
			emittable[id] = struct{}{}
		}
	}

	// return a copy to prevent modification of the original map
	return emittable
}

// getAllCancelled returns all cancelled event IDs.
func (es *eventsStates) getAllCancelled() map[events.ID]struct{} {
	return es.cancelled
}

func (es *eventsStates) GetAllCancelled() map[events.ID]struct{} {
	cancelled := make(map[events.ID]struct{}, len(es.getAllCancelled()))

	for id := range es.getAllCancelled() {
		cancelled[id] = struct{}{}
	}

	// return a copy to prevent modification of the original map
	return cancelled
}
