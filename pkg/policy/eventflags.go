package policy

import (
	"github.com/aquasecurity/tracee/pkg/events"
)

// ATTENTION!
// The eventFlags and eventsFlags are managed by the Policies struct,
// all of which are made available through read-only interfaces. This
// arrangement ensures safe access to these types from multiple goroutines
// without the necessity for additional locking mechanisms.

//
// eventFlags
//

// eventFlags describes the flags of an event.
type eventFlags struct {
	submit         uint64 // should be submitted to userspace (by policies bitmap)
	emit           uint64 // should be emitted to the user (by policies bitmap)
	reqBySignature bool   // required by a signature
}

// eventFlagsOption is a function that sets an option on an eventFlags.
type eventFlagsOption func(*eventFlags)

// eventFlagsWithSubmit sets the submit value.
func eventFlagsWithSubmit(submit uint64) eventFlagsOption {
	return func(es *eventFlags) {
		es.submit = submit
	}
}

// eventFlagsWithEmit sets the emit value.
func eventFlagsWithEmit(emit uint64) eventFlagsOption {
	return func(es *eventFlags) {
		es.emit = emit
	}
}

// eventFlagsWithReqBySignature sets the reqBySignature value.
func eventFlagsWithReqBySignature(required bool) eventFlagsOption {
	return func(es *eventFlags) {
		es.reqBySignature = required
	}
}

// newEventFlags creates a new eventFlags with the given options.
func newEventFlags(options ...eventFlagsOption) eventFlags {
	// default values
	es := eventFlags{
		submit:         0,
		emit:           0,
		reqBySignature: false,
	}

	// apply options
	for _, option := range options {
		option(&es)
	}

	return es
}

// eventFlags implements the events.EventFlags interface.

func (es eventFlags) GetSubmit() uint64 {
	return es.submit
}

func (es eventFlags) GetEmit() uint64 {
	return es.emit
}

func (es eventFlags) ShouldSubmit() bool {
	return es.submit > 0
}

func (es eventFlags) ShouldEmit() bool {
	return es.emit > 0
}

func (es eventFlags) RequiredBySignature() bool {
	return es.reqBySignature
}

//
// eventsFlags
//

// eventsFlags is a struct describing a collection of eventFlags.
type eventsFlags struct {
	flags     map[events.ID]eventFlags
	cancelled map[events.ID]struct{}
}

// newEventsFlags creates a new eventsFlags.
func newEventsFlags() *eventsFlags {
	return &eventsFlags{
		flags:     make(map[events.ID]eventFlags),
		cancelled: make(map[events.ID]struct{}),
	}
}

// set sets the event's flags.
func (es *eventsFlags) set(id events.ID, flags events.EventFlags) {
	es.flags[id] = flags.(eventFlags)
}

// cancelEvent cancels an event and updates the cancelled events list.
func (es *eventsFlags) cancelEvent(id events.ID) {
	delete(es.flags, id)
	es.cancelled[id] = struct{}{}
}

// cancelEventAndAllDeps cancels an event and all its dependencies.
func (es *eventsFlags) cancelEventAndAllDeps(id events.ID) {
	es.cancelEvent(id)

	evtDef := events.Core.GetDefinitionByID(id)
	for _, evtDepID := range evtDef.GetDependencies().GetIDs() {
		es.cancelEventAndAllDeps(evtDepID)
	}
}

// eventsFlags implements the events.EventsFlags interface.

func (es *eventsFlags) Get(id events.ID) events.EventFlags {
	return es.flags[id]
}

func (es *eventsFlags) GetOk(id events.ID) (events.EventFlags, bool) {
	flags, ok := es.flags[id]
	return flags, ok
}

// getAll returns all event flags.
func (es *eventsFlags) getAll() map[events.ID]eventFlags {
	return es.flags
}

func (es *eventsFlags) GetAll() map[events.ID]events.EventFlags {
	all := make(map[events.ID]events.EventFlags, len(es.getAll()))

	for id, flags := range es.getAll() {
		all[id] = flags
	}

	// return a copy to prevent modification of the original map
	return all
}

// getAllCancelled returns all cancelled event IDs.
func (es *eventsFlags) getAllCancelled() map[events.ID]struct{} {
	return es.cancelled
}

func (es *eventsFlags) GetAllCancelled() []events.ID {
	cancelled := make([]events.ID, 0, len(es.getAllCancelled()))

	for id := range es.getAllCancelled() {
		cancelled = append(cancelled, id)
	}

	return cancelled
}
