package events

import (
	"sync"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
)

// TODO: add states to the EventGroup struct (to keep states of events from that group)

type EventState struct {
	Submit uint64 // event that should be submitted to userspace (by policies bitmap)
	Emit   uint64 // event that should be emitted to the user (by policies bitmap)
}

// ATTENTION: the event group is instantiable (all the rest is immutable)

//
// EventGroup
//

// EventGroup is a struct describing a collection of events.
type EventGroup struct {
	events map[ID]Event
	mutex  *sync.RWMutex // write lock for adding events (initialization/reconfig only)
}

// NewEventGroup creates a new EventGroup.
func NewEventGroup() *EventGroup {
	return &EventGroup{
		events: make(map[ID]Event),
		mutex:  &sync.RWMutex{},
	}
}

// Add adds an event to the event group.
func (e *EventGroup) Add(givenId ID, givenEvt Event) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	return e.add(givenId, givenEvt)
}

// AddBatch adds multiple events to the event group.
func (e *EventGroup) AddBatch(givenEvents map[ID]Event) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	for id, evt := range givenEvents {
		err := e.add(id, evt)
		if err != nil {
			return err
		}
	}

	return nil
}

// add adds an event to the event group (no locking).
func (e *EventGroup) add(givenId ID, givenEvt Event) error {
	if _, ok := e.events[givenId]; ok {
		return evtIdAlreadyExistsErr(givenId)
	}

	n := givenEvt.GetName()
	if _, ok := e.getEventIDByName(n); ok {
		return evtNameAlreadyExistsErr(n)
	}

	e.events[givenId] = givenEvt

	return nil
}

// GetEventByName returns a event ID by its name.
func (e *EventGroup) GetEventIDByName(givenName string) (ID, bool) {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return e.getEventIDByName(givenName)
}

// getEventIDByName returns a event ID by its name (no locking).
func (e *EventGroup) getEventIDByName(givenName string) (ID, bool) {
	for id, evt := range e.events {
		if evt.GetName() == givenName {
			return id, true
		}
	}
	logger.Debugw("event context: event name not found", "name", givenName)

	return Undefined, false
}

// GetEventByID returns an event by its ID.
// NOTE: should be used together with IsEventDefined when event might not exist.
func (e *EventGroup) GetEventByID(givenEvt ID) Event {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	evt, ok := e.events[givenEvt]
	if !ok {
		logger.Debugw("event context: event id not found", "id", givenEvt)
		return Event{id: Undefined}
	}

	return evt
}

// IsEventDefined returns true if the event is defined in the event group.
// NOTE: needed as GetEventByID() is used as GetEventByID().Method() multiple times.
func (e *EventGroup) IsEventDefined(givenEvt ID) bool {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	_, ok := e.events[givenEvt]
	return ok
}

// Length returns the number of events in the event group.
func (e *EventGroup) Length() int {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return len(e.events)
}

// GetEvents returns a new map of existing event instances (at the time of the call).
// TODO: iterate internally after event definition refactor is finished ?
func (e *EventGroup) GetEvents() map[ID]Event {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	mapCopy := make(map[ID]Event, len(e.events))

	for id, evt := range e.events {
		mapCopy[id] = evt // immutable data & copy
	}

	return mapCopy
}

// NamesToIDs returns a new map of event names to their IDs (at the time of the call).
func (e *EventGroup) NamesToIDs() map[string]ID {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	namesToIds := make(map[string]ID, len(e.events))

	for id, evt := range e.events {
		namesToIds[evt.GetName()] = id
	}

	return namesToIds
}

// IDs32ToIDs returns a new map of 32-bit event IDs to their IDs (at the time of the call).
func (e *EventGroup) IDs32ToIDs() map[ID]ID {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	idS32ToIDs := make(map[ID]ID, len(e.events))

	for id, evt := range e.events {
		evtId32Bit := evt.GetID32Bit()

		if evtId32Bit != Sys32Undefined {
			idS32ToIDs[evtId32Bit] = id
		}
	}

	return idS32ToIDs
}

// GetTailCalls returns a list of tailcalls of all events in the group (for initialization).
func (e *EventGroup) GetTailCalls(evtConfig map[ID]EventState) []TailCall {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	var tailCalls []TailCall

	for id, evt := range e.events {
		// Only events being traced should provide their tailcalls.
		if evtConfig[id].Submit > 0 {
			tailCalls = append(tailCalls, evt.GetDependencies().GetTailCalls()...)
		}
	}

	return tailCalls
}

// Errors

func evtIdAlreadyExistsErr(id ID) error {
	return errfmt.Errorf("error event id already exist: %v", id)
}

func evtNameAlreadyExistsErr(name string) error {
	return errfmt.Errorf("error event name already exist: %v", name)
}
