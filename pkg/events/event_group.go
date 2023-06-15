package events

import (
	"sync"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
)

//
// EventGroup
//

// EventGroup is a struct describing a collection of events.
type EventGroup struct {
	events map[ID]*Event
	mutex  *sync.RWMutex
}

// NewEventGroup creates a new EventGroup.
func NewEventGroup() *EventGroup {
	return &EventGroup{
		events: make(map[ID]*Event),
		mutex:  &sync.RWMutex{},
	}
}

// Add adds an event to the event group.
func (e *EventGroup) Add(eventId ID, evt *Event) error {
	return e.AddBatch(map[ID]*Event{eventId: evt})
}

// AddBatch adds multiple events to the event group.
func (e *EventGroup) AddBatch(givenEvents map[ID]*Event) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	for id, evt := range givenEvents {
		if _, ok := e.events[id]; ok {
			return evtIdAlreadyExistsErr(id)
		}

		n := evt.GetName()
		if _, ok := e.getEventIDByName(n); ok {
			return evtNameAlreadyExistsErr(n)
		}

		e.events[id] = evt
	}

	return nil
}

// GetEventByName returns a event ID by its name.
func (e *EventGroup) GetEventIDByName(eventName string) (ID, bool) {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return e.getEventIDByName(eventName)
}

// getEventIDByName returns a event ID by its name (no locking).
func (e *EventGroup) getEventIDByName(eventName string) (ID, bool) {
	for id, evt := range e.events {
		if evt.GetName() == eventName {
			return id, true
		}
	}
	logger.Debugw("event context: event name not found", "name", eventName)

	return Undefined, false
}

// GetEventByID returns a pointer to an event by its ID (or nil if not found)
func (e *EventGroup) GetEventByID(eventId ID) *Event {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	evt, ok := e.events[eventId]
	if !ok {
		logger.Debugw("event context: event id not found", "id", eventId)
		return nil
	}

	return evt
}

// Length returns the number of events in the event group.
func (e *EventGroup) Length() int {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return len(e.events)
}

// GetAllEvents returns a new map of existing event instances (at the time of the call).
func (e *EventGroup) GetAllEvents() map[ID]*Event {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	copy := make(map[ID]*Event, len(e.events))

	for id, evt := range e.events {
		copy[id] = evt
	}

	return copy
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

// Errors

func evtIdAlreadyExistsErr(id ID) error {
	return errfmt.Errorf("error event id already exist: %v", id)
}

func evtNameAlreadyExistsErr(name string) error {
	return errfmt.Errorf("error event name already exist: %v", name)
}
