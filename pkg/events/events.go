package events

import (
	"github.com/aquasecurity/tracee/pkg/errfmt"
)

func IsASignatureEvent(id ID) bool {
	if id >= StartSignatureID && id <= MaxSignatureID {
		return true
	}

	return false
}

// NewEventDefinition creates a new event definition
func NewEventDefinition(name string, sets []string, depsID []ID) Event {
	evt := Event{
		ID32Bit: sys32undefined,
		Name:    name,
		Sets:    sets,
	}

	d := Dependencies{
		Events: make([]ID, 0, len(depsID)),
	}

	for _, id := range depsID {
		d.Events = append(d.Events, id)
	}

	evt.Dependencies = d

	return evt
}

type eventDefinitions struct {
	events map[ID]Event
}

// Add adds an event to definitions
func (e *eventDefinitions) Add(eventId ID, evt Event) error {
	if _, ok := e.events[eventId]; ok {
		return errfmt.Errorf("error event id already exist: %v", eventId)
	}

	if _, ok := e.GetID(evt.Name); ok {
		return errfmt.Errorf("error event name already exist: %v", evt.Name)
	}

	e.events[eventId] = evt

	return nil
}

// Get gets the event without checking for Event existence
func (e *eventDefinitions) Get(eventId ID) Event {
	evt := e.events[eventId]
	return evt
}

// GetSafe gets the Event and also returns bool to check for existence
func (e *eventDefinitions) GetSafe(eventId ID) (Event, bool) {
	evt, ok := e.events[eventId]
	return evt, ok
}

// Events returns the underlying Event definitions map
// Use at own risk and do not modify the map
func (e *eventDefinitions) Events() map[ID]Event {
	return e.events
}

func (e *eventDefinitions) Length() int {
	return len(e.events)
}

func (e *eventDefinitions) NamesToIDs() map[string]ID {
	namesToIds := make(map[string]ID, len(e.events))

	for id, evt := range e.events {
		namesToIds[evt.Name] = id
	}
	return namesToIds
}

func (e *eventDefinitions) IDs32ToIDs() map[ID]ID {
	idS32ToIDs := make(map[ID]ID, len(e.events))

	for id, evt := range e.events {
		if evt.ID32Bit != sys32undefined {
			idS32ToIDs[evt.ID32Bit] = id
		}
	}
	return idS32ToIDs
}

func (e *eventDefinitions) GetID(eventName string) (ID, bool) {
	for id, evt := range e.events {
		if evt.Name == eventName {
			return id, true
		}
	}
	return -1, false
}
