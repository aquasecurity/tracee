package events

import "github.com/aquasecurity/tracee/pkg/errfmt"

type EventDefinitionGroup struct {
	// ksymbols and tailcalls are instantiable.
	// TODO: remove instance once event states is finished
	events map[ID]*EventDefinition
}

// Add adds an event to definitions
func (e *EventDefinitionGroup) Add(eventId ID, evt *EventDefinition) error {
	if _, ok := e.events[eventId]; ok {
		return errfmt.Errorf("error event id already exist: %v", eventId)
	}

	if _, ok := e.GetID(evt.GetName()); ok {
		return errfmt.Errorf("error event name already exist: %v", evt.GetName())
	}

	e.events[eventId] = evt

	return nil
}

// Get gets the event without checking for Event existence
func (e *EventDefinitionGroup) Get(eventId ID) *EventDefinition {
	evt := e.events[eventId]
	return evt
}

// GetSafe gets the Event and also returns bool to check for existence
func (e *EventDefinitionGroup) GetSafe(eventId ID) (*EventDefinition, bool) {
	evt, ok := e.events[eventId]
	return evt, ok
}

// Events returns the underlying Event definitions map
// Use at own risk and do not modify the map
func (e *EventDefinitionGroup) Events() map[ID]*EventDefinition {
	return e.events
}

func (e *EventDefinitionGroup) Length() int {
	return len(e.events)
}

func (e *EventDefinitionGroup) NamesToIDs() map[string]ID {
	namesToIds := make(map[string]ID, len(e.events))

	for id, evt := range e.events {
		namesToIds[evt.GetName()] = id
	}
	return namesToIds
}

func (e *EventDefinitionGroup) IDs32ToIDs() map[ID]ID {
	idS32ToIDs := make(map[ID]ID, len(e.events))

	for id, evt := range e.events {
		if evt.GetID32Bit() != sys32undefined {
			idS32ToIDs[evt.GetID32Bit()] = id
		}
	}
	return idS32ToIDs
}

func (e *EventDefinitionGroup) GetID(eventName string) (ID, bool) {
	for id, evt := range e.events {
		if evt.GetName() == eventName {
			return id, true
		}
	}
	return -1, false
}
