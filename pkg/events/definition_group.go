package events

import (
	"github.com/aquasecurity/tracee/pkg/errfmt"
)

type EventState struct {
	Submit uint64 // event that should be submitted to userspace (by policies bitmap)
	Emit   uint64 // event that should be emitted to the user (by policies bitmap)
}

type EventDefinitionGroup struct {
	events map[ID]EventDefinition
}

func (e *EventDefinitionGroup) Add(eventId ID, evt EventDefinition) error {
	if _, ok := e.events[eventId]; ok {
		return errfmt.Errorf("error event id already exist: %v", eventId)
	}

	if _, ok := e.GetID(evt.GetName()); ok {
		return errfmt.Errorf("error event name already exist: %v", evt.GetName())
	}

	e.events[eventId] = evt

	return nil
}

func (e *EventDefinitionGroup) Get(eventId ID) EventDefinition {
	return e.events[eventId]
}

func (e *EventDefinitionGroup) GetOk(eventId ID) (EventDefinition, bool) {
	evt, ok := e.events[eventId]
	return evt, ok
}

func (e *EventDefinitionGroup) Events() map[ID]EventDefinition {
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

func (e *EventDefinitionGroup) GetTailCalls(evtConfig map[ID]EventState) []TailCall {
	var tailCalls []TailCall

	for id, evt := range e.events {
		if evtConfig[id].Submit > 0 {
			tailCalls = append(tailCalls, evt.GetDependencies().TailCalls...)
		}
	}

	return tailCalls
}
