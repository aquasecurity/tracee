package events

import (
	"github.com/aquasecurity/tracee/pkg/errfmt"
)

type EventState struct {
	Submit uint64 // event that should be submitted to userspace (by policies bitmap)
	Emit   uint64 // event that should be emitted to the user (by policies bitmap)
}

// ATTENTION: the event group is instantiable (all the rest is immutable)

type EventGroup struct {
	events map[ID]Event
}

func (e *EventGroup) Add(eventId ID, evt Event) error {
	if _, ok := e.events[eventId]; ok {
		return errfmt.Errorf("error event id already exist: %v", eventId)
	}

	if _, ok := e.GetID(evt.GetName()); ok {
		return errfmt.Errorf("error event name already exist: %v", evt.GetName())
	}

	e.events[eventId] = evt

	return nil
}

func (e *EventGroup) Get(eventId ID) Event {
	return e.events[eventId]
}

func (e *EventGroup) GetOk(eventId ID) (Event, bool) {
	evt, ok := e.events[eventId]
	return evt, ok
}

func (e *EventGroup) Events() map[ID]Event {
	return e.events
}

func (e *EventGroup) Length() int {
	return len(e.events)
}

func (e *EventGroup) NamesToIDs() map[string]ID {
	namesToIds := make(map[string]ID, len(e.events))

	for id, evt := range e.events {
		namesToIds[evt.GetName()] = id
	}
	return namesToIds
}

func (e *EventGroup) IDs32ToIDs() map[ID]ID {
	idS32ToIDs := make(map[ID]ID, len(e.events))

	for id, evt := range e.events {
		if evt.GetID32Bit() != Sys32Undefined {
			idS32ToIDs[evt.GetID32Bit()] = id
		}
	}
	return idS32ToIDs
}

func (e *EventGroup) GetID(eventName string) (ID, bool) {
	for id, evt := range e.events {
		if evt.GetName() == eventName {
			return id, true
		}
	}
	return -1, false
}

func (e *EventGroup) GetTailCalls(evtConfig map[ID]EventState) []TailCall {
	var tailCalls []TailCall

	for id, evt := range e.events {
		if evtConfig[id].Submit > 0 {
			tailCalls = append(tailCalls, evt.GetDependencies().TailCalls...)
		}
	}

	return tailCalls
}
