package events

import (
	"github.com/aquasecurity/tracee/types/trace"
)

type Event struct {
	id           ID // TODO: use id ?
	id32Bit      ID
	name         string
	docPath      string // Relative to the 'doc/events' directory
	internal     bool
	syscall      bool
	dependencies Dependencies
	sets         []string
	params       []trace.ArgMeta
}

func NewEvent(name string, sets []string, depsID []ID) Event {
	evt := Event{
		id32Bit: Sys32Undefined,
		name:    name,
		sets:    sets,
	}

	d := Dependencies{
		Events: make([]ID, 0, len(depsID)),
	}

	d.Events = append(d.Events, depsID...)

	evt.dependencies = d

	return evt
}

// NewEvent creates a new Event with all its fields set.
func NewEventFull(
	id ID,
	id32Bit ID,
	name string,
	docPath string,
	internal bool,
	syscall bool,
	sets []string,
	deps Dependencies,
	params []trace.ArgMeta,
) Event {
	// TODO: use id ?
	return Event{
		id:           id,
		id32Bit:      id32Bit,
		name:         name,
		docPath:      docPath,
		internal:     internal,
		syscall:      syscall,
		dependencies: deps,
		sets:         sets,
		params:       params,
	}
}

// Getters (immutable data)

func (e *Event) GetID() ID {
	return e.id
}

func (e *Event) GetID32Bit() ID {
	return e.id32Bit
}

func (e *Event) GetName() string {
	return e.name
}

func (e *Event) GetDocPath() string {
	return e.docPath
}

func (e *Event) IsInternal() bool {
	return e.internal
}

func (e *Event) IsSyscall() bool {
	return e.syscall
}

func (e *Event) GetDependencies() Dependencies {
	return e.dependencies
}

func (e *Event) GetSets() []string {
	return e.sets
}

func (e *Event) GetParams() []trace.ArgMeta {
	return e.params
}

// TODO: remove all Setters (mutable data) once we have a proper event definition

func (e *Event) SetParams(params []trace.ArgMeta) {
	e.params = params
}

// TODO: remove this function once we have a proper event definition
func IsASignatureEvent(id ID) bool {
	if id >= StartSignatureID && id <= MaxSignatureID {
		return true
	}

	return false
}
