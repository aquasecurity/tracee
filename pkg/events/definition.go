package events

import "github.com/aquasecurity/tracee/types/trace"

type EventDefinition struct {
	id           ID
	id32Bit      ID
	name         string
	docPath      string // Relative to the 'doc/events' directory
	internal     bool
	syscall      bool
	dependencies Dependencies
	sets         []string
	params       []trace.ArgMeta
}

func NewEventDefinition(name string, sets []string, depsID []ID) EventDefinition {
	evt := EventDefinition{
		id32Bit: sys32undefined,
		name:    name,
		sets:    sets,
	}

	d := Dependencies{
		Events: make([]ID, 0, len(depsID)),
	}

	for _, id := range depsID {
		d.Events = append(d.Events, id)
	}

	evt.dependencies = d

	return evt
}

// NewEventDefinitionFull creates a new EventDefinition with all fields set.
func NewEventDefinitionFull(
	id32Bit ID, name string, docPath string, internal bool, syscall bool,
	deps Dependencies, sets []string, params []trace.ArgMeta,
) EventDefinition {
	return EventDefinition{
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

// TODO: remove this function once we have a proper event definition
func IsASignatureEvent(id ID) bool {
	if id >= StartSignatureID && id <= MaxSignatureID {
		return true
	}

	return false
}

// Getters (immutable data)

func (e *EventDefinition) GetID32Bit() ID {
	return e.id32Bit
}

func (e *EventDefinition) GetName() string {
	return e.name
}

func (e *EventDefinition) GetDocPath() string {
	return e.docPath
}

func (e *EventDefinition) IsInternal() bool {
	return e.internal
}

func (e *EventDefinition) IsSyscall() bool {
	return e.syscall
}

func (e *EventDefinition) GetDependencies() Dependencies {
	return e.dependencies
}

func (e *EventDefinition) GetSets() []string {
	return e.sets
}

func (e *EventDefinition) GetParams() []trace.ArgMeta {
	return e.params
}

// TODO: remove all Setters (mutable data) once we have a proper event definition

func (e *EventDefinition) SetParams(params []trace.ArgMeta) {
	e.params = params
}
