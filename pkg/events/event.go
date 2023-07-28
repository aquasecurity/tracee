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

func NewEvent(
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

func (e Event) GetID() ID {
	return e.id
}

func (e Event) GetID32Bit() ID {
	return e.id32Bit
}

func (e Event) GetName() string {
	return e.name
}

func (e Event) GetDocPath() string {
	return e.docPath
}

func (e Event) IsInternal() bool {
	return e.internal
}

func (e Event) IsSyscall() bool {
	return e.syscall
}

func (e Event) GetDependencies() Dependencies {
	return e.dependencies
}

func (e Event) GetSets() []string {
	return e.sets
}

func (e Event) GetParams() []trace.ArgMeta {
	return e.params
}

func (e Event) IsSignature() bool {
	if e.id >= StartSignatureID && e.id <= MaxSignatureID {
		return true
	}

	return false
}
