package events

import (
	"github.com/aquasecurity/tracee/types/trace"
)

type Definition struct {
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

func NewDefinition(
	id ID,
	id32Bit ID,
	name string,
	docPath string,
	internal bool,
	syscall bool,
	sets []string,
	deps Dependencies,
	params []trace.ArgMeta,
) Definition {
	return Definition{
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

func (d Definition) GetID() ID {
	return d.id
}

func (d Definition) GetID32Bit() ID {
	return d.id32Bit
}

func (d Definition) GetName() string {
	return d.name
}

func (d Definition) GetDocPath() string {
	return d.docPath
}

func (d Definition) IsInternal() bool {
	return d.internal
}

func (d Definition) IsSyscall() bool {
	return d.syscall
}

func (d Definition) GetDependencies() Dependencies {
	return d.dependencies
}

func (d Definition) GetSets() []string {
	return d.sets
}

func (d Definition) GetParams() []trace.ArgMeta {
	return d.params
}

func (d Definition) IsSignature() bool {
	if d.id >= StartSignatureID && d.id <= MaxSignatureID {
		return true
	}

	return false
}

func (d Definition) IsNetwork() bool {
	if d.id >= NetPacketIPv4 && d.id <= MaxUserNetID {
		return true
	}

	return false
}
