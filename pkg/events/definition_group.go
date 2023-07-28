package events

import (
	"sync"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
)

// TODO: add states to the EventGroup struct (to keep states of events from that group)

type EventState struct {
	Submit uint64 // should be submitted to userspace (by policies bitmap)
	Emit   uint64 // should be emitted to the user (by policies bitmap)
}

// ATTENTION: the definition group is instantiable (all the rest is immutable)

//
// DefinitionGroup
//

// DefinitionGroup is a struct describing a collection of Event Definitions.
type DefinitionGroup struct {
	definitions map[ID]Definition
	mutex       *sync.RWMutex // write lock for adding definitions (initialization/reconfig only)
}

// NewDefinitionGroup creates a new Event Definition Group.
func NewDefinitionGroup() *DefinitionGroup {
	return &DefinitionGroup{
		definitions: make(map[ID]Definition),
		mutex:       &sync.RWMutex{},
	}
}

// GetDefinitions returns a new map of existing definitions.
// TODO: iterate internally after event definition refactor is finished ?
func (e *DefinitionGroup) GetDefinitions() map[ID]Definition {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	mapCopy := make(map[ID]Definition, len(e.definitions))

	for id, def := range e.definitions {
		mapCopy[id] = def
	}

	return mapCopy
}

// GetDefinitionIDByName returns a definition ID by its name.
func (e *DefinitionGroup) GetDefinitionIDByName(givenName string) (ID, bool) {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return e.getDefinitionIDByName(givenName)
}

// getDefinitionIDByName returns a definition ID by its name (no locking).
func (e *DefinitionGroup) getDefinitionIDByName(givenName string) (ID, bool) {
	for id, def := range e.definitions {
		if def.GetName() == givenName {
			return id, true
		}
	}
	logger.Debugw("definition name not found", "name", givenName)

	return Undefined, false
}

// GetDefinitionByID returns a definition by its ID.
// NOTE: should be used together with IsDefined when definition might not exist.
func (e *DefinitionGroup) GetDefinitionByID(givenDef ID) Definition {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	def, ok := e.definitions[givenDef]
	if !ok {
		logger.Debugw("definition id not found", "id", givenDef)
		return Definition{id: Undefined}
	}

	return def
}

// IsDefined returns true if the definition exists in the definition group.
// NOTE: needed as GetDefinitionByID() is used as GetDefinitionByID().Method() multiple times.
func (e *DefinitionGroup) IsDefined(givenDef ID) bool {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	_, ok := e.definitions[givenDef]
	return ok
}

// Length returns the number of definitions in the definition group.
func (e *DefinitionGroup) Length() int {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return len(e.definitions)
}

// Add adds a definition to the definition group.
func (e *DefinitionGroup) Add(givenId ID, givenDef Definition) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	return e.add(givenId, givenDef)
}

// AddBatch adds multiple definitions to the definition group.
func (e *DefinitionGroup) AddBatch(givenDefs map[ID]Definition) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	for id, def := range givenDefs {
		err := e.add(id, def)
		if err != nil {
			return err
		}
	}

	return nil
}

// add adds a definition to the definition group (no locking).
func (e *DefinitionGroup) add(givenId ID, givenDef Definition) error {
	if _, ok := e.definitions[givenId]; ok {
		return definitionIDAlreadyExistsErr(givenId)
	}

	n := givenDef.GetName()
	if _, ok := e.getDefinitionIDByName(n); ok {
		return definitionNameAlreadyExistsErr(n)
	}

	e.definitions[givenId] = givenDef

	return nil
}

// NamesToIDs returns a new map of definition names to their IDs.
func (e *DefinitionGroup) NamesToIDs() map[string]ID {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	namesToIds := make(map[string]ID, len(e.definitions))

	for id, def := range e.definitions {
		namesToIds[def.GetName()] = id
	}

	return namesToIds
}

// IDs32ToIDs returns a new map of 32-bit definition IDs to their IDs.
func (e *DefinitionGroup) IDs32ToIDs() map[ID]ID {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	idS32ToIDs := make(map[ID]ID, len(e.definitions))

	for id, def := range e.definitions {
		id32Bit := def.GetID32Bit()

		if id32Bit != Sys32Undefined {
			idS32ToIDs[id32Bit] = id
		}
	}

	return idS32ToIDs
}

// GetTailCalls returns a list of tailcalls of all definitions in the group (for initialization).
func (e *DefinitionGroup) GetTailCalls(state map[ID]EventState) []TailCall {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	var tailCalls []TailCall

	for id, def := range e.definitions {
		if state[id].Submit > 0 { // only traced events to provide their tailcalls
			tailCalls = append(tailCalls, def.GetDependencies().GetTailCalls()...)
		}
	}

	return tailCalls
}

// Errors

func definitionIDAlreadyExistsErr(id ID) error {
	return errfmt.Errorf("definition id already exists: %v", id)
}

func definitionNameAlreadyExistsErr(name string) error {
	return errfmt.Errorf("definition name already exists: %v", name)
}
