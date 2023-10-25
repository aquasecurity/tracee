package events

import (
	"sort"
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

type ByID []Definition

func (a ByID) Len() int           { return len(a) }
func (a ByID) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByID) Less(i, j int) bool { return a[i].id < a[j].id }

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
func (d *DefinitionGroup) GetDefinitions() []Definition {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	definitions := make([]Definition, 0, len(d.definitions))
	for _, def := range d.definitions {
		definitions = append(definitions, def)
	}
	sort.Sort(ByID(definitions))

	return definitions
}

// GetDefinitionIDByName returns a definition ID by its name.
func (d *DefinitionGroup) GetDefinitionIDByName(givenName string) (ID, bool) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	id, found := d.getDefinitionIDByName(givenName)
	if !found {
		logger.Debugw("definition name not found", "name", givenName)
	}
	return id, found
}

// getDefinitionIDByName returns a definition ID by its name (no locking).
func (d *DefinitionGroup) getDefinitionIDByName(givenName string) (ID, bool) {
	for id, def := range d.definitions {
		if def.GetName() == givenName {
			return id, true
		}
	}

	return Undefined, false
}

// GetDefinitionByID returns a definition by its ID.
// NOTE: should be used together with IsDefined when definition might not exist.
func (d *DefinitionGroup) GetDefinitionByID(givenDef ID) Definition {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	def, ok := d.definitions[givenDef]
	if !ok {
		logger.Debugw("definition id not found", "id", givenDef)
		return Definition{id: Undefined}
	}

	return def
}

// IsDefined returns true if the definition exists in the definition group.
// NOTE: needed as GetDefinitionByID() is used as GetDefinitionByID().Method() multiple times.
func (d *DefinitionGroup) IsDefined(givenDef ID) bool {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	_, ok := d.definitions[givenDef]
	return ok
}

// Length returns the number of definitions in the definition group.
func (d *DefinitionGroup) Length() int {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return len(d.definitions)
}

// Add adds a definition to the definition group.
func (d *DefinitionGroup) Add(givenId ID, givenDef Definition) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return d.add(givenId, givenDef)
}

// AddBatch adds multiple definitions to the definition group.
func (d *DefinitionGroup) AddBatch(givenDefs map[ID]Definition) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	for id, def := range givenDefs {
		err := d.add(id, def)
		if err != nil {
			return err
		}
	}

	return nil
}

// add adds a definition to the definition group (no locking).
func (d *DefinitionGroup) add(givenId ID, givenDef Definition) error {
	if _, ok := d.definitions[givenId]; ok {
		return definitionIDAlreadyExistsErr(givenId)
	}

	n := givenDef.GetName()
	if _, ok := d.getDefinitionIDByName(n); ok {
		return definitionNameAlreadyExistsErr(n)
	}

	d.definitions[givenId] = givenDef

	return nil
}

// NamesToIDs returns a new map of definition names to their IDs.
func (d *DefinitionGroup) NamesToIDs() map[string]ID {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	namesToIds := make(map[string]ID, len(d.definitions))

	for id, def := range d.definitions {
		namesToIds[def.GetName()] = id
	}

	return namesToIds
}

// IDs32ToIDs returns a new map of 32-bit definition IDs to their IDs.
func (d *DefinitionGroup) IDs32ToIDs() map[ID]ID {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	idS32ToIDs := make(map[ID]ID, len(d.definitions))

	for id, def := range d.definitions {
		id32Bit := def.GetID32Bit()

		if id32Bit != Sys32Undefined {
			idS32ToIDs[id32Bit] = id
		}
	}

	return idS32ToIDs
}

// GetTailCalls returns a list of tailcalls of all definitions in the group (for initialization).
func (d *DefinitionGroup) GetTailCalls(state map[ID]EventState) []TailCall {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	var tailCalls []TailCall

	for evtDefID, evtDef := range d.definitions {
		if state[evtDefID].Submit > 0 { // only traced events to provide their tailcalls
			tailCalls = append(tailCalls, evtDef.GetDependencies().GetTailCalls()...)
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
