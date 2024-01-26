package events

import (
	"sort"
	"sync"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/extensions"
	"github.com/aquasecurity/tracee/pkg/logger"
)

// Make it sortable by ID

type ByID []Definition

func (a ByID) Len() int           { return len(a) }
func (a ByID) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByID) Less(i, j int) bool { return a[i].id < a[j].id }

// Definitions

// Definitions is a struct describing a collection of Event Definitions.
type Definitions struct {
	definitions map[ID]Definition
	mutex       *sync.RWMutex // write lock for adding definitions (initialization/reconfig only)
}

// NewDefinitions creates a new Event Definition Group.
func NewDefinitions() *Definitions {
	return &Definitions{
		definitions: make(map[ID]Definition),
		mutex:       &sync.RWMutex{},
	}
}

// GetDefinitions returns a new map of existing definitions.
func (d *Definitions) GetDefinitions() []Definition {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	definitions := make([]Definition, 0, len(d.definitions))

	for _, evtDef := range d.definitions {
		definitions = append(definitions, evtDef)
	}
	sort.Sort(ByID(definitions))

	return definitions
}

// GetDefinitionIDByName returns a definition ID by its name.
func (d *Definitions) GetDefinitionIDByName(givenName string) (ID, bool) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	evtDefID, found := d.getDefinitionIDByName(givenName)
	if !found {
		logger.Debugw("definition name not found", "name", givenName)
	}

	return evtDefID, found
}

// getDefinitionIDByName returns a definition ID by its name (no locking).
func (d *Definitions) getDefinitionIDByName(givenName string) (ID, bool) {
	for evtDefID, evtDef := range d.definitions {
		if evtDef.GetName() == givenName {
			return evtDefID, true
		}
	}

	return Undefined, false
}

// GetDefinitionByID returns a definition by its ID.
func (d *Definitions) GetDefinitionByID(givenDef ID) Definition {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	evtDef, ok := d.definitions[givenDef]
	if !ok {
		logger.Debugw("definition id not found", "id", givenDef)
		return Definition{id: Undefined}
	}

	return evtDef
}

// IsDefined returns true if the definition exists in the definition group.
func (d *Definitions) IsDefined(givenDef ID) bool {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	_, ok := d.definitions[givenDef]
	return ok
}

// Length returns the number of definitions in the definition group.
func (d *Definitions) Length() int {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return len(d.definitions)
}

// Add adds a definition to the definition group.
func (d *Definitions) Add(givenId ID, givenDef Definition) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return d.add(givenId, givenDef)
}

// AddBatch adds multiple definitions to the definition group.
func (d *Definitions) AddBatch(givenDefs map[ID]Definition) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	for evtDefID, evtDef := range givenDefs {
		err := d.add(evtDefID, evtDef)
		if err != nil {
			return err
		}
	}

	return nil
}

// add adds a definition to the definition group (no locking).
func (d *Definitions) add(givenId ID, givenDef Definition) error {
	if _, ok := d.definitions[givenId]; ok {
		return errfmt.Errorf("definition id already exists: %v", givenId)
	}

	n := givenDef.GetName()
	if _, ok := d.getDefinitionIDByName(n); ok {
		return errfmt.Errorf("definition name already exists: %v", n)
	}

	d.definitions[givenId] = givenDef

	return nil
}

// NamesToIDs returns a new map of definition names to their IDs.
func (d *Definitions) NamesToIDs() map[string]ID {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	namesToIds := make(map[string]ID, len(d.definitions))

	for evtDefID, evtDef := range d.definitions {
		namesToIds[evtDef.GetName()] = evtDefID
	}

	return namesToIds
}

// IDs32ToIDs returns a new map of 32-bit definition IDs to their IDs.
func (d *Definitions) IDs32ToIDs() map[ID]ID {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	idS32ToIDs := make(map[ID]ID, len(d.definitions))

	for evtDefID, evtDef := range d.definitions {
		id32Bit := evtDef.GetID32Bit()
		if id32Bit != Sys32Undefined {
			idS32ToIDs[id32Bit] = evtDefID
		}
	}

	return idS32ToIDs
}

// GetTailCalls returns a list of all tailcalls of all traced events.
func (d *Definitions) GetTailCalls() []TailCall {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	tailCalls := make([]TailCall, 0, len(d.definitions))

	for evtDefID, evtDef := range d.definitions {
		state, ok := extensions.States.GetOk("core", int(evtDefID))
		if !ok {
			continue
		}
		// Only events bring traced will provide their tailcalls.
		if state.AnySubmitEnabled() {
			tailCalls = append(tailCalls, evtDef.GetDependencies().GetTailCalls()...)
		}
	}

	return tailCalls
}
