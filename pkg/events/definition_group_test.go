package events

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

var amountOfTestThreads = 100

var version = NewVersion(1, 0, 0)

var getNames = func() map[string]ID {
	names := map[string]ID{}

	for i := 0; i < amountOfTestThreads; i++ {
		names[fmt.Sprintf("def%d", i)] = ID(i)
	}

	return names
}

// TestDefinitionGroup_Add tests that Add adds a definition to the definition group.
func TestDefinitionGroup_Add(t *testing.T) {
	t.Parallel()

	defGroup := NewDefinitionGroup()

	id := ID(1)

	def := NewDefinition(id, id+1000, "def", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)

	err := defGroup.Add(id, def)
	require.NoError(t, err)

	_, ok := defGroup.definitions[id]
	require.True(t, ok, true)
}

// TestDefinitionGroup_AddBatch tests that AddBatch adds multiple definitions to the definition group.
func TestDefinitionGroup_AddBatch(t *testing.T) {
	t.Parallel()

	defGroup := NewDefinitionGroup()

	id1 := ID(1)
	id2 := ID(2)

	def1 := NewDefinition(id1, id1+1000, "def1", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)
	def2 := NewDefinition(id2, id2+1000, "def2", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)

	err := defGroup.AddBatch(map[ID]Definition{id1: def1, id2: def2})
	require.NoError(t, err)

	_, ok := defGroup.definitions[id1]
	require.True(t, ok, true)

	_, ok = defGroup.definitions[id2]
	require.True(t, ok, true)
}

// TestDefinitionGroup_GetDefinitionIDByName tests that GetDefinitionIDByName returns a definition ID by its name.
func TestDefinitionGroup_GetDefinitionIDByName(t *testing.T) {
	t.Parallel()

	defGroup := NewDefinitionGroup()

	id1 := ID(1)
	id2 := ID(2)

	def1 := NewDefinition(id1, id1+1000, "def1", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)
	def2 := NewDefinition(id2, id2+1000, "def2", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)

	defGroup.AddBatch(map[ID]Definition{id1: def1, id2: def2})

	id, ok := defGroup.GetDefinitionIDByName("def1")
	require.True(t, ok, true)
	require.Equal(t, id, id1)

	id, ok = defGroup.GetDefinitionIDByName("def2")
	require.True(t, ok, true)
	require.Equal(t, id, id2)
}

// TestGetDefinitionByName tests that GetDefinitionByName returns a definition by its name.
func TestDefinitionGroup_GetDefinitionByName(t *testing.T) {
	t.Parallel()

	defGroup := NewDefinitionGroup()

	id1 := ID(1)
	id2 := ID(2)

	def1 := NewDefinition(id1, id1+1000, "def1", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)
	def2 := NewDefinition(id2, id2+1000, "def2", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)

	defGroup.AddBatch(map[ID]Definition{id1: def1, id2: def2})

	// found definition

	def := defGroup.GetDefinitionByName("def1")
	require.Equal(t, def.GetID(), id1)
	require.Equal(t, def.GetName(), "def1")

	// definition not found (undefined)

	def = defGroup.GetDefinitionByName("def3")
	require.Equal(t, def.GetID(), Undefined)
}

// TestDefinitionGroup_GetDefinitionByID tests that GetDefinitionByID returns a definition by its ID.
func TestDefinitionGroup_GetDefinitionByID(t *testing.T) {
	t.Parallel()

	defGroup := NewDefinitionGroup()

	id1 := ID(1)
	id2 := ID(2)

	def1 := NewDefinition(id1, id1+1000, "def1", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)
	def2 := NewDefinition(id2, id2+1000, "def2", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)

	defGroup.AddBatch(map[ID]Definition{id1: def1, id2: def2})

	// found definition

	require.True(t, defGroup.IsDefined(id1))
	def := defGroup.GetDefinitionByID(id1)
	require.Equal(t, def.GetName(), "def1")

	// definition not found (undefined)

	require.False(t, defGroup.IsDefined(ID(3)))
	def = defGroup.GetDefinitionByID(ID(3))
	require.Equal(t, def.GetID(), Undefined)
}

// TestDefinitionGroup_Length tests that Length returns the number of definitions in the definition group.
func TestDefinitionGroup_Length(t *testing.T) {
	t.Parallel()

	defGroup := NewDefinitionGroup()

	require.Equal(t, defGroup.Length(), 0) // empty definition group

	id := ID(1)

	def := NewDefinition(id, id+1000, "def", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)
	defGroup.Add(id, def)

	require.Equal(t, defGroup.Length(), 1) // definition group with one definition

	id2 := ID(2)
	def2 := NewDefinition(id2, id2+1000, "def2", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)
	defGroup.Add(id2, def2)

	require.Equal(t, defGroup.Length(), 2) // definition group with two definitions
}

// TestDefinitionGroup_GetDefinitions tests that GetDefinitions returns a map of definition IDs to their definitions.
func TestDefinitionGroup_GetDefinitions(t *testing.T) {
	t.Parallel()

	defGroup := NewDefinitionGroup()

	id1 := ID(1)
	id2 := ID(2)

	def1 := NewDefinition(id1, id1+1000, "def1", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)
	def2 := NewDefinition(id2, id2+1000, "def2", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)

	defGroup.AddBatch(map[ID]Definition{id1: def1, id2: def2})

	defs := defGroup.GetDefinitions()

	require.Equal(t, len(defs), len(defGroup.definitions)) // same number of definitions
	require.Contains(t, defs, def1)                        // same definition
	require.Contains(t, defs, def2)                        // same definition
}

// TestDefinitionGroup_NamesToIDs tests that NamesToIDs returns a map of definition names to their IDs.
func TestDefinitionGroup_NamesToIDs(t *testing.T) {
	t.Parallel()

	defGroup := NewDefinitionGroup()

	id1 := ID(1)
	id2 := ID(2)

	def1 := NewDefinition(id1, id1+1000, "def1", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)
	def2 := NewDefinition(id2, id2+1000, "def2", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)

	defGroup.AddBatch(map[ID]Definition{id1: def1, id2: def2})

	namesToIds := defGroup.NamesToIDs()

	require.Equal(t, len(namesToIds), len(defGroup.definitions)) // same number of definitions
	require.Equal(t, namesToIds["def1"], id1)                    // same definition ID
	require.Equal(t, namesToIds["def2"], id2)                    // same definition ID
}

// TestDefinitionGroup_IDs32ToIDs tests that IDs32ToIDs returns a map of definition IDs to their 32-bit IDs.
func TestDefinitionGroup_IDs32ToIDs(t *testing.T) {
	t.Parallel()

	defGroup := NewDefinitionGroup()

	id1 := ID(1)
	id2 := ID(2)

	def1 := NewDefinition(id1, id1+1000, "def1", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)
	def2 := NewDefinition(id2, id2+1000, "def2", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)

	defGroup.AddBatch(map[ID]Definition{id1: def1, id2: def2})

	idS32ToIDs := defGroup.IDs32ToIDs()

	require.Equal(t, len(idS32ToIDs), len(defGroup.definitions)) // same number of definitions
	require.Equal(t, idS32ToIDs[id1+1000], id1)                  // same definition ID
	require.Equal(t, idS32ToIDs[id2+1000], id2)                  // same definition ID
}

//
// Thread Safety
//

// TestDefinitionGroup_AddBatchAndGetDefinitions_MultipleThreads tests Add and Get functions for thread-safety.
func TestDefinitionGroup_AddBatch_MultipleThreads(t *testing.T) {
	t.Parallel()

	defGroup := NewDefinitionGroup()

	names := getNames()

	wg := &sync.WaitGroup{}

	for name, id := range names {
		wg.Add(1)
		go func(name string, id ID) {
			def := NewDefinition(id, id+1000, name, version, "", "", false, false, []string{}, Dependencies{}, nil, nil)

			err := defGroup.AddBatch(map[ID]Definition{id: def})
			require.NoError(t, err)

			odef := defGroup.GetDefinitionByID(id)          // concurrent calls
			oid, ok := defGroup.GetDefinitionIDByName(name) // concurrent calls

			require.True(t, true, ok)
			require.Equal(t, def, odef) // same definition
			require.Equal(t, id, oid)   // same definition ID

			wg.Done()
		}(name, id)
	}

	wg.Wait()
}

// TestDefinitionGroup_Length_MultipleThreads tests that Length is thread-safe.
func TestDefinitionGroup_Length_MultipleThreads(t *testing.T) {
	t.Parallel()

	defGroup := NewDefinitionGroup()

	names := getNames()

	wg := &sync.WaitGroup{}

	for name, id := range names {
		wg.Add(1)
		go func(name string, id ID) {
			def := NewDefinition(id, id+1000, name, version, "", "", false, false, []string{}, Dependencies{}, nil, nil)
			err := defGroup.AddBatch(map[ID]Definition{id: def})
			require.NoError(t, err)
			defGroup.Length() // concurrent calls
			wg.Done()
		}(name, id)
	}

	wg.Wait()

	require.Equal(t, amountOfTestThreads, defGroup.Length()) // definition group with 20 definitions
}

// TestDefinitionGroup_GetDefinitions_MultipleThread tests that GetDefinitions is thread-safe.
func TestDefinitionGroup_GetDefinitions_MultipleThread(t *testing.T) {
	t.Parallel()

	defGroup := NewDefinitionGroup()

	names := getNames()

	wg := &sync.WaitGroup{}

	for name, id := range names {
		wg.Add(1)
		go func(name string, id ID) {
			def := NewDefinition(id, id+1000, name, version, "", "", false, false, []string{}, Dependencies{}, nil, nil)
			err := defGroup.AddBatch(map[ID]Definition{id: def})
			require.NoError(t, err)
			defGroup.GetDefinitions() // concurrent calls
			wg.Done()
		}(name, id)
	}

	wg.Wait()

	require.Equal(t, amountOfTestThreads, defGroup.Length()) // definition group with 20 definitions
}

// TestDefinitionGroup_NamesToIDs_MultipleThreads tests that NamesToIDs is thread-safe.
func TestDefinitionGroup_NamesToIDs_MultipleThreads(t *testing.T) {
	t.Parallel()

	defGroup := NewDefinitionGroup()

	wg := &sync.WaitGroup{}

	names := getNames()

	for name, id := range names {
		wg.Add(1)
		go func(name string, id ID) {
			def := NewDefinition(id, id+1000, name, version, "", "", false, false, []string{}, Dependencies{}, nil, nil)

			err := defGroup.Add(id, def)
			require.NoError(t, err)

			namesToIds := defGroup.NamesToIDs() // concurrent calls

			require.Equal(t, namesToIds[name], id) // same definition ID

			wg.Done()
		}(name, id)
	}

	wg.Wait()
}

// TestDefinitionGroup_IDs32ToIDs_MultipleThreads tests that IDs32ToIDs is thread-safe.
func TestDefinitionGroup_IDs32ToIDs_MultipleThreads(t *testing.T) {
	t.Parallel()

	defGroup := NewDefinitionGroup()

	wg := &sync.WaitGroup{}

	names := getNames()

	for name, id := range names {
		wg.Add(1)
		go func(name string, id ID) {
			def := NewDefinition(id, id+1000, name, version, "", "", false, false, []string{}, Dependencies{}, nil, nil)

			err := defGroup.Add(id, def)
			require.NoError(t, err)

			idS32ToIDs := defGroup.IDs32ToIDs() // concurrent calls

			require.Equal(t, id, idS32ToIDs[id+1000]) // same definitio ID

			wg.Done()
		}(name, id)
	}

	wg.Wait()
}
