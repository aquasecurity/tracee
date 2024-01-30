package events

// var amountOfTestThreads = 100

// var version = NewVersion(1, 0, 0)

// var getNames = func() map[string]ID {
// 	names := map[string]ID{}

// 	for i := 0; i < amountOfTestThreads; i++ {
// 		names[fmt.Sprintf("def%d", i)] = ID(i)
// 	}

// 	return names
// }

// // TestDefinitions_Add tests that Add adds a definition to the definition group.
// func TestDefinitions_Add(t *testing.T) {
// 	t.Parallel()

// 	defGroup := NewDefinitions()

// 	id := ID(1)

// 	def := NewDefinition(id, id+1000, "def", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)

// 	err := defGroup.Add(id, def)
// 	require.NoError(t, err)

// 	_, ok := defGroup.definitions[id]
// 	require.True(t, ok, true)
// }

// // TestDefinitions_AddBatch tests that AddBatch adds multiple definitions to the definition group.
// func TestDefinitions_AddBatch(t *testing.T) {
// 	t.Parallel()

// 	defGroup := NewDefinitions()

// 	id1 := ID(1)
// 	id2 := ID(2)

// 	def1 := NewDefinition(id1, id1+1000, "def1", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)
// 	def2 := NewDefinition(id2, id2+1000, "def2", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)

// 	err := defGroup.AddBatch(map[ID]Definition{id1: def1, id2: def2})
// 	require.NoError(t, err)

// 	_, ok := defGroup.definitions[id1]
// 	require.True(t, ok, true)

// 	_, ok = defGroup.definitions[id2]
// 	require.True(t, ok, true)
// }

// // TestDefinitions_GetDefinitionIDByName tests that GetDefinitionIDByName returns a definition ID by its name.
// func TestDefinitions_GetDefinitionIDByName(t *testing.T) {
// 	t.Parallel()

// 	defGroup := NewDefinitions()

// 	id1 := ID(1)
// 	id2 := ID(2)

// 	def1 := NewDefinition(id1, id1+1000, "def1", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)
// 	def2 := NewDefinition(id2, id2+1000, "def2", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)

// 	defGroup.AddBatch(map[ID]Definition{id1: def1, id2: def2})

// 	id, ok := defGroup.GetDefinitionIDByName("def1")
// 	require.True(t, ok, true)
// 	require.Equal(t, id, id1)

// 	id, ok = defGroup.GetDefinitionIDByName("def2")
// 	require.True(t, ok, true)
// 	require.Equal(t, id, id2)
// }

// // TestDefinitions_GetDefinitionByID tests that GetDefinitionByID returns a definition by its ID.
// func TestDefinitions_GetDefinitionByID(t *testing.T) {
// 	t.Parallel()

// 	defGroup := NewDefinitions()

// 	id1 := ID(1)
// 	id2 := ID(2)

// 	def1 := NewDefinition(id1, id1+1000, "def1", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)
// 	def2 := NewDefinition(id2, id2+1000, "def2", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)

// 	defGroup.AddBatch(map[ID]Definition{id1: def1, id2: def2})

// 	// found definition

// 	require.True(t, defGroup.IsDefined(id1))
// 	def := defGroup.GetDefinitionByID(id1)
// 	require.Equal(t, def.GetName(), "def1")

// 	// definition not found (undefined)

// 	require.False(t, defGroup.IsDefined(ID(3)))
// 	def = defGroup.GetDefinitionByID(ID(3))
// 	require.Equal(t, def.GetID(), Undefined)
// }

// // TestDefinitions_Length tests that Length returns the number of definitions in the definition group.
// func TestDefinitions_Length(t *testing.T) {
// 	t.Parallel()

// 	defGroup := NewDefinitions()

// 	require.Equal(t, defGroup.Length(), 0) // empty definition group

// 	id := ID(1)

// 	def := NewDefinition(id, id+1000, "def", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)
// 	defGroup.Add(id, def)

// 	require.Equal(t, defGroup.Length(), 1) // definition group with one definition

// 	id2 := ID(2)
// 	def2 := NewDefinition(id2, id2+1000, "def2", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)
// 	defGroup.Add(id2, def2)

// 	require.Equal(t, defGroup.Length(), 2) // definition group with two definitions
// }

// // TestDefinitions_GetDefinitions tests that GetDefinitions returns a map of definition IDs to their definitions.
// func TestDefinitions_GetDefinitions(t *testing.T) {
// 	t.Parallel()

// 	defGroup := NewDefinitions()

// 	id1 := ID(1)
// 	id2 := ID(2)

// 	def1 := NewDefinition(id1, id1+1000, "def1", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)
// 	def2 := NewDefinition(id2, id2+1000, "def2", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)

// 	defGroup.AddBatch(map[ID]Definition{id1: def1, id2: def2})

// 	defs := defGroup.GetDefinitions()

// 	require.Equal(t, len(defs), len(defGroup.definitions)) // same number of definitions
// 	require.Contains(t, defs, def1)                        // same definition
// 	require.Contains(t, defs, def2)                        // same definition
// }

// // TestDefinitions_NamesToIDs tests that NamesToIDs returns a map of definition names to their IDs.
// func TestDefinitions_NamesToIDs(t *testing.T) {
// 	t.Parallel()

// 	defGroup := NewDefinitions()

// 	id1 := ID(1)
// 	id2 := ID(2)

// 	def1 := NewDefinition(id1, id1+1000, "def1", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)
// 	def2 := NewDefinition(id2, id2+1000, "def2", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)

// 	defGroup.AddBatch(map[ID]Definition{id1: def1, id2: def2})

// 	namesToIds := defGroup.NamesToIDs()

// 	require.Equal(t, len(namesToIds), len(defGroup.definitions)) // same number of definitions
// 	require.Equal(t, namesToIds["def1"], id1)                    // same definition ID
// 	require.Equal(t, namesToIds["def2"], id2)                    // same definition ID
// }

// // TestDefinitions_IDs32ToIDs tests that IDs32ToIDs returns a map of definition IDs to their 32-bit IDs.
// func TestDefinitions_IDs32ToIDs(t *testing.T) {
// 	t.Parallel()

// 	defGroup := NewDefinitions()

// 	id1 := ID(1)
// 	id2 := ID(2)

// 	def1 := NewDefinition(id1, id1+1000, "def1", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)
// 	def2 := NewDefinition(id2, id2+1000, "def2", version, "", "", false, false, []string{}, Dependencies{}, nil, nil)

// 	defGroup.AddBatch(map[ID]Definition{id1: def1, id2: def2})

// 	idS32ToIDs := defGroup.IDs32ToIDs()

// 	require.Equal(t, len(idS32ToIDs), len(defGroup.definitions)) // same number of definitions
// 	require.Equal(t, idS32ToIDs[id1+1000], id1)                  // same definition ID
// 	require.Equal(t, idS32ToIDs[id2+1000], id2)                  // same definition ID
// }

// //
// // Thread Safety
// //

// // TestDefinitions_AddBatchAndGetDefinitions_MultipleThreads tests Add and Get functions for thread-safety.
// func TestDefinitions_AddBatch_MultipleThreads(t *testing.T) {
// 	t.Parallel()

// 	defGroup := NewDefinitions()

// 	names := getNames()

// 	wg := &sync.WaitGroup{}

// 	for name, id := range names {
// 		wg.Add(1)
// 		go func(name string, id ID) {
// 			def := NewDefinition(id, id+1000, name, version, "", "", false, false, []string{}, Dependencies{}, nil, nil)

// 			err := defGroup.AddBatch(map[ID]Definition{id: def})
// 			require.NoError(t, err)

// 			odef := defGroup.GetDefinitionByID(id)          // concurrent calls
// 			oid, ok := defGroup.GetDefinitionIDByName(name) // concurrent calls

// 			require.True(t, true, ok)
// 			require.Equal(t, def, odef) // same definition
// 			require.Equal(t, id, oid)   // same definition ID

// 			wg.Done()
// 		}(name, id)
// 	}

// 	wg.Wait()
// }

// // TestDefinitions_Length_MultipleThreads tests that Length is thread-safe.
// func TestDefinitions_Length_MultipleThreads(t *testing.T) {
// 	t.Parallel()

// 	defGroup := NewDefinitions()

// 	names := getNames()

// 	wg := &sync.WaitGroup{}

// 	for name, id := range names {
// 		wg.Add(1)
// 		go func(name string, id ID) {
// 			def := NewDefinition(id, id+1000, name, version, "", "", false, false, []string{}, Dependencies{}, nil, nil)
// 			err := defGroup.AddBatch(map[ID]Definition{id: def})
// 			require.NoError(t, err)
// 			defGroup.Length() // concurrent calls
// 			wg.Done()
// 		}(name, id)
// 	}

// 	wg.Wait()

// 	require.Equal(t, amountOfTestThreads, defGroup.Length()) // definition group with 20 definitions
// }

// // TestDefinitions_GetDefinitions_MultipleThread tests that GetDefinitions is thread-safe.
// func TestDefinitions_GetDefinitions_MultipleThread(t *testing.T) {
// 	t.Parallel()

// 	defGroup := NewDefinitions()

// 	names := getNames()

// 	wg := &sync.WaitGroup{}

// 	for name, id := range names {
// 		wg.Add(1)
// 		go func(name string, id ID) {
// 			def := NewDefinition(id, id+1000, name, version, "", "", false, false, []string{}, Dependencies{}, nil, nil)
// 			err := defGroup.AddBatch(map[ID]Definition{id: def})
// 			require.NoError(t, err)
// 			defGroup.GetDefinitions() // concurrent calls
// 			wg.Done()
// 		}(name, id)
// 	}

// 	wg.Wait()

// 	require.Equal(t, amountOfTestThreads, defGroup.Length()) // definition group with 20 definitions
// }

// // TestDefinitions_NamesToIDs_MultipleThreads tests that NamesToIDs is thread-safe.
// func TestDefinitions_NamesToIDs_MultipleThreads(t *testing.T) {
// 	t.Parallel()

// 	defGroup := NewDefinitions()

// 	wg := &sync.WaitGroup{}

// 	names := getNames()

// 	for name, id := range names {
// 		wg.Add(1)
// 		go func(name string, id ID) {
// 			def := NewDefinition(id, id+1000, name, version, "", "", false, false, []string{}, Dependencies{}, nil, nil)

// 			err := defGroup.Add(id, def)
// 			require.NoError(t, err)

// 			namesToIds := defGroup.NamesToIDs() // concurrent calls

// 			require.Equal(t, namesToIds[name], id) // same definition ID

// 			wg.Done()
// 		}(name, id)
// 	}

// 	wg.Wait()
// }

// // TestDefinitions_IDs32ToIDs_MultipleThreads tests that IDs32ToIDs is thread-safe.
// func TestDefinitions_IDs32ToIDs_MultipleThreads(t *testing.T) {
// 	t.Parallel()

// 	defGroup := NewDefinitions()

// 	wg := &sync.WaitGroup{}

// 	names := getNames()

// 	for name, id := range names {
// 		wg.Add(1)
// 		go func(name string, id ID) {
// 			def := NewDefinition(id, id+1000, name, version, "", "", false, false, []string{}, Dependencies{}, nil, nil)

// 			err := defGroup.Add(id, def)
// 			require.NoError(t, err)

// 			idS32ToIDs := defGroup.IDs32ToIDs() // concurrent calls

// 			require.Equal(t, id, idS32ToIDs[id+1000]) // same definitio ID

// 			wg.Done()
// 		}(name, id)
// 	}

// 	wg.Wait()
// }
