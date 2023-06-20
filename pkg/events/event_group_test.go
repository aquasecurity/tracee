package events

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

var get10Names = func() map[string]ID {
	names := map[string]ID{}

	for i := 1; i <= 10; i++ {
		names[fmt.Sprintf("evt%d", i)] = ID(i)
	}

	return names
}

// TestEventGroup_Add tests that Add adds an event to the event group.
func TestEventGroup_Add(t *testing.T) {
	eg := NewEventGroup()

	id := ID(1)
	evt := NewEvent(id, id, "evt", "", false, false, []string{}, nil, nil)

	err := eg.Add(id, evt)
	require.NoError(t, err)

	_, ok := eg.events[id]
	require.True(t, ok, true)
}

// TestEventGroup_AddBatch tests that AddBatch adds multiple events to the event group.
func TestEventGroup_AddBatch(t *testing.T) {
	eg := NewEventGroup()

	id1 := ID(1)
	id2 := ID(2)
	evt1 := NewEvent(id1, id1, "evt1", "", false, false, []string{}, nil, nil)
	evt2 := NewEvent(id2, id2, "evt2", "", false, false, []string{}, nil, nil)

	err := eg.AddBatch(map[ID]*Event{id1: evt1, id2: evt2})
	require.NoError(t, err)

	_, ok := eg.events[id1]
	require.True(t, ok, true)

	_, ok = eg.events[id2]
	require.True(t, ok, true)
}

// TestEventGroup_AddBatch_MultipleThreads tests that Add/AddBatch is thread-safe.
func TestEventGroup_AddBatch_MultipleThreads(t *testing.T) {
	eg := NewEventGroup()

	wg := &sync.WaitGroup{}

	for i := 1; i <= 20; i++ {
		id := ID(i)
		evt := NewEvent(id, id, fmt.Sprintf("evt%d", i), "", false, false, []string{}, nil, nil)

		wg.Add(1)
		go func(evt *Event) {
			err := eg.AddBatch(map[ID]*Event{id: evt})
			if err != nil {
				wg.Done()
			}
			require.NoError(t, err)
			wg.Done()
		}(evt)
	}

	wg.Wait()

	for i := 1; i <= 20; i++ {
		id := ID(i)
		_, ok := eg.events[id]
		require.True(t, ok, true)
	}
}

// TestEventGroup_GetEventIDByName tests that GetEventIDByName returns a event ID by its name.
func TestEventGroup_GetEventIDByName(t *testing.T) {
	eg := NewEventGroup()

	id1 := ID(1)
	id2 := ID(2)
	evt1 := NewEvent(id1, id1, "evt1", "", false, false, []string{}, nil, nil)
	evt2 := NewEvent(id2, id2, "evt2", "", false, false, []string{}, nil, nil)

	eg.AddBatch(map[ID]*Event{id1: evt1, id2: evt2})

	id, ok := eg.GetEventIDByName("evt1")
	require.True(t, ok, true)
	require.Equal(t, id, id1)

	id, ok = eg.GetEventIDByName("evt2")
	require.True(t, ok, true)
	require.Equal(t, id, id2)
}

// TestEventGroup_GetEventIDByName_MultipleThreads tests that GetEventIDByName is thread-safe.
func TestEventGroup_GetEventByID(t *testing.T) {
	eg := NewEventGroup()

	id1 := ID(1)
	id2 := ID(2)
	evt1 := NewEvent(id1, id1, "evt1", "", false, false, []string{}, nil, nil)
	evt2 := NewEvent(id2, id2, "evt2", "", false, false, []string{}, nil, nil)

	eg.AddBatch(map[ID]*Event{id1: evt1, id2: evt2})

	// found event
	evt := eg.GetEventByID(id1)
	require.NotNil(t, evt)                  // event has to be found
	require.Equal(t, evt.GetName(), "evt1") // name has to be correct

	// event not found
	evt = eg.GetEventByID(ID(3))
	require.Nil(t, evt) // event should not be found
}

// TestEventGroup_GetEventByID_MultipleThreads tests that GetEventByID is thread-safe.
func TestEventGroup_GetEvent_MultipleThreads(t *testing.T) {
	eg := NewEventGroup()

	wg := &sync.WaitGroup{}

	names := get10Names()

	for name, id := range names {
		wg.Add(1)
		go func(name string, id ID) {
			evt := NewEvent(id, id, name, "", false, false, []string{}, nil, nil)

			err := eg.AddBatch(map[ID]*Event{id: evt})
			require.NoError(t, err)

			oevt := eg.GetEventByID(id)          // concurrent calls
			oid, ok := eg.GetEventIDByName(name) // concurrent calls

			require.True(t, true, ok)
			require.Same(t, evt, oevt) // same event (Same: same pointer)
			require.Equal(t, id, oid)  // same event ID

			wg.Done()
		}(name, id)
	}

	wg.Wait()
}

// TestEventGroup_Length tests that Length returns the number of events in the event group.
func TestEventGroup_Length(t *testing.T) {
	eg := NewEventGroup()

	require.Equal(t, eg.Length(), 0) // empty event group

	id := ID(1)
	evt := NewEvent(id, id, "evt", "", false, false, []string{}, nil, nil)
	eg.Add(id, evt)

	require.Equal(t, eg.Length(), 1) // event group with one event

	id2 := ID(2)
	evt2 := NewEvent(id2, id2, "evt2", "", false, false, []string{}, nil, nil)
	eg.Add(id2, evt2)

	require.Equal(t, eg.Length(), 2) // event group with two events
}

// TestEventGroup_Length_MultipleThreads tests that Length is thread-safe.
func TestEventGroup_Length_MultipleThreads(t *testing.T) {
	eg := NewEventGroup()

	wg := &sync.WaitGroup{}

	for i := 1; i <= 20; i++ {
		id := ID(i)
		evt := NewEvent(id, id, fmt.Sprintf("evt%d", i), "", false, false, []string{}, nil, nil)

		wg.Add(1)
		go func(evt *Event) {
			err := eg.AddBatch(map[ID]*Event{id: evt})
			require.NoError(t, err)
			eg.Length() // concurrent calls
			wg.Done()
		}(evt)
	}

	wg.Wait()

	require.Equal(t, eg.Length(), 20) // event group with 20 events
}

// TestEventGroup_GetAllEvents tests that GetAllEvents returns a slice of instanced events.
func TestEventGroup_GetAllEvents(t *testing.T) {
	eg := NewEventGroup()

	id1 := ID(1)
	id2 := ID(2)
	evt1 := NewEvent(id1, id1, "evt1", "", false, false, []string{}, nil, nil)
	evt2 := NewEvent(id2, id2, "evt2", "", false, false, []string{}, nil, nil)

	eg.AddBatch(map[ID]*Event{id1: evt1, id2: evt2})

	copy := eg.GetAllEvents() // slice of instanced events at the time of the call

	require.Equal(t, len(copy), len(eg.events)) // same number of events
	require.Same(t, copy[id1], evt1)            // same event (Same: same pointer)
	require.Same(t, copy[id2], evt2)            // same event (Same: same pointer)
}

// TestEventGroup_GetAllEvents_MultipleThreads tests that GetAllEvents is thread-safe.
func TestEventGroup_GetAllEvents_MultipleThreads(t *testing.T) {
	eg := NewEventGroup()

	wg := &sync.WaitGroup{}

	names := get10Names()

	for name, id := range names {
		wg.Add(1)
		go func(name string, id ID) {
			evt := NewEvent(id, id, name, "", false, false, []string{}, nil, nil)

			err := eg.Add(id, evt)
			require.NoError(t, err)

			aevts := eg.GetAllEvents() // concurrent calls
			oevt, ok := aevts[id]

			require.True(t, true, ok)  // event has to be found
			require.Same(t, evt, oevt) // same event (Same: same pointer)

			wg.Done()
		}(name, id)
	}

	wg.Wait()
}

// TestEventGroup_NamesToIDs tests that NamesToIDs returns a map of event names to their IDs.
func TestEventGroup_NamesToIDs(t *testing.T) {
	eg := NewEventGroup()

	id1 := ID(1)
	id2 := ID(2)
	evt1 := NewEvent(id1, id1, "evt1", "", false, false, []string{}, nil, nil)
	evt2 := NewEvent(id2, id2, "evt2", "", false, false, []string{}, nil, nil)

	eg.AddBatch(map[ID]*Event{id1: evt1, id2: evt2})

	namesToIds := eg.NamesToIDs()

	require.Equal(t, len(namesToIds), len(eg.events)) // same number of events
	require.Equal(t, namesToIds["evt1"], id1)         // same event ID
	require.Equal(t, namesToIds["evt2"], id2)         // same event ID
}

// TestEventGroup_NamesToIDs_MultipleThreads tests that NamesToIDs is thread-safe.
func TestEventGroup_NamesToIDs_MultipleThreads(t *testing.T) {
	eg := NewEventGroup()

	wg := &sync.WaitGroup{}

	names := get10Names()

	for name, id := range names {
		wg.Add(1)
		go func(name string, id ID) {
			evt := NewEvent(id, id, name, "", false, false, []string{}, nil, nil)

			err := eg.Add(id, evt)
			require.NoError(t, err)

			namesToIds := eg.NamesToIDs() // concurrent calls

			require.Equal(t, namesToIds[name], id) // same event ID

			wg.Done()
		}(name, id)
	}

	wg.Wait()
}

// TestEventGroup_IDs32ToIDs tests that IDs32ToIDs returns a map of event IDs to their 32-bit IDs.
func TestEventGroup_IDs32ToIDs(t *testing.T) {
	eg := NewEventGroup()

	id1 := ID(1)
	id2 := ID(2)
	id32Bit1 := ID(1001)
	id32Bit2 := ID(1002)
	evt1 := NewEvent(id1, id32Bit1, "evt1", "", false, false, []string{}, nil, nil)
	evt2 := NewEvent(id2, id32Bit2, "evt2", "", false, false, []string{}, nil, nil)

	eg.AddBatch(map[ID]*Event{id1: evt1, id2: evt2})

	idS32ToIDs := eg.IDs32ToIDs()

	require.Equal(t, len(idS32ToIDs), len(eg.events)) // same number of events
	require.Equal(t, idS32ToIDs[id32Bit1], id1)       // same event ID
	require.Equal(t, idS32ToIDs[id32Bit2], id2)       // same event ID
}

// TestEventGroup_IDs32ToIDs_MultipleThreads tests that IDs32ToIDs is thread-safe.
func TestEventGroup_IDs32ToIDs_MultipleThreads(t *testing.T) {
	eg := NewEventGroup()

	wg := &sync.WaitGroup{}

	names := get10Names()

	for name, id := range names {
		wg.Add(1)
		go func(name string, id ID) {
			evt := NewEvent(id, id+1000, name, "", false, false, []string{}, nil, nil)

			err := eg.Add(id, evt)
			require.NoError(t, err)

			idS32ToIDs := eg.IDs32ToIDs() // concurrent calls

			require.Equal(t, id, idS32ToIDs[id+1000]) // same event ID

			wg.Done()
		}(name, id)
	}

	wg.Wait()
}
