package events

import (
	"sort"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

//
// Dependencies: Events Tests
//

func initIDs() ([]ID, []ID) {
	evenIDs := []ID{}
	ids := []ID{}

	for i := 0; i < amountOfTestThreads; i++ {
		if i%2 == 0 {
			evenIDs = append(evenIDs, ID(i))
		}
		ids = append(ids, ID(i))
	}

	sortIDs(ids)
	sortIDs(evenIDs)

	return ids, evenIDs
}

func sortIDs(i []ID) {
	sort.Slice(i, func(i, j int) bool {
		return i < j
	})
}

// TestDependencies_SetEvents_MultipleThreads tests that SetEvents is thread-safe.
func TestDependencies_SetEvents_MultipleThreads(t *testing.T) {
	ids, _ := initIDs()

	d := NewDependencies(nil, nil, nil, nil, nil)

	wg := &sync.WaitGroup{}

	for i := 0; i < amountOfTestThreads; i++ {
		wg.Add(1)
		go func(i int) {
			d.SetEvents([]ID{ids[i]})
			wg.Done()
		}(i)
	}

	wg.Wait()

	actualEvents := d.GetEvents()

	require.Condition(t, func() bool {
		return actualEvents[0] < ID(amountOfTestThreads) // only testing races here, not values
	})
}

// TestDependencies_GetEvents_MultipleThreads tests that GetEvents is thread-safe.
func TestDependencies_GetEvents_MultipleThreads(t *testing.T) {
	ids, _ := initIDs()

	d := NewDependencies(nil, nil, nil, nil, nil)

	d.SetEvents(ids)

	wg := &sync.WaitGroup{}

	for i := 0; i < amountOfTestThreads; i++ {
		wg.Add(1)
		go func() {
			e := d.GetEvents()
			require.ElementsMatch(t, ids, e)
			wg.Done()
		}()
	}

	wg.Wait()
}

// TestDependencies_AddEvent_MultipleThreads tests that AddEvent is thread-safe.
func TestDependencies_AddEvent_MultipleThreads(t *testing.T) {
	ids, _ := initIDs()

	d := NewDependencies(nil, nil, nil, nil, nil)

	wg := &sync.WaitGroup{}

	for i := 0; i < amountOfTestThreads; i++ {
		wg.Add(1)
		go func(i int) {
			d.AddEvent(ids[i])
			wg.Done()
		}(i)
	}

	wg.Wait()

	actualEvents := d.GetEvents()
	require.ElementsMatch(t, ids, actualEvents)
}

// TestDependencies_AddEvents_MultipleThreads tests that AddEvents is thread-safe.
func TestDependencies_AddEvents_MultipleThreads(t *testing.T) {
	ids, _ := initIDs()

	d := NewDependencies(nil, nil, nil, nil, nil)

	wg := &sync.WaitGroup{}

	for i := 0; i < amountOfTestThreads; i++ {
		wg.Add(1)
		go func(i int) {
			d.AddEvents([]ID{ids[i]})
			wg.Done()
		}(i)
	}

	wg.Wait()

	actualEvents := d.GetEvents()
	require.ElementsMatch(t, ids, actualEvents)
}

// TestDependencies_SetAndAddDuplicateEvents_MultipleThreads tests AddKSymbol for duplicates.
// SetEvents.
func TestDependencies_SetAndAddDuplicateEvents_MultipleThreads(t *testing.T) {
	_, evenIDs := initIDs()

	d := NewDependencies(nil, nil, nil, nil, nil)

	d.SetEvents(evenIDs)

	wg := &sync.WaitGroup{}

	for i := 0; i < len(evenIDs); i++ {
		wg.Add(1)
		go func(i int) {
			d.AddEvent(evenIDs[i])
			wg.Done()
		}(i)
	}

	wg.Wait()

	actualEvents := d.GetEvents()
	sortIDs(actualEvents)
	require.ElementsMatch(t, evenIDs, actualEvents)
}

// TestDependencies_DelEvent_MultipleThreads tests that DelEvent is thread-safe.
func TestDependencies_DelEvent_MultipleThreads(t *testing.T) {
	ids, evenIDs := initIDs()

	d := NewDependencies(nil, nil, nil, nil, nil)

	d.SetEvents(ids)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < amountOfTestThreads; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 != 0 {
					d.DelEvent(ids[i])
				}
				wg.Done()
			}(i)
		}
		wg.Done()
	}()

	wg.Wait()

	actualEvents := d.GetEvents()
	sortIDs(actualEvents)
	require.ElementsMatch(t, evenIDs, actualEvents)
}

// TestDependencies_DelEvents_MultipleThreads tests that DelEvents is thread-safe.
func TestDependencies_DelEvents_MultipleThreads(t *testing.T) {
	ids, evenIDs := initIDs()

	d := NewDependencies(nil, nil, nil, nil, nil)

	d.SetEvents(evenIDs)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < amountOfTestThreads; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 != 0 {
					d.DelEvents([]ID{ids[i]})
				}
				wg.Done()
			}(i)
		}
		wg.Done()
	}()

	wg.Wait()

	actualEvents := d.GetEvents()
	sortIDs(actualEvents)
	require.ElementsMatch(t, evenIDs, actualEvents)
}
