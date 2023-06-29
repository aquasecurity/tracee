package events

import (
	"sort"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

//
// Dependencies: TailCalls Tests
//

var tailCalls = []*TailCall{
	NewTailCall("1", "11", []uint32{1, 11, 111}),
	NewTailCall("1", "12", []uint32{1, 12}),
	NewTailCall("1", "13", []uint32{1, 13, 113}),
	NewTailCall("2", "24", []uint32{2, 24}),
	NewTailCall("2", "25", []uint32{2, 25, 225}),
	NewTailCall("2", "26", []uint32{2, 26}),
	NewTailCall("2", "27", []uint32{2, 27, 227}),
	NewTailCall("2", "28", []uint32{2, 28}),
	NewTailCall("2", "29", []uint32{2, 29, 229}),
	NewTailCall("3", "31", []uint32{3, 31, 331}),
	NewTailCall("3", "32", []uint32{3, 32}),
	NewTailCall("3", "33", []uint32{3, 33, 333}),
	NewTailCall("3", "34", []uint32{3, 34}),
}

var evenTailCalls = []*TailCall{
	NewTailCall("1", "11", []uint32{1, 11, 111}),
	NewTailCall("1", "13", []uint32{1, 13, 113}),
	NewTailCall("2", "25", []uint32{2, 25, 225}),
	NewTailCall("2", "27", []uint32{2, 27, 227}),
	NewTailCall("2", "29", []uint32{2, 29, 229}),
	NewTailCall("3", "32", []uint32{3, 32}),
	NewTailCall("3", "34", []uint32{3, 34}),
}

var thirdEvenTailCalls = []*TailCall{
	NewTailCall("3", "31", []uint32{3, 31, 331}),
	NewTailCall("3", "32", []uint32{3, 32}),
	NewTailCall("3", "33", []uint32{3, 33, 333}),
	NewTailCall("3", "34", []uint32{3, 34}),
}

func sortTailCalls(k []*TailCall) {
	sort.Slice(k, func(i, j int) bool {
		iN, _ := strconv.Atoi(k[i].GetProgName())
		jN, _ := strconv.Atoi(k[j].GetProgName())
		return iN < jN
	})
}

// TestDependencies_SetTailCalls_MultipleThreads tests that SetTailCalls is thread-safe.
func TestDependencies_SetTailCalls_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	wg := &sync.WaitGroup{}

	for i := 0; i < len(tailCalls); i++ {
		wg.Add(1)
		go func(i int) {
			d.SetTailCalls([]*TailCall{tailCalls[i]})
			wg.Done()
		}(i)
	}

	wg.Wait()

	actualTailCalls := d.GetTailCalls()

	require.Condition(t, func() bool {
		return actualTailCalls[0].GetMapName() != "" // only testing races here, not values
	})
}

// TestDependencies_GetTailCalls_MultipleThreads tests that GetTailCalls is thread-safe.
func TestDependencies_GetTailCalls_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	d.SetTailCalls(tailCalls)

	wg := &sync.WaitGroup{}

	for i := 0; i < len(tailCalls); i++ {
		wg.Add(1)
		go func() {
			tcs := d.GetTailCalls()
			require.ElementsMatch(t, tailCalls, tcs)
			wg.Done()
		}()
	}

	wg.Wait()
}

// TestDependencies_AddTailCall_MultipleThreads tests that AddTailCall is thread-safe.
func TestDependencies_AddTailCall_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	wg := &sync.WaitGroup{}

	for i := 0; i < len(tailCalls); i++ {
		wg.Add(1)
		go func(i int) {
			d.AddTailCall(tailCalls[i])
			wg.Done()
		}(i)
	}

	wg.Wait()

	actualTailCalls := d.GetTailCalls()
	require.ElementsMatch(t, tailCalls, actualTailCalls)
}

// TestDependencies_AddTailCalls_MultipleThreads tests that AddTailCalls is thread-safe.
func TestDependencies_AddTailCalls_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	wg := &sync.WaitGroup{}

	for i := 0; i < len(tailCalls); i++ {
		wg.Add(1)
		go func(i int) {
			d.AddTailCalls([]*TailCall{tailCalls[i]})
			wg.Done()
		}(i)
	}

	wg.Wait()

	actualTailCalls := d.GetTailCalls()
	require.ElementsMatch(t, tailCalls, actualTailCalls)
}

// TestDependencies_SetAndAddDuplicateTailCalls_MultipleThreads tests that SetTailCalls and
// AddTailCalls are thread-safe.
func TestDependencies_SetAndAddDuplicateTailCalls_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	d.SetTailCalls(tailCalls)

	wg := &sync.WaitGroup{}

	for i := 0; i < len(tailCalls); i++ {
		wg.Add(1)
		go func(i int) {
			d.AddTailCalls([]*TailCall{tailCalls[i]})
			wg.Done()
		}(i)
	}

	wg.Wait()

	actualTailCalls := d.GetTailCalls()
	require.ElementsMatch(t, tailCalls, actualTailCalls)
}

// TestDependencies_DelTailCallByMapAndProgName_MultipleThreads tests that
// DelTailCallByMapAndProgName is thread-safe.
func TestDependencies_DelTailCallByMapAndProgName_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	sortTailCalls(tailCalls)
	sortTailCalls(evenTailCalls)

	d.SetTailCalls(tailCalls)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < len(tailCalls); i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 != 0 {
					d.DelTailCallByMapAndProgName(
						tailCalls[i].GetMapName(),
						tailCalls[i].GetProgName(),
					)
				}
				wg.Done()
			}(i)
		}
		wg.Done()
	}()

	wg.Wait()

	actualTailCalls := d.GetTailCalls()
	sortTailCalls(actualTailCalls)
	require.ElementsMatch(t, evenTailCalls, actualTailCalls)
}

// TestDependencies_DelTailCallByMapName_MultipleThreads tests that DelTailCallByMapName is
// thread-safe.
func TestDependencies_DelTailCallByMapName_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	sortTailCalls(tailCalls)
	sortTailCalls(evenTailCalls)

	d.SetTailCalls(tailCalls)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < len(tailCalls); i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 == 0 { // for no reason but to split diff work among diff threads
					d.DelTailCallsByMapNames([]string{"1"})
				} else {
					d.DelTailCallsByMapNames([]string{"2"})
				}
				wg.Done()
			}(i)
		}
		wg.Done()
	}()

	wg.Wait()

	actualTailCalls := d.GetTailCalls()
	sortTailCalls(actualTailCalls)
	require.ElementsMatch(t, thirdEvenTailCalls, actualTailCalls)
}
