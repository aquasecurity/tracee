package events

import (
	"sort"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

//
// TailCall Dependency
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

// TestSetTailCalls_MultipleThreads tests that SetTailCalls is thread-safe.
func TestSetTailCalls_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 == 0 {
					d.SetTailCalls(
						[]*TailCall{tailCalls[i]},
					)
				}
				wg.Done()
			}(i)
		}

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 != 0 {
					d.SetTailCalls(
						[]*TailCall{tailCalls[i]},
					)
				}
				wg.Done()
			}(i)
		}

		wg.Done()
	}()

	wg.Wait()

	actualTailCalls := d.GetTailCalls()

	assert.Condition(t, func() bool {
		return actualTailCalls[0].GetMapName() != "" // only testing races here, not values
	})
}

// TestGetTailCalls_MultipleThreads tests that GetTailCalls is thread-safe.
func TestGetTailCalls_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	d.SetTailCalls(tailCalls)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				tcs := d.GetTailCalls()
				assert.ElementsMatch(t, tailCalls, tcs)
				wg.Done()
			}()
		}

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				tcs := d.GetTailCalls()
				assert.ElementsMatch(t, tailCalls, tcs)
				wg.Done()
			}()
		}

		wg.Done()
	}()

	wg.Wait()
}

// TestAddTailCall_MultipleThreads tests that AddTailCall is thread-safe.
func TestAddTailCall_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < len(tailCalls); i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 == 0 {
					d.AddTailCall(tailCalls[i])
				}
				wg.Done()
			}(i)
		}

		for i := 0; i < len(tailCalls); i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 != 0 {
					d.AddTailCall(tailCalls[i])
				}
				wg.Done()
			}(i)
		}

		wg.Done()
	}()

	wg.Wait()

	actualTailCalls := d.GetTailCalls()
	assert.ElementsMatch(t, tailCalls, actualTailCalls)
}

// TestAddTailCalls_MultipleThreads tests that AddTailCalls is thread-safe.
func TestAddTailCalls_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < len(tailCalls); i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 == 0 {
					d.AddTailCalls([]*TailCall{tailCalls[i]})
				}
				wg.Done()
			}(i)
		}

		for i := 0; i < len(tailCalls); i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 != 0 {
					d.AddTailCalls([]*TailCall{tailCalls[i]})
				}
				wg.Done()
			}(i)
		}

		wg.Done()
	}()

	wg.Wait()

	actualTailCalls := d.GetTailCalls()
	assert.ElementsMatch(t, tailCalls, actualTailCalls)
}

// TestSetAndAddDuplicateTailCalls_MultipleThreads tests that SetTailCalls and AddTailCalls are
// thread-safe.
func TestSetAndAddDuplicateTailCalls_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	d.SetTailCalls(tailCalls)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < len(tailCalls); i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 == 0 {
					d.AddTailCalls([]*TailCall{tailCalls[i]})
				}
				wg.Done()
			}(i)
		}

		for i := 0; i < len(tailCalls); i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 != 0 {
					d.AddTailCalls([]*TailCall{tailCalls[i]})
				}
				wg.Done()
			}(i)
		}

		wg.Done()
	}()

	wg.Wait()

	actualTailCalls := d.GetTailCalls()
	assert.ElementsMatch(t, tailCalls, actualTailCalls)
}

// TestDelTailCallByMapAndProgName_MultipleThreads tests that DelTailCallByMapAndProgName is
// thread-safe.
func TestDelTailCallByMapAndProgName_MultipleThreads(t *testing.T) {
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
	assert.ElementsMatch(t, evenTailCalls, actualTailCalls)
}

// TestDelTailCallByMapName_MultipleThreads tests that DelTailCallByMapName is thread-safe.
func TestDelTailCallByMapName_MultipleThreads(t *testing.T) {
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
				if i%2 == 0 { // for no reason but to split the work
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
	assert.ElementsMatch(t, thirdEvenTailCalls, actualTailCalls)
}
