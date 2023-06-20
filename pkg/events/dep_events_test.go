package events

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

//
// EventDependency
//

// TestSetEvents_MultipleThreads tests that SetEvents is thread-safe.
func TestSetEvents_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 == 0 {
					d.SetEvents([]ID{ID(i)})
				}
				wg.Done()
			}(i)
		}

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 != 0 {
					d.SetEvents([]ID{ID(i)})
				}
				wg.Done()
			}(i)
		}

		wg.Done()
	}()

	wg.Wait()

	actualEvents := d.GetEvents()

	assert.Condition(t, func() bool {
		return actualEvents[0] < 10 // only testing races here, not values
	})
}

// TestGetEvents_MultipleThreads tests that GetEvents is thread-safe.
func TestGetEvents_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	d.SetEvents([]ID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				e := d.GetEvents()
				assert.ElementsMatch(t, []ID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, e)
				wg.Done()
			}()
		}

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				e := d.GetEvents()
				assert.ElementsMatch(t, []ID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, e)
				wg.Done()
			}()
		}

		wg.Done()
	}()

	wg.Wait()
}

// TestAddEvent_MultipleThreads tests that AddEvent is thread-safe.
func TestAddEvent_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 == 0 {
					d.AddEvent(ID(i))
				}
				wg.Done()
			}(i)
		}

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 != 0 {
					d.AddEvent(ID(i))
				}
				wg.Done()
			}(i)
		}

		wg.Done()
	}()

	wg.Wait()

	actualEvents := d.GetEvents()
	assert.ElementsMatch(t, []ID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, actualEvents)
}

// TestAddEvents_MultipleThreads tests that AddEvents is thread-safe.
func TestAddEvents_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 == 0 {
					d.AddEvents([]ID{0, 2, 4, 6, 8})
				}
				wg.Done()
			}(i)
		}

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 != 0 {
					d.AddEvents([]ID{1, 3, 5, 7, 9})
				}
				wg.Done()
			}(i)
		}

		wg.Done()
	}()

	wg.Wait()

	actualEvents := d.GetEvents()
	assert.ElementsMatch(t, []ID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, actualEvents)
}

// TestSetAndAddDuplicateEvents_MultipleThreads tests for duplicte events after SetEvents.
func TestSetAndAddDuplicateEvents_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	d.SetEvents([]ID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 == 0 {
					d.AddEvent(ID(i))
				}
				wg.Done()
			}(i)
		}

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 != 0 {
					d.AddEvents([]ID{ID(i)})
				}
				wg.Done()
			}(i)
		}

		wg.Done()
	}()

	wg.Wait()

	actualEvents := d.GetEvents()
	assert.ElementsMatch(t, []ID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, actualEvents)
}

// TestDelEvent_MultipleThreads tests that DelEvent is thread-safe.
func TestDelEvent_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	d.SetEvents([]ID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 != 0 {
					d.DelEvent(ID(i))
				}
				wg.Done()
			}(i)
		}
		wg.Done()
	}()

	wg.Wait()

	actualEvents := d.GetEvents()
	assert.ElementsMatch(t, []ID{0, 2, 4, 6, 8}, actualEvents)
}

// TestDelEvents_MultipleThreads tests that DelEvents is thread-saf
func TestDelEvents_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	d.SetEvents([]ID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 != 0 {
					d.DelEvents([]ID{ID(i)})
				}
				wg.Done()
			}(i)
		}
		wg.Done()
	}()

	wg.Wait()

	actualEvents := d.GetEvents()
	assert.ElementsMatch(t, []ID{0, 2, 4, 6, 8}, actualEvents)
}
