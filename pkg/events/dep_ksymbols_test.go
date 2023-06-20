package events

import (
	"sort"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

//
// KSymbol Dependency
//

var kSymbols = []*KSymbol{
	NewKSymbol("0", false),
	NewKSymbol("1", true),
	NewKSymbol("2", false),
	NewKSymbol("3", true),
	NewKSymbol("4", false),
	NewKSymbol("5", true),
	NewKSymbol("6", false),
	NewKSymbol("7", true),
	NewKSymbol("8", false),
	NewKSymbol("9", true),
}

var evenKSymbols = []*KSymbol{
	NewKSymbol("0", false),
	NewKSymbol("2", false),
	NewKSymbol("4", false),
	NewKSymbol("6", false),
	NewKSymbol("8", false),
}

func sortKSymbols(k []*KSymbol) {
	sort.Slice(k, func(i, j int) bool {
		return k[i].GetSymbol() < k[j].GetSymbol()
	})
}

// TestSetKSymbols_MultipleThreads tests that SetKSymbols is thread-safe.
func TestSetKSymbols_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 == 0 {
					d.SetKSymbols(
						[]*KSymbol{kSymbols[i]},
					)
				}
				wg.Done()
			}(i)
		}

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 != 0 {
					d.SetKSymbols(
						[]*KSymbol{kSymbols[i]},
					)
				}
				wg.Done()
			}(i)
		}

		wg.Done()
	}()

	wg.Wait()

	actualKSymbols := d.GetKSymbols()

	assert.Condition(t, func() bool {
		return actualKSymbols[0].GetSymbol() != "" // only testing races here, not values
	})
}

// TestGetKSymbols_MultipleThreads tests that GetKSymbols is thread-safe.
func TestGetKSymbols_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	d.SetKSymbols(kSymbols)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				s := d.GetKSymbols()
				assert.ElementsMatch(t, kSymbols, s)
				wg.Done()
			}()
		}

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				s := d.GetKSymbols()
				assert.ElementsMatch(t, kSymbols, s)
				wg.Done()
			}()
		}

		wg.Done()
	}()

	wg.Wait()
}

// TestAddKSymbol_MultipleThreads tests that AddKSymbol is thread-safe.
func TestAddKSymbol_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 == 0 {
					d.AddKSymbol(kSymbols[i])
				}
				wg.Done()
			}(i)
		}

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 != 0 {
					d.AddKSymbol(kSymbols[i])
				}
				wg.Done()
			}(i)
		}

		wg.Done()
	}()

	wg.Wait()

	actualKSymbols := d.GetKSymbols()
	assert.ElementsMatch(t, kSymbols, actualKSymbols)
}

// TestAddKSymbols_MultipleThreads tests that AddKSymbols is thread-safe.
func TestAddKSymbols_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 == 0 {
					d.AddKSymbols([]*KSymbol{kSymbols[i]})
				}
				wg.Done()
			}(i)
		}

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 != 0 {
					d.AddKSymbols([]*KSymbol{kSymbols[i]})
				}
				wg.Done()
			}(i)
		}

		wg.Done()
	}()

	wg.Wait()

	actualKSymbols := d.GetKSymbols()
	assert.ElementsMatch(t, kSymbols, actualKSymbols)
}

// TestSetAndAddDuplicateKSymbols_MultipleThreads tests for duplicte kSymbols after SetKSymbols.
func TestSetAndAddDuplicateKSymbols_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	d.SetKSymbols(kSymbols)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 == 0 {
					d.AddKSymbol(kSymbols[i])
				}
				wg.Done()
			}(i)
		}

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 != 0 {
					d.AddKSymbol(kSymbols[i])
				}
				wg.Done()
			}(i)
		}

		wg.Done()
	}()

	wg.Wait()

	actualKSymbols := d.GetKSymbols()
	assert.ElementsMatch(t, kSymbols, actualKSymbols)
}

// TestDelKSymbol_MultipleThreads tests that DelKSymbol is thread-safe.
func TestDelKSymbol_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	sortKSymbols(kSymbols)
	sortKSymbols(evenKSymbols)

	d.SetKSymbols(kSymbols)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 != 0 {
					d.DelKSymbol(kSymbols[i].GetSymbol())
				}
				wg.Done()
			}(i)
		}
		wg.Done()
	}()

	wg.Wait()

	actualKSymbols := d.GetKSymbols()
	sortKSymbols(actualKSymbols)
	assert.ElementsMatch(t, evenKSymbols, actualKSymbols)
}

// TestDelKSymbols_MultipleThreads tests that DelKSymbols is thread-safe.
func TestDelKSymbols_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	sortKSymbols(kSymbols)
	sortKSymbols(evenKSymbols)

	d.SetKSymbols(kSymbols)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 != 0 {
					d.DelKSymbols([]string{kSymbols[i].GetSymbol()})
				}
				wg.Done()
			}(i)
		}
		wg.Done()
	}()

	wg.Wait()

	actualKSymbols := d.GetKSymbols()
	sortKSymbols(actualKSymbols)
	assert.ElementsMatch(t, evenKSymbols, actualKSymbols)
}
