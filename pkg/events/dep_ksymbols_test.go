package events

import (
	"fmt"
	"sort"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

//
// Dependencies: KSymbols Tests
//

func initKSymbols() ([]*KSymbol, []*KSymbol) {
	kSymbols := []*KSymbol{}
	evenKSymbols := []*KSymbol{}

	for i := 0; i < amountOfTestThreads; i++ {
		if i%2 == 0 {
			yesOrNo := i%5 == 0 // just to have some true values
			kSymbols = append(kSymbols, NewKSymbol(fmt.Sprintf("%v", i), yesOrNo))
			evenKSymbols = append(evenKSymbols, NewKSymbol(fmt.Sprintf("%v", i), yesOrNo))
		} else {
			kSymbols = append(kSymbols, NewKSymbol(fmt.Sprintf("%v", i), false))
		}
	}

	sortKSymbols(kSymbols)
	sortKSymbols(evenKSymbols)

	return kSymbols, evenKSymbols
}

func sortKSymbols(k []*KSymbol) {
	sort.Slice(k, func(i, j int) bool {
		iSymNum, _ := strconv.Atoi(k[i].GetSymbol())
		jSymNum, _ := strconv.Atoi(k[j].GetSymbol())
		return iSymNum < jSymNum
	})
}

// TestDependencies_SetKSymbols_MultipleThreads tests that SetKSymbols is thread-safe.
func TestDependencies_SetKSymbols_MultipleThreads(t *testing.T) {
	kSymbols, _ := initKSymbols()

	d := NewDependencies(nil, nil, nil, nil, nil)

	wg := &sync.WaitGroup{}

	for i := 0; i < len(kSymbols); i++ {
		wg.Add(1)
		go func(i int) {
			d.SetKSymbols([]*KSymbol{kSymbols[i]})
			wg.Done()
		}(i)
	}

	wg.Wait()

	actualKSymbols := d.GetKSymbols()

	require.Condition(t, func() bool {
		return actualKSymbols[0].GetSymbol() != "" // only testing races here, not values
	})
}

// TestDependencies_GetKSymbols_MultipleThreads tests that GetKSymbols is thread-safe.
func TestDependencies_GetKSymbols_MultipleThreads(t *testing.T) {
	kSymbols, _ := initKSymbols()

	d := NewDependencies(nil, nil, nil, nil, nil)

	d.SetKSymbols(kSymbols)

	wg := &sync.WaitGroup{}

	for i := 0; i < len(kSymbols); i++ {
		wg.Add(1)
		go func() {
			s := d.GetKSymbols()
			require.ElementsMatch(t, kSymbols, s)
			wg.Done()
		}()
	}

	wg.Wait()

	require.True(t, true, true) // only testing races here, not values
}

// TestDependencies_AddKSymbol_MultipleThreads tests that AddKSymbol is thread-safe.
func TestDependencies_AddKSymbol_MultipleThreads(t *testing.T) {
	kSymbols, _ := initKSymbols()

	d := NewDependencies(nil, nil, nil, nil, nil)

	wg := &sync.WaitGroup{}

	for i := 0; i < len(kSymbols); i++ {
		wg.Add(1)
		go func(i int) {
			d.AddKSymbol(kSymbols[i])
			wg.Done()
		}(i)
	}

	wg.Wait()

	actualKSymbols := d.GetKSymbols()
	require.ElementsMatch(t, kSymbols, actualKSymbols)
}

// TestDependencies_AddKSymbols_MultipleThreads tests that AddKSymbols is thread-safe.
func TestDependencies_AddKSymbols_MultipleThreads(t *testing.T) {
	kSymbols, _ := initKSymbols()

	d := NewDependencies(nil, nil, nil, nil, nil)

	wg := &sync.WaitGroup{}

	for i := 0; i < len(kSymbols); i++ {
		wg.Add(1)
		go func(i int) {
			d.AddKSymbols([]*KSymbol{kSymbols[i]})
			wg.Done()
		}(i)
	}

	wg.Wait()

	actualKSymbols := d.GetKSymbols()
	require.ElementsMatch(t, kSymbols, actualKSymbols)
}

// TestDependencies_SetAndAddDuplicateKSymbols_MultipleThreads tests AddKSymbol for duplicates.
func TestDependencies_SetAndAddDuplicateKSymbols_MultipleThreads(t *testing.T) {
	_, evenKSymbols := initKSymbols()

	d := NewDependencies(nil, nil, nil, nil, nil)

	d.SetKSymbols(evenKSymbols)

	wg := &sync.WaitGroup{}

	for i := 0; i < len(evenKSymbols); i++ {
		wg.Add(1)
		go func(i int) {
			d.AddKSymbol(evenKSymbols[i])
			wg.Done()
		}(i)
	}

	wg.Wait()

	actualKSymbols := d.GetKSymbols()
	require.ElementsMatch(t, evenKSymbols, actualKSymbols)
}

// TestDependencies_DelKSymbol_MultipleThreads tests that DelKSymbol is thread-safe.
func TestDependencies_DelKSymbol_MultipleThreads(t *testing.T) {
	kSymbols, evenKSymbols := initKSymbols()

	d := NewDependencies(nil, nil, nil, nil, nil)

	d.SetKSymbols(kSymbols)

	wg := &sync.WaitGroup{}

	for i := 0; i < len(kSymbols); i++ {
		wg.Add(1)
		go func(i int) {
			if i%2 != 0 {
				d.DelKSymbol(kSymbols[i].GetSymbol())
			}
			wg.Done()
		}(i)
	}

	wg.Wait()

	actualKSymbols := d.GetKSymbols()
	sortKSymbols(actualKSymbols)
	require.ElementsMatch(t, evenKSymbols, actualKSymbols)
}

// TestDependencies_DelKSymbols_MultipleThreads tests that DelKSymbols is thread-safe.
func TestDependencies_DelKSymbols_MultipleThreads(t *testing.T) {
	kSymbols, evenKSymbols := initKSymbols()

	d := NewDependencies(nil, nil, nil, nil, nil)

	d.SetKSymbols(kSymbols)

	wg := &sync.WaitGroup{}

	for i := 0; i < len(kSymbols); i++ {
		wg.Add(1)
		go func(i int) {
			if i%2 != 0 {
				d.DelKSymbols([]string{kSymbols[i].GetSymbol()})
			}
			wg.Done()
		}(i)
	}

	wg.Wait()

	actualKSymbols := d.GetKSymbols()
	sortKSymbols(actualKSymbols)
	require.ElementsMatch(t, evenKSymbols, actualKSymbols)
}
