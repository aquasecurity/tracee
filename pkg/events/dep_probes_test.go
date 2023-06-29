package events

import (
	"sort"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
)

//
// Dependencies: Probes Tests
//

func initProbes() ([]*Probe, []*Probe) {
	prbs := []*Probe{}
	evenPrbs := []*Probe{}

	for i := 0; i < amountOfTestThreads; i++ {
		if i%2 == 0 {
			yesOrNo := i%5 == 0 // just to have some true values
			prbs = append(prbs, NewProbe(probes.Handle(i), yesOrNo))
			evenPrbs = append(evenPrbs, NewProbe(probes.Handle(i), yesOrNo))
		} else {
			prbs = append(prbs, NewProbe(probes.Handle(i), false))
		}
	}

	sortProbes(prbs)
	sortProbes(evenPrbs)

	return prbs, evenPrbs
}

func sortProbes(p []*Probe) {
	sort.Slice(p, func(i, j int) bool {
		return p[i].GetHandle() < p[j].GetHandle()
	})
}

// TestDependencies_SetProbes_MultipleThreads tests that SetProbes is thread-safe.
func TestDependencies_SetProbes_MultipleThreads(t *testing.T) {
	prbs, _ := initProbes()

	d := NewDependencies(nil, nil, nil, nil, nil)

	wg := &sync.WaitGroup{}

	for i := 0; i < len(prbs); i++ {
		wg.Add(1)
		go func(i int) {
			d.SetProbes([]*Probe{prbs[i]})
			wg.Done()
		}(i)
	}

	wg.Wait()

	actualProbes := d.GetProbes()

	require.Condition(t, func() bool {
		return actualProbes[0].GetHandle() < probes.Handle(amountOfTestThreads) // only testing races here, not values
	})
}

// TestDependencies_GetProbes_MultipleThreads tests that GetProbes is thread-safe.
func TestDependencies_GetProbes_MultipleThreads(t *testing.T) {
	prbs, _ := initProbes()

	d := NewDependencies(nil, nil, nil, nil, nil)

	d.SetProbes(prbs)

	wg := &sync.WaitGroup{}

	for i := 0; i < len(prbs); i++ {
		wg.Add(1)
		go func() {
			p := d.GetProbes()
			require.ElementsMatch(t, prbs, p)
			wg.Done()
		}()
	}

	wg.Wait()

	require.True(t, true, true) // only testing races here, not values
}

// TestDependencies_AddProbe_MultipleThreads tests that AddProbe is thread-safe.
func TestDependencies_AddProbe_MultipleThreads(t *testing.T) {
	prbs, _ := initProbes()

	d := NewDependencies(nil, nil, nil, nil, nil)

	wg := &sync.WaitGroup{}

	for i := 0; i < len(prbs); i++ {
		wg.Add(1)
		go func(i int) {
			d.AddProbe(prbs[i])
			wg.Done()
		}(i)
	}

	wg.Wait()

	actualProbes := d.GetProbes()
	sortProbes(actualProbes)
	require.ElementsMatch(t, prbs, actualProbes)
}

// TestDependencies_AddProbes_MultipleThreads tests that AddProbes is thread-safe.
func TestDependencies_AddProbes_MultipleThreads(t *testing.T) {
	prbs, _ := initProbes()

	d := NewDependencies(nil, nil, nil, nil, nil)

	wg := &sync.WaitGroup{}

	for i := 0; i < len(prbs); i++ {
		wg.Add(1)
		go func(i int) {
			d.AddProbes([]*Probe{prbs[i]})
			wg.Done()
		}(i)
	}

	wg.Wait()

	actualProbes := d.GetProbes()
	sortProbes(actualProbes)
	require.ElementsMatch(t, prbs, actualProbes)
}

// TestDependencies_SetAndAddDuplicateProbes_MultipleThreads tests AddProbe for duplicates.
func TestDependencies_SetAndAddDuplicatedProbes_MultipleThreads(t *testing.T) {
	_, evenPrbs := initProbes()

	d := NewDependencies(nil, nil, nil, nil, nil)

	d.SetProbes(evenPrbs)

	wg := &sync.WaitGroup{}

	for i := 0; i < len(evenPrbs); i++ {
		wg.Add(1)
		go func(i int) {
			d.AddProbe(evenPrbs[i])
			wg.Done()
		}(i)
	}

	wg.Wait()

	actualProbes := d.GetProbes()
	sortProbes(actualProbes)
	require.ElementsMatch(t, evenPrbs, actualProbes)
}

// TestDependencies_DelProbe_MultipleThreads tests that DelProbe is thread-safe.
func TestDependencies_DelProbe_MultipleThreads(t *testing.T) {
	prbs, evenPrbs := initProbes()

	d := NewDependencies(nil, nil, nil, nil, nil)

	d.SetProbes(prbs)

	wg := &sync.WaitGroup{}

	for i := 0; i < len(prbs); i++ {
		wg.Add(1)
		go func(i int) {
			if i%2 != 0 {
				d.DelProbe(probes.Handle(i))
			}
			wg.Done()
		}(i)
	}

	wg.Wait()

	actualProbes := d.GetProbes()
	sortProbes(actualProbes)
	require.ElementsMatch(t, evenPrbs, actualProbes)
}

// TestDependencies_DelProbes_MultipleThreads tests that DelProbes is thread-safe.
func TestDependencies_DelProbes_MultipleThreads(t *testing.T) {
	prbs, evenPrbs := initProbes()

	d := NewDependencies(nil, nil, nil, nil, nil)

	d.SetProbes(prbs)

	wg := &sync.WaitGroup{}

	for i := 0; i < len(prbs); i++ {
		wg.Add(1)
		go func(i int) {
			if i%2 != 0 {
				d.DelProbes([]probes.Handle{probes.Handle(i)})
			}
			wg.Done()
		}(i)
	}

	wg.Wait()

	actualProbes := d.GetProbes()
	sortProbes(actualProbes)
	require.ElementsMatch(t, evenPrbs, actualProbes)
}
