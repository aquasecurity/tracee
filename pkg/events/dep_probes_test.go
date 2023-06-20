package events

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
)

//
// ProbeDependency
//

var prbs = []*Probe{
	NewProbe(0, true),
	NewProbe(1, false),
	NewProbe(2, true),
	NewProbe(3, false),
	NewProbe(4, true),
	NewProbe(5, false),
	NewProbe(6, true),
	NewProbe(7, false),
	NewProbe(8, true),
	NewProbe(9, false),
}

var evenPrbs = []*Probe{
	NewProbe(0, true),
	NewProbe(2, true),
	NewProbe(4, true),
	NewProbe(6, true),
	NewProbe(8, true),
}

// TestSetProbes_MultipleThreads tests that SetProbes is thread-safe.
func TestSetProbes_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 == 0 {
					d.SetProbes(
						[]*Probe{prbs[i]},
					)
				}
				wg.Done()
			}(i)
		}

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 != 0 {
					d.SetProbes(
						[]*Probe{prbs[i]},
					)
				}
				wg.Done()
			}(i)
		}

		wg.Done()
	}()

	wg.Wait()

	actualProbes := d.GetProbes()

	assert.Condition(t, func() bool {
		return actualProbes[0].GetHandle() < 10 // only testing races here, not values
	})
}

// TestGetProbes_MultipleThreads tests that GetProbes is thread-safe.
func TestGetProbes_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	d.SetProbes(prbs)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				p := d.GetProbes()
				assert.ElementsMatch(t, prbs, p)
				wg.Done()
			}()
		}

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				p := d.GetProbes()
				assert.ElementsMatch(t, prbs, p)
				wg.Done()
			}()
		}

		wg.Done()
	}()

	wg.Wait()
}

// TestAddProbe_MultipleThreads tests that AddProbe is thread-safe.
func TestAddProbe_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 == 0 {
					d.AddProbe(prbs[i])
				}
				wg.Done()
			}(i)
		}

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 != 0 {
					d.AddProbe(prbs[i])
				}
				wg.Done()
			}(i)
		}

		wg.Done()
	}()

	wg.Wait()

	actualProbes := d.GetProbes()
	assert.ElementsMatch(t, prbs, actualProbes)
}

// TestAddProbes_MultipleThreads tests that AddProbes is thread-safe.
func TestAddProbes_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 == 0 {
					d.AddProbes([]*Probe{prbs[i]})
				}
				wg.Done()
			}(i)
		}

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 != 0 {
					d.AddProbes([]*Probe{prbs[i]})
				}
				wg.Done()
			}(i)
		}

		wg.Done()
	}()

	wg.Wait()

	actualProbes := d.GetProbes()
	assert.ElementsMatch(t, prbs, actualProbes)
}

// TestSetAndAddDuplicateProbes_MultipleThreads tests for duplicte probes after SetProbes.
func TestSetAndAddDuplicateProbes_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	d.SetProbes(prbs)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 == 0 {
					d.AddProbe(prbs[i])
				}
				wg.Done()
			}(i)
		}

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 != 0 {
					d.AddProbe(prbs[i])
				}
				wg.Done()
			}(i)
		}

		wg.Done()
	}()

	wg.Wait()

	actualProbes := d.GetProbes()
	assert.ElementsMatch(t, prbs, actualProbes)
}

// TestDelProbe_MultipleThreads tests that DelProbe is thread-safe.
func TestDelProbe_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	d.SetProbes(prbs)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 != 0 {
					d.DelProbe(probes.Handle(i))
				}
				wg.Done()
			}(i)
		}
		wg.Done()
	}()

	wg.Wait()

	actualProbes := d.GetProbes()
	assert.ElementsMatch(t, evenPrbs, actualProbes)
}

// TestDelProbes_MultipleThreads tests that DelProbes is thread-safe.
func TestDelProbes_MultipleThreads(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	d.SetProbes(prbs)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 != 0 {
					d.DelProbes([]probes.Handle{probes.Handle(i)})
				}
				wg.Done()
			}(i)
		}
		wg.Done()
	}()

	wg.Wait()

	actualProbes := d.GetProbes()
	assert.ElementsMatch(t, evenPrbs, actualProbes)
}
