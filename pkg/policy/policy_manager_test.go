package policy

import (
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/dependencies"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/filters/sets"
)

func TestPolicyManagerEnableEvent(t *testing.T) {
	t.Parallel()

	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.Dependencies {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	policyManager, err := NewManager(ManagerConfig{}, depsManager)
	assert.NoError(t, err)

	assert.False(t, policyManager.IsEventEnabled(events.SecurityBPF))
	assert.False(t, policyManager.IsEventEnabled(events.SecurityFileOpen))
	assert.False(t, policyManager.IsEventEnabled(events.SecuritySocketAccept))

	policyManager.EnableEvent(events.SecurityBPF)
	policyManager.EnableEvent(events.SecurityFileOpen)
	policyManager.EnableEvent(events.SecuritySocketAccept)

	assert.True(t, policyManager.IsEventEnabled(events.SecurityBPF))
	assert.True(t, policyManager.IsEventEnabled(events.SecurityFileOpen))
	assert.True(t, policyManager.IsEventEnabled(events.SecuritySocketAccept))
}

func TestPolicyManagerDisableEvent(t *testing.T) {
	t.Parallel()

	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.Dependencies {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	policyManager, err := NewManager(ManagerConfig{}, depsManager)
	assert.NoError(t, err)

	policyManager.EnableEvent(events.SecurityBPF)
	policyManager.EnableEvent(events.SecurityFileOpen)
	policyManager.EnableEvent(events.SecuritySocketAccept)

	assert.True(t, policyManager.IsEventEnabled(events.SecurityBPF))
	assert.True(t, policyManager.IsEventEnabled(events.SecurityFileOpen))
	assert.True(t, policyManager.IsEventEnabled(events.SecuritySocketAccept))

	policyManager.DisableEvent(events.SecurityBPF)
	policyManager.DisableEvent(events.SecurityFileOpen)

	assert.False(t, policyManager.IsEventEnabled(events.SecurityBPF))
	assert.False(t, policyManager.IsEventEnabled(events.SecurityFileOpen))
	assert.True(t, policyManager.IsEventEnabled(events.SecuritySocketAccept))
}

func TestPolicyManagerEnableAndDisableEventConcurrent(t *testing.T) {
	t.Parallel()

	eventsToEnable := []events.ID{
		events.SecurityBPF,
		events.SchedGetPriorityMax,
		events.SchedProcessExec,
		events.SchedProcessExit,
		events.Ptrace,
	}

	eventsToDisable := []events.ID{
		events.SecurityBPFMap,
		events.Openat2,
		events.SchedProcessFork,
		events.MagicWrite,
		events.FileModification,
	}

	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.Dependencies {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	policyManager, err := NewManager(ManagerConfig{}, depsManager)
	assert.NoError(t, err)

	// activate events
	for _, e := range eventsToDisable {
		policyManager.EnableEvent(e)
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		for i := 0; i < PolicyMax; i++ {
			for _, e := range eventsToEnable {
				policyManager.EnableEvent(e)
			}
		}
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		for i := 0; i < PolicyMax; i++ {
			for _, e := range eventsToDisable {
				policyManager.DisableEvent(e)
			}
		}
		wg.Done()
	}()

	wg.Wait()

	for i := 0; i < PolicyMax; i++ {
		for _, e := range eventsToEnable {
			assert.True(t, policyManager.IsEventEnabled(e))
		}
		for _, e := range eventsToDisable {
			assert.False(t, policyManager.IsEventEnabled(e))
		}
	}
}

func TestPoliciesClone(t *testing.T) {
	t.Parallel()

	ps := NewPolicies()

	p1 := NewPolicy()
	p1.Name = "p1"
	err := p1.PIDFilter.Parse("=1")
	require.NoError(t, err)

	p2 := NewPolicy()
	p2.Name = "p2"
	err = p2.UIDFilter.Parse("=2")
	require.NoError(t, err)

	// Initialize the rule first
	p2.Rules[events.Read] = RuleData{
		EventID:     events.Read,
		DataFilter:  filters.NewDataFilter(),
		RetFilter:   filters.NewIntFilter(),
		ScopeFilter: filters.NewScopeFilter(),
	}
	err = p2.Rules[events.Read].DataFilter.Parse(events.Read, "fd", "=dataval")
	require.NoError(t, err)

	err = ps.add(p1)
	require.NoError(t, err)
	err = ps.add(p2)
	require.NoError(t, err)

	copy := ps.Clone()

	opt1 := cmp.AllowUnexported(
		policies{},
		sync.Mutex{},
		sync.RWMutex{},
		atomic.Int32{},
		filters.StringFilter{},
		filters.UIntFilter[uint32]{},
		filters.UIntFilter[uint64]{},
		filters.BoolFilter{},
		filters.IntFilter[int64]{},
		filters.DataFilter{},
		filters.ScopeFilter{},
		filters.ProcessTreeFilter{},
		filters.BinaryFilter{},
		sets.PrefixSet{},
		sets.SuffixSet{},
		filters.KernelDataFilter{},
	)
	opt2 := cmp.FilterPath(
		func(p cmp.Path) bool {
			// ignore the function field
			// https://cs.opensource.google/go/go/+/refs/tags/go1.22.0:src/reflect/deepequal.go;l=187
			return p.Last().Type().Kind() == reflect.Func
		},
		cmp.Ignore(),
	)
	if !cmp.Equal(ps, copy, opt1, opt2) {
		diff := cmp.Diff(ps, copy, opt1, opt2)
		t.Errorf("Clone did not produce an identical copy\ndiff: %s", diff)
	}

	// ensure that changes to the copy do not affect the original
	p3 := NewPolicy()
	p3.Name = "p3"
	err = p3.CommFilter.Parse("=comm")
	require.NoError(t, err)
	err = copy.add(p3)
	require.NoError(t, err)

	p1, err = copy.lookupByName("p1")
	require.NoError(t, err)
	p1.Name = "p1-modified"

	if cmp.Equal(ps, copy, opt1, opt2) {
		t.Errorf("Changes to copied policy affected the original: %+v", ps)
	}
}
