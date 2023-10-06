package policy

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPoliciesClone(t *testing.T) {
	t.Parallel()

	policies := NewPolicies()

	p1 := NewPolicy()
	err := p1.PIDFilter.Parse("=1")
	require.NoError(t, err)

	p2 := NewPolicy()
	err = p2.UIDFilter.Parse("=2")
	require.NoError(t, err)

	err = policies.Add(p1)
	require.NoError(t, err)
	err = policies.Add(p2)
	require.NoError(t, err)

	copy := policies.Clone().(*Policies)

	if !arePoliciesEqual(policies, copy) {
		t.Errorf("Clone did not produce an identical copy")
	}

	// ensure that changes to the copy do not affect the original
	p3 := NewPolicy()
	err = p3.CommFilter.Parse("=comm")
	require.NoError(t, err)
	err = copy.Add(p3)
	require.NoError(t, err)

	if arePoliciesEqual(policies, copy) {
		t.Errorf("Changes to copied policy affected the original")
	}
}

// arePoliciesEqual is a helper function for TestPoliciesClone
// since reflect.DeepEqual does not dereference pointers which are keys in maps.
// TODO: remove this when Policies is refactored to not use pointers as keys in maps
func arePoliciesEqual(p1, p2 *Policies) bool {
	// check non-pointer fields
	if !areNonPointerFieldsEqual(p1, p2) {
		return false
	}

	// then compare the maps with pointers as keys
	return areMapsEqual(p1.filterEnabledPoliciesMap, p2.filterEnabledPoliciesMap) &&
		areMapsEqual(p1.filterUserlandPoliciesMap, p2.filterUserlandPoliciesMap)
}

func areMapsEqual(map1, map2 map[*Policy]int) bool {
	if len(map1) != len(map2) {
		return false
	}

	for k1, v1 := range map1 {
		found := false
		for k2, v2 := range map2 {
			if reflect.DeepEqual(k1, k2) && v1 == v2 {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

func areNonPointerFieldsEqual(p1, p2 *Policies) bool {
	return p1.version == p2.version &&
		reflect.DeepEqual(p1.bpfInnerMaps, p2.bpfInnerMaps) &&
		reflect.DeepEqual(p1.policiesArray, p2.policiesArray) &&
		p1.uidFilterMin == p2.uidFilterMin &&
		p1.uidFilterMax == p2.uidFilterMax &&
		p1.pidFilterMin == p2.pidFilterMin &&
		p1.pidFilterMax == p2.pidFilterMax &&
		p1.uidFilterableInUserland == p2.uidFilterableInUserland &&
		p1.pidFilterableInUserland == p2.pidFilterableInUserland &&
		p1.containerFiltersEnabled == p2.containerFiltersEnabled
}
