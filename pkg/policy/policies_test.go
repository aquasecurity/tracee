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
	p1.Name = "p1"
	err := p1.PIDFilter.Parse("=1")
	require.NoError(t, err)

	p2 := NewPolicy()
	p2.Name = "p2"
	err = p2.UIDFilter.Parse("=2")
	require.NoError(t, err)

	err = policies.Add(p1)
	require.NoError(t, err)
	err = policies.Add(p2)
	require.NoError(t, err)

	copy := policies.Clone().(*Policies)

	if !reflect.DeepEqual(policies, copy) {
		t.Errorf("Clone did not produce an identical copy")
	}

	// ensure that changes to the copy do not affect the original
	p3 := NewPolicy()
	p3.Name = "p3"
	err = p3.CommFilter.Parse("=comm")
	require.NoError(t, err)
	err = copy.Add(p3)
	require.NoError(t, err)

	if reflect.DeepEqual(policies, copy) {
		t.Errorf("Changes to copied policy affected the original")
	}
}
