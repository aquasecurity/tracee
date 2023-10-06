package policy

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPolicyClone(t *testing.T) {
	policy := NewPolicy()
	err := policy.PIDFilter.Parse("=1")
	require.NoError(t, err)

	copy := policy.Clone().(*Policy)

	if !reflect.DeepEqual(policy, copy) {
		t.Errorf("Clone did not produce an identical copy")
	}

	// ensure that changes to the copy do not affect the original
	copy.UIDFilter.Parse("=2")
	if reflect.DeepEqual(policy, copy) {
		t.Errorf("Changes to copied policy affected the original")
	}
}
