package policy

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/filters/sets"
)

func TestPolicyClone(t *testing.T) {
	policy := NewPolicy()
	err := policy.PIDFilter.Parse("=1")
	require.NoError(t, err)

	copy := policy.Clone()

	opt1 := cmp.AllowUnexported(
		filters.StringFilter{},
		filters.UIntFilter[uint32]{},
		filters.UIntFilter[uint64]{},
		filters.BoolFilter{},
		filters.RetFilter{},
		filters.DataFilter{},
		filters.ScopeFilter{},
		filters.ProcessTreeFilter{},
		filters.BinaryFilter{},
		sets.PrefixSet{},
		sets.SuffixSet{},
	)
	opt2 := cmp.FilterPath(
		func(p cmp.Path) bool {
			// ignore the function field
			// https://cs.opensource.google/go/go/+/refs/tags/go1.22.0:src/reflect/deepequal.go;l=187
			return p.Last().Type().Kind() == reflect.Func
		},
		cmp.Ignore(),
	)
	if !cmp.Equal(policy, copy, opt1, opt2) {
		diff := cmp.Diff(policy, copy, opt1, opt2)
		t.Errorf("Clone did not produce an identical copy\ndiff: %s", diff)
	}

	// ensure that changes to the copy do not affect the original
	copy.UIDFilter.Parse("=2")
	if cmp.Equal(policy, copy, opt1, opt2) {
		t.Errorf("Changes to copied policy affected the original: %+v", policy)
	}
}
