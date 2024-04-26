package filters

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/filters/sets"
)

func TestScopeFilterClone(t *testing.T) {
	t.Parallel()

	filter := NewScopeFilter()
	err := filter.Parse("openat.scope.processorId", "=0")
	require.NoError(t, err)

	copy := filter.Clone()

	opt1 := cmp.AllowUnexported(
		ScopeFilter{},
		eventCtxFilter{},
		IntFilter[int64]{},
		UIntFilter[uint64]{},
		BoolFilter{},
		StringFilter{},
		sets.PrefixSet{},
		sets.SuffixSet{},
	)
	if !cmp.Equal(filter, copy, opt1) {
		diff := cmp.Diff(filter, copy, opt1)
		t.Errorf("Clone did not produce an identical copy\ndiff: %s", diff)
	}

	// ensure that changes to the copy do not affect the original
	err = copy.Parse("openat.scope.pid", "=1")
	require.NoError(t, err)
	if cmp.Equal(filter, copy, opt1) {
		t.Errorf("Changes to copied filter affected the original")
	}
}
