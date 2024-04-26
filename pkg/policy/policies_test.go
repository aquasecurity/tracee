package policy

import (
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/filters/sets"
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

	err = p2.ArgFilter.Parse("read.args.fd", "=argval", events.Core.NamesToIDs())
	require.NoError(t, err)

	err = policies.Add(p1)
	require.NoError(t, err)
	err = policies.Add(p2)
	require.NoError(t, err)

	copy := policies.Clone()

	opt1 := cmp.AllowUnexported(
		Policies{},
		sync.Mutex{},
		sync.RWMutex{},
		atomic.Int32{},
		filters.StringFilter{},
		filters.UIntFilter[uint32]{},
		filters.UIntFilter[uint64]{},
		filters.BoolFilter{},
		filters.RetFilter{},
		filters.ArgFilter{},
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
	if !cmp.Equal(policies, copy, opt1, opt2) {
		diff := cmp.Diff(policies, copy, opt1, opt2)
		t.Errorf("Clone did not produce an identical copy\ndiff: %s", diff)
	}

	// ensure that changes to the copy do not affect the original
	p3 := NewPolicy()
	p3.Name = "p3"
	err = p3.CommFilter.Parse("=comm")
	require.NoError(t, err)
	err = copy.Add(p3)
	require.NoError(t, err)

	p1, err = copy.LookupByName("p1")
	require.NoError(t, err)
	p1.Name = "p1-modified"

	if cmp.Equal(policies, copy, opt1, opt2) {
		t.Errorf("Changes to copied policy affected the original: %+v", policies)
	}
}
