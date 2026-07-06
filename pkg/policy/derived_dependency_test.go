package policy

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/dependencies"
	"github.com/aquasecurity/tracee/pkg/filters"
)

// Test_DerivedEventPullsInBaseAsDependency guards the invariant the decode-stage drop relies on (after the
// coarse hasDerivation keep was removed, see pkg/ebpf/events_pipeline.go): selecting a DERIVED event pulls
// its derive-from base into the rule set as a DEPENDENCY rule, so matchPolicies keeps the base (scope-aware)
// - not a coarse "can this type derive?" check. If a derived event stopped declaring its base dependency,
// this fails, catching the footgun before the base gets silently dropped at decode.
func Test_DerivedEventPullsInBaseAsDependency(t *testing.T) {
	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	// A policy selecting the DERIVED event container_create (which derives from cgroup_mkdir).
	p := NewPolicy()
	p.Name = "derived"
	p.Rules = map[events.ID]RuleData{
		events.ContainerCreate: {
			EventID:     events.ContainerCreate,
			ScopeFilter: filters.NewScopeFilter(),
			DataFilter:  filters.NewDataFilter(),
			RetFilter:   filters.NewIntFilter(),
		},
	}

	pm, err := NewManager(ManagerConfig{}, depsManager, p)
	require.NoError(t, err)

	// The derive-from base (cgroup_mkdir) must be present in the rule set...
	baseRules, ok := pm.rules[events.CgroupMkdir]
	require.True(t, ok, "the derive-from base (cgroup_mkdir) must be pulled in when the derived event is selected")

	// ...and it must carry a DEPENDENCY rule - that is what keeps the base at decode via matchPolicies.
	hasDep := false
	for _, r := range baseRules.Rules {
		if r.IsDependency() {
			hasDep = true
		}
	}
	require.True(t, hasDep, "the base must carry a dependency rule (else the decode drop would discard it)")
}
