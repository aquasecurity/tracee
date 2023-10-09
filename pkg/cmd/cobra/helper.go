package cobra

import (
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/policy/v1beta1"
)

func createPoliciesFromPolicyFiles(
	policyFlags []string,
	evtsToDisable map[string]struct{},
) (*policy.Policies, error) {
	policyFiles, err := v1beta1.PoliciesFromPaths(policyFlags)
	if err != nil {
		return nil, err
	}

	policyScopeMap, policyEventsMap, err := flags.PrepareFilterMapsFromPolicies(policyFiles)
	if err != nil {
		return nil, err
	}

	return flags.CreatePolicies(policyScopeMap, policyEventsMap, evtsToDisable, true)
}

func createPoliciesFromCLIFlags(
	scopeFlags, eventFlags []string,
	evtsToDisable map[string]struct{},
) (*policy.Policies, error) {
	policyScopeMap, err := flags.PrepareScopeMapFromFlags(scopeFlags)
	if err != nil {
		return nil, err
	}

	policyEventsMap, err := flags.PrepareEventMapFromFlags(eventFlags)
	if err != nil {
		return nil, err
	}

	return flags.CreatePolicies(policyScopeMap, policyEventsMap, evtsToDisable, true)
}
