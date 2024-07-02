package cobra

import (
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	k8s "github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/policy/v1beta1"
)

func createPoliciesFromK8SPolicy(policies []k8s.PolicyInterface) ([]*policy.Policy, error) {
	policyScopeMap, policyEventsMap, err := flags.PrepareFilterMapsFromPolicies(policies)
	if err != nil {
		return nil, err
	}

	return flags.CreatePolicies(policyScopeMap, policyEventsMap, true)
}

func createPoliciesFromPolicyFiles(policyFlags []string) ([]*policy.Policy, error) {
	policyFiles, err := v1beta1.PoliciesFromPaths(policyFlags)
	if err != nil {
		return nil, err
	}

	policyScopeMap, policyEventsMap, err := flags.PrepareFilterMapsFromPolicies(policyFiles)
	if err != nil {
		return nil, err
	}

	return flags.CreatePolicies(policyScopeMap, policyEventsMap, true)
}

func createPoliciesFromCLIFlags(scopeFlags, eventFlags []string) ([]*policy.Policy, error) {
	policyScopeMap, err := flags.PrepareScopeMapFromFlags(scopeFlags)
	if err != nil {
		return nil, err
	}

	policyEventsMap, err := flags.PrepareEventMapFromFlags(eventFlags)
	if err != nil {
		return nil, err
	}

	return flags.CreatePolicies(policyScopeMap, policyEventsMap, true)
}
