package cobra

import (
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/config"
	k8s "github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/policy/v1beta1"
)

func createPoliciesFromK8SPolicy(cfg config.PoliciesConfig, policies []k8s.PolicyInterface) (*policy.Policies, error) {
	policyScopeMap, policyEventsMap, err := flags.PrepareFilterMapsFromPolicies(policies)
	if err != nil {
		return nil, err
	}

	return flags.CreatePolicies(cfg, policyScopeMap, policyEventsMap, true)
}

func createPoliciesFromPolicyFiles(cfg config.PoliciesConfig, policyFlags []string) (*policy.Policies, error) {
	policyFiles, err := v1beta1.PoliciesFromPaths(policyFlags)
	if err != nil {
		return nil, err
	}

	policyScopeMap, policyEventsMap, err := flags.PrepareFilterMapsFromPolicies(policyFiles)
	if err != nil {
		return nil, err
	}

	return flags.CreatePolicies(cfg, policyScopeMap, policyEventsMap, true)
}

func createPoliciesFromCLIFlags(cfg config.PoliciesConfig, scopeFlags, eventFlags []string) (*policy.Policies, error) {
	policyScopeMap, err := flags.PrepareScopeMapFromFlags(scopeFlags)
	if err != nil {
		return nil, err
	}

	policyEventsMap, err := flags.PrepareEventMapFromFlags(eventFlags)
	if err != nil {
		return nil, err
	}

	return flags.CreatePolicies(cfg, policyScopeMap, policyEventsMap, true)
}
