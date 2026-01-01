package cobra

import (
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	k8s "github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/policy/v1beta1"
)

func createPoliciesFromK8SPolicy(policies []k8s.PolicyInterface, detectors []detection.EventDetector) ([]*policy.Policy, error) {
	policyScopeMap, policyEventsMap, err := flags.PrepareFilterMapsFromPolicies(policies, detectors)
	if err != nil {
		return nil, err
	}

	return flags.CreatePolicies(policyScopeMap, policyEventsMap)
}

func createPoliciesFromPolicyFiles(policyFlags []string, detectors []detection.EventDetector) ([]*policy.Policy, error) {
	policyFiles, err := v1beta1.PoliciesFromPaths(policyFlags)
	if err != nil {
		return nil, err
	}

	policyScopeMap, policyEventsMap, err := flags.PrepareFilterMapsFromPolicies(policyFiles, detectors)
	if err != nil {
		return nil, err
	}

	return flags.CreatePolicies(policyScopeMap, policyEventsMap)
}

func createPoliciesFromCLIFlags(scopeFlags, eventFlags []string, detectors []detection.EventDetector) ([]*policy.Policy, error) {
	policyScopeMap, err := flags.PrepareScopeMapFromFlags(scopeFlags)
	if err != nil {
		return nil, err
	}

	policyEventsMap, err := flags.PrepareEventMapFromFlags(eventFlags, detectors)
	if err != nil {
		return nil, err
	}

	return flags.CreatePolicies(policyScopeMap, policyEventsMap)
}
