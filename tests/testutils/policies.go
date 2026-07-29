package testutils

import (
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/events"
	k8s "github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/policy/v1beta1"
)

// BuildPoliciesFromEvents create a Policies instance with a single policy,
// which chooses the given events without filters or scopes
func BuildPoliciesFromEvents(eventsToChoose []events.ID) []*policy.Policy {
	var policyRules []k8s.Rule

	for _, event := range eventsToChoose {
		eventDef := events.Core.GetDefinitionByID(event)
		rule := k8s.Rule{
			Event:   eventDef.GetName(),
			Filters: []string{},
		}
		policyRules = append(policyRules, rule)
	}

	policiesFiles := []PolicyFileWithID{
		{
			Id: 1,
			PolicyFile: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "test-policy",
				},
				Spec: k8s.PolicySpec{
					DefaultActions: []string{"log"},
					Rules:          policyRules,
				},
			},
		},
	}

	return NewPolicies(policiesFiles)
}

// NewPolicies builds policies from the given in-memory policy files. The rule model no longer
// assigns per-policy IDs (policies are identified by name), so the Id field is ignored; it is
// kept for source compatibility with existing callers. New tests should prefer
// NewPoliciesFromPaths to exercise the real YAML load path.
func NewPolicies(polsFilesID []PolicyFileWithID) []*policy.Policy {
	var polsFiles []k8s.PolicyInterface

	for _, polFile := range polsFilesID {
		polsFiles = append(polsFiles, polFile.PolicyFile)
	}

	policyScopeMap, policyEventMap, err := flags.PrepareFilterMapsFromPolicies(polsFiles, nil)
	if err != nil {
		panic(err)
	}

	policies, err := flags.CreatePolicies(policyScopeMap, policyEventMap)
	if err != nil {
		panic(err)
	}

	return policies
}

// NewPoliciesFromPaths loads real policy YAML files (the same path the Tracee CLI uses for
// --policy) and returns the resulting policies. Preferred for integration tests: it exercises
// the actual parse -> load pipeline and is decoupled from internal policy IDs. paths may be
// files or directories of .yaml/.yml policies.
func NewPoliciesFromPaths(paths []string) ([]*policy.Policy, error) {
	polsFiles, err := v1beta1.PoliciesFromPaths(paths)
	if err != nil {
		return nil, err
	}

	policyScopeMap, policyEventMap, err := flags.PrepareFilterMapsFromPolicies(polsFiles, nil)
	if err != nil {
		return nil, err
	}

	return flags.CreatePolicies(policyScopeMap, policyEventMap)
}

type PolicyFileWithID struct {
	PolicyFile v1beta1.PolicyFile
	Id         int
}
