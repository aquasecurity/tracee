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
func BuildPoliciesFromEvents(eventsToChoose []events.ID) *policy.Policies {
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

// NewPolicies creates a new policies object with the given policies files with IDs.
func NewPolicies(polsFilesID []PolicyFileWithID) *policy.Policies {
	var polsFiles []k8s.PolicyInterface

	for _, polFile := range polsFilesID {
		polsFiles = append(polsFiles, polFile.PolicyFile)
	}

	policyScopeMap, policyEventMap, err := flags.PrepareFilterMapsFromPolicies(polsFiles)
	if err != nil {
		panic(err)
	}

	policies, err := flags.CreatePolicies(policyScopeMap, policyEventMap, true)
	if err != nil {
		panic(err)
	}

	policiesWithIDSet := policy.NewPolicies()
	for it := policies.CreateAllIterator(); it.HasNext(); {
		pol := it.Next()
		pol.ID = polsFilesID[pol.ID].Id - 1
		_ = policiesWithIDSet.Set(pol)
	}

	return policiesWithIDSet
}

type PolicyFileWithID struct {
	PolicyFile v1beta1.PolicyFile
	Id         int
}
