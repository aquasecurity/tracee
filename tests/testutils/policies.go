package testutils

import (
	"fmt"

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

// NewPolicies creates a slice of policies setting the ID of each policy to the given ID.
func NewPolicies(polsFilesID []PolicyFileWithID) []*policy.Policy {
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

	for i := range policies {
		found := false
		for j := range polsFilesID {
			if policies[i].Name == polsFilesID[j].PolicyFile.Metadata.Name {
				policies[i].ID = polsFilesID[j].Id - 1
				found = true
				break
			}
		}

		if !found {
			panic(fmt.Errorf("policy %s not found in polsFilesID", policies[i].Name))
		}
	}

	return policies
}

type PolicyFileWithID struct {
	PolicyFile v1beta1.PolicyFile
	Id         int
}
