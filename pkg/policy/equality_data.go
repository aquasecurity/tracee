package policy

import (
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/utils"
)

// Constants for match states (kernel)
const (
	exactMatchEnabled = 1 << iota
	notExactMatchEnabled
	prefixMatchEnabled
	notPrefixMatchEnabled
	suffixMatchEnabled
	notSuffixMatchEnabled
)

// KernelMatchStates - stores the bitfield for match states
type KernelMatchStates struct {
	matchState uint8
}

type KernelDataFields struct {
	ID     events.ID
	String string
}

// computeDataFilterEqualities computes the equalities for the kernel data filter
// in the policies updating the provided eqs map.
func (ps *policies) computeDataFilterEqualities(fEqs *filtersEqualities) error {
	for _, p := range ps.allFromMap() {
		// Reinitialize variables at the start of each iteration
		combinedEqualities := make(map[KernelDataFields]struct{})
		combinedNotEqualities := make(map[KernelDataFields]struct{})
		combinedPrefixEqualities := make(map[KernelDataFields]struct{})
		combinedNotPrefixEqualities := make(map[KernelDataFields]struct{})
		combinedSuffixEqualities := make(map[KernelDataFields]struct{})
		combinedNotSuffixEqualities := make(map[KernelDataFields]struct{})

		policyID := p.ID
		for eventID, rule := range p.Rules {
			equalities, err := rule.DataFilter.Equalities()
			if err != nil {
				continue
			}
			ps.handleExactMatches(policyID, eventID, equalities, combinedEqualities, combinedNotEqualities)
			ps.handlePrefixMatches(policyID, eventID, equalities, combinedPrefixEqualities, combinedNotPrefixEqualities)
			ps.handleSuffixMatches(policyID, eventID, equalities, combinedSuffixEqualities, combinedNotSuffixEqualities)
		}

		// Exact match equalities
		updateEqualities(fEqs.dataEqualitiesExact, combinedNotEqualities, notEqual, uint(policyID))
		updateEqualities(fEqs.dataEqualitiesExact, combinedEqualities, equal, uint(policyID))

		// Prefix match equalities
		updateAffixEqualities(fEqs.dataEqualitiesPrefix, combinedNotPrefixEqualities, notEqual, uint(policyID))
		updateAffixEqualities(fEqs.dataEqualitiesPrefix, combinedPrefixEqualities, equal, uint(policyID))

		// Suffix match equalities
		updateAffixEqualities(fEqs.dataEqualitiesSuffix, combinedNotSuffixEqualities, notEqual, uint(policyID))
		updateAffixEqualities(fEqs.dataEqualitiesSuffix, combinedSuffixEqualities, equal, uint(policyID))
	}

	return nil
}

func (ps *policies) handleExactMatches(policyId int, eventID events.ID, equalities filters.StringFilterEqualities, combinedEqualities, combinedNotEqualities map[KernelDataFields]struct{}) {
	for k := range equalities.ExactEqual {
		combinedEqualities[KernelDataFields{eventID, k}] = struct{}{}
		ps.kernellandPolicyMatchStates[policyId].EnableState(exactMatchEnabled)
	}
	for k := range equalities.ExactNotEqual {
		combinedNotEqualities[KernelDataFields{eventID, k}] = struct{}{}
		ps.kernellandPolicyMatchStates[policyId].EnableState(exactMatchEnabled)
		ps.kernellandPolicyMatchStates[policyId].EnableState(notExactMatchEnabled)
	}
}

func (ps *policies) handlePrefixMatches(policyId int, eventID events.ID, equalities filters.StringFilterEqualities, combinedPrefixEqualities, combinedNotPrefixEqualities map[KernelDataFields]struct{}) {
	for k := range equalities.PrefixEqual {
		combinedPrefixEqualities[KernelDataFields{eventID, k}] = struct{}{}
		ps.kernellandPolicyMatchStates[policyId].EnableState(prefixMatchEnabled)
	}
	for k := range equalities.PrefixNotEqual {
		combinedNotPrefixEqualities[KernelDataFields{eventID, k}] = struct{}{}
		ps.kernellandPolicyMatchStates[policyId].EnableState(prefixMatchEnabled)
		ps.kernellandPolicyMatchStates[policyId].EnableState(notPrefixMatchEnabled)
	}
}

func (ps *policies) handleSuffixMatches(policyId int, eventID events.ID, equalities filters.StringFilterEqualities, combinedSuffixEqualities, combinedNotSuffixEqualities map[KernelDataFields]struct{}) {
	for k := range equalities.SuffixEqual {
		reversed := utils.ReverseString(k)
		combinedSuffixEqualities[KernelDataFields{eventID, reversed}] = struct{}{}
		ps.kernellandPolicyMatchStates[policyId].EnableState(suffixMatchEnabled)
	}
	for k := range equalities.SuffixNotEqual {
		reversed := utils.ReverseString(k)
		combinedNotSuffixEqualities[KernelDataFields{eventID, reversed}] = struct{}{}
		ps.kernellandPolicyMatchStates[policyId].EnableState(suffixMatchEnabled)
		ps.kernellandPolicyMatchStates[policyId].EnableState(notSuffixMatchEnabled)
	}
}

func (k *KernelMatchStates) EnableState(state uint8) {
	k.matchState |= state
}

func (k *KernelMatchStates) IsStateEnabled(state uint8) bool {
	return k.matchState&state != 0
}

func (k *KernelMatchStates) EnabledDataExactMatch() bool {
	return k.IsStateEnabled(exactMatchEnabled)
}

func (k *KernelMatchStates) MatchIfKeyMissingDataExactMatch() bool {
	return k.IsStateEnabled(notExactMatchEnabled)
}

func (k *KernelMatchStates) EnabledDataPrefixMatch() bool {
	return k.IsStateEnabled(prefixMatchEnabled)
}

func (k *KernelMatchStates) MatchIfKeyMissingDataPrefixMatch() bool {
	return k.IsStateEnabled(notPrefixMatchEnabled)
}

func (k *KernelMatchStates) EnabledDataSuffixMatch() bool {
	return k.IsStateEnabled(suffixMatchEnabled)
}

func (k *KernelMatchStates) MatchIfKeyMissingDataSuffixMatch() bool {
	return k.IsStateEnabled(notSuffixMatchEnabled)
}
