package policy

import (
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/utils"
)

type RulesData struct {
	Data                        map[events.ID]RuleData
	kernelDataFilterMatchStates KernelDataFilterMatchStates
}

type RuleData struct {
	EventID     events.ID
	ScopeFilter *filters.ScopeFilter
	DataFilter  *filters.DataFilter
	RetFilter   *filters.IntFilter[int64]
}

type KernelDataFilterMatchStates struct {
	matchState uint8
}

// Constants for match states (kernel)
const (
	exactMatchEnabled = 1 << iota
	notExactMatchEnabled
	prefixMatchEnabled
	notPrefixMatchEnabled
	suffixMatchEnabled
	notSuffixMatchEnabled
)

type KernelDataFields struct {
	ID     events.ID
	String string
}

type KernelDataFilterEqualities struct {
	ExactEqual     map[KernelDataFields]struct{}
	ExactNotEqual  map[KernelDataFields]struct{}
	PrefixEqual    map[KernelDataFields]struct{}
	PrefixNotEqual map[KernelDataFields]struct{}
	SuffixEqual    map[KernelDataFields]struct{}
	SuffixNotEqual map[KernelDataFields]struct{}
}

func (k *KernelDataFilterMatchStates) EnableState(state uint8) {
	k.matchState |= state
}

func (k *KernelDataFilterMatchStates) IsStateEnabled(state uint8) bool {
	return k.matchState&state != 0
}

func (r *RulesData) EnabledDataExactMatch() bool {
	return r.kernelDataFilterMatchStates.IsStateEnabled(exactMatchEnabled)
}

func (r *RulesData) MatchIfKeyMissingDataExactMatch() bool {
	return r.kernelDataFilterMatchStates.IsStateEnabled(notExactMatchEnabled)
}

func (r *RulesData) EnabledDataPrefixMatch() bool {
	return r.kernelDataFilterMatchStates.IsStateEnabled(prefixMatchEnabled)
}

func (r *RulesData) MatchIfKeyMissingDataPrefixMatch() bool {
	return r.kernelDataFilterMatchStates.IsStateEnabled(notPrefixMatchEnabled)
}

func (r *RulesData) EnabledDataSuffixMatch() bool {
	return r.kernelDataFilterMatchStates.IsStateEnabled(suffixMatchEnabled)
}

func (r *RulesData) MatchIfKeyMissingDataSuffixMatch() bool {
	return r.kernelDataFilterMatchStates.IsStateEnabled(notSuffixMatchEnabled)
}

func (r *RulesData) handleExactMatches(eventID events.ID, equalities filters.StringFilterEqualities, combinedEqualities, combinedNotEqualities map[KernelDataFields]struct{}) {
	for k := range equalities.ExactEqual {
		combinedEqualities[KernelDataFields{eventID, k}] = struct{}{}
		r.kernelDataFilterMatchStates.EnableState(exactMatchEnabled)
	}
	for k := range equalities.ExactNotEqual {
		combinedNotEqualities[KernelDataFields{eventID, k}] = struct{}{}
		r.kernelDataFilterMatchStates.EnableState(notExactMatchEnabled)
	}
}

func (r *RulesData) handlePrefixMatches(eventID events.ID, equalities filters.StringFilterEqualities, combinedPrefixEqualities, combinedNotPrefixEqualities map[KernelDataFields]struct{}) {
	for k := range equalities.PrefixEqual {
		combinedPrefixEqualities[KernelDataFields{eventID, k}] = struct{}{}
		r.kernelDataFilterMatchStates.EnableState(prefixMatchEnabled)
	}
	for k := range equalities.PrefixNotEqual {
		combinedNotPrefixEqualities[KernelDataFields{eventID, k}] = struct{}{}
		r.kernelDataFilterMatchStates.EnableState(notPrefixMatchEnabled)
	}
}

func (r *RulesData) handleSuffixMatches(eventID events.ID, equalities filters.StringFilterEqualities, combinedSuffixEqualities, combinedNotSuffixEqualities map[KernelDataFields]struct{}) {
	for k := range equalities.SuffixEqual {
		reversed := utils.ReverseString(k)
		combinedSuffixEqualities[KernelDataFields{eventID, reversed}] = struct{}{}
		r.kernelDataFilterMatchStates.EnableState(suffixMatchEnabled)
	}
	for k := range equalities.SuffixNotEqual {
		reversed := utils.ReverseString(k)
		combinedNotSuffixEqualities[KernelDataFields{eventID, reversed}] = struct{}{}
		r.kernelDataFilterMatchStates.EnableState(notSuffixMatchEnabled)
	}
}

// DataFilterEqualities returns the kernel data filters enabled for all event IDs and fields.
func (r *RulesData) DataFilterEqualities() KernelDataFilterEqualities {
	combinedEqualities := make(map[KernelDataFields]struct{})
	combinedNotEqualities := make(map[KernelDataFields]struct{})
	combinedPrefixEqualities := make(map[KernelDataFields]struct{})
	combinedNotPrefixEqualities := make(map[KernelDataFields]struct{})
	combinedSuffixEqualities := make(map[KernelDataFields]struct{})
	combinedNotSuffixEqualities := make(map[KernelDataFields]struct{})

	for eventID, rule := range r.Data {
		equalities := rule.DataFilter.Equalities()
		r.handleExactMatches(eventID, equalities, combinedEqualities, combinedNotEqualities)
		r.handlePrefixMatches(eventID, equalities, combinedPrefixEqualities, combinedNotPrefixEqualities)
		r.handleSuffixMatches(eventID, equalities, combinedSuffixEqualities, combinedNotSuffixEqualities)
	}

	return KernelDataFilterEqualities{
		ExactEqual:     combinedEqualities,
		ExactNotEqual:  combinedNotEqualities,
		PrefixEqual:    combinedPrefixEqualities,
		PrefixNotEqual: combinedNotPrefixEqualities,
		SuffixEqual:    combinedSuffixEqualities,
		SuffixNotEqual: combinedNotSuffixEqualities,
	}
}

func (r *RulesData) Clone() RulesData {
	if r == nil || r.Data == nil {
		return RulesData{Data: make(map[events.ID]RuleData)}
	}

	clonedData := make(map[events.ID]RuleData)
	for eID, ruleData := range r.Data {
		clonedData[eID] = RuleData{
			EventID:     ruleData.EventID,
			ScopeFilter: ruleData.ScopeFilter.Clone(),
			DataFilter:  ruleData.DataFilter.Clone(),
			RetFilter:   ruleData.RetFilter.Clone(),
		}
	}

	return RulesData{Data: clonedData}
}
