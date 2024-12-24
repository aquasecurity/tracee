package policy

import (
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/utils"
)

type dataFilterConfig struct {
	string stringFilterConfig
	// other types of filters
}

type stringFilterConfig struct {
	prefixEnabled           uint64
	suffixEnabled           uint64
	exactEnabled            uint64
	prefixMatchIfKeyMissing uint64
	suffixMatchIfKeyMissing uint64
	exactMatchIfKeyMissing  uint64
}

type KernelDataFields struct {
	ID     events.ID
	String string
}

func (d *stringFilterConfig) EnableExact(policyID int) {
	d.exactEnabled |= 1 << policyID
}

func (d *stringFilterConfig) EnablePrefix(policyID int) {
	d.prefixEnabled |= 1 << policyID
}

func (d *stringFilterConfig) EnableSuffix(policyID int) {
	d.suffixEnabled |= 1 << policyID
}

func (d *stringFilterConfig) EnablePrefixMatchIfKeyMissing(policyID int) {
	d.prefixMatchIfKeyMissing |= 1 << policyID
}

func (d *stringFilterConfig) EnableSuffixMatchIfKeyMissing(policyID int) {
	d.suffixMatchIfKeyMissing |= 1 << policyID
}

func (d *stringFilterConfig) EnableExactMatchIfKeyMissing(policyID int) {
	d.exactMatchIfKeyMissing |= 1 << policyID
}

func combineEventBitmap(eventsMap map[events.ID]stringFilterConfig, eventID events.ID, strCfgFilter *stringFilterConfig) {
	existingFilter, exists := eventsMap[eventID]
	if !exists {
		eventsMap[eventID] = stringFilterConfig{
			prefixEnabled:           strCfgFilter.prefixEnabled,
			suffixEnabled:           strCfgFilter.suffixEnabled,
			exactEnabled:            strCfgFilter.exactEnabled,
			prefixMatchIfKeyMissing: strCfgFilter.prefixMatchIfKeyMissing,
			suffixMatchIfKeyMissing: strCfgFilter.suffixMatchIfKeyMissing,
			exactMatchIfKeyMissing:  strCfgFilter.exactMatchIfKeyMissing,
		}
		return
	}

	existingFilter.prefixEnabled |= strCfgFilter.prefixEnabled
	existingFilter.suffixEnabled |= strCfgFilter.suffixEnabled
	existingFilter.exactEnabled |= strCfgFilter.exactEnabled
	existingFilter.prefixMatchIfKeyMissing |= strCfgFilter.prefixMatchIfKeyMissing
	existingFilter.suffixMatchIfKeyMissing |= strCfgFilter.suffixMatchIfKeyMissing
	existingFilter.exactMatchIfKeyMissing |= strCfgFilter.exactMatchIfKeyMissing

	eventsMap[eventID] = existingFilter
}

// computeDataFilterEqualities computes the equalities for the kernel data filter
// in the policies updating the provided eqs map.
func (ps *policies) computeDataFilterEqualities(fEqs *filtersEqualities, eventsConfig map[events.ID]stringFilterConfig) error {
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
			strCfgFilter := &stringFilterConfig{}
			equalities, err := rule.DataFilter.Equalities()
			if err != nil {
				continue
			}
			ps.handleExactMatches(policyID, eventID, strCfgFilter, equalities, combinedEqualities, combinedNotEqualities)
			ps.handlePrefixMatches(policyID, eventID, strCfgFilter, equalities, combinedPrefixEqualities, combinedNotPrefixEqualities)
			ps.handleSuffixMatches(policyID, eventID, strCfgFilter, equalities, combinedSuffixEqualities, combinedNotSuffixEqualities)

			// Combine the event bitmap across all policies
			combineEventBitmap(eventsConfig, eventID, strCfgFilter)
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

func (ps *policies) handleExactMatches(policyId int, eventID events.ID, filter *stringFilterConfig, equalities filters.StringFilterEqualities, combinedEqualities, combinedNotEqualities map[KernelDataFields]struct{}) {
	for k := range equalities.ExactEqual {
		combinedEqualities[KernelDataFields{eventID, k}] = struct{}{}

		filter.EnableExact(policyId)
	}
	for k := range equalities.ExactNotEqual {
		combinedNotEqualities[KernelDataFields{eventID, k}] = struct{}{}

		filter.EnableExact(policyId)
		filter.EnableExactMatchIfKeyMissing(policyId)
	}
}

func (ps *policies) handlePrefixMatches(policyId int, eventID events.ID, filter *stringFilterConfig, equalities filters.StringFilterEqualities, combinedPrefixEqualities, combinedNotPrefixEqualities map[KernelDataFields]struct{}) {
	for k := range equalities.PrefixEqual {
		combinedPrefixEqualities[KernelDataFields{eventID, k}] = struct{}{}

		filter.EnablePrefix(policyId)
	}
	for k := range equalities.PrefixNotEqual {
		combinedNotPrefixEqualities[KernelDataFields{eventID, k}] = struct{}{}

		filter.EnablePrefix(policyId)
		filter.EnablePrefixMatchIfKeyMissing(policyId)
	}
}

func (ps *policies) handleSuffixMatches(policyId int, eventID events.ID, filter *stringFilterConfig, equalities filters.StringFilterEqualities, combinedSuffixEqualities, combinedNotSuffixEqualities map[KernelDataFields]struct{}) {
	for k := range equalities.SuffixEqual {
		reversed := utils.ReverseString(k)
		combinedSuffixEqualities[KernelDataFields{eventID, reversed}] = struct{}{}

		filter.EnableSuffix(policyId)
	}
	for k := range equalities.SuffixNotEqual {
		reversed := utils.ReverseString(k)
		combinedNotSuffixEqualities[KernelDataFields{eventID, reversed}] = struct{}{}

		filter.EnableSuffix(policyId)
		filter.EnableSuffixMatchIfKeyMissing(policyId)
	}
}
