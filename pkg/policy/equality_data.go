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

func (d *stringFilterConfig) EnableExact(ruleID int) {
	d.exactEnabled |= 1 << ruleID
}

func (d *stringFilterConfig) EnablePrefix(ruleID int) {
	d.prefixEnabled |= 1 << ruleID
}

func (d *stringFilterConfig) EnableSuffix(ruleID int) {
	d.suffixEnabled |= 1 << ruleID
}

func (d *stringFilterConfig) EnablePrefixMatchIfKeyMissing(ruleID int) {
	d.prefixMatchIfKeyMissing |= 1 << ruleID
}

func (d *stringFilterConfig) EnableSuffixMatchIfKeyMissing(ruleID int) {
	d.suffixMatchIfKeyMissing |= 1 << ruleID
}

func (d *stringFilterConfig) EnableExactMatchIfKeyMissing(ruleID int) {
	d.exactMatchIfKeyMissing |= 1 << ruleID
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
func (pm *PolicyManager) computeDataFilterEqualities(fEqs *filtersEqualities, eventsConfig map[events.ID]stringFilterConfig) error {
	for eventID, eventRules := range pm.rules {
		// Reinitialize variables at the start of each iteration
		combinedEqualities := make(map[KernelDataFields]struct{})
		combinedNotEqualities := make(map[KernelDataFields]struct{})
		combinedPrefixEqualities := make(map[KernelDataFields]struct{})
		combinedNotPrefixEqualities := make(map[KernelDataFields]struct{})
		combinedSuffixEqualities := make(map[KernelDataFields]struct{})
		combinedNotSuffixEqualities := make(map[KernelDataFields]struct{})

		for _, rule := range eventRules.Rules {
			ruleID := int(rule.ID)
			strCfgFilter := &stringFilterConfig{}
			equalities, err := rule.Data.DataFilter.Equalities()
			if err != nil {
				continue
			}
			pm.handleExactMatches(ruleID, eventID, strCfgFilter, equalities, combinedEqualities, combinedNotEqualities)
			pm.handlePrefixMatches(ruleID, eventID, strCfgFilter, equalities, combinedPrefixEqualities, combinedNotPrefixEqualities)
			pm.handleSuffixMatches(ruleID, eventID, strCfgFilter, equalities, combinedSuffixEqualities, combinedNotSuffixEqualities)

			// Combine the event bitmap across all policies
			combineEventBitmap(eventsConfig, eventID, strCfgFilter)
		}

		// Exact match equalities
		updateEqualities(fEqs.dataEqualitiesExact, combinedNotEqualities, notEqual, uint(ruleID))
		updateEqualities(fEqs.dataEqualitiesExact, combinedEqualities, equal, uint(ruleID))

		// Prefix match equalities
		updateAffixEqualities(fEqs.dataEqualitiesPrefix, combinedNotPrefixEqualities, notEqual, uint(ruleID))
		updateAffixEqualities(fEqs.dataEqualitiesPrefix, combinedPrefixEqualities, equal, uint(ruleID))

		// Suffix match equalities
		updateAffixEqualities(fEqs.dataEqualitiesSuffix, combinedNotSuffixEqualities, notEqual, uint(ruleID))
		updateAffixEqualities(fEqs.dataEqualitiesSuffix, combinedSuffixEqualities, equal, uint(ruleID))
	}

	return nil
}

func (pm *PolicyManager) handleExactMatches(ruleId int, eventID events.ID, filter *stringFilterConfig, equalities filters.StringFilterEqualities, combinedEqualities, combinedNotEqualities map[KernelDataFields]struct{}) {
	for k := range equalities.ExactEqual {
		combinedEqualities[KernelDataFields{eventID, k}] = struct{}{}

		filter.EnableExact(ruleId)
	}
	for k := range equalities.ExactNotEqual {
		combinedNotEqualities[KernelDataFields{eventID, k}] = struct{}{}

		filter.EnableExact(ruleId)
		filter.EnableExactMatchIfKeyMissing(ruleId)
	}
}

func (pm *PolicyManager) handlePrefixMatches(ruleId int, eventID events.ID, filter *stringFilterConfig, equalities filters.StringFilterEqualities, combinedPrefixEqualities, combinedNotPrefixEqualities map[KernelDataFields]struct{}) {
	for k := range equalities.PrefixEqual {
		combinedPrefixEqualities[KernelDataFields{eventID, k}] = struct{}{}

		filter.EnablePrefix(ruleId)
	}
	for k := range equalities.PrefixNotEqual {
		combinedNotPrefixEqualities[KernelDataFields{eventID, k}] = struct{}{}

		filter.EnablePrefix(ruleId)
		filter.EnablePrefixMatchIfKeyMissing(ruleId)
	}
}

func (pm *PolicyManager) handleSuffixMatches(ruleId int, eventID events.ID, filter *stringFilterConfig, equalities filters.StringFilterEqualities, combinedSuffixEqualities, combinedNotSuffixEqualities map[KernelDataFields]struct{}) {
	for k := range equalities.SuffixEqual {
		reversed := utils.ReverseString(k)
		combinedSuffixEqualities[KernelDataFields{eventID, reversed}] = struct{}{}

		filter.EnableSuffix(ruleId)
	}
	for k := range equalities.SuffixNotEqual {
		reversed := utils.ReverseString(k)
		combinedNotSuffixEqualities[KernelDataFields{eventID, reversed}] = struct{}{}

		filter.EnableSuffix(ruleId)
		filter.EnableSuffixMatchIfKeyMissing(ruleId)
	}
}
