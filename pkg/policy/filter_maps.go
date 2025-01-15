package policy

import (
	"strings"

	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/utils"
)

// ruleBitmap mirrors the C struct equality (eq_t)
// it stores information about which rules a filter value applies to.
// equalsInRules:  A bitmap representing whether a value is equal to the filter value.
// keyUsedInRules: A bitmap representing whether a value's key is used in the rule.
type ruleBitmap struct {
	equalsInRules  uint64
	keyUsedInRules uint64
}

const (
	ruleBitmapSize = 16 // 8 bytes for equalsInRules and 8 bytes for keyUsedInRules
)

// filterVersionKey matches C's filter_version_key_t struct
type filterVersionKey struct {
	Version uint16
	Pad     uint16
	EventID uint32
}

// filterMaps contains maps that mirror the corresponding eBPF filter maps.
// Each field corresponds to a specific eBPF map used for filtering events in kernel space.
// The computed values in these maps are used to update their eBPF counterparts.
// The outer map key is a combination of event ID and rules version (filterVersionKey),
// while the inner map key varies by filter type (e.g., uint64, string) and the value is a ruleBitmap.
type filterMaps struct {
	uidFilters        map[filterVersionKey]map[uint64]ruleBitmap
	pidFilters        map[filterVersionKey]map[uint64]ruleBitmap
	mntNSFilters      map[filterVersionKey]map[uint64]ruleBitmap
	pidNSFilters      map[filterVersionKey]map[uint64]ruleBitmap
	cgroupIdFilters   map[filterVersionKey]map[uint64]ruleBitmap
	utsFilters        map[filterVersionKey]map[string]ruleBitmap
	commFilters       map[filterVersionKey]map[string]ruleBitmap
	dataPrefixFilters map[filterVersionKey]map[string]ruleBitmap
	dataSuffixFilters map[filterVersionKey]map[string]ruleBitmap
	dataExactFilters  map[filterVersionKey]map[string]ruleBitmap
	binaryFilters     map[filterVersionKey]map[filters.NSBinary]ruleBitmap
	dataFilterConfigs map[events.ID]dataFilterConfig
}

type equalityType int

const (
	notEqual equalityType = iota
	equal
)

type dataFilterConfig struct {
	string stringFilterConfig
	// other types of filters
}

// stringFilterConfig stores configuration for string matching filters.
type stringFilterConfig struct {
	prefixEnabled           uint64 // Bitmap of rules with prefix matching enabled
	suffixEnabled           uint64 // Bitmap of rules with suffix matching enabled
	exactEnabled            uint64 // Bitmap of rules with exact matching enabled
	prefixMatchIfKeyMissing uint64 // Bitmap of rules with prefix matching enabled if the filter key is missing
	suffixMatchIfKeyMissing uint64 // Bitmap of rules with suffix matching enabled if the filter key is missing
	exactMatchIfKeyMissing  uint64 // Bitmap of rules with exact matching enabled if the filter key is missing
}

// computeFilterMaps processes policy rules and returns two data structures:
//   - A filterMaps instance containing maps that mirror eBPF filter maps in kernel space,
//     used for filtering events based on scope and data filters.
//   - A map of data filter configurations per event ID, containing information about
//     enabled string matching operations for each rule.
//
// The cts parameter provides container information required for resolving container IDs
// to cgroup IDs when processing container filters.
//
// Returns error if filter processing fails for any rule.
func (pm *PolicyManager) computeFilterMaps(
	conts *containers.Containers,
) (maps *filterMaps, err error) {
	maps = &filterMaps{
		uidFilters:        make(map[filterVersionKey]map[uint64]ruleBitmap),
		pidFilters:        make(map[filterVersionKey]map[uint64]ruleBitmap),
		mntNSFilters:      make(map[filterVersionKey]map[uint64]ruleBitmap),
		pidNSFilters:      make(map[filterVersionKey]map[uint64]ruleBitmap),
		cgroupIdFilters:   make(map[filterVersionKey]map[uint64]ruleBitmap),
		utsFilters:        make(map[filterVersionKey]map[string]ruleBitmap),
		commFilters:       make(map[filterVersionKey]map[string]ruleBitmap),
		dataPrefixFilters: make(map[filterVersionKey]map[string]ruleBitmap),
		dataSuffixFilters: make(map[filterVersionKey]map[string]ruleBitmap),
		dataExactFilters:  make(map[filterVersionKey]map[string]ruleBitmap),
		binaryFilters:     make(map[filterVersionKey]map[filters.NSBinary]ruleBitmap),
		dataFilterConfigs: make(map[events.ID]dataFilterConfig),
	}

	for eventID, eventRules := range pm.rules {
		vKey := filterVersionKey{
			Version: eventRules.rulesVersion,
			EventID: uint32(eventID),
		}

		for _, rule := range eventRules.Rules {
			if err = pm.processRuleScopeFilters(maps, vKey, rule, conts); err != nil {
				return nil, errfmt.WrapError(err)
			}

			if err = pm.processRuleDataFilters(maps, vKey, rule, eventID); err != nil {
				return nil, errfmt.WrapError(err)
			}
		}
	}
	return maps, nil
}

func (pm *PolicyManager) processRuleScopeFilters(
	filterMaps *filterMaps,
	vKey filterVersionKey,
	rule *EventRule,
	cts *containers.Containers,
) error {
	if rule.Policy == nil {
		return nil
	}

	// UIDFilters
	uidEqs := rule.Policy.UIDFilter.Equalities()
	updateRuleBitmapsForEvent(filterMaps.uidFilters, vKey, rule.ID, uidEqs.NotEqual, uidEqs.Equal)

	// PIDFilters
	pidEqs := rule.Policy.PIDFilter.Equalities()
	updateRuleBitmapsForEvent(filterMaps.pidFilters, vKey, rule.ID, pidEqs.NotEqual, pidEqs.Equal)

	// MntNSFilters
	mntNSEqs := rule.Policy.MntNSFilter.Equalities()
	updateRuleBitmapsForEvent(filterMaps.mntNSFilters, vKey, rule.ID, mntNSEqs.NotEqual, mntNSEqs.Equal)

	// PidNSFilters
	pidNSEqs := rule.Policy.PidNSFilter.Equalities()
	updateRuleBitmapsForEvent(filterMaps.pidNSFilters, vKey, rule.ID, pidNSEqs.NotEqual, pidNSEqs.Equal)

	// ContIDFilters requires special handling for container lookup
	contIDEqs := rule.Policy.ContIDFilter.Equalities()
	for contID := range contIDEqs.ExactNotEqual {
		cgroupIDs, err := cts.FindContainerCgroupID32LSB(contID)
		if err != nil {
			return err
		}
		updateRuleBitmapForKey(filterMaps.cgroupIdFilters, vKey, uint64(cgroupIDs[0]), rule.ID, notEqual)
	}
	for contID := range contIDEqs.ExactEqual {
		cgroupIDs, err := cts.FindContainerCgroupID32LSB(contID)
		if err != nil {
			return err
		}
		updateRuleBitmapForKey(filterMaps.cgroupIdFilters, vKey, uint64(cgroupIDs[0]), rule.ID, equal)
	}

	// UTSFilters
	utsEqs := rule.Policy.UTSFilter.Equalities()
	updateRuleBitmapsForEvent(filterMaps.utsFilters, vKey, rule.ID, utsEqs.ExactNotEqual, utsEqs.ExactEqual)

	// CommFilters
	commEqs := rule.Policy.CommFilter.Equalities()
	updateRuleBitmapsForEvent(filterMaps.commFilters, vKey, rule.ID, commEqs.ExactNotEqual, commEqs.ExactEqual)

	// BinaryFilters
	binEqs := rule.Policy.BinaryFilter.Equalities()
	updateRuleBitmapsForEvent(filterMaps.binaryFilters, vKey, rule.ID, binEqs.NotEqual, binEqs.Equal)

	return nil
}

// updateRuleBitmapsForEvent updates the rule bitmaps for a given filter version and rule ID.
// It processes both "not equal" and "equal" filter values.
// NotEqual values must be processed first because Equal values have precedence.
// If a value is present in both NotEqual and Equal maps, it will be treated as Equal.
func updateRuleBitmapsForEvent[K comparable](
	eqs map[filterVersionKey]map[K]ruleBitmap,
	vKey filterVersionKey,
	ruleID uint8,
	notEqualsMap map[K]struct{},
	equalsMap map[K]struct{},
) {
	for key := range notEqualsMap {
		updateRuleBitmapForKey(eqs, vKey, key, ruleID, notEqual)
	}
	for key := range equalsMap {
		updateRuleBitmapForKey(eqs, vKey, key, ruleID, equal)
	}
}

// updateRuleBitmapForKey updates the rule bitmap for a specific key, version, rule, and equality type.
func updateRuleBitmapForKey[K comparable](
	eqs map[filterVersionKey]map[K]ruleBitmap,
	vKey filterVersionKey,
	key K,
	ruleID uint8,
	eqType equalityType,
) {
	innerMap := getOrCreateRuleBitmapMap(eqs, vKey)
	eq := innerMap[key]
	updateRuleBitmap(&eq, ruleID, eqType)
	innerMap[key] = eq
}

// getOrCreateRuleBitmapMap ensures that an inner map exists for a given filterVersionKey.
// If it doesn't exist, a new map is created and stored in the outer map.
func getOrCreateRuleBitmapMap[K comparable](
	outerMap map[filterVersionKey]map[K]ruleBitmap,
	vKey filterVersionKey,
) map[K]ruleBitmap {
	if innerMap, exists := outerMap[vKey]; exists {
		return innerMap
	}
	innerMap := make(map[K]ruleBitmap)
	outerMap[vKey] = innerMap
	return innerMap
}

// updateRuleBitmap updates the rule bitmap for a specific rule and equality type.
func updateRuleBitmap(rb *ruleBitmap, ruleID uint8, eqType equalityType) {
	switch eqType {
	case equal:
		utils.SetBit(&rb.equalsInRules, uint(ruleID))
		utils.SetBit(&rb.keyUsedInRules, uint(ruleID))
	case notEqual:
		utils.ClearBit(&rb.equalsInRules, uint(ruleID))
		utils.SetBit(&rb.keyUsedInRules, uint(ruleID))
	}
}

func (pm *PolicyManager) processRuleDataFilters(
	filterMaps *filterMaps,
	vKey filterVersionKey,
	rule *EventRule,
	eventID events.ID,
) error {
	if rule.Data == nil {
		return nil
	}

	equalities, err := rule.Data.DataFilter.Equalities()
	if err != nil {
		return nil // Skip this rule
	}

	// Get or create config
	config, exists := filterMaps.dataFilterConfigs[eventID]
	if !exists {
		config = dataFilterConfig{}
	}

	// Process string filters
	pm.processStringFilterRule(filterMaps, vKey, rule.ID, equalities, &config.string)

	// Store updated config
	filterMaps.dataFilterConfigs[eventID] = config
	return nil
}

// processStringFilterRule processes string equality filters (exact, prefix, and suffix matches)
// for a given rule. It updates the filter maps with rule bitmaps and returns a string filter
// configuration indicating which matching operations are enabled for this rule.
//
// For each type of string match (exact, prefix, suffix):
// - Updates rule bitmaps in the corresponding filter map
// - Handles both equal and not-equal cases
// - For suffix matches, strings are reversed to allow prefix-based matching in eBPF
// - Special handling for overlapping prefix/suffix patterns
func (pm *PolicyManager) processStringFilterRule(
	filterMaps *filterMaps,
	vKey filterVersionKey,
	ruleID uint8,
	equalities filters.StringFilterEqualities,
	strFilterCfg *stringFilterConfig,
) {
	// Handle exact matches
	exactBitmaps := getOrCreateRuleBitmapMap(filterMaps.dataExactFilters, vKey)
	for k := range equalities.ExactNotEqual {
		eb := exactBitmaps[k]
		updateRuleBitmap(&eb, ruleID, notEqual)
		exactBitmaps[k] = eb
		utils.SetBit(&strFilterCfg.exactEnabled, uint(ruleID))
		utils.SetBit(&strFilterCfg.exactMatchIfKeyMissing, uint(ruleID))
	}
	for k := range equalities.ExactEqual {
		eb := exactBitmaps[k]
		updateRuleBitmap(&eb, ruleID, equal)
		exactBitmaps[k] = eb
		utils.SetBit(&strFilterCfg.exactEnabled, uint(ruleID))
	}

	// Handle prefix matches
	prefixBitmaps := getOrCreateRuleBitmapMap(filterMaps.dataPrefixFilters, vKey)
	for k := range equalities.PrefixNotEqual {
		updatePrefixOrSuffixMatch(prefixBitmaps, k, ruleID, notEqual)
		utils.SetBit(&strFilterCfg.prefixEnabled, uint(ruleID))
		utils.SetBit(&strFilterCfg.prefixMatchIfKeyMissing, uint(ruleID))
	}
	for k := range equalities.PrefixEqual {
		updatePrefixOrSuffixMatch(prefixBitmaps, k, ruleID, equal)
		utils.SetBit(&strFilterCfg.prefixEnabled, uint(ruleID))
	}

	// Handle suffix matches
	suffixBitmaps := getOrCreateRuleBitmapMap(filterMaps.dataSuffixFilters, vKey)
	for k := range equalities.SuffixNotEqual {
		reversed := utils.ReverseString(k)
		updatePrefixOrSuffixMatch(suffixBitmaps, reversed, ruleID, notEqual)
		utils.SetBit(&strFilterCfg.suffixEnabled, uint(ruleID))
		utils.SetBit(&strFilterCfg.suffixMatchIfKeyMissing, uint(ruleID))
	}
	for k := range equalities.SuffixEqual {
		reversed := utils.ReverseString(k)
		updatePrefixOrSuffixMatch(suffixBitmaps, reversed, ruleID, equal)
		utils.SetBit(&strFilterCfg.suffixEnabled, uint(ruleID))
	}
}

// updatePrefixOrSuffixMatch handles both prefix and suffix matches by updating the rule bitmap
// for the given pattern and rule ID. It also updates existing entries with matching prefixes.
func updatePrefixOrSuffixMatch(
	ruleBitmaps map[string]ruleBitmap,
	pattern string,
	ruleID uint8,
	eqType equalityType,
) {
	newRuleBitmap := ruleBitmaps[pattern]
	var longestMatch string
	var hasMatch bool

	// Iterate through existing entries to find overlapping prefixes
	for existingPattern, existingRuleBitmap := range ruleBitmaps {
		if strings.HasPrefix(existingPattern, pattern) {
			// Update existing rule bitmap for entries with matching prefix
			updateRuleBitmap(&existingRuleBitmap, ruleID, eqType)
			ruleBitmaps[existingPattern] = existingRuleBitmap
		} else if strings.HasPrefix(pattern, existingPattern) {
			// Find the longest existing prefix match
			if !hasMatch || len(existingPattern) > len(longestMatch) {
				longestMatch = existingPattern
				newRuleBitmap = existingRuleBitmap
				hasMatch = true
			}
		}
	}

	// Update the rule bitmap for the new pattern
	updateRuleBitmap(&newRuleBitmap, ruleID, eqType)
	ruleBitmaps[pattern] = newRuleBitmap
}
