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
	uidEqualities        map[filterVersionKey]map[uint64]ruleBitmap
	pidEqualities        map[filterVersionKey]map[uint64]ruleBitmap
	mntNSEqualities      map[filterVersionKey]map[uint64]ruleBitmap
	pidNSEqualities      map[filterVersionKey]map[uint64]ruleBitmap
	cgroupIdEqualities   map[filterVersionKey]map[uint64]ruleBitmap
	utsEqualities        map[filterVersionKey]map[string]ruleBitmap
	commEqualities       map[filterVersionKey]map[string]ruleBitmap
	dataEqualitiesPrefix map[filterVersionKey]map[string]ruleBitmap
	dataEqualitiesSuffix map[filterVersionKey]map[string]ruleBitmap
	dataEqualitiesExact  map[filterVersionKey]map[string]ruleBitmap
	binaryEqualities     map[filterVersionKey]map[filters.NSBinary]ruleBitmap
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
	cts *containers.Containers,
) (maps *filterMaps, configs map[events.ID]dataFilterConfig, err error) {
	maps = &filterMaps{
		uidEqualities:        make(map[filterVersionKey]map[uint64]ruleBitmap),
		pidEqualities:        make(map[filterVersionKey]map[uint64]ruleBitmap),
		mntNSEqualities:      make(map[filterVersionKey]map[uint64]ruleBitmap),
		pidNSEqualities:      make(map[filterVersionKey]map[uint64]ruleBitmap),
		cgroupIdEqualities:   make(map[filterVersionKey]map[uint64]ruleBitmap),
		utsEqualities:        make(map[filterVersionKey]map[string]ruleBitmap),
		commEqualities:       make(map[filterVersionKey]map[string]ruleBitmap),
		dataEqualitiesPrefix: make(map[filterVersionKey]map[string]ruleBitmap),
		dataEqualitiesSuffix: make(map[filterVersionKey]map[string]ruleBitmap),
		dataEqualitiesExact:  make(map[filterVersionKey]map[string]ruleBitmap),
		binaryEqualities:     make(map[filterVersionKey]map[filters.NSBinary]ruleBitmap),
	}
	configs = make(map[events.ID]dataFilterConfig)

	for eventID, eventRules := range pm.rules {
		vKey := filterVersionKey{
			Version: eventRules.rulesVersion,
			EventID: uint32(eventID),
		}

		for _, rule := range eventRules.Rules {
			if err = pm.processScopeFilters(maps, vKey, rule, cts); err != nil {
				return nil, nil, errfmt.WrapError(err)
			}

			if err = pm.processDataFilters(maps, vKey, rule, configs, eventID); err != nil {
				return nil, nil, errfmt.WrapError(err)
			}
		}
	}
	return maps, configs, nil
}

func (pm *PolicyManager) processScopeFilters(
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
	updateRuleBitmapsForEvent(filterMaps.uidEqualities, vKey, rule.ID, uidEqs.NotEqual, uidEqs.Equal)

	// PIDFilters
	pidEqs := rule.Policy.PIDFilter.Equalities()
	updateRuleBitmapsForEvent(filterMaps.pidEqualities, vKey, rule.ID, pidEqs.NotEqual, pidEqs.Equal)

	// MntNSFilters
	mntNSEqs := rule.Policy.MntNSFilter.Equalities()
	updateRuleBitmapsForEvent(filterMaps.mntNSEqualities, vKey, rule.ID, mntNSEqs.NotEqual, mntNSEqs.Equal)

	// PidNSFilters
	pidNSEqs := rule.Policy.PidNSFilter.Equalities()
	updateRuleBitmapsForEvent(filterMaps.pidNSEqualities, vKey, rule.ID, pidNSEqs.NotEqual, pidNSEqs.Equal)

	// ContIDFilters requires special handling for container lookup
	contIDEqs := rule.Policy.ContIDFilter.Equalities()
	for contID := range contIDEqs.ExactNotEqual {
		cgroupIDs, err := cts.FindContainerCgroupID32LSB(contID)
		if err != nil {
			return err
		}
		updateRuleBitmapForKey(filterMaps.cgroupIdEqualities, vKey, uint64(cgroupIDs[0]), rule.ID, notEqual)
	}
	for contID := range contIDEqs.ExactEqual {
		cgroupIDs, err := cts.FindContainerCgroupID32LSB(contID)
		if err != nil {
			return err
		}
		updateRuleBitmapForKey(filterMaps.cgroupIdEqualities, vKey, uint64(cgroupIDs[0]), rule.ID, equal)
	}

	// UTSFilters
	utsEqs := rule.Policy.UTSFilter.Equalities()
	updateRuleBitmapsForEvent(filterMaps.utsEqualities, vKey, rule.ID, utsEqs.ExactNotEqual, utsEqs.ExactEqual)

	// CommFilters
	commEqs := rule.Policy.CommFilter.Equalities()
	updateRuleBitmapsForEvent(filterMaps.commEqualities, vKey, rule.ID, commEqs.ExactNotEqual, commEqs.ExactEqual)

	// BinaryFilters
	binEqs := rule.Policy.BinaryFilter.Equalities()
	updateRuleBitmapsForEvent(filterMaps.binaryEqualities, vKey, rule.ID, binEqs.NotEqual, binEqs.Equal)

	return nil
}

func (pm *PolicyManager) processDataFilters(
	filterMaps *filterMaps,
	vKey filterVersionKey,
	rule *EventRule,
	eventDataFilterConfigs map[events.ID]dataFilterConfig,
	eventID events.ID,
) error {
	strCfgFilter := &stringFilterConfig{}
	equalities, err := rule.Data.DataFilter.Equalities()
	if err != nil {
		return nil // Skip this rule
	}

	pm.processStringFilterRule(filterMaps, vKey, rule.ID, equalities, strCfgFilter)

	// Create or update dataFilterConfig
	existing, exists := eventDataFilterConfigs[eventID]
	if !exists {
		eventDataFilterConfigs[eventID] = dataFilterConfig{
			string: *strCfgFilter,
		}
		return nil
	}

	// Merge string filters
	mergeDataFilterConfig(&existing.string, strCfgFilter)
	eventDataFilterConfigs[eventID] = existing
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

func (pm *PolicyManager) processStringFilterRule(
	filterMaps *filterMaps,
	vKey filterVersionKey,
	ruleID uint8,
	equalities filters.StringFilterEqualities,
	filter *stringFilterConfig,
) {
	// Handle exact matches
	handleExactMap := getOrCreateRuleBitmapMap(filterMaps.dataEqualitiesExact, vKey)
	for k := range equalities.ExactNotEqual {
		eq := handleExactMap[k]
		updateRuleBitmap(&eq, ruleID, notEqual)
		handleExactMap[k] = eq
		utils.SetBit(&filter.exactEnabled, uint(ruleID))
		utils.SetBit(&filter.exactMatchIfKeyMissing, uint(ruleID))
	}
	for k := range equalities.ExactEqual {
		eq := handleExactMap[k]
		updateRuleBitmap(&eq, ruleID, equal)
		handleExactMap[k] = eq
		utils.SetBit(&filter.exactEnabled, uint(ruleID))
	}

	// Handle prefix matches
	handlePrefixMap := getOrCreateRuleBitmapMap(filterMaps.dataEqualitiesPrefix, vKey)
	for k := range equalities.PrefixNotEqual {
		updatePrefixOrSuffixMatch(handlePrefixMap, k, ruleID, notEqual)
		utils.SetBit(&filter.prefixEnabled, uint(ruleID))
		utils.SetBit(&filter.prefixMatchIfKeyMissing, uint(ruleID))
	}
	for k := range equalities.PrefixEqual {
		updatePrefixOrSuffixMatch(handlePrefixMap, k, ruleID, equal)
		utils.SetBit(&filter.prefixEnabled, uint(ruleID))
	}

	// Handle suffix matches
	handleSuffixMap := getOrCreateRuleBitmapMap(filterMaps.dataEqualitiesSuffix, vKey)
	for k := range equalities.SuffixNotEqual {
		reversed := utils.ReverseString(k)
		updatePrefixOrSuffixMatch(handleSuffixMap, reversed, ruleID, notEqual)
		utils.SetBit(&filter.suffixEnabled, uint(ruleID))
		utils.SetBit(&filter.suffixMatchIfKeyMissing, uint(ruleID))
	}
	for k := range equalities.SuffixEqual {
		reversed := utils.ReverseString(k)
		updatePrefixOrSuffixMatch(handleSuffixMap, reversed, ruleID, equal)
		utils.SetBit(&filter.suffixEnabled, uint(ruleID))
	}
}

// updatePrefixOrSuffixMatch handles both prefix and suffix matches by updating the rule bitmap
// for the given path and rule ID. It also updates existing entries with matching prefixes.
func updatePrefixOrSuffixMatch(
	innerMap map[string]ruleBitmap,
	path string,
	ruleID uint8,
	eqType equalityType,
) {
	newEq := innerMap[path]
	var longestMatch string
	var hasMatch bool

	// Iterate through existing entries to find overlapping prefixes
	for existingPath, existingEq := range innerMap {
		if strings.HasPrefix(existingPath, path) {
			// Update existing rule bitmap for entries with matching prefix
			updateRuleBitmap(&existingEq, ruleID, eqType)
			innerMap[existingPath] = existingEq
		} else if strings.HasPrefix(path, existingPath) {
			// Find the longest existing prefix match
			if !hasMatch || len(existingPath) > len(longestMatch) {
				longestMatch = existingPath
				newEq = existingEq
				hasMatch = true
			}
		}
	}

	// Update the rule bitmap for the new path
	updateRuleBitmap(&newEq, ruleID, eqType)
	innerMap[path] = newEq
}

func mergeDataFilterConfig(
	existing *stringFilterConfig,
	new *stringFilterConfig,
) {
	existing.prefixEnabled |= new.prefixEnabled
	existing.suffixEnabled |= new.suffixEnabled
	existing.exactEnabled |= new.exactEnabled
	existing.prefixMatchIfKeyMissing |= new.prefixMatchIfKeyMissing
	existing.suffixMatchIfKeyMissing |= new.suffixMatchIfKeyMissing
	existing.exactMatchIfKeyMissing |= new.exactMatchIfKeyMissing
}
