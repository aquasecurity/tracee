package policy

import (
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/utils"
)

// equality mirrors the C struct equality (eq_t)
// it stores information about which rules a filter value applies to.
// equalsInRules:  A bitmap representing whether a value is equal to the filter value.
// keyUsedInRules: A bitmap representing whether a value's key is used in the rule.
// TODO: for clarity, consider renaming to ruleBitmap (in bpf code as well)
type equality struct {
	equalsInRules  uint64
	keyUsedInRules uint64
}

const (
	equalityValueSize = 16 // 8 bytes for equalsInRules and 8 bytes for keyUsedInRules
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
// while the inner map key varies by filter type (e.g., uint64, string) and the value is an equality bitmap.
type filterMaps struct {
	uidEqualities        map[filterVersionKey]map[uint64]equality
	pidEqualities        map[filterVersionKey]map[uint64]equality
	mntNSEqualities      map[filterVersionKey]map[uint64]equality
	pidNSEqualities      map[filterVersionKey]map[uint64]equality
	cgroupIdEqualities   map[filterVersionKey]map[uint64]equality
	utsEqualities        map[filterVersionKey]map[string]equality
	commEqualities       map[filterVersionKey]map[string]equality
	dataEqualitiesPrefix map[filterVersionKey]map[string]equality
	dataEqualitiesSuffix map[filterVersionKey]map[string]equality
	dataEqualitiesExact  map[filterVersionKey]map[string]equality
	binaryEqualities     map[filterVersionKey]map[filters.NSBinary]equality
}

// newFilterMaps creates a new filterMaps instance with initialized maps.
// The maps are pre-allocated to store filter values that will be used to update
// the corresponding eBPF maps in kernel space.
func newFilterMaps() *filterMaps {
	const initialMapSize = 16 // Reasonable starting size for outer maps

	return &filterMaps{
		uidEqualities:        make(map[filterVersionKey]map[uint64]equality, initialMapSize),
		pidEqualities:        make(map[filterVersionKey]map[uint64]equality, initialMapSize),
		mntNSEqualities:      make(map[filterVersionKey]map[uint64]equality, initialMapSize),
		pidNSEqualities:      make(map[filterVersionKey]map[uint64]equality, initialMapSize),
		cgroupIdEqualities:   make(map[filterVersionKey]map[uint64]equality, initialMapSize),
		utsEqualities:        make(map[filterVersionKey]map[string]equality, initialMapSize),
		commEqualities:       make(map[filterVersionKey]map[string]equality, initialMapSize),
		dataEqualitiesPrefix: make(map[filterVersionKey]map[string]equality, initialMapSize),
		dataEqualitiesSuffix: make(map[filterVersionKey]map[string]equality, initialMapSize),
		dataEqualitiesExact:  make(map[filterVersionKey]map[string]equality, initialMapSize),
		binaryEqualities:     make(map[filterVersionKey]map[filters.NSBinary]equality, initialMapSize),
	}
}

type equalityType int

const (
	notEqual equalityType = iota
	equal
)

// computeScopeFilters processes policy rules and updates filter maps for scope-based filtering.
// The filterMaps parameter contains the maps that mirror eBPF filter maps in kernel space.
// The cts parameter provides container information for resolving container IDs to cgroup IDs.
func (pm *PolicyManager) computeScopeFilterMaps(
	filterMaps *filterMaps,
	cts *containers.Containers,
) error {
	for eventID, eventRules := range pm.rules {
		vKey := filterVersionKey{
			Version: eventRules.rulesVersion,
			EventID: uint32(eventID),
		}

		for _, rule := range eventRules.Rules {
			if rule.Policy == nil {
				continue
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
		}
	}

	return nil
}

// updateRuleBitmapsForEvent updates the rule bitmaps for a given filter version and rule ID.
// It processes both "not equal" and "equal" filter values.
// NotEqual values must be processed first because Equal values have precedence.
// If a value is present in both NotEqual and Equal maps, it will be treated as Equal.
func updateRuleBitmapsForEvent[K comparable](
	eqs map[filterVersionKey]map[K]equality,
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
	eqs map[filterVersionKey]map[K]equality,
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
	outerMap map[filterVersionKey]map[K]equality,
	vKey filterVersionKey,
) map[K]equality {
	if innerMap, exists := outerMap[vKey]; exists {
		return innerMap
	}
	innerMap := make(map[K]equality)
	outerMap[vKey] = innerMap
	return innerMap
}

// updateRuleBitmap updates the rule bitmap for a specific rule and equality type.
func updateRuleBitmap(eq *equality, ruleID uint8, eqType equalityType) {
	switch eqType {
	case equal:
		utils.SetBit(&eq.equalsInRules, uint(ruleID))
		utils.SetBit(&eq.keyUsedInRules, uint(ruleID))
	case notEqual:
		utils.ClearBit(&eq.equalsInRules, uint(ruleID))
		utils.SetBit(&eq.keyUsedInRules, uint(ruleID))
	}
}
