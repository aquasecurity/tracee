package policy

import (
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/utils"
)

// equality mirrors the C struct equality (eq_t)
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

// filtersEqualities contains maps that mirror the corresponding eBPF filter maps.
// Each field corresponds to a specific eBPF map used for filtering events in kernel space.
// The computed values in these maps are used to update their eBPF counterparts.
// The outer map key is a combination of event ID and rules version (filterVersionKey),
// while the inner map key varies by filter type (uint64/string) and value is an equality bitmap.
type filtersEqualities struct {
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

// NewFiltersEqualities creates a new filtersEqualities instance with initialized maps.
// The maps are pre-allocated to store filter values that will be used to update
// the corresponding eBPF maps in kernel space.
func NewFiltersEqualities() *filtersEqualities {
	const initialMapSize = 16 // Reasonable starting size for outer maps

	return &filtersEqualities{
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

// getOrCreateEqualityMap ensures inner map exists for given version key
func getOrCreateEqualityMap[K comparable](
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

// updateEquality updates equality bits for specific rule
func updateEquality(eq *equality, ruleID uint8, eqType equalityType) {
	switch eqType {
	case equal:
		utils.SetBit(&eq.equalsInRules, uint(ruleID))
		utils.SetBit(&eq.keyUsedInRules, uint(ruleID))
	case notEqual:
		utils.ClearBit(&eq.equalsInRules, uint(ruleID))
		utils.SetBit(&eq.keyUsedInRules, uint(ruleID))
	}
}

// updateEqualitiesForKey updates equalities map for specific key and version
func updateEqualitiesForKey[K comparable](
	eqs map[filterVersionKey]map[K]equality,
	vKey filterVersionKey,
	key K,
	ruleID uint8,
	eqType equalityType,
) {
	innerMap := getOrCreateEqualityMap(eqs, vKey)
	eq := innerMap[key]
	updateEquality(&eq, ruleID, eqType)
	innerMap[key] = eq
}

// updateEqualities updates equalities for a given filter
func updateEqualities[K comparable](
	eqs map[filterVersionKey]map[K]equality,
	vKey filterVersionKey,
	ruleID uint8,
	notEqualsMap map[K]struct{},
	equalsMap map[K]struct{},
) {
	// Equal has precedence over NotEqual, so NotEqual must be updated first
	for key := range notEqualsMap {
		updateEqualitiesForKey(eqs, vKey, key, ruleID, notEqual)
	}
	for key := range equalsMap {
		updateEqualitiesForKey(eqs, vKey, key, ruleID, equal)
	}
}

// computeFilterEqualities computes the equalities for each filter type in the policies
func (pm *PolicyManager) computeFilterEqualities(
	fEqs *filtersEqualities,
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
			updateEqualities(fEqs.uidEqualities, vKey, rule.ID, uidEqs.NotEqual, uidEqs.Equal)

			// PIDFilters
			pidEqs := rule.Policy.PIDFilter.Equalities()
			updateEqualities(fEqs.pidEqualities, vKey, rule.ID, pidEqs.NotEqual, pidEqs.Equal)

			// MntNSFilters
			mntNSEqs := rule.Policy.MntNSFilter.Equalities()
			updateEqualities(fEqs.mntNSEqualities, vKey, rule.ID, mntNSEqs.NotEqual, mntNSEqs.Equal)

			// PidNSFilters
			pidNSEqs := rule.Policy.PidNSFilter.Equalities()
			updateEqualities(fEqs.pidNSEqualities, vKey, rule.ID, pidNSEqs.NotEqual, pidNSEqs.Equal)

			// ContIDFilters requires special handling for container lookup
			contIDEqs := rule.Policy.ContIDFilter.Equalities()
			for contID := range contIDEqs.ExactNotEqual {
				cgroupIDs, err := cts.FindContainerCgroupID32LSB(contID)
				if err != nil {
					return err
				}
				updateEqualitiesForKey(fEqs.cgroupIdEqualities, vKey, uint64(cgroupIDs[0]), rule.ID, notEqual)
			}
			for contID := range contIDEqs.ExactEqual {
				cgroupIDs, err := cts.FindContainerCgroupID32LSB(contID)
				if err != nil {
					return err
				}
				updateEqualitiesForKey(fEqs.cgroupIdEqualities, vKey, uint64(cgroupIDs[0]), rule.ID, equal)
			}

			// UTSFilters
			utsEqs := rule.Policy.UTSFilter.Equalities()
			updateEqualities(fEqs.utsEqualities, vKey, rule.ID, utsEqs.ExactNotEqual, utsEqs.ExactEqual)

			// CommFilters
			commEqs := rule.Policy.CommFilter.Equalities()
			updateEqualities(fEqs.commEqualities, vKey, rule.ID, commEqs.ExactNotEqual, commEqs.ExactEqual)

			// BinaryFilters
			binEqs := rule.Policy.BinaryFilter.Equalities()
			updateEqualities(fEqs.binaryEqualities, vKey, rule.ID, binEqs.NotEqual, binEqs.Equal)
		}
	}

	return nil
}
