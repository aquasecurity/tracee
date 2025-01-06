package policy

import (
	"strings"

	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils"
)

// equality mirrors the C struct equality (eq_t).
// Check it for more info.
type equality struct {
	equalsInRules  uint64
	keyUsedInRules uint64
}

const (
	// 8 bytes for equalsInRules and 8 bytes for keyUsedInRules
	equalityValueSize = 16
)

// filtersEqualities stores the equalities for each filter in the policies
TODO: filter keys should include event id, just like the kernel data filters
type filtersEqualities struct {
	uidEqualities        map[uint64]equality
	pidEqualities        map[uint64]equality
	mntNSEqualities      map[uint64]equality
	pidNSEqualities      map[uint64]equality
	cgroupIdEqualities   map[uint64]equality
	utsEqualities        map[string]equality
	commEqualities       map[string]equality
	dataEqualitiesPrefix map[KernelDataFields]equality
	dataEqualitiesSuffix map[KernelDataFields]equality
	dataEqualitiesExact  map[KernelDataFields]equality
	binaryEqualities     map[filters.NSBinary]equality
}

// equalityType represents the type of equality.
type equalityType int

const (
	notEqual equalityType = iota
	equal
)

// equalUpdater updates the equality with the given ruleID.
type equalityUpdater func(eq *equality, ruleID uint)

// notEqualUpdate updates the equality as not equal with the given ruleID.
func notEqualUpdate(eq *equality, ruleID uint) {
	// NotEqual == 0, so clear n bitmap bit
	utils.ClearBit(&eq.equalsInRules, ruleID)
	utils.SetBit(&eq.keyUsedInRules, ruleID)
}

// equalUpdate updates the equality as equal with the given ruleID.
func equalUpdate(eq *equality, ruleID uint) {
	// Equal == 1, so set n bitmap bit
	utils.SetBit(&eq.equalsInRules, ruleID)
	utils.SetBit(&eq.keyUsedInRules, ruleID)
}

// updateEqualities updates the equalities map with the given filter equalities
// for the given equality type and rule ID.
func updateEqualities[T comparable](
	equalitiesMap map[T]equality,
	filterEqualities map[T]struct{},
	eqType equalityType,
	ruleID uint,
) {
	var update equalityUpdater

	switch eqType {
	case notEqual:
		update = notEqualUpdate
	case equal:
		update = equalUpdate
	default:
		logger.Errorw("Invalid equality type", "type", eqType)
		return
	}

	for k := range filterEqualities {
		eq, ok := equalitiesMap[k]
		if !ok {
			eq = equality{} // initialize if not exists
		}
		update(&eq, ruleID)   // update the equality
		equalitiesMap[k] = eq // update the map
	}
}

// updateAffixEqualities updates the equalities map with the given filter equalities
// for the specified equality type and rule ID. It handles corner cases where paths
// in the prefix/suffix filter are substrings of existing paths in the equalities map.
// In cases where one prefix/suffix path overlaps with another, their equality bitmaps
// are combined, addressing the corner case. This ensures that a single lookup retrieves
// the longest matching path, with equality bitmaps merged from overlapping rules.
func updateAffixEqualities[T comparable](
	equalitiesMap map[T]equality,
	filterEqualities map[T]struct{},
	eqType equalityType,
	ruleID uint,
) {
	var update equalityUpdater

	switch eqType {
	case notEqual:
		update = notEqualUpdate
	case equal:
		update = equalUpdate
	default:
		logger.Errorw("Invalid equality type", "type", eqType)
		return
	}

	for newK := range filterEqualities {
		newEq, exists := equalitiesMap[newK]
		if !exists {
			newEq = equality{} // initialize if not exists
		}

		newKD, isKernelData := any(newK).(KernelDataFields)

		var longestMatch KernelDataFields
		var longestMatchEq equality

		if isKernelData {
			for existingK, existingEq := range equalitiesMap {
				existingKD, isExistingKernelData := any(existingK).(KernelDataFields)
				// skip if event ID is different
				if !isExistingKernelData || existingKD.ID != newKD.ID {
					continue
				}

				// check if exists a substrings of existing paths in the equalities map
				if strings.HasPrefix(existingKD.String, newKD.String) {
					// Directly update the equality if the new path is a prefix
					update(&existingEq, ruleID)
					equalitiesMap[existingK] = existingEq
				} else if strings.HasPrefix(newKD.String, existingKD.String) {
					// Cache the longest match
					if len(existingKD.String) > len(longestMatch.String) {
						longestMatch = existingKD
						longestMatchEq = existingEq
					}
				}
			}

			// If a match was found, use the longest matching equality
			if len(longestMatch.String) > 0 {
				newEq = longestMatchEq
			}
		}

		update(&newEq, ruleID)      // update the equality
		equalitiesMap[newK] = newEq // update the map
	}
}

// computeFilterEqualities computes the equalities for each filter type in the policies
// updating the provided filtersEqualities struct.
func (pm *PolicyManager) computeFilterEqualities(
	fEqs *filtersEqualities,
	cts *containers.Containers,
) error {
	for eventID, eventRules := range pm.rules {
		for _, rule := range eventRules.Rules {
			ruleID := uint(rule.ID)

			// NOTE: Equal has precedence over NotEqual, so NotEqual must be updated first
			// TODO: we need to compute this per event id and save into fEqs!!!!!!!!!!!!!!!

			// UIDFilters
			uidEqualities := rule.Policy.UIDFilter.Equalities()
			updateEqualities(fEqs.uidEqualities, uidEqualities.NotEqual, notEqual, ruleID)
			updateEqualities(fEqs.uidEqualities, uidEqualities.Equal, equal, ruleID)

			// PIDFilters
			pidEqualities := rule.Policy.PIDFilter.Equalities()
			updateEqualities(fEqs.pidEqualities, pidEqualities.NotEqual, notEqual, ruleID)
			updateEqualities(fEqs.pidEqualities, pidEqualities.Equal, equal, ruleID)

			// MntNSFilters
			mntNSEqualities := rule.Policy.MntNSFilter.Equalities()
			updateEqualities(fEqs.mntNSEqualities, mntNSEqualities.NotEqual, notEqual, ruleID)
			updateEqualities(fEqs.mntNSEqualities, mntNSEqualities.Equal, equal, ruleID)

			// PidNSFilters
			pidNSEqualities := rule.Policy.PidNSFilter.Equalities()
			updateEqualities(fEqs.pidNSEqualities, pidNSEqualities.NotEqual, notEqual, ruleID)
			updateEqualities(fEqs.pidNSEqualities, pidNSEqualities.Equal, equal, ruleID)

			// ContIDFilters
			contIDEqualities := rule.Policy.ContIDFilter.Equalities()
			for contID := range contIDEqualities.ExactNotEqual {
				cgroupIDs, err := cts.FindContainerCgroupID32LSB(contID)
				if err != nil {
					return err
				}

				eq := fEqs.cgroupIdEqualities[uint64(cgroupIDs[0])]
				notEqualUpdate(&eq, ruleID)
				fEqs.cgroupIdEqualities[uint64(cgroupIDs[0])] = eq
			}
			for contID := range contIDEqualities.ExactEqual {
				cgroupIDs, err := cts.FindContainerCgroupID32LSB(contID)
				if err != nil {
					return err
				}

				eq := fEqs.cgroupIdEqualities[uint64(cgroupIDs[0])]
				equalUpdate(&eq, ruleID)
				fEqs.cgroupIdEqualities[uint64(cgroupIDs[0])] = eq
			}

			// UTSFilters
			utsEqualities := rule.Policy.UTSFilter.Equalities()
			updateEqualities(fEqs.utsEqualities, utsEqualities.ExactNotEqual, notEqual, ruleID)
			updateEqualities(fEqs.utsEqualities, utsEqualities.ExactEqual, equal, ruleID)

			// CommFilters
			commEqualities := rule.Policy.CommFilter.Equalities()
			updateEqualities(fEqs.commEqualities, commEqualities.ExactNotEqual, notEqual, ruleID)
			updateEqualities(fEqs.commEqualities, commEqualities.ExactEqual, equal, ruleID)

			// BinaryFilters
			binaryEqualities := rule.Policy.BinaryFilter.Equalities()
			updateEqualities(fEqs.binaryEqualities, binaryEqualities.NotEqual, notEqual, ruleID)
			updateEqualities(fEqs.binaryEqualities, binaryEqualities.Equal, equal, ruleID)
		}
	}

	return nil
}
