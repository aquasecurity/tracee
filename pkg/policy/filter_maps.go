package policy

import (
	"strings"

	"github.com/aquasecurity/tracee/common/bitwise"
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/stringutil"
	"github.com/aquasecurity/tracee/pkg/datastores/container"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
)

// ruleBitmap mirrors the C struct equality (eq_t)
// it stores information about which rules a filter value applies to.
// equalsInRules:  A bitmap representing whether a value is equal to the filter value.
// keyUsedInRules: A bitmap representing whether a value's key is used in the rule.
type ruleBitmap struct {
	equalsInRules  uint64
	keyUsedInRules uint64
}

// RuleBitmap is the exported version of ruleBitmap for external access
type RuleBitmap struct {
	EqualsInRules  uint64
	KeyUsedInRules uint64
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

// FilterVersionKey is the exported version of filterVersionKey for external use
type FilterVersionKey = filterVersionKey

// FilterMaps contains maps that mirror the corresponding eBPF filter maps.
// Each field corresponds to a specific eBPF map used for filtering events in kernel space.
// The computed values in these maps are used to update their eBPF counterparts.
// The outer map key is a combination of event ID and rules version (filterVersionKey),
// while the inner map key varies by filter type (e.g., uint64, string) and the value is a ruleBitmap.
// filterMaps contains maps that mirror the corresponding eBPF filter maps.
// Each field corresponds to a specific eBPF map used for filtering events in kernel space.
// The computed values in these maps are used to update their eBPF counterparts.
// The outer map key is a combination of event ID and rules version (filterVersionKey),
// while the inner map key varies by filter type (e.g., uint64, string) and the value is a ruleBitmap.
type filterMaps struct {
	uidFilters                 map[filterVersionKey]map[uint64][]ruleBitmap
	pidFilters                 map[filterVersionKey]map[uint64][]ruleBitmap
	mntNSFilters               map[filterVersionKey]map[uint64][]ruleBitmap
	pidNSFilters               map[filterVersionKey]map[uint64][]ruleBitmap
	cgroupIdFilters            map[filterVersionKey]map[uint64][]ruleBitmap
	utsFilters                 map[filterVersionKey]map[string][]ruleBitmap
	commFilters                map[filterVersionKey]map[string][]ruleBitmap
	containerFilters           map[filterVersionKey]map[string][]ruleBitmap
	dataPrefixFilters          map[filterVersionKey]map[string][]ruleBitmap
	dataSuffixFilters          map[filterVersionKey]map[string][]ruleBitmap
	dataExactFilters           map[filterVersionKey]map[string][]ruleBitmap
	binaryFilters              map[filterVersionKey]map[filters.NSBinary][]ruleBitmap
	dataFilterConfigs          map[events.ID]dataFilterConfig
	extendedScopeFilterConfigs map[events.ID]extendedScopeFiltersConfig
}

// ExtendedScopeFiltersConfig is the exported version of extendedScopeFiltersConfig
// ExtendedScopeFiltersConfig is the exported mirror of extendedScopeFiltersConfig and
// is produced by a direct struct conversion, so its fields MUST stay identical (names,
// types, order) to that type.
type ExtendedScopeFiltersConfig struct {
	UIDFilterEnabled         []uint64
	PIDFilterEnabled         []uint64
	MntNsFilterEnabled       []uint64
	PidNsFilterEnabled       []uint64
	UtsNsFilterEnabled       []uint64
	CommFilterEnabled        []uint64
	CgroupIdFilterEnabled    []uint64
	ContFilterEnabled        []uint64
	NewContFilterEnabled     []uint64
	ContStartedFilterEnabled []uint64
	NewPidFilterEnabled      []uint64
	ProcTreeFilterEnabled    []uint64
	BinPathFilterEnabled     []uint64
	FollowFilterEnabled      []uint64

	UIDFilterMatchIfKeyMissing         []uint64
	PIDFilterMatchIfKeyMissing         []uint64
	MntNsFilterMatchIfKeyMissing       []uint64
	PidNsFilterMatchIfKeyMissing       []uint64
	UtsNsFilterMatchIfKeyMissing       []uint64
	CommFilterMatchIfKeyMissing        []uint64
	CgroupIdFilterMatchIfKeyMissing    []uint64
	ContFilterMatchIfKeyMissing        []uint64
	NewContFilterMatchIfKeyMissing     []uint64
	ContStartedFilterMatchIfKeyMissing []uint64
	NewPidFilterMatchIfKeyMissing      []uint64
	ProcTreeFilterMatchIfKeyMissing    []uint64
	BinPathFilterMatchIfKeyMissing     []uint64
}

// FilterMaps is the exported version of filterMaps for external access
type FilterMaps struct {
	UIDFilters                 map[FilterVersionKey]map[uint64][]RuleBitmap
	PIDFilters                 map[FilterVersionKey]map[uint64][]RuleBitmap
	MntNsFilters               map[FilterVersionKey]map[uint64][]RuleBitmap
	PidNsFilters               map[FilterVersionKey]map[uint64][]RuleBitmap
	CgroupFilters              map[FilterVersionKey]map[uint64][]RuleBitmap
	UTSFilters                 map[FilterVersionKey]map[string][]RuleBitmap
	CommFilters                map[FilterVersionKey]map[string][]RuleBitmap
	ContainerFilters           map[FilterVersionKey]map[string][]RuleBitmap
	ExtendedScopeFilterConfigs map[events.ID]ExtendedScopeFiltersConfig
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
	prefixEnabled           []uint64 // Bitmap of rules with prefix matching enabled
	suffixEnabled           []uint64 // Bitmap of rules with suffix matching enabled
	exactEnabled            []uint64 // Bitmap of rules with exact matching enabled
	prefixMatchIfKeyMissing []uint64 // Bitmap of rules with prefix matching enabled if the filter key is missing
	suffixMatchIfKeyMissing []uint64 // Bitmap of rules with suffix matching enabled if the filter key is missing
	exactMatchIfKeyMissing  []uint64 // Bitmap of rules with exact matching enabled if the filter key is missing
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
	conts *container.Manager,
) (maps *filterMaps, err error) {
	maps = &filterMaps{
		uidFilters:                 make(map[filterVersionKey]map[uint64][]ruleBitmap),
		pidFilters:                 make(map[filterVersionKey]map[uint64][]ruleBitmap),
		mntNSFilters:               make(map[filterVersionKey]map[uint64][]ruleBitmap),
		pidNSFilters:               make(map[filterVersionKey]map[uint64][]ruleBitmap),
		cgroupIdFilters:            make(map[filterVersionKey]map[uint64][]ruleBitmap),
		utsFilters:                 make(map[filterVersionKey]map[string][]ruleBitmap),
		commFilters:                make(map[filterVersionKey]map[string][]ruleBitmap),
		dataPrefixFilters:          make(map[filterVersionKey]map[string][]ruleBitmap),
		dataSuffixFilters:          make(map[filterVersionKey]map[string][]ruleBitmap),
		dataExactFilters:           make(map[filterVersionKey]map[string][]ruleBitmap),
		binaryFilters:              make(map[filterVersionKey]map[filters.NSBinary][]ruleBitmap),
		dataFilterConfigs:          make(map[events.ID]dataFilterConfig),
		extendedScopeFilterConfigs: make(map[events.ID]extendedScopeFiltersConfig),
	}

	for eventID, eventRules := range pm.rules {
		vKey := filterVersionKey{
			Version: eventRules.rulesVersion,
			EventID: uint32(eventID),
		}

		for _, rule := range eventRules.Rules {
			// Scope filters are workload-level and valid on every event in a
			// dependency chain, so they apply to all rules (incl. dependency rules).
			if err = pm.processRuleScopeFilters(maps, vKey, rule, conts); err != nil {
				return nil, errfmt.WrapError(err)
			}

			// Phase 2: a detector's per-base data filter IS on this base event's own schema (unlike
			// the shared Data.DataFilter), so seed the kernel data-filter maps from it for EVERY rule,
			// including dependency rules. Only pathname-class filters are kernel-capable; anything else
			// errors out of Equalities() and stays a userland-only filter (matchPolicies backstop).
			if err = pm.processDataFilter(maps, vKey, rule.ID, rule.DetectorDataFilter, eventID); err != nil {
				return nil, errfmt.WrapError(err)
			}

			// Dependency rules are scope-only: their shared RuleData's data filters
			// belong to the dependent/derived event's schema, not this base event, so
			// they must not seed this event's kernel data-filter maps (that would
			// wrongly drop base events and break derivations). See EventRule.IsDependency.
			if rule.IsDependency() {
				continue
			}

			if rule.Data != nil {
				if err = pm.processDataFilter(maps, vKey, rule.ID, rule.Data.DataFilter, eventID); err != nil {
					return nil, errfmt.WrapError(err)
				}
			}
		}

		// Compute extended scope filter configs for overflow rules
		maps.extendedScopeFilterConfigs[eventID] = pm.computeScopeFiltersConfig(eventID)
	}
	return maps, nil
}

// ruleDataScope returns a rule's per-rule scope filter (from the event rule's `filters:` list), or nil.
// This is the workload-level scope carried in rule.Data.ScopeFilter, which processRuleScopeFilters pushes
// to the kernel and matchPolicies backstops in user space.
func ruleDataScope(rule *EventRule) *filters.ScopeFilter {
	if rule.Data == nil {
		return nil
	}
	return rule.Data.ScopeFilter
}

// effectiveScopeComm returns the comm scope filter the kernel should apply for a rule: the policy comm,
// else the detector-declared comm scope, else the rule's per-rule comm. Both the map-value path
// (processRuleScopeFilters) and the enabled-config path (computeScopeFiltersConfig) call this, so the two
// cannot disagree about which comm source is pushed. Callers guarantee rule.Policy != nil.
func effectiveScopeComm(rule *EventRule) *filters.StringFilter {
	if f := rule.Policy.CommFilter; f.Enabled() {
		return f
	}
	if ds := rule.DetectorScopeFilter; ds != nil && ds.Comm().Enabled() {
		return ds.Comm()
	}
	if pr := ruleDataScope(rule); pr != nil && pr.Comm().Enabled() {
		return pr.Comm()
	}
	// Nothing enabled: return the (disabled) policy filter; its Equalities() are empty, so nothing is
	// pushed and no enabled bit is set.
	return rule.Policy.CommFilter
}

func (pm *PolicyManager) processRuleScopeFilters(
	filterMaps *filterMaps,
	vKey filterVersionKey,
	rule *EventRule,
	cts *container.Manager,
) error {
	if rule.Policy == nil {
		return nil
	}

	// The effective kernel scope for each dimension prefers the policy scope, then a detector-declared
	// scope (Phase 2), then the rule's own per-rule scope (rule `filters:`, rule.Data.ScopeFilter). All
	// three are workload-level; pushing the per-rule scope to the kernel drops non-matching instances
	// before submission. matchPolicies still ANDs rule.Data.ScopeFilter in user space as a correctness
	// backstop (and covers dimensions the kernel cannot represent, e.g. tree).
	perRule := ruleDataScope(rule)

	// UIDFilters - uid equalities are uint32; widen to uint64 to match the
	// uniformly-uint64 numeric filter maps (the BPF writer narrows back to u32).
	uidEqs := rule.Policy.UIDFilter.Equalities()
	uidNotEqual, uidEqual := widenUint32Set(uidEqs.NotEqual), widenUint32Set(uidEqs.Equal)
	if !rule.Policy.UIDFilter.Enabled() {
		if ds := rule.DetectorScopeFilter; ds != nil && ds.UID().Enabled() {
			e := ds.UID().Equalities()
			uidNotEqual, uidEqual = widenInt64Set(e.NotEqual), widenInt64Set(e.Equal)
		} else if perRule != nil && perRule.UID().Enabled() {
			e := perRule.UID().Equalities()
			uidNotEqual, uidEqual = widenInt64Set(e.NotEqual), widenInt64Set(e.Equal)
		}
	}
	updateRuleBitmapsForEvent(filterMaps.uidFilters, vKey, rule.ID, uidNotEqual, uidEqual)

	// PIDFilters (host pid).
	pidEqs := rule.Policy.PIDFilter.Equalities()
	pidNotEqual, pidEqual := widenUint32Set(pidEqs.NotEqual), widenUint32Set(pidEqs.Equal)
	if !rule.Policy.PIDFilter.Enabled() {
		if ds := rule.DetectorScopeFilter; ds != nil && ds.PID().Enabled() {
			e := ds.PID().Equalities()
			pidNotEqual, pidEqual = widenInt64Set(e.NotEqual), widenInt64Set(e.Equal)
		} else if perRule != nil && perRule.PID().Enabled() {
			e := perRule.PID().Equalities()
			pidNotEqual, pidEqual = widenInt64Set(e.NotEqual), widenInt64Set(e.Equal)
		}
	}
	updateRuleBitmapsForEvent(filterMaps.pidFilters, vKey, rule.ID, pidNotEqual, pidEqual)

	// MntNSFilters.
	mntNSEqs := rule.Policy.MntNSFilter.Equalities()
	mntNSNotEqual, mntNSEqual := mntNSEqs.NotEqual, mntNSEqs.Equal
	if !rule.Policy.MntNSFilter.Enabled() {
		if ds := rule.DetectorScopeFilter; ds != nil && ds.MntNS().Enabled() {
			e := ds.MntNS().Equalities()
			mntNSNotEqual, mntNSEqual = widenInt64Set(e.NotEqual), widenInt64Set(e.Equal)
		} else if perRule != nil && perRule.MntNS().Enabled() {
			e := perRule.MntNS().Equalities()
			mntNSNotEqual, mntNSEqual = widenInt64Set(e.NotEqual), widenInt64Set(e.Equal)
		}
	}
	updateRuleBitmapsForEvent(filterMaps.mntNSFilters, vKey, rule.ID, mntNSNotEqual, mntNSEqual)

	// PidNSFilters.
	pidNSEqs := rule.Policy.PidNSFilter.Equalities()
	pidNSNotEqual, pidNSEqual := pidNSEqs.NotEqual, pidNSEqs.Equal
	if !rule.Policy.PidNSFilter.Enabled() {
		if ds := rule.DetectorScopeFilter; ds != nil && ds.PidNS().Enabled() {
			e := ds.PidNS().Equalities()
			pidNSNotEqual, pidNSEqual = widenInt64Set(e.NotEqual), widenInt64Set(e.Equal)
		} else if perRule != nil && perRule.PidNS().Enabled() {
			e := perRule.PidNS().Equalities()
			pidNSNotEqual, pidNSEqual = widenInt64Set(e.NotEqual), widenInt64Set(e.Equal)
		}
	}
	updateRuleBitmapsForEvent(filterMaps.pidNSFilters, vKey, rule.ID, pidNSNotEqual, pidNSEqual)

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

	// CommFilters: policy comm, else the detector-declared comm scope, else the rule's per-rule comm.
	commEqs := effectiveScopeComm(rule).Equalities()
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
// widenUint32Set converts a uint32 key set to uint64, so uint32 numeric filter
// equalities (uid, pid) can feed the uniformly-uint64 rule bitmap maps.
func widenUint32Set(in map[uint32]struct{}) map[uint64]struct{} {
	out := make(map[uint64]struct{}, len(in))
	for k := range in {
		out[uint64(k)] = struct{}{}
	}
	return out
}

// widenInt64Set converts an int64 key set to uint64, so int64 numeric scope-filter equalities
// (e.g. a detector's declared uid scope) can feed the uniformly-uint64 rule bitmap maps.
func widenInt64Set(in map[int64]struct{}) map[uint64]struct{} {
	out := make(map[uint64]struct{}, len(in))
	for k := range in {
		out[uint64(k)] = struct{}{}
	}
	return out
}

func updateRuleBitmapsForEvent[K comparable](
	eqs map[filterVersionKey]map[K][]ruleBitmap,
	vKey filterVersionKey,
	ruleID uint,
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
	eqs map[filterVersionKey]map[K][]ruleBitmap,
	vKey filterVersionKey,
	key K,
	ruleID uint,
	eqType equalityType,
) {
	bitmapIndex := ruleID / 64
	bitOffset := ruleID % 64

	innerMap := getOrCreateRuleBitmapMap(eqs, vKey)

	// Ensure that the slice of bitmaps exists for the key and has enough bitmaps
	for len(innerMap[key]) <= int(bitmapIndex) {
		innerMap[key] = append(innerMap[key], ruleBitmap{})
	}

	// Update the proper bitmap
	updateRuleBitmap(&innerMap[key][bitmapIndex], bitOffset, eqType)
}

// getOrCreateRuleBitmapMap ensures that an inner map exists for a given filterVersionKey.
// If it doesn't exist, a new map is created and stored in the outer map.
func getOrCreateRuleBitmapMap[K comparable](
	outerMap map[filterVersionKey]map[K][]ruleBitmap,
	vKey filterVersionKey,
) map[K][]ruleBitmap {
	if innerMap, exists := outerMap[vKey]; exists {
		return innerMap
	}
	innerMap := make(map[K][]ruleBitmap)
	outerMap[vKey] = innerMap
	return innerMap
}

// updateRuleBitmap updates the rule bitmap for a specific rule and equality type.
func updateRuleBitmap(rb *ruleBitmap, bitOffset uint, eqType equalityType) {
	switch eqType {
	case equal:
		bitwise.SetBit(&rb.equalsInRules, bitOffset)
		bitwise.SetBit(&rb.keyUsedInRules, bitOffset)
	case notEqual:
		bitwise.ClearBit(&rb.equalsInRules, bitOffset)
		bitwise.SetBit(&rb.keyUsedInRules, bitOffset)
	}
}

// processDataFilter seeds this event's kernel data-filter maps for a single rule from one data
// filter. Only pathname-class filters are kernel-capable: Equalities() returns the pathname sets and
// errors for any other field, in which case the filter is skipped here and stays a userland-only
// filter. Used for both a rule's own Data.DataFilter and a detector's per-base DetectorDataFilter.
func (pm *PolicyManager) processDataFilter(
	filterMaps *filterMaps,
	vKey filterVersionKey,
	ruleID uint,
	dataFilter *filters.DataFilter,
	eventID events.ID,
) error {
	if dataFilter == nil {
		return nil
	}

	equalities, err := dataFilter.Equalities()
	if err != nil {
		return nil // not kernel-capable (e.g. non-pathname field): stays userland
	}

	// Get or create config
	config, exists := filterMaps.dataFilterConfigs[eventID]
	if !exists {
		config = dataFilterConfig{}
	}

	// Process string filters
	pm.processStringFilterRule(filterMaps, vKey, ruleID, equalities, &config.string)

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
	ruleID uint,
	equalities filters.StringFilterEqualities,
	strFilterCfg *stringFilterConfig,
) {
	// Calculate bitmap index and bit offset
	bitmapIndex := ruleID / 64
	bitOffset := ruleID % 64

	// Handle exact matches
	exactBitmaps := getOrCreateRuleBitmapMap(filterMaps.dataExactFilters, vKey)
	for k := range equalities.ExactNotEqual {
		eb := exactBitmaps[k]
		for len(eb) <= int(bitmapIndex) {
			eb = append(eb, ruleBitmap{})
		}
		updateRuleBitmap(&eb[bitmapIndex], bitOffset, notEqual)
		exactBitmaps[k] = eb

		// Ensure strFilterCfg.exactEnabled has enough bitmaps
		for len(strFilterCfg.exactEnabled) <= int(bitmapIndex) {
			strFilterCfg.exactEnabled = append(strFilterCfg.exactEnabled, 0)
		}
		bitwise.SetBit(&strFilterCfg.exactEnabled[bitmapIndex], bitOffset)

		// Ensure strFilterCfg.exactMatchIfKeyMissing has enough bitmaps
		for len(strFilterCfg.exactMatchIfKeyMissing) <= int(bitmapIndex) {
			strFilterCfg.exactMatchIfKeyMissing = append(strFilterCfg.exactMatchIfKeyMissing, 0)
		}
		bitwise.SetBit(&strFilterCfg.exactMatchIfKeyMissing[bitmapIndex], bitOffset)
	}
	for k := range equalities.ExactEqual {
		eb := exactBitmaps[k]
		for len(eb) <= int(bitmapIndex) {
			eb = append(eb, ruleBitmap{})
		}
		updateRuleBitmap(&eb[bitmapIndex], bitOffset, equal)
		exactBitmaps[k] = eb

		// Ensure strFilterCfg.exactEnabled has enough bitmaps
		for len(strFilterCfg.exactEnabled) <= int(bitmapIndex) {
			strFilterCfg.exactEnabled = append(strFilterCfg.exactEnabled, 0)
		}
		bitwise.SetBit(&strFilterCfg.exactEnabled[bitmapIndex], bitOffset)
	}

	// Handle prefix matches
	prefixBitmaps := getOrCreateRuleBitmapMap(filterMaps.dataPrefixFilters, vKey)
	for k := range equalities.PrefixNotEqual {
		updatePrefixOrSuffixMatch(prefixBitmaps, k, ruleID, notEqual)

		// Ensure strFilterCfg.prefixEnabled has enough bitmaps
		for len(strFilterCfg.prefixEnabled) <= int(bitmapIndex) {
			strFilterCfg.prefixEnabled = append(strFilterCfg.prefixEnabled, 0)
		}
		bitwise.SetBit(&strFilterCfg.prefixEnabled[bitmapIndex], bitOffset)

		// Ensure strFilterCfg.prefixMatchIfKeyMissing has enough bitmaps
		for len(strFilterCfg.prefixMatchIfKeyMissing) <= int(bitmapIndex) {
			strFilterCfg.prefixMatchIfKeyMissing = append(strFilterCfg.prefixMatchIfKeyMissing, 0)
		}
		bitwise.SetBit(&strFilterCfg.prefixMatchIfKeyMissing[bitmapIndex], bitOffset)
	}
	for k := range equalities.PrefixEqual {
		updatePrefixOrSuffixMatch(prefixBitmaps, k, ruleID, equal)

		// Ensure strFilterCfg.prefixEnabled has enough bitmaps
		for len(strFilterCfg.prefixEnabled) <= int(bitmapIndex) {
			strFilterCfg.prefixEnabled = append(strFilterCfg.prefixEnabled, 0)
		}
		bitwise.SetBit(&strFilterCfg.prefixEnabled[bitmapIndex], bitOffset)
	}

	// Handle suffix matches
	suffixBitmaps := getOrCreateRuleBitmapMap(filterMaps.dataSuffixFilters, vKey)
	for k := range equalities.SuffixNotEqual {
		reversed := stringutil.ReverseString(k)
		updatePrefixOrSuffixMatch(suffixBitmaps, reversed, ruleID, notEqual)

		// Ensure strFilterCfg.suffixEnabled has enough bitmaps
		for len(strFilterCfg.suffixEnabled) <= int(bitmapIndex) {
			strFilterCfg.suffixEnabled = append(strFilterCfg.suffixEnabled, 0)
		}
		bitwise.SetBit(&strFilterCfg.suffixEnabled[bitmapIndex], bitOffset)

		// Ensure strFilterCfg.suffixMatchIfKeyMissing has enough bitmaps
		for len(strFilterCfg.suffixMatchIfKeyMissing) <= int(bitmapIndex) {
			strFilterCfg.suffixMatchIfKeyMissing = append(strFilterCfg.suffixMatchIfKeyMissing, 0)
		}
		bitwise.SetBit(&strFilterCfg.suffixMatchIfKeyMissing[bitmapIndex], bitOffset)
	}
	for k := range equalities.SuffixEqual {
		reversed := stringutil.ReverseString(k)
		updatePrefixOrSuffixMatch(suffixBitmaps, reversed, ruleID, equal)

		// Ensure strFilterCfg.suffixEnabled has enough bitmaps
		for len(strFilterCfg.suffixEnabled) <= int(bitmapIndex) {
			strFilterCfg.suffixEnabled = append(strFilterCfg.suffixEnabled, 0)
		}
		bitwise.SetBit(&strFilterCfg.suffixEnabled[bitmapIndex], bitOffset)
	}
}

// updatePrefixOrSuffixMatch handles both prefix and suffix matches by updating the rule bitmap
// for the given pattern and rule ID. It also updates existing entries with matching prefixes.
func updatePrefixOrSuffixMatch(
	ruleBitmaps map[string][]ruleBitmap,
	pattern string,
	ruleID uint,
	eqType equalityType,
) {
	bitmapIndex := ruleID / 64
	bitOffset := ruleID % 64

	// Ensure slice exists and has enough capacity
	for len(ruleBitmaps[pattern]) <= int(bitmapIndex) {
		ruleBitmaps[pattern] = append(ruleBitmaps[pattern], ruleBitmap{})
	}

	newRuleBitmap := ruleBitmaps[pattern][bitmapIndex]
	var longestMatch string
	var hasMatch bool

	// Iterate through existing entries to find overlapping prefixes
	for existingPattern, existingRuleBitmaps := range ruleBitmaps {
		if strings.HasPrefix(existingPattern, pattern) {
			// Update existing rule bitmap for entries with matching prefix
			for len(existingRuleBitmaps) <= int(bitmapIndex) {
				existingRuleBitmaps = append(existingRuleBitmaps, ruleBitmap{})
			}
			updateRuleBitmap(&existingRuleBitmaps[bitmapIndex], bitOffset, eqType)
			ruleBitmaps[existingPattern] = existingRuleBitmaps
		} else if strings.HasPrefix(pattern, existingPattern) {
			// Find the longest existing prefix match
			if !hasMatch || len(existingPattern) > len(longestMatch) {
				longestMatch = existingPattern
				for len(existingRuleBitmaps) <= int(bitmapIndex) {
					existingRuleBitmaps = append(existingRuleBitmaps, ruleBitmap{})
				}
				newRuleBitmap = existingRuleBitmaps[bitmapIndex]
				hasMatch = true
			}
		}
	}

	// Update the rule bitmap for the new pattern
	updateRuleBitmap(&newRuleBitmap, bitOffset, eqType)
	ruleBitmaps[pattern][bitmapIndex] = newRuleBitmap
}
