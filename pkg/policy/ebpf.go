package policy

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/utils/proc"
)

const (
	// Filter version map names
	UIDFilterMapVersion        = "uid_filter_version"
	PIDFilterMapVersion        = "pid_filter_version"
	MntNSFilterMapVersion      = "mnt_ns_filter_version"
	PidNSFilterMapVersion      = "pid_ns_filter_version"
	UTSFilterMapVersion        = "uts_ns_filter_version"
	CommFilterMapVersion       = "comm_filter_version"
	DataFilterPrefixMapVersion = "data_filter_prefix_version"
	DataFilterSuffixMapVersion = "data_filter_suffix_version"
	DataFilterExactMapVersion  = "data_filter_exact_version"
	CgroupIdFilterVersion      = "cgroup_id_filter_version"
	BinaryFilterMapVersion     = "binary_filter_version"

	// Filter map names
	UIDFilterMap        = "uid_filter"
	PIDFilterMap        = "pid_filter"
	MntNSFilterMap      = "mnt_ns_filter"
	PidNSFilterMap      = "pid_ns_filter"
	UTSFilterMap        = "uts_ns_filter"
	CommFilterMap       = "comm_filter"
	CgroupIdFilterMap   = "cgroup_id_filter"
	BinaryFilterMap     = "binary_filter"
	DataFilterPrefixMap = "data_filter_prefix"
	DataFilterSuffixMap = "data_filter_suffix"
	DataFilterExactMap  = "data_filter_exact"

	// Special maps
	ProcInfoMap     = "proc_info_map"
	EventsConfigMap = "events_config_map"

	// Sizes and limits
	maxBpfStrFilterSize     = 256 // should be at least as big as the bpf map value size
	maxBpfBinPathSize       = 256 // maximum binary path size supported by BPF (MAX_BIN_PATH_SIZE)
	bpfBinFilterSize        = 264 // the key size of the BPF binary filter map entry
	maxBpfDataFilterStrSize = 256 // maximum str size supported by Data filter in BPF (MAX_DATA_FILTER_STR_SIZE)
	bpfDataFilterStrSize    = 260 // path size + 4 bytes prefix len
)

// updateBPF updates the BPF maps with the policies filters.
// createNewMaps indicates whether new maps should be created or not.
func (pm *PolicyManager) updateBPF(
	bpfModule *bpf.Module,
	cts *containers.Containers,
	eventsFields map[events.ID][]bufferdecoder.ArgType,
) error {
	fMaps, err := pm.computeFilterMaps(cts)
	if err != nil {
		return errfmt.WrapError(err)
	}
	pm.fMaps = fMaps

	if err := pm.updateEventsConfigMap(bpfModule, eventsFields, fMaps.dataFilterConfigs); err != nil {
		return errfmt.WrapError(err)
	}

	// Update UInt RuleBitmaps filter maps
	if err := pm.updateUIntFilterBPF(bpfModule, fMaps.uidFilters, UIDFilterMap, UIDFilterMapVersion); err != nil {
		return errfmt.WrapError(err)
	}
	if err := pm.updateUIntFilterBPF(bpfModule, fMaps.pidFilters, PIDFilterMap, PIDFilterMapVersion); err != nil {
		return errfmt.WrapError(err)
	}
	if err := pm.updateUIntFilterBPF(bpfModule, fMaps.mntNSFilters, MntNSFilterMap, MntNSFilterMapVersion); err != nil {
		return errfmt.WrapError(err)
	}
	if err := pm.updateUIntFilterBPF(bpfModule, fMaps.pidNSFilters, PidNSFilterMap, PidNSFilterMapVersion); err != nil {
		return errfmt.WrapError(err)
	}
	if err := pm.updateUIntFilterBPF(bpfModule, fMaps.cgroupIdFilters, CgroupIdFilterMap, CgroupIdFilterVersion); err != nil {
		return errfmt.WrapError(err)
	}

	// Update String RuleBitmaps filter maps
	if err := pm.updateStringFilterBPF(bpfModule, fMaps.utsFilters, UTSFilterMap, UTSFilterMapVersion); err != nil {
		return errfmt.WrapError(err)
	}
	if err := pm.updateStringFilterBPF(bpfModule, fMaps.commFilters, CommFilterMap, CommFilterMapVersion); err != nil {
		return errfmt.WrapError(err)
	}

	// Update Binary RuleBitmaps filter map
	if err := pm.updateBinaryFilterBPF(bpfModule, fMaps.binaryFilters, BinaryFilterMap, BinaryFilterMapVersion); err != nil {
		return errfmt.WrapError(err)
	}
	// Update ProcInfo map (required for binary filters)
	if err := populateProcInfoMap(bpfModule, fMaps.binaryFilters); err != nil {
		return errfmt.WrapError(err)
	}

	// Update Data Filters
	if err := pm.updateStringDataFilterLPMBPF(bpfModule, fMaps.dataPrefixFilters, DataFilterPrefixMap, DataFilterPrefixMapVersion); err != nil {
		return errfmt.WrapError(err)
	}
	if err := pm.updateStringDataFilterLPMBPF(bpfModule, fMaps.dataSuffixFilters, DataFilterSuffixMap, DataFilterSuffixMapVersion); err != nil {
		return errfmt.WrapError(err)
	}
	if err := pm.updateStringDataFilterBPF(bpfModule, fMaps.dataExactFilters, DataFilterExactMap, DataFilterExactMapVersion); err != nil {
		return errfmt.WrapError(err)
	}

	return nil
}

type eventConfig struct {
	rulesVersion   uint16
	padding        [6]uint8 // free for further use
	submitForRules uint64
	fieldTypes     uint64
	scopeFilters   scopeFiltersConfig
	dataFilter     dataFilterConfig
}

// updateEventsConfigMap updates the events config map with the given events fields and filter config.
func (pm *PolicyManager) updateEventsConfigMap(
	bpfModule *bpf.Module,
	eventsFields map[events.ID][]bufferdecoder.ArgType,
	dataFilterConfigs map[events.ID]dataFilterConfig,
) error {
	eventsConfigMap, err := bpfModule.GetMap(EventsConfigMap)
	if err != nil {
		return errfmt.WrapError(err)
	}

	for id, ecfg := range pm.rules {
		filterConfig, exist := dataFilterConfigs[id]
		if !exist {
			filterConfig = dataFilterConfig{}
		}

		// encoded event's field types
		var fieldTypes uint64
		fields := eventsFields[id]
		for n, fieldType := range fields {
			fieldTypes = fieldTypes | (uint64(fieldType) << (8 * n))
		}

		// Create submit bitmap based on rules count - n least significant bits set to 1
		submitForRules := uint64(0)
		if ecfg.rulesCount > 0 {
			submitForRules = (uint64(1) << ecfg.rulesCount) - 1
		}

		eventConfig := eventConfig{
			rulesVersion:   ecfg.rulesVersion,
			submitForRules: submitForRules,
			fieldTypes:     fieldTypes,
			scopeFilters:   pm.computeScopeFiltersConfig(id),
			dataFilter:     filterConfig,
		}

		err := eventsConfigMap.Update(unsafe.Pointer(&id), unsafe.Pointer(&eventConfig))
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}

// ScopeFiltersConfig mirrors the C struct scope_filters_config (scope_filters_config_t).
// Order of fields is important, as it is used as a value for the EventsConfigMap BPF map.
type scopeFiltersConfig struct {
	UIDFilterEnabled      uint64
	PIDFilterEnabled      uint64
	MntNsFilterEnabled    uint64
	PidNsFilterEnabled    uint64
	UtsNsFilterEnabled    uint64
	CommFilterEnabled     uint64
	CgroupIdFilterEnabled uint64
	ContFilterEnabled     uint64
	NewContFilterEnabled  uint64
	NewPidFilterEnabled   uint64
	BinPathFilterEnabled  uint64

	UIDFilterMatchIfKeyMissing      uint64
	PIDFilterMatchIfKeyMissing      uint64
	MntNsFilterMatchIfKeyMissing    uint64
	PidNsFilterMatchIfKeyMissing    uint64
	UtsNsFilterMatchIfKeyMissing    uint64
	CommFilterMatchIfKeyMissing     uint64
	CgroupIdFilterMatchIfKeyMissing uint64
	ContFilterMatchIfKeyMissing     uint64
	NewContFilterMatchIfKeyMissing  uint64
	NewPidFilterMatchIfKeyMissing   uint64
	BinPathFilterMatchIfKeyMissing  uint64
}

// computeScopeFiltersConfig computes the scope filters config for a specific event ID
func (pm *PolicyManager) computeScopeFiltersConfig(eventID events.ID) scopeFiltersConfig {
	cfg := scopeFiltersConfig{}

	eventRules, ok := pm.rules[eventID]
	if !ok {
		return cfg
	}

	// TODO: we need to consider both policies scope filters and events scope filters.
	// This can be done by accessing rule.Data.ScopeFilters
	// We first need to update this in filters computation.

	// Loop through rules for this event
	for _, rule := range eventRules.Rules {
		if rule.Policy == nil {
			continue // Skip dependency rules that have no policy
		}

		offset := rule.ID // Use rule ID (0-63) for bitmap position

		// Enabled filters bitmap
		if rule.Policy.UIDFilter.Enabled() {
			cfg.UIDFilterEnabled |= 1 << offset
		}
		if rule.Policy.PIDFilter.Enabled() {
			cfg.PIDFilterEnabled |= 1 << offset
		}
		if rule.Policy.MntNSFilter.Enabled() {
			cfg.MntNsFilterEnabled |= 1 << offset
		}
		if rule.Policy.PidNSFilter.Enabled() {
			cfg.PidNsFilterEnabled |= 1 << offset
		}
		if rule.Policy.UTSFilter.Enabled() {
			cfg.UtsNsFilterEnabled |= 1 << offset
		}
		if rule.Policy.CommFilter.Enabled() {
			cfg.CommFilterEnabled |= 1 << offset
		}
		if rule.Policy.ContIDFilter.Enabled() {
			cfg.CgroupIdFilterEnabled |= 1 << offset
		}
		if rule.Policy.ContFilter.Enabled() {
			cfg.ContFilterEnabled |= 1 << offset
		}
		if rule.Policy.NewContFilter.Enabled() {
			cfg.NewContFilterEnabled |= 1 << offset
		}
		if rule.Policy.NewPidFilter.Enabled() {
			cfg.NewPidFilterEnabled |= 1 << offset
		}
		if rule.Policy.BinaryFilter.Enabled() {
			cfg.BinPathFilterEnabled |= 1 << offset
		}

		// MatchIfKeyMissing filters bitmap
		if rule.Policy.UIDFilter.MatchIfKeyMissing() {
			cfg.UIDFilterMatchIfKeyMissing |= 1 << offset
		}
		if rule.Policy.PIDFilter.MatchIfKeyMissing() {
			cfg.PIDFilterMatchIfKeyMissing |= 1 << offset
		}
		if rule.Policy.MntNSFilter.MatchIfKeyMissing() {
			cfg.MntNsFilterMatchIfKeyMissing |= 1 << offset
		}
		if rule.Policy.PidNSFilter.MatchIfKeyMissing() {
			cfg.PidNsFilterMatchIfKeyMissing |= 1 << offset
		}
		if rule.Policy.UTSFilter.MatchIfKeyMissing() {
			cfg.UtsNsFilterMatchIfKeyMissing |= 1 << offset
		}
		if rule.Policy.CommFilter.MatchIfKeyMissing() {
			cfg.CommFilterMatchIfKeyMissing |= 1 << offset
		}
		if rule.Policy.ContIDFilter.MatchIfKeyMissing() {
			cfg.CgroupIdFilterMatchIfKeyMissing |= 1 << offset
		}
		if rule.Policy.ContFilter.MatchIfKeyMissing() {
			cfg.ContFilterMatchIfKeyMissing |= 1 << offset
		}
		if rule.Policy.NewContFilter.MatchIfKeyMissing() {
			cfg.NewContFilterMatchIfKeyMissing |= 1 << offset
		}
		if rule.Policy.NewPidFilter.MatchIfKeyMissing() {
			cfg.NewPidFilterMatchIfKeyMissing |= 1 << offset
		}
		if rule.Policy.BinaryFilter.MatchIfKeyMissing() {
			cfg.BinPathFilterMatchIfKeyMissing |= 1 << offset
		}
	}

	return cfg
}

// updateUIntFilterBPF updates the BPF maps for the given uint RuleBitmaps.
func (pm *PolicyManager) updateUIntFilterBPF(
	bpfModule *bpf.Module,
	ruleBitmaps map[filterVersionKey]map[uint64]ruleBitmap,
	innerMapName string,
	outerMapName string,
) error {
	for fvKey, rBitmaps := range ruleBitmaps {
		// Skip if no rules exist for this version/event
		if len(rBitmaps) == 0 {
			continue
		}

		// Get or create inner map
		bpfMap, _, err := pm.createAndUpdateInnerMap(bpfModule, innerMapName, outerMapName, fvKey)
		if err != nil {
			return fmt.Errorf("creating/getting inner map for version %d event %d: %w",
				fvKey.Version, fvKey.EventID, err)
		}

		for k, v := range rBitmaps {
			// Inner map type: u32 (key) -> eq_t (value)
			// where eq_t is { uint64_t equals_in_rules, uint64_t key_used_in_rules }
			u32Key := uint32(k)
			keyPointer := unsafe.Pointer(&u32Key)

			eqVal := make([]byte, ruleBitmapSize)
			valuePointer := unsafe.Pointer(&eqVal[0])

			binary.LittleEndian.PutUint64(eqVal[0:8], v.equalsInRules)
			binary.LittleEndian.PutUint64(eqVal[8:16], v.keyUsedInRules)

			if err := bpfMap.Update(keyPointer, valuePointer); err != nil {
				return errfmt.WrapError(err)
			}
		}
	}

	return nil
}

// updateStringFilterBPF updates the BPF maps for the given string RuleBitmaps.
func (pm *PolicyManager) updateStringFilterBPF(
	bpfModule *bpf.Module,
	ruleBitmaps map[filterVersionKey]map[string]ruleBitmap,
	innerMapName string,
	outerMapName string,
) error {
	for fvKey, rBitmaps := range ruleBitmaps {
		// Skip if no rules exist for this version/event
		if len(rBitmaps) == 0 {
			continue
		}

		// Get or create inner map
		bpfMap, _, err := pm.createAndUpdateInnerMap(bpfModule, innerMapName, outerMapName, fvKey)
		if err != nil {
			return fmt.Errorf("creating/getting inner map for version %d event %d: %w",
				fvKey.Version, fvKey.EventID, err)
		}

		for k, v := range rBitmaps {
			// Inner map type: string_filter_t (key) -> eq_t (value)
			// where string_filter_t is a fixed size char array
			// and eq_t is { uint64_t equals_in_rules, uint64_t key_used_in_rules }
			byteStr := make([]byte, maxBpfStrFilterSize)
			copy(byteStr, k)
			keyPointer := unsafe.Pointer(&byteStr[0])

			eqVal := make([]byte, ruleBitmapSize)
			valuePointer := unsafe.Pointer(&eqVal[0])

			binary.LittleEndian.PutUint64(eqVal[0:8], v.equalsInRules)
			binary.LittleEndian.PutUint64(eqVal[8:16], v.keyUsedInRules)

			if err := bpfMap.Update(keyPointer, valuePointer); err != nil {
				return errfmt.WrapError(err)
			}
		}
	}

	return nil
}

// updateBinaryFilterBPF updates the BPF maps for the given binary RuleBitmaps.
func (pm *PolicyManager) updateBinaryFilterBPF(
	bpfModule *bpf.Module,
	ruleBitmaps map[filterVersionKey]map[filters.NSBinary]ruleBitmap,
	innerMapName string,
	outerMapName string,
) error {
	for fvKey, rBitmaps := range ruleBitmaps {
		// Skip if no rules exist for this version/event
		if len(rBitmaps) == 0 {
			continue
		}

		// Get or create inner map
		bpfMap, _, err := pm.createAndUpdateInnerMap(bpfModule, innerMapName, outerMapName, fvKey)
		if err != nil {
			return fmt.Errorf("creating/getting inner map for version %d event %d: %w",
				fvKey.Version, fvKey.EventID, err)
		}

		for k, v := range rBitmaps {
			if len(k.Path) > maxBpfBinPathSize {
				return filters.InvalidValue(k.Path)
			}

			// Inner map type: binary_t (key) -> eq_t (value)
			// where binary_t is { uint32_t mount_ns, char path[MAX_BIN_PATH_SIZE] }
			// and eq_t is { uint64_t equals_in_rules, uint64_t key_used_in_rules }
			binBytes := make([]byte, bpfBinFilterSize)
			if k.MntNS == 0 {
				// if no mount namespace given, bpf map key is only the path
				copy(binBytes, k.Path)
			} else {
				// otherwise, key is composed of the mount namespace and the path
				binary.LittleEndian.PutUint32(binBytes, k.MntNS)
				copy(binBytes[4:], k.Path)
			}
			keyPointer := unsafe.Pointer(&binBytes[0])

			eqVal := make([]byte, ruleBitmapSize)
			valuePointer := unsafe.Pointer(&eqVal[0])

			binary.LittleEndian.PutUint64(eqVal[0:8], v.equalsInRules)
			binary.LittleEndian.PutUint64(eqVal[8:16], v.keyUsedInRules)

			if err := bpfMap.Update(keyPointer, valuePointer); err != nil {
				return errfmt.WrapError(err)
			}
		}
	}

	return nil
}

// updateStringDataFilterLPMBPF updates the BPF maps for the given kernel data LPM RuleBitmaps.
func (pm *PolicyManager) updateStringDataFilterLPMBPF(
	bpfModule *bpf.Module,
	ruleBitmaps map[filterVersionKey]map[string]ruleBitmap,
	innerMapName string,
	outerMapName string,
) error {
	for fvKey, rBitmaps := range ruleBitmaps {
		// Skip if no rules exist for this version/event
		if len(rBitmaps) == 0 {
			continue
		}

		// Get or create inner map
		bpfMap, _, err := pm.createAndUpdateInnerMap(bpfModule, innerMapName, outerMapName, fvKey)
		if err != nil {
			return fmt.Errorf("creating/getting inner map for version %d event %d: %w",
				fvKey.Version, fvKey.EventID, err)
		}

		for k, v := range rBitmaps {
			// Ensure the string length is within the maximum allowed limit,
			// excluding the NULL terminator.
			if len(k) > maxBpfDataFilterStrSize-1 {
				return filters.InvalidValueMax(k, maxBpfDataFilterStrSize-1)
			}

			// Inner map type: data_filter_lpm_key_t (key) -> eq_t (value)
			// where data_filter_lpm_key_t is { uint32_t prefixlen, char str[MAX_DATA_STR_SIZE] }
			// and eq_t is { uint64_t equals_in_rules, uint64_t key_used_in_rules }
			binBytes := make([]byte, bpfDataFilterStrSize)

			// key is composed of: prefixlen and a string
			// multiply by 8 to convert prefix length from bytes to bits for LPM Trie
			prefixlen := len(k) * 8
			binary.LittleEndian.PutUint32(binBytes, uint32(prefixlen)) // prefixlen
			copy(binBytes[4:], k)                                      // string

			keyPointer := unsafe.Pointer(&binBytes[0])

			eqVal := make([]byte, ruleBitmapSize)
			valuePointer := unsafe.Pointer(&eqVal[0])

			binary.LittleEndian.PutUint64(eqVal[0:8], v.equalsInRules)
			binary.LittleEndian.PutUint64(eqVal[8:16], v.keyUsedInRules)

			if err := bpfMap.Update(keyPointer, valuePointer); err != nil {
				return errfmt.WrapError(err)
			}
		}
	}

	return nil
}

// updateStringDataFilterBPF updates the BPF maps for the given kernel data RuleBitmaps.
func (pm *PolicyManager) updateStringDataFilterBPF(
	bpfModule *bpf.Module,
	ruleBitmaps map[filterVersionKey]map[string]ruleBitmap,
	innerMapName string,
	outerMapName string,
) error {
	for fvKey, rBitmaps := range ruleBitmaps {
		// Skip if no rules exist for this version/event
		if len(rBitmaps) == 0 {
			continue
		}

		// Get or create inner map
		bpfMap, _, err := pm.createAndUpdateInnerMap(bpfModule, innerMapName, outerMapName, fvKey)
		if err != nil {
			return fmt.Errorf("creating/getting inner map for version %d event %d: %w",
				fvKey.Version, fvKey.EventID, err)
		}

		for k, v := range rBitmaps {
			// Ensure the string length is within the maximum allowed limit,
			// excluding the NULL terminator
			if len(k) > maxBpfDataFilterStrSize-1 {
				return filters.InvalidValueMax(k, maxBpfDataFilterStrSize-1)
			}

			// Inner map type: data_filter_key_t (key) -> eq_t (value)
			// where data_filter_key_t is a fixed size char array
			// and eq_t is { uint64_t equals_in_rules, uint64_t key_used_in_rules }
			binBytes := make([]byte, maxBpfDataFilterStrSize)
			copy(binBytes, k) // string
			keyPointer := unsafe.Pointer(&binBytes[0])

			eqVal := make([]byte, ruleBitmapSize)
			valuePointer := unsafe.Pointer(&eqVal[0])

			binary.LittleEndian.PutUint64(eqVal[0:8], v.equalsInRules)
			binary.LittleEndian.PutUint64(eqVal[8:16], v.keyUsedInRules)

			if err := bpfMap.Update(keyPointer, valuePointer); err != nil {
				return errfmt.WrapError(err)
			}
		}
	}

	return nil
}

// createAndUpdateInnerMap creates a new inner map and updates the outer map with it.
// It returns the created map, its name and any error encountered.
func (pm *PolicyManager) createAndUpdateInnerMap(
	bpfModule *bpf.Module,
	innerMapName string,
	outerMapName string,
	vKey filterVersionKey,
) (*bpf.BPFMapLow, string, error) {
	// Check if map already exists
	newInnerMapName := fmt.Sprintf("%s_%d_%d", innerMapName, vKey.Version, vKey.EventID)
	if pm.bpfInnerMaps[newInnerMapName] != nil {
		return pm.bpfInnerMaps[newInnerMapName], newInnerMapName, nil
	}

	// Create new inner map
	newInnerMap, newInnerMapName, err := createNewInnerMapEventId(bpfModule, innerMapName, vKey.Version, vKey.EventID)
	if err != nil {
		return nil, "", errfmt.WrapError(err)
	}

	// Update outer map
	if err := updateOuterMapWithEventId(bpfModule, outerMapName, vKey, newInnerMap); err != nil {
		return nil, "", errfmt.WrapError(err)
	}

	// Store map reference
	pm.bpfInnerMaps[newInnerMapName] = newInnerMap

	return newInnerMap, newInnerMapName, nil
}

// createNewInnerMapEventId creates a new map for the given map name, version and event id.
func createNewInnerMapEventId(m *bpf.Module, mapName string, mapVersion uint16, eventId uint32) (*bpf.BPFMapLow, string, error) {
	// use the map prototype to create a new map with the same properties
	prototypeMap, err := m.GetMap(mapName)
	if err != nil {
		return nil, "", errfmt.WrapError(err)
	}

	info, err := bpf.GetMapInfoByFD(prototypeMap.FileDescriptor())
	if err != nil {
		return nil, "", errfmt.WrapError(err)
	}

	btfFD, err := bpf.GetBTFFDByID(info.BTFID)
	if err != nil {
		return nil, "", errfmt.WrapError(err)
	}

	opts := &bpf.BPFMapCreateOpts{
		BTFFD:                 uint32(btfFD),
		BTFKeyTypeID:          info.BTFKeyTypeID,
		BTFValueTypeID:        info.BTFValueTypeID,
		BTFVmlinuxValueTypeID: info.BTFVmlinuxValueTypeID,
		MapFlags:              info.MapFlags,
		MapExtra:              info.MapExtra,
		MapIfIndex:            info.IfIndex,
	}

	newInnerMapName := fmt.Sprintf("%s_%d_%d", mapName, mapVersion, eventId)

	newInnerMap, err := bpf.CreateMap(
		prototypeMap.Type(),
		newInnerMapName, // new map name
		prototypeMap.KeySize(),
		prototypeMap.ValueSize(),
		int(prototypeMap.MaxEntries()),
		opts,
	)
	if err != nil {
		return nil, "", errfmt.WrapError(err)
	}

	return newInnerMap, newInnerMapName, nil
}

// updateOuterMapWithEventId updates the outer map with the given map name, version and event id.
func updateOuterMapWithEventId(m *bpf.Module, mapName string, fvKey filterVersionKey, innerMap *bpf.BPFMapLow) error {
	outerMap, err := m.GetMap(mapName)
	if err != nil {
		return errfmt.WrapError(err)
	}

	keyPointer := unsafe.Pointer(&fvKey)

	innerMapFD := uint32(innerMap.FileDescriptor())
	valuePointer := unsafe.Pointer(&innerMapFD)

	// update version filter map
	// - key is the map version + event id
	// - value is the related filter map FD.
	if err := outerMap.Update(keyPointer, valuePointer); err != nil {
		return errfmt.WrapError(err)
	}

	return nil
}

type procInfo struct {
	newProc        bool
	followPolicies uint64
	mntNS          uint32
	binaryBytes    [maxBpfBinPathSize]byte
	binNoMnt       uint32
}

// populateProcInfoMap populates the ProcInfoMap with the binaries to track.
// TODO: Should ProcInfoMap be cleared when a Policies new version is created?
// Or should it be versioned too?
func populateProcInfoMap(bpfModule *bpf.Module, ruleBitmaps map[filterVersionKey]map[filters.NSBinary]ruleBitmap) error {
	procInfoMap, err := bpfModule.GetMap(ProcInfoMap)
	if err != nil {
		return errfmt.WrapError(err)
	}

	binsProcs, err := proc.GetAllBinaryProcs()
	if err != nil {
		return errfmt.WrapError(err)
	}

	for _, rBitmaps := range ruleBitmaps {
		for bin := range rBitmaps {
			procs := binsProcs[bin.Path]
			for _, p := range procs {
				binBytes := make([]byte, maxBpfBinPathSize)
				copy(binBytes, bin.Path)
				binBytesCopy := (*[maxBpfBinPathSize]byte)(binBytes)
				// TODO: Default values for newProc and followPolicies are 0 are safe only in
				// init phase. As Policies are updated at runtime, this is not true anymore.
				procInfo := procInfo{
					newProc:        false,
					followPolicies: 0,
					mntNS:          bin.MntNS,
					binaryBytes:    *binBytesCopy,
					binNoMnt:       0, // always 0, see bin_no_mnt in tracee.bpf.c
				}
				if err := procInfoMap.Update(unsafe.Pointer(&p), unsafe.Pointer(&procInfo)); err != nil {
					return errfmt.WrapError(err)
				}
			}
		}
	}

	return nil
}
