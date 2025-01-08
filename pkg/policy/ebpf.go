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
	// outer maps
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

	// inner maps
	UIDFilterMap        = "uid_filter"
	PIDFilterMap        = "pid_filter"
	MntNSFilterMap      = "mnt_ns_filter"
	PidNSFilterMap      = "pid_ns_filter"
	UTSFilterMap        = "uts_ns_filter"
	CommFilterMap       = "comm_filter"
	DataFilterPrefixMap = "data_filter_prefix"
	DataFilterSuffixMap = "data_filter_suffix"
	DataFilterExactMap  = "data_filter_exact"
	CgroupIdFilterMap   = "cgroup_id_filter"
	BinaryFilterMap     = "binary_filter"

	ProcInfoMap     = "proc_info_map"
	EventsConfigMap = "events_config_map"
)

// createNewInnerMapEventId creates a new map for the given map name, version and event id.
func createNewInnerMapEventId(m *bpf.Module, mapName string, mapVersion uint16, eventId events.ID) (*bpf.BPFMapLow, string, error) {
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

	newInnerMapName := fmt.Sprintf("%s_%d_%d", mapName, mapVersion, uint32(eventId))

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
func updateOuterMapWithEventId(m *bpf.Module, mapName string, mapVersion uint16, eventId events.ID, innerMap *bpf.BPFMapLow) error {
	outerMap, err := m.GetMap(mapName)
	if err != nil {
		return errfmt.WrapError(err)
	}

	keyBytes := make([]byte, 8)
	binary.LittleEndian.PutUint16(keyBytes, mapVersion)          // version
	binary.LittleEndian.PutUint16(keyBytes[2:], 0)               // padding
	binary.LittleEndian.PutUint32(keyBytes[4:], uint32(eventId)) // eventid
	keyPointer := unsafe.Pointer(&keyBytes[0])

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

// createNewDataFilterMapsVersion creates a new data filter maps based on filter equalities.
func (pm *PolicyManager) createNewDataFilterMapsVersion(
	bpfModule *bpf.Module,
	fMaps *filterMaps,
) error {
	mapsNames := map[string]struct {
		outerMapName string
		equalities   map[KernelDataFields]equality
	}{
		DataFilterPrefixMap: {DataFilterPrefixMapVersion, fMaps.dataEqualitiesPrefix},
		DataFilterSuffixMap: {DataFilterSuffixMapVersion, fMaps.dataEqualitiesSuffix},
		DataFilterExactMap:  {DataFilterExactMapVersion, fMaps.dataEqualitiesExact},
	}

	for innerMapName, mapEquality := range mapsNames {
		outerMapName := mapEquality.outerMapName
		// For each combination of version and event ID, a new inner map is created
		//
		// outerMap maps:
		// 1. data_filter_prefix_version        (u16, u32), data_filter_prefix
		// 2. data_filter_suffix_version        (u16, u32), data_filter_suffix
		// 3. data_filter_exact_version         (u16, u32), data_filter_exact
		for key := range mapEquality.equalities {
			innerMapNameTemp := fmt.Sprintf("%s_%d_%d", innerMapName, polsVersion, uint32(key.ID))
			if pm.bpfInnerMaps[innerMapNameTemp] != nil {
				continue
			}

			newInnerMap, newInnerMapName, err := createNewInnerMapEventId(bpfModule, innerMapName, polsVersion, key.ID)
			if err != nil {
				return errfmt.WrapError(err)
			}

			if err := updateOuterMapWithEventId(bpfModule, outerMapName, polsVersion, key.ID, newInnerMap); err != nil {
				return errfmt.WrapError(err)
			}

			// store pointer to the new inner map version
			pm.bpfInnerMaps[newInnerMapName] = newInnerMap
		}
	}

	return nil
}

// createNewFilterMapsVersion creates a new version of the filter maps.
func (pm *PolicyManager) createNewFilterMapsVersion(bpfModule *bpf.Module) error {
	mapsNames := map[string]string{ // inner map name: outer map name
		UIDFilterMap:      UIDFilterMapVersion,
		PIDFilterMap:      PIDFilterMapVersion,
		MntNSFilterMap:    MntNSFilterMapVersion,
		PidNSFilterMap:    PidNSFilterMapVersion,
		UTSFilterMap:      UTSFilterMapVersion,
		CommFilterMap:     CommFilterMapVersion,
		CgroupIdFilterMap: CgroupIdFilterVersion,
		BinaryFilterMap:   BinaryFilterMapVersion,
	}

	for innerMapName, outerMapName := range mapsNames {
		// TODO: This only spawns new inner filter maps. Their termination must
		// be tackled by the versioning mechanism.
		newInnerMap, err := createNewInnerMapEventId(bpfModule, innerMapName, polsVersion)
		if err != nil {
			return errfmt.WrapError(err)
		}

		// typedef struct filter_version_key {
		// 	u16 version;
		// 	u16 __pad;
		// 	u32 event_id;
		// } filter_version_key_t;

		// outerMap maps:
		// 1. uid_filter_version           	u16, uid_filter
		// 2. pid_filter_version           	u16, pid_filter
		// 3. mnt_ns_filter_version        	u16, mnt_ns_filter
		// 4. pid_ns_filter_version        	u16, pid_ns_filter
		// 5. cgroup_id_filter_version     	u16, cgroup_id_filter
		// 6. uts_ns_filter_version        	u16, uts_ns_filter
		// 7. comm_filter_version          	u16, comm_filter
		// 8. binary_filter_version		    u16, binary_filter
		if err := updateOuterMapWithEventId(bpfModule, outerMapName, polsVersion, newInnerMap); err != nil {
			return errfmt.WrapError(err)
		}

		// store pointer to the new inner map version
		pm.bpfInnerMaps[innerMapName] = newInnerMap
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

// createSubmitBitmap creates a bitmap with n least significant bits set to 1
func createSubmitBitmap(n uint8) uint64 {
	if n == 0 {
		return 0
	}
	return (uint64(1) << n) - 1
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

		// Create submit bitmap based on rules count
		submitForRules := createSubmitBitmap(ecfg.rulesCount)

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

// updateUIntFilterBPF updates the BPF maps for the given uint equalities.
func (pm *PolicyManager) updateUIntFilterBPF(uintEqualities map[uint64]equality, innerMapName string) error {
	// UInt equalities
	// 1. uid_filter        u32, eq_t
	// 2. pid_filter        u32, eq_t
	// 3. mnt_ns_filter     u32, eq_t
	// 4. pid_ns_filter     u32, eq_t
	// 5. cgroup_id_filter  u32, eq_t

	for k, v := range uintEqualities {
		u32Key := uint32(k)
		keyPointer := unsafe.Pointer(&u32Key)

		eqVal := make([]byte, equalityValueSize)
		valuePointer := unsafe.Pointer(&eqVal[0])

		binary.LittleEndian.PutUint64(eqVal[0:8], v.equalsInRules)
		binary.LittleEndian.PutUint64(eqVal[8:16], v.keyUsedInRules)

		bpfMap, ok := pm.bpfInnerMaps[innerMapName]
		if !ok {
			return errfmt.Errorf("bpf map not found: %s", innerMapName)
		}
		if err := bpfMap.Update(keyPointer, valuePointer); err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}

const (
	maxBpfStrFilterSize = 256 // should be at least as big as the bpf map value size
)

// updateStringFilterBPF updates the BPF maps for the given string equalities.
func (pm *PolicyManager) updateStringFilterBPF(strEqualities map[string]equality, innerMapName string) error {
	// String equalities
	// 1. uts_ns_filter  string_filter_t, eq_t
	// 2. comm_filter    string_filter_t, eq_t

	for k, v := range strEqualities {
		byteStr := make([]byte, maxBpfStrFilterSize)
		copy(byteStr, k)
		keyPointer := unsafe.Pointer(&byteStr[0])

		eqVal := make([]byte, equalityValueSize)
		valuePointer := unsafe.Pointer(&eqVal[0])

		binary.LittleEndian.PutUint64(eqVal[0:8], v.equalsInRules)
		binary.LittleEndian.PutUint64(eqVal[8:16], v.keyUsedInRules)

		bpfMap, ok := pm.bpfInnerMaps[innerMapName]
		if !ok {
			return errfmt.Errorf("bpf map not found: %s", innerMapName)
		}
		if err := bpfMap.Update(keyPointer, valuePointer); err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}

const (
	maxBpfBinPathSize = 256 // maximum binary path size supported by BPF (MAX_BIN_PATH_SIZE)
	bpfBinFilterSize  = 264 // the key size of the BPF binary filter map entry

	maxBpfDataFilterStrSize = 256 // maximum str size supported by Data filter in BPF (MAX_DATA_FILTER_STR_SIZE)
	bpfDataFilterStrSize    = 260 // path size + 4 bytes prefix len
)

// updateBinaryFilterBPF updates the BPF maps for the given binary equalities.
func (pm *PolicyManager) updateBinaryFilterBPF(binEqualities map[filters.NSBinary]equality, innerMapName string) error {
	// BinaryNS equality
	// 1. binary_filter  binary_t, eq_t

	for k, v := range binEqualities {
		if len(k.Path) > maxBpfBinPathSize {
			return filters.InvalidValue(k.Path)
		}
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

		eqVal := make([]byte, equalityValueSize)
		valuePointer := unsafe.Pointer(&eqVal[0])

		binary.LittleEndian.PutUint64(eqVal[0:8], v.equalsInRules)
		binary.LittleEndian.PutUint64(eqVal[8:16], v.keyUsedInRules)

		bpfMap, ok := pm.bpfInnerMaps[innerMapName]
		if !ok {
			return errfmt.Errorf("bpf map not found: %s", innerMapName)
		}
		if err := bpfMap.Update(keyPointer, valuePointer); err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}

// updateStringDataFilterLPMBPF updates the BPF maps for the given kernel data LPM equalities.
func (pm *PolicyManager) updateStringDataFilterLPMBPF(dataEqualities map[KernelDataFields]equality, innerMapName string) error {
	// KernelDataFields equality
	// 1. data_filter_prefix  data_filter_lpm_key_t, eq_t
	// 2. data_filter_suffix  data_filter_lpm_key_t, eq_t

	for k, v := range dataEqualities {
		// Ensure the string length is within the maximum allowed limit,
		// excluding the NULL terminator.
		if len(k.String) > maxBpfDataFilterStrSize-1 {
			return filters.InvalidValueMax(k.String, maxBpfDataFilterStrSize-1)
		}
		binBytes := make([]byte, bpfDataFilterStrSize)

		// key is composed of: prefixlen and a string
		// multiplication by 8 - convert prefix length from bytes to bits
		// for LPM Trie compatibility.
		prefixlen := len(k.String) * 8
		binary.LittleEndian.PutUint32(binBytes, uint32(prefixlen)) // prefixlen
		copy(binBytes[4:], k.String)                               // string

		keyPointer := unsafe.Pointer(&binBytes[0])

		eqVal := make([]byte, equalityValueSize)
		valuePointer := unsafe.Pointer(&eqVal[0])

		binary.LittleEndian.PutUint64(eqVal[0:8], v.equalsInRules)
		binary.LittleEndian.PutUint64(eqVal[8:16], v.keyUsedInRules)

		innerMapName := fmt.Sprintf("%s_%d_%d", innerMapName, ps.version(), uint32(k.ID))

		bpfMap, ok := pm.bpfInnerMaps[innerMapName]
		if !ok {
			return errfmt.Errorf("bpf map not found: %s", innerMapName)
		}
		if err := bpfMap.Update(keyPointer, valuePointer); err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}

// updateStringDataFilterBPF updates the BPF maps for the given kernel data equalities.
func (pm *PolicyManager) updateStringDataFilterBPF(dataEqualities map[KernelDataFields]equality, innerMapName string) error {
	// KernelDataFields equality
	// 1. data_filter_exact  data_filter_key_t, eq_t

	for k, v := range dataEqualities {
		// Ensure the string length is within the maximum allowed limit,
		// excluding the NULL terminator.
		if len(k.String) > maxBpfDataFilterStrSize-1 {
			return filters.InvalidValueMax(k.String, maxBpfDataFilterStrSize-1)
		}
		binBytes := make([]byte, maxBpfDataFilterStrSize)

		// key is composed of a string
		copy(binBytes, k.String) // string

		keyPointer := unsafe.Pointer(&binBytes[0])

		eqVal := make([]byte, equalityValueSize)
		valuePointer := unsafe.Pointer(&eqVal[0])

		binary.LittleEndian.PutUint64(eqVal[0:8], v.equalsInRules)
		binary.LittleEndian.PutUint64(eqVal[8:16], v.keyUsedInRules)

		innerMapName := fmt.Sprintf("%s_%d_%d", innerMapName, ps.version(), uint32(k.ID))

		bpfMap, ok := pm.bpfInnerMaps[innerMapName]
		if !ok {
			return errfmt.Errorf("bpf map not found: %s", innerMapName)
		}
		if err := bpfMap.Update(keyPointer, valuePointer); err != nil {
			return errfmt.WrapError(err)
		}
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
func populateProcInfoMap(bpfModule *bpf.Module, binEqualities map[filters.NSBinary]equality) error {
	procInfoMap, err := bpfModule.GetMap(ProcInfoMap)
	if err != nil {
		return errfmt.WrapError(err)
	}

	binsProcs, err := proc.GetAllBinaryProcs()
	if err != nil {
		return errfmt.WrapError(err)
	}

	for bin := range binEqualities {
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

	return nil
}

// updateBPF updates the BPF maps with the policies filters.
// createNewMaps indicates whether new maps should be created or not.
func (pm *PolicyManager) updateBPF(
	bpfModule *bpf.Module,
	cts *containers.Containers,
	eventsFields map[events.ID][]bufferdecoder.ArgType,
	createNewMaps bool,
) error {
	fMaps, dataFilterConfigs, err := pm.computeFilterMaps(cts)
	if err != nil {
		return errfmt.WrapError(err)
	}

	if err := pm.updateEventsConfigMap(bpfModule, eventsFields, dataFilterConfigs); err != nil {
		return errfmt.WrapError(err)
	}

	if createNewMaps {
		// Create new filter maps version
		if err := pm.createNewFilterMapsVersion(bpfModule); err != nil {
			return errfmt.WrapError(err)
		}

		// Create new filter maps version based on version and event id
		if err := pm.createNewDataFilterMapsVersion(bpfModule, fMaps); err != nil {
			return errfmt.WrapError(err)
		}
	}

	// Update UInt equalities filter maps
	if err := pm.updateUIntFilterBPF(fMaps.uidEqualities, UIDFilterMap); err != nil {
		return errfmt.WrapError(err)
	}
	if err := pm.updateUIntFilterBPF(fMaps.pidEqualities, PIDFilterMap); err != nil {
		return errfmt.WrapError(err)
	}
	if err := pm.updateUIntFilterBPF(fMaps.mntNSEqualities, MntNSFilterMap); err != nil {
		return errfmt.WrapError(err)
	}
	if err := pm.updateUIntFilterBPF(fMaps.pidNSEqualities, PidNSFilterMap); err != nil {
		return errfmt.WrapError(err)
	}
	if err := pm.updateUIntFilterBPF(fMaps.cgroupIdEqualities, CgroupIdFilterMap); err != nil {
		return errfmt.WrapError(err)
	}

	// Update String equalities filter maps
	if err := pm.updateStringFilterBPF(fMaps.utsEqualities, UTSFilterMap); err != nil {
		return errfmt.WrapError(err)
	}
	if err := pm.updateStringFilterBPF(fMaps.commEqualities, CommFilterMap); err != nil {
		return errfmt.WrapError(err)
	}

	// Data Filter - Prefix match
	if err := pm.updateStringDataFilterLPMBPF(fMaps.dataEqualitiesPrefix, DataFilterPrefixMap); err != nil {
		return errfmt.WrapError(err)
	}

	// Data Filter - Suffix match
	if err := pm.updateStringDataFilterLPMBPF(fMaps.dataEqualitiesSuffix, DataFilterSuffixMap); err != nil {
		return errfmt.WrapError(err)
	}

	// Data Filter - Exact match
	if err := pm.updateStringDataFilterBPF(fMaps.dataEqualitiesExact, DataFilterExactMap); err != nil {
		return errfmt.WrapError(err)
	}

	// Update Binary equalities filter map
	if err := pm.updateBinaryFilterBPF(fMaps.binaryEqualities, BinaryFilterMap); err != nil {
		return errfmt.WrapError(err)
	}
	// Update ProcInfo map (required for binary filters)
	if err := populateProcInfoMap(bpfModule, fMaps.binaryEqualities); err != nil {
		return errfmt.WrapError(err)
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
