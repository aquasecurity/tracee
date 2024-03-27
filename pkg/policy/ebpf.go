package policy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils/proc"
)

const (
	//
	// outer maps
	//

	// filter maps
	UIDFilterMapVersion         = "uid_filter_version"
	PIDFilterMapVersion         = "pid_filter_version"
	MntNSFilterMapVersion       = "mnt_ns_filter_version"
	PidNSFilterMapVersion       = "pid_ns_filter_version"
	UTSFilterMapVersion         = "uts_ns_filter_version"
	CommFilterMapVersion        = "comm_filter_version"
	CgroupIdFilterVersion       = "cgroup_id_filter_version"
	ProcessTreeFilterMapVersion = "process_tree_map_version"
	BinaryFilterMapVersion      = "binary_filter_version"

	EventsMapVersion      = "events_map_version"
	PoliciesConfigVersion = "policies_config_version"

	//
	// inner maps
	//

	// filter maps
	UIDFilterMap         = "uid_filter"
	PIDFilterMap         = "pid_filter"
	MntNSFilterMap       = "mnt_ns_filter"
	PidNSFilterMap       = "pid_ns_filter"
	UTSFilterMap         = "uts_ns_filter"
	CommFilterMap        = "comm_filter"
	CgroupIdFilterMap    = "cgroup_id_filter"
	ProcessTreeFilterMap = "process_tree_map"
	BinaryFilterMap      = "binary_filter"

	EventsMap         = "events_map"
	PoliciesConfigMap = "policies_config_map"

	//
	// other maps
	//

	ProcInfoMap = "proc_info_map"
)

var (
	mapsVersionNames = map[string]string{ // inner map name: outer map name
		// filter maps
		UIDFilterMap:         UIDFilterMapVersion,
		PIDFilterMap:         PIDFilterMapVersion,
		MntNSFilterMap:       MntNSFilterMapVersion,
		PidNSFilterMap:       PidNSFilterMapVersion,
		UTSFilterMap:         UTSFilterMapVersion,
		CommFilterMap:        CommFilterMapVersion,
		CgroupIdFilterMap:    CgroupIdFilterVersion,
		ProcessTreeFilterMap: ProcessTreeFilterMapVersion,
		BinaryFilterMap:      BinaryFilterMapVersion,

		EventsMap:         EventsMapVersion,
		PoliciesConfigMap: PoliciesConfigVersion,
	}
)

// createNewInnerMap creates a new map for the given map name and version.
func createNewInnerMap(m *bpf.Module, mapName string, mapVersion uint16) (*bpf.BPFMapLow, error) {
	// use the map prototype to create a new map with the same properties
	prototypeMap, err := m.GetMap(mapName)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	info, err := bpf.GetMapInfoByFD(prototypeMap.FileDescriptor())
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	btfFD, err := bpf.GetBTFFDByID(info.BTFID)
	if err != nil {
		return nil, errfmt.WrapError(err)
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
	newInnerMap, err := bpf.CreateMap(
		prototypeMap.Type(),
		fmt.Sprintf("%s_%d", mapName, mapVersion), // new map name
		prototypeMap.KeySize(),
		prototypeMap.ValueSize(),
		int(prototypeMap.MaxEntries()),
		opts,
	)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	return newInnerMap, nil
}

// updateOuterMap updates the outer map with the given map name and version.
func updateOuterMap(m *bpf.Module, mapName string, mapVersion uint16, innerMap *bpf.BPFMapLow) error {
	outerMap, err := m.GetMap(mapName)
	if err != nil {
		return errfmt.WrapError(err)
	}

	u16Key := mapVersion
	keyPointer := unsafe.Pointer(&u16Key)
	innerMapFD := uint32(innerMap.FileDescriptor())
	valuePointer := unsafe.Pointer(&innerMapFD)

	// update the outer map with the new inner map version
	// - key is the map version
	// - value is the related filter map FD.
	if err := outerMap.Update(keyPointer, valuePointer); err != nil {
		return errfmt.WrapError(err)
	}

	return nil
}

// deleteMapFromOuterMap deletes the given map version from the outer map.
func deleteMapFromOuterMap(m *bpf.Module, mapName string, mapVersion uint16) error {
	outerMap, err := m.GetMap(mapName)
	if err != nil {
		return errfmt.WrapError(err)
	}

	u16Key := mapVersion
	keyPointer := unsafe.Pointer(&u16Key)

	// delete the map version from the outer map
	// - key is the map version
	if err := outerMap.DeleteKey(keyPointer); err != nil {
		var errno syscall.Errno
		if errors.As(err, &errno) && errno == syscall.ENOENT {
			return nil
		}

		return errfmt.WrapError(err)
	}

	return nil
}

// pruneBPFMaps closes the version BPF maps and deletes the version from the outer maps.
// It also resets the versionBPFMaps map.
func (ps *Policies) pruneBPFMaps(m *bpf.Module) {
	for innerMapName, bm := range ps.versionBPFMaps {
		outerMapName, ok := mapsVersionNames[innerMapName]
		if !ok {
			logger.Errorw(
				"Outer map name not found for inner map",
				"inner_map", innerMapName,
			)
			continue
		}
		if err := deleteMapFromOuterMap(m, outerMapName, ps.version); err != nil {
			logger.Errorw(
				"Deleting inner BPF map",
				"outer_map", outerMapName,
				"version", ps.version,
				"error", err,
			)
		}

		fd := bm.FileDescriptor()
		if err := syscall.Close(int(fd)); err != nil {
			logger.Errorw(
				"Closing BPF map",
				"map", bm.Name(),
				"error", err,
			)
		}
	}

	ps.versionBPFMaps = make(map[string]*bpf.BPFMapLow) // reset the inner maps
}

// createNewMapsVersionBPF creates a new version of the maps and updates the outer
// maps with the new inner.
func (ps *Policies) createNewMapsVersionBPF(
	bpfModule *bpf.Module,
	versionNames map[string]string,
) error {
	for innerMapName, outerMapName := range versionNames {
		newInnerMap, err := createNewInnerMap(bpfModule, innerMapName, ps.version)
		if err != nil {
			return errfmt.WrapError(err)
		}

		// store the new filter map version
		ps.versionBPFMaps[innerMapName] = newInnerMap

		// outerMap maps:
		// 1. uid_filter_version           u16, uid_filter
		// 2. pid_filter_version           u16, pid_filter
		// 3. mnt_ns_filter_version        u16, mnt_ns_filter
		// 4. pid_ns_filter_version        u16, pid_ns_filter
		// 5. cgroup_id_filter_version     u16, cgroup_id_filter
		// 6. uts_ns_filter_version        u16, uts_ns_filter
		// 7. comm_filter_version          u16, comm_filter
		// 8. process_tree_filter_version  u16, process_tree_filter
		// 9. binary_filter_version        u16, binary_filter
		// 10. events_map_version          u16, events_map
		// 11. policies_config_version     u16, policies_config_map
		if err := updateOuterMap(bpfModule, outerMapName, ps.version, newInnerMap); err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}

func (ps *Policies) populateEventsMapBPF(eventsParamTypes map[events.ID][]bufferdecoder.ArgType) error {
	bm, ok := ps.versionBPFMaps[EventsMap]
	if !ok {
		return errfmt.Errorf("bpf map not found: %s", EventsMap)
	}

	for id, ecfg := range ps.eventsFlags().getAll() {
		eventConfigVal := make([]byte, 16)

		// bitmap of policies that require this event to be submitted
		binary.LittleEndian.PutUint64(eventConfigVal[0:8], ecfg.GetSubmit())

		// encoded event's parameter types
		var paramTypes uint64
		params := eventsParamTypes[id]
		for n, paramType := range params {
			paramTypes = paramTypes | (uint64(paramType) << (8 * n))
		}
		binary.LittleEndian.PutUint64(eventConfigVal[8:16], paramTypes)

		err := bm.Update(unsafe.Pointer(&id), unsafe.Pointer(&eventConfigVal[0]))
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}

// populateUIntFilterBPF updates the BPF maps for the given uint equalities.
func (ps *Policies) populateUIntFilterBPF(uintEqualities map[uint64]equality, innerMapName string) error {
	// UInt equalities
	// 1. uid_filter        u32, eq_t
	// 2. pid_filter        u32, eq_t
	// 3. mnt_ns_filter     u64, eq_t
	// 4. pid_ns_filter     u64, eq_t
	// 5. cgroup_id_filter  u32, eq_t

	bm, ok := ps.versionBPFMaps[innerMapName]
	if !ok {
		return errfmt.Errorf("bpf map not found: %s", innerMapName)
	}

	for k, v := range uintEqualities {
		var (
			u32Value   uint32
			u64Value   uint64
			keyPointer unsafe.Pointer
		)

		switch innerMapName {
		case UIDFilterMap, PIDFilterMap, CgroupIdFilterMap:
			// key is uint32
			u32Value = uint32(k)
			keyPointer = unsafe.Pointer(&u32Value)
		case MntNSFilterMap, PidNSFilterMap:
			// key is uint64
			u64Value = uint64(k)
			keyPointer = unsafe.Pointer(&u64Value)
		}

		eqVal := make([]byte, equalityValueSize)
		valuePointer := unsafe.Pointer(&eqVal[0])

		binary.LittleEndian.PutUint64(eqVal[0:8], v.equalInPolicies)
		binary.LittleEndian.PutUint64(eqVal[8:16], v.equalitySetInPolicies)

		if err := bm.Update(keyPointer, valuePointer); err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}

const (
	maxBpfStrFilterSize = 256 // should be at least as big as the bpf map value size
)

// populateStringFilterBPF updates the BPF maps for the given string equalities.
func (ps *Policies) populateStringFilterBPF(strEqualities map[string]equality, innerMapName string) error {
	// String equalities
	// 1. uts_ns_filter  string_filter_t, eq_t
	// 2. comm_filter    string_filter_t, eq_t

	bm, ok := ps.versionBPFMaps[innerMapName]
	if !ok {
		return errfmt.Errorf("bpf map not found: %s", innerMapName)
	}

	for k, v := range strEqualities {
		byteStr := make([]byte, maxBpfStrFilterSize)
		copy(byteStr, k)
		keyPointer := unsafe.Pointer(&byteStr[0])

		eqVal := make([]byte, equalityValueSize)
		valuePointer := unsafe.Pointer(&eqVal[0])

		binary.LittleEndian.PutUint64(eqVal[0:8], v.equalInPolicies)
		binary.LittleEndian.PutUint64(eqVal[8:16], v.equalitySetInPolicies)

		if err := bm.Update(keyPointer, valuePointer); err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}

// populateProcTreeFilterBPF updates the BPF maps for the given process tree equalities.
func (ps *Policies) populateProcTreeFilterBPF(procTreeEqualities map[uint32]equality, innerMapName string) error {
	// ProcessTree equality
	// 1. process_tree_filter  u32, eq_t

	updateBPF := func(pid uint32, v equality) (err error) {
		u32Key := pid
		keyPointer := unsafe.Pointer(&u32Key)

		eqVal := make([]byte, equalityValueSize)
		valuePointer := unsafe.Pointer(&eqVal[0])

		binary.LittleEndian.PutUint64(eqVal[0:8], v.equalInPolicies)
		binary.LittleEndian.PutUint64(eqVal[8:16], v.equalitySetInPolicies)

		bm, ok := ps.versionBPFMaps[innerMapName]
		if !ok {
			return errfmt.Errorf("bpf map not found: %s", innerMapName)
		}
		if err := bm.Update(keyPointer, valuePointer); err != nil {
			return errfmt.WrapError(err)
		}

		return nil
	}

	// First, update BPF for provided pids equalities
	for pid, eq := range procTreeEqualities {
		if err := updateBPF(pid, eq); err != nil {
			return err
		}
	}

	procDir, err := os.Open("/proc")
	if err != nil {
		return errfmt.Errorf("could not open proc dir: %v", err)
	}
	defer func() {
		if err := procDir.Close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return errfmt.Errorf("could not read proc dir: %v", err)
	}

	// Then, update BPF for all processes that are children of the provided pids
	for _, entry := range entries {
		pid, err := strconv.ParseUint(entry, 10, 32)
		if err != nil {
			continue
		}

		var updateBPFIfParentMatches func(uint32)
		updateBPFIfParentMatches = func(curPid uint32) {
			stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", curPid))
			if err != nil {
				return
			}
			// see https://man7.org/linux/man-pages/man5/proc.5.html for how to read /proc/pid/stat
			splitStat := bytes.SplitN(stat, []byte{' '}, 5)
			if len(splitStat) != 5 {
				return
			}
			ppid, err := strconv.Atoi(string(splitStat[3]))
			if err != nil {
				return
			}
			if ppid == 1 {
				return
			}

			// if the parent pid is in the provided pids, update BPF with its child pid
			if eq, ok := procTreeEqualities[uint32(ppid)]; ok {
				_ = updateBPF(uint32(pid), eq)
				return
			}

			updateBPFIfParentMatches(uint32(ppid))
		}

		updateBPFIfParentMatches(uint32(pid))
	}

	return nil
}

const (
	maxBpfBinPathSize = 256 // maximum binary path size supported by BPF (MAX_BIN_PATH_SIZE)
	bpfBinFilterSize  = 264 // the key size of the BPF binary filter map entry
)

// populateBinaryFilterBPF updates the BPF maps for the given binary equalities.
func (ps *Policies) populateBinaryFilterBPF(binEqualities map[filters.NSBinary]equality) error {
	// BinaryNS equality
	// 1. binary_filter  binary_t, eq_t

	innerMapName := BinaryFilterMap
	bm, ok := ps.versionBPFMaps[innerMapName]
	if !ok {
		return errfmt.Errorf("bpf map not found: %s", innerMapName)
	}

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

		binary.LittleEndian.PutUint64(eqVal[0:8], v.equalInPolicies)
		binary.LittleEndian.PutUint64(eqVal[8:16], v.equalitySetInPolicies)

		if err := bm.Update(keyPointer, valuePointer); err != nil {
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

// populateProcInfoMapBPF populates the ProcInfoMap with the binaries to track.
func populateProcInfoMapBPF(
	bpfModule *bpf.Module,
	binEqualities map[filters.NSBinary]equality,
	newProc bool,
	followPolicies uint64,
) error {
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
			procInfo := procInfo{
				newProc:        newProc,
				followPolicies: followPolicies,
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

// PopulateProcessTreeBPF populates the BPF maps with the policies process tree filters.
//
// This logic is separated from PopulateBPF because updating the process tree filters
// needs to occur after the probes are attached. This approach minimizes the potential
// for race conditions between the BPF programs that are updating the maps and the
// user space processes that are reading procfs and interacting with the same maps.
func (ps *Policies) PopulateProcessTreeBPF() error {
	ps.rwmu.Lock()
	defer ps.rwmu.Unlock()

	// ProcessTreeFilters equalities
	procTreeEqualities := make(map[uint32]equality)
	ps.computeProcTreeEqualities(procTreeEqualities)

	// Update ProcessTree equalities filter map
	if err := ps.populateProcTreeFilterBPF(procTreeEqualities, ProcessTreeFilterMap); err != nil {
		return errfmt.WrapError(err)
	}

	return nil
}

// PopulateBPF creates and populates the current policies version related BPF maps.
// It must be called only once per policies version change.
func (ps *Policies) PopulateBPF(
	m *bpf.Module,
	cts *containers.Containers,
	eventsParamTypes map[events.ID][]bufferdecoder.ArgType,
) (*PoliciesConfig, error) {
	ps.rwmu.Lock()
	defer ps.rwmu.Unlock()

	if len(ps.versionBPFMaps) > 0 {
		return nil, errfmt.Errorf("BPF maps already populated")
	}

	var (
		fEqs = &filtersEqualities{
			uidEqualities:      make(map[uint64]equality),
			pidEqualities:      make(map[uint64]equality),
			mntNSEqualities:    make(map[uint64]equality),
			pidNSEqualities:    make(map[uint64]equality),
			cgroupIdEqualities: make(map[uint64]equality),
			utsEqualities:      make(map[string]equality),
			commEqualities:     make(map[string]equality),
			binaryEqualities:   make(map[filters.NSBinary]equality),
		}
		pCfgVersion *PoliciesConfig
		bm          *bpf.BPFMapLow
		ok          bool
		err         error
	)

	//
	// Create new maps version
	//

	// Create new maps version, including ProcessTreeFilterMapVersion which
	// is not populated here. It must be populated after the probes are attached by
	// calling PopulateProcessTreeBPF.
	err = ps.createNewMapsVersionBPF(m, mapsVersionNames)
	if err != nil {
		goto bailout
	}

	//
	// Populate filter maps
	//

	// EventsMap (versioned)
	err = ps.populateEventsMapBPF(eventsParamTypes)
	if err != nil {
		goto bailout
	}

	err = ps.computeFilterEqualities(fEqs, cts)
	if err != nil {
		goto bailout
	}

	// UInt equalities filter maps (versioned)
	err = ps.populateUIntFilterBPF(fEqs.uidEqualities, UIDFilterMap)
	if err != nil {
		goto bailout
	}
	err = ps.populateUIntFilterBPF(fEqs.pidEqualities, PIDFilterMap)
	if err != nil {
		goto bailout
	}
	err = ps.populateUIntFilterBPF(fEqs.mntNSEqualities, MntNSFilterMap)
	if err != nil {
		goto bailout
	}
	err = ps.populateUIntFilterBPF(fEqs.pidNSEqualities, PidNSFilterMap)
	if err != nil {
		goto bailout
	}
	err = ps.populateUIntFilterBPF(fEqs.cgroupIdEqualities, CgroupIdFilterMap)
	if err != nil {
		goto bailout
	}

	// String equalities filter maps (versioned)
	err = ps.populateStringFilterBPF(fEqs.utsEqualities, UTSFilterMap)
	if err != nil {
		goto bailout
	}
	err = ps.populateStringFilterBPF(fEqs.commEqualities, CommFilterMap)
	if err != nil {
		goto bailout
	}

	// Binary equalities filter map (versioned)
	err = ps.populateBinaryFilterBPF(fEqs.binaryEqualities)
	if err != nil {
		goto bailout
	}
	// Populate ProcInfoMap (required by binary filter map)
	// NOTE: this must be populated after the binary filter map
	err = populateProcInfoMapBPF(m, fEqs.binaryEqualities, false, PolicyNone)
	if err != nil {
		goto bailout
	}

	//
	// Populate policies config map (final step)
	//

	// PoliciesConfigMap (versioned)
	bm, ok = ps.versionBPFMaps[PoliciesConfigMap]
	if !ok {
		err = errfmt.Errorf("bpf map not found: %s", PoliciesConfigMap)
		goto bailout
	}
	pCfgVersion = ps.computePoliciesConfig()
	err = pCfgVersion.populateBPF(bm)
	if err != nil {
		goto bailout
	}

	return pCfgVersion, nil

bailout:
	ps.pruneBPFMaps(m)
	return nil, errfmt.WrapError(err)
}

// PoliciesConfig mirrors the C struct policies_config (policies_config_t).
// Order of fields is important, as it is used as a value for
// the PoliciesConfigMap BPF map.
type PoliciesConfig struct {
	UIDFilterEnabledScopes      uint64
	PIDFilterEnabledScopes      uint64
	MntNsFilterEnabledScopes    uint64
	PidNsFilterEnabledScopes    uint64
	UtsNsFilterEnabledScopes    uint64
	CommFilterEnabledScopes     uint64
	CgroupIdFilterEnabledScopes uint64
	ContFilterEnabledScopes     uint64
	NewContFilterEnabledScopes  uint64
	NewPidFilterEnabledScopes   uint64
	ProcTreeFilterEnabledScopes uint64
	BinPathFilterEnabledScopes  uint64
	FollowFilterEnabledScopes   uint64

	UIDFilterOutScopes      uint64
	PIDFilterOutScopes      uint64
	MntNsFilterOutScopes    uint64
	PidNsFilterOutScopes    uint64
	UtsNsFilterOutScopes    uint64
	CommFilterOutScopes     uint64
	CgroupIdFilterOutScopes uint64
	ContFilterOutScopes     uint64
	NewContFilterOutScopes  uint64
	NewPidFilterOutScopes   uint64
	ProcTreeFilterOutScopes uint64
	BinPathFilterOutScopes  uint64

	EnabledScopes uint64

	UidMax uint64
	UidMin uint64
	PidMax uint64
	PidMin uint64
}

func (pc *PoliciesConfig) populateBPF(bpfConfigMap *bpf.BPFMapLow) error {
	if bpfConfigMap == nil {
		return errfmt.Errorf("bpfConfigMap is nil")
	}

	cZero := 0
	if err := bpfConfigMap.Update(unsafe.Pointer(&cZero), unsafe.Pointer(pc)); err != nil {
		return errfmt.WrapError(err)
	}

	return nil
}

// computePoliciesConfig computes the policies config from the policies.
func (ps *Policies) computePoliciesConfig() *PoliciesConfig {
	cfg := &PoliciesConfig{}

	for p := range ps.filterEnabledPoliciesMap {
		offset := p.ID

		// filter enabled policies bitmap
		if p.UIDFilter.Enabled() {
			cfg.UIDFilterEnabledScopes |= 1 << offset
		}
		if p.PIDFilter.Enabled() {
			cfg.PIDFilterEnabledScopes |= 1 << offset
		}
		if p.MntNSFilter.Enabled() {
			cfg.MntNsFilterEnabledScopes |= 1 << offset
		}
		if p.PidNSFilter.Enabled() {
			cfg.PidNsFilterEnabledScopes |= 1 << offset
		}
		if p.UTSFilter.Enabled() {
			cfg.UtsNsFilterEnabledScopes |= 1 << offset
		}
		if p.CommFilter.Enabled() {
			cfg.CommFilterEnabledScopes |= 1 << offset
		}
		if p.ContIDFilter.Enabled() {
			cfg.CgroupIdFilterEnabledScopes |= 1 << offset
		}
		if p.ContFilter.Enabled() {
			cfg.ContFilterEnabledScopes |= 1 << offset
		}
		if p.NewContFilter.Enabled() {
			cfg.NewContFilterEnabledScopes |= 1 << offset
		}
		if p.NewPidFilter.Enabled() {
			cfg.NewPidFilterEnabledScopes |= 1 << offset
		}
		if p.ProcessTreeFilter.Enabled() {
			cfg.ProcTreeFilterEnabledScopes |= 1 << offset
		}
		if p.BinaryFilter.Enabled() {
			cfg.BinPathFilterEnabledScopes |= 1 << offset
		}
		if p.Follow {
			cfg.FollowFilterEnabledScopes |= 1 << offset
		}

		// filter out scopes bitmap
		if p.UIDFilter.FilterOut() {
			cfg.UIDFilterOutScopes |= 1 << offset
		}
		if p.PIDFilter.FilterOut() {
			cfg.PIDFilterOutScopes |= 1 << offset
		}
		if p.MntNSFilter.FilterOut() {
			cfg.MntNsFilterOutScopes |= 1 << offset
		}
		if p.PidNSFilter.FilterOut() {
			cfg.PidNsFilterOutScopes |= 1 << offset
		}
		if p.UTSFilter.FilterOut() {
			cfg.UtsNsFilterOutScopes |= 1 << offset
		}
		if p.CommFilter.FilterOut() {
			cfg.CommFilterOutScopes |= 1 << offset
		}
		if p.ContIDFilter.FilterOut() {
			cfg.CgroupIdFilterOutScopes |= 1 << offset
		}
		if p.ContFilter.FilterOut() {
			cfg.ContFilterOutScopes |= 1 << offset
		}
		if p.NewContFilter.FilterOut() {
			cfg.NewContFilterOutScopes |= 1 << offset
		}
		if p.NewPidFilter.FilterOut() {
			cfg.NewPidFilterOutScopes |= 1 << offset
		}
		if p.ProcessTreeFilter.FilterOut() {
			cfg.ProcTreeFilterOutScopes |= 1 << offset
		}
		if p.BinaryFilter.FilterOut() {
			cfg.BinPathFilterOutScopes |= 1 << offset
		}

		cfg.EnabledScopes |= 1 << offset
	}

	cfg.UidMax = ps.uidFilterMax
	cfg.UidMin = ps.uidFilterMin
	cfg.PidMax = ps.pidFilterMax
	cfg.PidMin = ps.pidFilterMin

	return cfg
}
