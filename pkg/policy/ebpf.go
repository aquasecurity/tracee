package policy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
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
	EventsMap = "events_map"

	// outer maps
	UIDFilterMapVersion   = "uid_fltr_outer"
	PIDFilterMapVersion   = "pid_fltr_outer"
	MntNSFilterMapVersion = "mntns_fltr_outer"
	PidNSFilterMapVersion = "pidns_fltr_outer"
	UTSFilterMapVersion   = "utsns_fltr_outer"
	CommFilterMapVersion  = "comm_fltr_outer"
	CgroupIdFilterVersion = "cgrpid_fltr_outer"

	ProcessTreeFilterMapVersion = "ptree_fltr_outer"
	BinaryFilterMapVersion      = "bin_fltr_outer"
	// PoliciesConfigVersion       = "policies_config_version"

	// inner maps
	UIDFilterMap         = "uid_fltr"
	PIDFilterMap         = "pid_fltr"
	MntNSFilterMap       = "mntns_fltr"
	PidNSFilterMap       = "pidns_fltr"
	UTSFilterMap         = "utsns_fltr"
	CommFilterMap        = "comm_fltr"
	CgroupIdFilterMap    = "cgrpid_fltr"
	ProcessTreeFilterMap = "ptree_fltr"
	BinaryFilterMap      = "bin_fltr"
	// PoliciesConfigMap    = "policies_config_map"

	ProcInfoMap = "proc_info_map"
)

// ruleKey mirrors the C struct rule_key (rule_key_t).
type ruleKey struct {
	eventID events.ID
	ruleID  uint8
	_       uint8  // padding free for further use
	_       uint16 // padding free for further use
}

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

	// update version filter map
	// - key is the map version
	// - value is the related filter map FD.
	if err := outerMap.Update(keyPointer, valuePointer); err != nil {
		return errfmt.WrapError(err)
	}

	return nil
}

// createNewFilterMapsVersion creates a new version of the filter maps.
func (ps *Policies) createNewFilterMapsVersion(bpfModule *bpf.Module) error {
	mapsNames := map[string]string{ // inner map name: outer map name
		UIDFilterMap:         UIDFilterMapVersion,
		PIDFilterMap:         PIDFilterMapVersion,
		MntNSFilterMap:       MntNSFilterMapVersion,
		PidNSFilterMap:       PidNSFilterMapVersion,
		UTSFilterMap:         UTSFilterMapVersion,
		CommFilterMap:        CommFilterMapVersion,
		CgroupIdFilterMap:    CgroupIdFilterVersion,
		ProcessTreeFilterMap: ProcessTreeFilterMapVersion,
		BinaryFilterMap:      BinaryFilterMapVersion,
	}

	polsVersion := ps.Version()
	for innerMapName, outerMapName := range mapsNames {
		// TODO: This only spawns new inner filter maps. Their termination must
		// be tackled by the versioning mechanism.
		newInnerMap, err := createNewInnerMap(bpfModule, innerMapName, polsVersion)
		if err != nil {
			return errfmt.WrapError(err)
		}

		// typedef struct rule_key {
		// 	u32 event_id;
		// 	u8 rules_id;
		// 	u8 padding1; // free for further use
		// 	u16 padding2; // free for further use
		// } rule_key_t;

		// outerMap maps:
		// 1. uid_fltr_outer           rule_key_t, uid_fltr
		// 2. pid_fltr_outer           rule_key_t, pid_fltr
		// 3. mntns_fltr_outer        rule_key_t, mntns_fltr
		// 4. pidns_fltr_outer        rule_key_t, pidns_fltr
		// 5. cgrpid_fltr_outer       rule_key_t, cgroup_id_fltr
		// 6. utsns_fltr_outer        rule_key_t, utsns_fltr
		// 7. comm_fltr_outer          rule_key_t, comm_fltr
		// 8. process_tree_fltr_rules  rule_key_t, process_tree_fltr
		// 9. bin_fltr_outer           rule_key_t, binary_fltr
		if err := updateOuterMap(bpfModule, outerMapName, polsVersion, newInnerMap); err != nil {
			return errfmt.WrapError(err)
		}

		// store pointer to the new inner map version
		ps.bpfInnerMaps[innerMapName] = newInnerMap
	}

	return nil
}

// updateEventsMap
func (ps *Policies) updateEventsMap(
	bpfModule *bpf.Module,
	eventsState map[events.ID]events.EventState,
	eventsParams map[events.ID][]bufferdecoder.ArgType,
) error {
	// polsVersion := ps.Version()
	// innerMapName := "events_map"
	// outerMapName := "events_map_version"

	// // TODO: This only spawns a new inner event map. Their termination must
	// // be tackled by the versioning mechanism.
	// newInnerMap, err := createNewInnerMap(bpfModule, innerMapName, polsVersion)
	// if err != nil {
	// 	return errfmt.WrapError(err)
	// }

	// if err := updateOuterMap(bpfModule, outerMapName, polsVersion, newInnerMap); err != nil {
	// 	return errfmt.WrapError(err)
	// }

	// // store pointer to the new inner map version
	// ps.bpfInnerMaps[innerMapName] = newInnerMap

	evtMap, err := bpfModule.GetMap(EventsMap)
	if err != nil {
		return errfmt.WrapError(err)
	}

	for id, ecfg := range eventsState {
		// evtConfig := EventConfig{}
		// evtConfig.SubmitForRules = ecfg.Submit

		eventConfigVal := make([]byte, 16)

		// bitmap of policies that require this event to be submitted
		binary.LittleEndian.PutUint64(eventConfigVal[0:8], ecfg.Submit)

		// encoded event's parameter types
		var paramTypes uint64
		params := eventsParams[id]
		for n, paramType := range params {
			paramTypes = paramTypes | (uint64(paramType) << (8 * n))
		}
		binary.LittleEndian.PutUint64(eventConfigVal[8:16], paramTypes)

		err := evtMap.Update(unsafe.Pointer(&id), unsafe.Pointer(&eventConfigVal[0]))
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}

// updateUIntFilterBPF updates the BPF maps for the given uint equalities.
func (ps *Policies) updateUIntFilterBPF(uintEqualities map[uint64]equality, innerMapName string) error {
	// UInt equalities
	// 1. uid_fltr      u32, eq_t
	// 2. pid_fltr      u32, eq_t
	// 3. mntns_fltr   u32, eq_t
	// 4. pidns_fltr   u32, eq_t
	// 5. cgrpid_fltr  u32, eq_t

	for k, v := range uintEqualities {
		u32Key := uint32(k)
		keyPointer := unsafe.Pointer(&u32Key)

		eqVal := make([]byte, equalityValueSize)
		valuePointer := unsafe.Pointer(&eqVal[0])

		binary.LittleEndian.PutUint64(eqVal[0:8], v.equalInPolicies)
		binary.LittleEndian.PutUint64(eqVal[8:16], v.equalitySetInPolicies)

		bpfMap, ok := ps.bpfInnerMaps[innerMapName]
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
func (ps *Policies) updateStringFilterBPF(strEqualities map[string]equality, innerMapName string) error {
	// String equalities
	// 1. utsns_fltr  string_filter_t, eq_t
	// 2. comm_fltr    string_filter_t, eq_t

	for k, v := range strEqualities {
		byteStr := make([]byte, maxBpfStrFilterSize)
		copy(byteStr, k)
		keyPointer := unsafe.Pointer(&byteStr[0])

		eqVal := make([]byte, equalityValueSize)
		valuePointer := unsafe.Pointer(&eqVal[0])

		binary.LittleEndian.PutUint64(eqVal[0:8], v.equalInPolicies)
		binary.LittleEndian.PutUint64(eqVal[8:16], v.equalitySetInPolicies)

		bpfMap, ok := ps.bpfInnerMaps[innerMapName]
		if !ok {
			return errfmt.Errorf("bpf map not found: %s", innerMapName)
		}
		if err := bpfMap.Update(keyPointer, valuePointer); err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}

// updateProcTreeFilterBPF updates the BPF maps for the given process tree equalities.
func (ps *Policies) updateProcTreeFilterBPF(procTreeEqualities map[uint32]equality, innerMapName string) error {
	// ProcessTree equality
	// 1. process_tree_filter  u32, eq_t

	updateBPF := func(pid uint32, v equality) (err error) {
		u32Key := pid
		keyPointer := unsafe.Pointer(&u32Key)

		eqVal := make([]byte, equalityValueSize)
		valuePointer := unsafe.Pointer(&eqVal[0])

		binary.LittleEndian.PutUint64(eqVal[0:8], v.equalInPolicies)
		binary.LittleEndian.PutUint64(eqVal[8:16], v.equalitySetInPolicies)

		bpfMap, ok := ps.bpfInnerMaps[innerMapName]
		if !ok {
			return errfmt.Errorf("bpf map not found: %s", innerMapName)
		}
		if err := bpfMap.Update(keyPointer, valuePointer); err != nil {
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

// updateBinaryFilterBPF updates the BPF maps for the given binary equalities.
func (ps *Policies) updateBinaryFilterBPF(binEqualities map[filters.NSBinary]equality, innerMapName string) error {
	// BinaryNS equality
	// 1. bin_fltr  binary_t, eq_t

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

		bpfMap, ok := ps.bpfInnerMaps[innerMapName]
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

// UpdateBPF updates the BPF maps with the policies filters.
// createNewMaps indicates whether new maps should be created or not.
// updateProcTree indicates whether the process tree map should be updated or not.
func (ps *Policies) UpdateBPF(
	bpfModule *bpf.Module,
	cts *containers.Containers,
	eventsState map[events.ID]events.EventState,
	eventsParams map[events.ID][]bufferdecoder.ArgType,
	createNewMaps bool,
	updateProcTree bool,
) error {
	ps.rwmu.Lock()
	defer ps.rwmu.Unlock()

	// if createNewMaps {
	// 	// Create new events map version
	// 	if err := ps.createNewEventsMapVersion(bpfModule, eventsState, eventsParams); err != nil {
	// 		return nil, errfmt.WrapError(err)
	// 	}
	// }

	fEqs := &filtersEqualities{
		uidEqualities:      make(map[uint64]equality),
		pidEqualities:      make(map[uint64]equality),
		mntNSEqualities:    make(map[uint64]equality),
		pidNSEqualities:    make(map[uint64]equality),
		cgroupIdEqualities: make(map[uint64]equality),
		utsEqualities:      make(map[string]equality),
		commEqualities:     make(map[string]equality),
		binaryEqualities:   make(map[filters.NSBinary]equality),
	}

	if err := ps.computeFilterEqualities(fEqs, cts); err != nil {
		return errfmt.WrapError(err)
	}

	if createNewMaps {
		// Create new filter maps version
		if err := ps.createNewFilterMapsVersion(bpfModule); err != nil {
			return errfmt.WrapError(err)
		}
	}

	// if err := ps.createNewEventsMapVersion()

	// Update UInt equalities filter maps
	if err := ps.updateUIntFilterBPF(fEqs.uidEqualities, UIDFilterMap); err != nil {
		return errfmt.WrapError(err)
	}
	if err := ps.updateUIntFilterBPF(fEqs.pidEqualities, PIDFilterMap); err != nil {
		return errfmt.WrapError(err)
	}
	if err := ps.updateUIntFilterBPF(fEqs.mntNSEqualities, MntNSFilterMap); err != nil {
		return errfmt.WrapError(err)
	}
	if err := ps.updateUIntFilterBPF(fEqs.pidNSEqualities, PidNSFilterMap); err != nil {
		return errfmt.WrapError(err)
	}
	if err := ps.updateUIntFilterBPF(fEqs.cgroupIdEqualities, CgroupIdFilterMap); err != nil {
		return errfmt.WrapError(err)
	}

	// Update String equalities filter maps
	if err := ps.updateStringFilterBPF(fEqs.utsEqualities, UTSFilterMap); err != nil {
		return errfmt.WrapError(err)
	}
	if err := ps.updateStringFilterBPF(fEqs.commEqualities, CommFilterMap); err != nil {
		return errfmt.WrapError(err)
	}

	if updateProcTree {
		// ProcessTreeFilter equalities
		procTreeEqualities := make(map[uint32]equality)
		ps.computeProcTreeEqualities(procTreeEqualities)

		// Update ProcessTree equalities filter map
		if err := ps.updateProcTreeFilterBPF(procTreeEqualities, ProcessTreeFilterMap); err != nil {
			return errfmt.WrapError(err)
		}
	}

	// Update Binary equalities filter map
	if err := ps.updateBinaryFilterBPF(fEqs.binaryEqualities, BinaryFilterMap); err != nil {
		return errfmt.WrapError(err)
	}
	// Update ProcInfo map (required for binary filters)
	if err := populateProcInfoMap(bpfModule, fEqs.binaryEqualities); err != nil {
		return errfmt.WrapError(err)
	}

	// if createNewMaps {
	// 	// Create the policies config map version
	// 	//
	// 	// This must be done after the filter maps have been updated, as the
	// 	// policies config map contains the filter config computed from the
	// 	// policies filters.
	// 	if err := ps.createNewPoliciesConfigMap(bpfModule); err != nil {
	// 		return nil, errfmt.WrapError(err)
	// 	}
	// }

	// Update policies config map version
	// pCfg := ps.computePoliciesConfig()
	// if err := pCfg.UpdateBPF(ps.bpfInnerMaps[PoliciesConfigMap]); err != nil {
	// 	return nil, errfmt.WrapError(err)
	// }

	return nil
}

// createNewPoliciesConfigMap creates a new version of the policies config map
// func (ps *Policies) createNewPoliciesConfigMap(bpfModule *bpf.Module) error {
// 	version := ps.Version()
// 	newInnerMap, err := createNewInnerMap(bpfModule, PoliciesConfigMap, version)
// 	if err != nil {
// 		return errfmt.WrapError(err)
// 	}

// 	// policies_config_version  u16, policies_config_map
// 	if err := updateOuterMap(bpfModule, PoliciesConfigVersion, version, newInnerMap); err != nil {
// 		return errfmt.WrapError(err)
// 	}

// 	ps.bpfInnerMaps[PoliciesConfigMap] = newInnerMap

// 	return nil
// }

// RulesConfig mirrors the C struct rules_config (rules_config_t).
// Order of fields is important, as it is used as part of a value for
// the EventConfig.
type RulesConfig struct {
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
	ProcTreeFilterEnabled uint64
	BinPathFilterEnabled  uint64
	FollowFilterEnabled   uint64

	UIDFilterOut      uint64
	PIDFilterOut      uint64
	MntNsFilterOut    uint64
	PidNsFilterOut    uint64
	UtsNsFilterOut    uint64
	CommFilterOut     uint64
	CgroupIdFilterOut uint64
	ContFilterOut     uint64
	NewContFilterOut  uint64
	NewPidFilterOut   uint64
	ProcTreeFilterOut uint64
	BinPathFilterOut  uint64

	Enabled uint64

	UidMax uint64
	UidMin uint64
	PidMax uint64
	PidMin uint64
}

// EventConfig mirrors the C struct event_config (event_config_t).
// Order of fields is important, as it is used as part of a value for
// the EventsMap.
type EventConfig struct {
	ParamTypes     uint64
	_              uint32 // padding1
	_              uint16 // padding2
	_              uint8  // padding3
	RulesId        uint8
	SubmitForRules uint64
	RulesConfig    RulesConfig
}

func (ec *EventConfig) UpdateBPF(bpfConfigMap *bpf.BPFMapLow, key ruleKey) error {
	if ec == nil {
		return errfmt.Errorf("event config is nil")
	}
	if bpfConfigMap == nil {
		return errfmt.Errorf("bpfConfigMap is nil")
	}

	if err := bpfConfigMap.Update(unsafe.Pointer(&key), unsafe.Pointer(ec)); err != nil {
		return errfmt.WrapError(err)
	}

	return nil
}

// computeRulesConfig computes the rules config from the events set in the policies.
func (ps *Policies) computeRulesConfig(eID events.ID) *RulesConfig {
	cfg := &RulesConfig{}

	for _, p := range ps.allFromMap() {
		ruleVersion, ok := p.ruleVersionByEvent[eID]
		if !ok {
			continue
		}
		offset := ruleVersion - 1

		// filter enabled policies bitmap
		if p.UIDFilter.Enabled() {
			cfg.UIDFilterEnabled |= 1 << offset
		}
		if p.PIDFilter.Enabled() {
			cfg.PIDFilterEnabled |= 1 << offset
		}
		if p.MntNSFilter.Enabled() {
			cfg.MntNsFilterEnabled |= 1 << offset
		}
		if p.PidNSFilter.Enabled() {
			cfg.PidNsFilterEnabled |= 1 << offset
		}
		if p.UTSFilter.Enabled() {
			cfg.UtsNsFilterEnabled |= 1 << offset
		}
		if p.CommFilter.Enabled() {
			cfg.CommFilterEnabled |= 1 << offset
		}
		if p.ContIDFilter.Enabled() {
			cfg.CgroupIdFilterEnabled |= 1 << offset
		}
		if p.ContFilter.Enabled() {
			cfg.ContFilterEnabled |= 1 << offset
		}
		if p.NewContFilter.Enabled() {
			cfg.NewContFilterEnabled |= 1 << offset
		}
		if p.NewPidFilter.Enabled() {
			cfg.NewPidFilterEnabled |= 1 << offset
		}
		if p.ProcessTreeFilter.Enabled() {
			cfg.ProcTreeFilterEnabled |= 1 << offset
		}
		if p.BinaryFilter.Enabled() {
			cfg.BinPathFilterEnabled |= 1 << offset
		}
		if p.Follow {
			cfg.FollowFilterEnabled |= 1 << offset
		}

		// filter out scopes bitmap
		if p.UIDFilter.FilterOut() {
			cfg.UIDFilterOut |= 1 << offset
		}
		if p.PIDFilter.FilterOut() {
			cfg.PIDFilterOut |= 1 << offset
		}
		if p.MntNSFilter.FilterOut() {
			cfg.MntNsFilterOut |= 1 << offset
		}
		if p.PidNSFilter.FilterOut() {
			cfg.PidNsFilterOut |= 1 << offset
		}
		if p.UTSFilter.FilterOut() {
			cfg.UtsNsFilterOut |= 1 << offset
		}
		if p.CommFilter.FilterOut() {
			cfg.CommFilterOut |= 1 << offset
		}
		if p.ContIDFilter.FilterOut() {
			cfg.CgroupIdFilterOut |= 1 << offset
		}
		if p.ContFilter.FilterOut() {
			cfg.ContFilterOut |= 1 << offset
		}
		if p.NewContFilter.FilterOut() {
			cfg.NewContFilterOut |= 1 << offset
		}
		if p.NewPidFilter.FilterOut() {
			cfg.NewPidFilterOut |= 1 << offset
		}
		if p.ProcessTreeFilter.FilterOut() {
			cfg.ProcTreeFilterOut |= 1 << offset
		}
		if p.BinaryFilter.FilterOut() {
			cfg.BinPathFilterOut |= 1 << offset
		}

		cfg.Enabled |= 1 << offset
	}

	cfg.UidMax = ps.uidFilterMax
	cfg.UidMin = ps.uidFilterMin
	cfg.PidMax = ps.pidFilterMax
	cfg.PidMin = ps.pidFilterMin

	return cfg
}
