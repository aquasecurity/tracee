package policy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"syscall"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/common/bitwise"
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/common/proc"
	"github.com/aquasecurity/tracee/pkg/datastores/container"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/data"
	"github.com/aquasecurity/tracee/pkg/filters"
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
	ProcInfoMap           = "proc_info_map"
	EventsConfigMap       = "events_config_map"
	EventsTreeConfigMap   = "events_tree_config_map"
	ProcTreeMembershipMap = "proc_tree_membership"

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
	cts *container.Manager,
	eventsFields map[events.ID][]data.DecodeAs,
) error {
	fMaps, err := pm.computeFilterMaps(cts)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Snapshot the versions currently live in the kernel BEFORE updateEventsConfigMap overwrites
	// them, so the reaper can retain {new pushed, previous pushed}. UpdatePolicy bumps a rules
	// version by +2 (remove+add), so a {cur, cur-1} rule would reap the generation an in-flight
	// kernel program that read the previous config is still doing filter-map lookups against.
	prevPushed := make(map[events.ID]uint16, len(pm.pushedVersions))
	for k, v := range pm.pushedVersions {
		prevPushed[k] = v
	}

	// Reconcile the tree/follow group allocations with the current policy set, then sweep the
	// retired groups' bits out of the kernel per-process state BEFORE anything below uses (or
	// reuses) the indices.
	if _, err := pm.computeTreeGroups(); err != nil {
		return errfmt.WrapError(err)
	}
	if _, err := pm.computeFollowGroups(); err != nil {
		return errfmt.WrapError(err)
	}
	pm.sweepRetiredGroupBits(bpfModule)

	// Seed per-process tree membership (root pids); descendants inherit via fork-time
	// propagation in the kernel.
	if err := pm.seedProcTreeMembership(bpfModule); err != nil {
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

	// events_config_map is written LAST, honoring its documented invariant (maps.h): the
	// rules_version it carries selects the (version, event) filter-map generation, so every
	// versioned filter map above must exist BEFORE the kernel can be told to use them. The
	// reverse order opens a window where an include filter drops every event of that type and
	// an exclude filter matches everything (filter-map lookups miss until the maps land).
	if err := pm.updateEventsConfigMap(bpfModule, eventsFields, fMaps.dataFilterConfigs); err != nil {
		return errfmt.WrapError(err)
	}

	// With the new generation live in the kernel, retire everything unreachable: stale
	// (version, event) inner maps and their outer entries (unbounded FD/memory leak, and
	// eventually E2BIG on the outer maps, without this).
	pm.reapStaleInnerMaps(bpfModule, prevPushed)

	// Publish the computed maps to the manager only after EVERY kernel write succeeded: a
	// partial failure above must not leave later snapshots exporting filter maps the kernel
	// never fully received. (Full rollback of the kernel state is still an open problem -
	// the caller keeps the old snapshot on error - but at least the exported view and the
	// kernel can only disagree in the direction the error already reported.)
	pm.fMaps = fMaps
	// Cache the read-only export consumed per-event by the userland overflow matcher, so the
	// conversion runs once per reload rather than on every overflow event. updateBPF holds
	// the write lock (via UpdateBPF).
	pm.exportedFMaps = buildExportedFilterMaps(fMaps)

	return nil
}

// eBPF data filter only supports first 64 rules for each key.
type stringFilterConfigBPF struct {
	prefixEnabled           uint64
	suffixEnabled           uint64
	exactEnabled            uint64
	prefixMatchIfKeyMissing uint64
	suffixMatchIfKeyMissing uint64
	exactMatchIfKeyMissing  uint64
}

type dataFilterConfigBPF struct {
	string stringFilterConfigBPF
}

// eventConfig must match C event_config_t byte layout EXACTLY (field order). treeTable
// was added between scopeFilters and dataFilter to mirror the C struct.
type eventConfig struct {
	rulesVersion   uint16
	hasOverflow    uint8
	padding        [5]uint8 // free for further use
	submitForRules uint64
	fieldTypes     uint64
	scopeFilters   scopeFiltersConfig
	dataFilter     dataFilterConfigBPF
}

// eventTreeConfig mirrors C event_tree_config_t (kept in a separate map, not in the
// per-CPU event_data, because the rule tables are large).
type eventTreeConfig struct {
	treeTable   treeRuleTable
	followTable treeRuleTable
}

// updateEventsConfigMap updates the events config map with the given events fields and filter config.
func (pm *PolicyManager) updateEventsConfigMap(
	bpfModule *bpf.Module,
	eventsFields map[events.ID][]data.DecodeAs,
	dataFilterConfigs map[events.ID]dataFilterConfig,
) error {
	eventsConfigMap, err := bpfModule.GetMap(EventsConfigMap)
	if err != nil {
		return errfmt.WrapError(err)
	}
	eventsTreeConfigMap, err := bpfModule.GetMap(EventsTreeConfigMap)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Global, stable process-tree policy->group assignment (shared with membership seeding).
	treeGroups, err := pm.computeTreeGroups()
	if err != nil {
		return err
	}
	// Global, stable follow policy->group assignment.
	followGroups, err := pm.computeFollowGroups()
	if err != nil {
		return err
	}

	for id, ecfg := range pm.rules {
		filterConfig, exist := dataFilterConfigs[id]
		if !exist {
			filterConfig = dataFilterConfig{}
		}

		// Extract the first bitmap from each field of stringFilterConfig
		dataFilterCfg := dataFilterConfigBPF{}
		if len(filterConfig.string.prefixEnabled) > 0 {
			dataFilterCfg.string.prefixEnabled = filterConfig.string.prefixEnabled[0]
		}
		if len(filterConfig.string.suffixEnabled) > 0 {
			dataFilterCfg.string.suffixEnabled = filterConfig.string.suffixEnabled[0]
		}
		if len(filterConfig.string.exactEnabled) > 0 {
			dataFilterCfg.string.exactEnabled = filterConfig.string.exactEnabled[0]
		}
		if len(filterConfig.string.prefixMatchIfKeyMissing) > 0 {
			dataFilterCfg.string.prefixMatchIfKeyMissing = filterConfig.string.prefixMatchIfKeyMissing[0]
		}
		if len(filterConfig.string.suffixMatchIfKeyMissing) > 0 {
			dataFilterCfg.string.suffixMatchIfKeyMissing = filterConfig.string.suffixMatchIfKeyMissing[0]
		}
		if len(filterConfig.string.exactMatchIfKeyMissing) > 0 {
			dataFilterCfg.string.exactMatchIfKeyMissing = filterConfig.string.exactMatchIfKeyMissing[0]
		}

		// encoded event's field types
		var fieldTypes uint64
		fields := eventsFields[id]
		for n, fieldType := range fields {
			fieldTypes = fieldTypes | (uint64(fieldType) << (8 * n))
		}

		// Submit bitmap from the REAL rule IDs (word 0 only; overflow rules are evaluated in
		// userland). Stable rule IDs can leave gaps below rulesCount when a rule retires; a
		// gap bit carries no rule, so no scope filter is enabled for it and it would survive
		// every kernel filter (mask = ~enabled) - making matched_rules != 0 for every task
		// and silently disabling kernel pushdown for the event until the gap refills.
		submitForRules := uint64(0)
		for ruleID := range ecfg.ruleIDToEventRule {
			if ruleID < 64 {
				submitForRules |= uint64(1) << ruleID
			}
		}

		// Set hasOverflow flag
		var overflowFlag uint8
		if ecfg.hasOverflow {
			overflowFlag = 1
		}

		// TODO: this should be saved in poicy manager as well, next to fMaps
		scopeFiltersConfig := pm.computeBPFScopeFiltersConfig(id)

		eventConfig := eventConfig{
			rulesVersion:   ecfg.rulesVersion,
			hasOverflow:    overflowFlag,
			submitForRules: submitForRules,
			fieldTypes:     fieldTypes,
			scopeFilters:   scopeFiltersConfig,
			dataFilter:     dataFilterCfg,
		}

		// Tree + follow rule tables go in a separate map, kept out of the per-CPU
		// event_data_t (which is near the 32KB per-CPU limit). Written BEFORE the event
		// config: the config's tree/follow enabled bits and rule IDs reference this table,
		// so the reverse order would let the kernel evaluate the new bits against the old
		// table for a window.
		treeTable, err := pm.computeTreeRuleTable(id, treeGroups)
		if err != nil {
			return err
		}
		followTable, err := pm.computeFollowRuleTable(id, followGroups)
		if err != nil {
			return err
		}
		eventTreeCfg := eventTreeConfig{treeTable: treeTable, followTable: followTable}
		if err := eventsTreeConfigMap.Update(unsafe.Pointer(&id), unsafe.Pointer(&eventTreeCfg)); err != nil {
			return errfmt.WrapError(err)
		}

		if err := eventsConfigMap.Update(unsafe.Pointer(&id), unsafe.Pointer(&eventConfig)); err != nil {
			return errfmt.WrapError(err)
		}
		// Record the version now live in the kernel for this event: the reaper retains this
		// (and the previous pushed version) rather than {cur, cur-1}, and the net-event
		// userland scope pass keys exportedFMaps by it. Set only here, on a successful write,
		// so it never claims a version the kernel does not actually hold.
		pm.pushedVersions[id] = eventConfig.rulesVersion
	}

	// Delete the entries of events that no longer have rules (a policy removal can deselect
	// an event entirely): a stale entry would keep the old submit_for_rules and filter config
	// alive in the kernel indefinitely. Keys are collected first - deleting while iterating a
	// BPF hash map can skip entries.
	var staleKeys []uint32
	it := eventsConfigMap.Iterator()
	for it.Next() {
		key := binary.LittleEndian.Uint32(it.Key())
		if _, ok := pm.rules[events.ID(key)]; !ok {
			staleKeys = append(staleKeys, key)
		}
	}
	// A partial iteration would leave some stale config entries alive; surface it rather than
	// silently skip them (they keep old submit_for_rules/filter config in the kernel).
	if err := it.Err(); err != nil {
		return errfmt.WrapError(err)
	}
	for _, key := range staleKeys {
		k := key
		if err := eventsConfigMap.DeleteKey(unsafe.Pointer(&k)); err != nil {
			logger.Debugw("Deleting stale events_config entry", "event", k, "error", err)
		}
		// The tree config entry is best-effort: it may never have been written for this event.
		_ = eventsTreeConfigMap.DeleteKey(unsafe.Pointer(&k))
		// The event holds no version in the kernel any more; drop its pushed-version record so
		// the reaper frees all of its filter-map generations.
		delete(pm.pushedVersions, events.ID(key))
	}

	return nil
}

// groupAllocator hands out STABLE bit positions (groups) to policies for the per-process
// tree/follow membership words. Stability is a correctness requirement, not a nicety: a
// policy's group bit is persisted in kernel per-process state (proc_tree_membership /
// proc_info.follow_in_scopes) that outlives any single rules push. If indices were
// positional (sorted-name order), removing one policy would shift every later policy onto
// a bit still set for the REMOVED policy's processes - matching whole wrong subtrees.
//
// A retired index is not reusable until its bit has been SWEPT from the kernel maps
// (sweepRetiredGroupBits); until then it is quarantined in pending.
type groupAllocator struct {
	byName map[string]uint8
	used   map[uint8]bool
	// A retired index passes through TWO quarantine generations before it is reusable:
	// pending (retired this generation, not yet swept) -> sweptOnce (swept once, kept one more
	// generation). Both are re-swept every push and neither may be reassigned. The extra
	// generation catches the sweep-vs-fork race: the kernel fork hook COPIES a parent's whole
	// membership eq_t to a child, so a fork between the sweep's key-collection and the parent's
	// clear can leave a child carrying a just-retired bit; that child key exists by the next
	// push and is caught by the second sweep. (A fork racing the SECOND sweep is still possible -
	// the fully race-free fix is a kernel-side "valid groups" mask ANDed at match time; this
	// bounds the exposure to processes forked during a single operator-rare sweep.)
	pending   map[uint8]bool
	sweptOnce map[uint8]bool
	limit     int
}

func newGroupAllocator(limit int) *groupAllocator {
	return &groupAllocator{
		byName:    make(map[string]uint8),
		used:      make(map[uint8]bool),
		pending:   make(map[uint8]bool),
		sweptOnce: make(map[uint8]bool),
		limit:     limit,
	}
}

// getOrAssign returns the policy's existing group, or the smallest index that is neither in
// use nor awaiting sweep.
func (a *groupAllocator) getOrAssign(name string) (uint8, error) {
	if g, ok := a.byName[name]; ok {
		return g, nil
	}
	for i := 0; i < a.limit; i++ {
		g := uint8(i)
		if !a.used[g] && !a.pending[g] && !a.sweptOnce[g] {
			a.byName[name] = g
			a.used[g] = true
			return g, nil
		}
	}
	return 0, errfmt.Errorf(
		"no free tree/follow group (max %d concurrent policies; %d awaiting cleanup)",
		a.limit, len(a.pending)+len(a.sweptOnce))
}

// reconcile retires every allocated name absent from current (policy removed, or its
// tree/follow filter dropped by an update), quarantining the freed indices until swept.
func (a *groupAllocator) reconcile(current map[string]bool) {
	for name, g := range a.byName {
		if !current[name] {
			delete(a.byName, name)
			delete(a.used, g)
			a.pending[g] = true
		}
	}
}

// retire quarantines a still-present policy's index (so getOrAssign hands it a fresh one and
// the sweep clears the old one). Used when a surviving policy's ROOT SET changed: its group
// bit persists in the kernel per-process membership of its OLD roots' subtrees, so it must be
// swept and reassigned or the policy would keep matching both the old and new subtrees.
func (a *groupAllocator) retire(name string) {
	if g, ok := a.byName[name]; ok {
		delete(a.byName, name)
		delete(a.used, g)
		a.pending[g] = true
	}
}

// pendingMask returns the bitmask of ALL quarantined indices (both generations), which the
// sweep clears from the kernel membership maps every push.
func (a *groupAllocator) pendingMask() uint64 {
	var mask uint64
	for g := range a.pending {
		mask |= uint64(1) << g
	}
	for g := range a.sweptOnce {
		mask |= uint64(1) << g
	}
	return mask
}

// sweepDone advances the two-generation quarantine on a successful sweep: indices swept twice
// (sweptOnce) are released for reuse; indices swept once this push (pending) move to sweptOnce
// for a second pass next push.
func (a *groupAllocator) sweepDone() {
	a.sweptOnce = a.pending
	a.pending = make(map[uint8]bool)
}

// computeTreeGroups assigns a stable group index (bit position in the per-process
// proc_tree_membership eq_t) to each POLICY that has a process-tree filter. All of a
// policy's roots fold into its single group bit, so the number of roots is unbounded; the
// only cap is 64 concurrently-live policies-using-tree (one membership word), which matches
// the effective limit of the prior per-policy model. Assignment order is name-sorted so a
// fresh load is reproducible; RUNTIME add/remove keeps existing indices (see groupAllocator
// for why that is a correctness requirement). Exceeding the cap is a hard error (never a
// silent truncation): a dropped tree filter is silently wrong filtering.
func (pm *PolicyManager) computeTreeGroups() (map[string]uint8, error) {
	current := make(map[string]bool)
	names := make([]string, 0)
	for name, policy := range pm.policies {
		if policy == nil || policy.ProcessTreeFilter == nil || !policy.ProcessTreeFilter.Enabled() {
			continue
		}
		current[name] = true
		names = append(names, name)
	}
	sort.Strings(names)

	pm.treeGroupAlloc.reconcile(current)
	// A SURVIVING policy that changed its root set keeps its group bit, but that bit still
	// marks its OLD roots' subtrees in the kernel membership map - so it would keep matching
	// them. Force-retire its bit on a root-set change: the sweep clears the old subtrees and it
	// gets a fresh bit seeded to the new roots. (reconcile already handled removed policies.)
	for _, name := range names {
		sig := treeRootSignature(pm.policies[name].ProcessTreeFilter)
		if old, ok := pm.treeRootSig[name]; ok && old != sig {
			pm.treeGroupAlloc.retire(name)
		}
		pm.treeRootSig[name] = sig
	}
	for name := range pm.treeRootSig {
		if !current[name] {
			delete(pm.treeRootSig, name)
		}
	}

	groups := make(map[string]uint8, len(names))
	for _, name := range names {
		g, err := pm.treeGroupAlloc.getOrAssign(name)
		if err != nil {
			return nil, errfmt.Errorf("process-tree (tree) filter groups: %v", err)
		}
		groups[name] = g
	}
	return groups, nil
}

// treeRootSignature is an order-independent digest of a process-tree filter's root pids (both =
// and != roots), used to detect when a surviving policy's root set changed between pushes.
func treeRootSignature(f *filters.ProcessTreeFilter) uint64 {
	if f == nil {
		return 0
	}
	eq := f.Equalities()
	// FNV-1a over the pid set; XOR-combined so order does not matter.
	var sig uint64 = 1469598103934665603
	mix := func(pid uint32, eqBit uint64) {
		h := (uint64(pid) << 1) | eqBit
		h ^= 1099511628211
		sig ^= h * 1099511628211
	}
	for pid := range eq.Equal {
		mix(pid, 1)
	}
	for pid := range eq.NotEqual {
		mix(pid, 0)
	}
	return sig
}

// computeTreeRuleTable builds the per-event tree rule table (mirrors C tree_rule_table_t): for
// each of the event's rules whose policy has a process-tree filter, record the rule under
// its policy's tree group. The =/!= sense is NOT carried here - it lives in the per-process
// membership eq_t (seeded by seedProcTreeMembership) plus the per-rule
// proc_tree_filter_match_if_key_missing bitmap, so the kernel folds membership into matched
// rules with the generic equality formula. Exceeding maxTreeGroupsPerEvent is a hard error
// (never a silent truncation).
// NOTE: tree filters are supported for rule IDs 0-63 (single word); overflow rules with
// tree filters are a TODO.
func (pm *PolicyManager) computeTreeRuleTable(
	eventID events.ID, treeGroups map[string]uint8,
) (treeRuleTable, error) {
	var table treeRuleTable

	eventRules, ok := pm.rules[eventID]
	if !ok {
		return table, nil
	}

	perGroup := make(map[uint8]uint64) // tree-group -> rule bitmap
	for _, rule := range eventRules.Rules {
		if rule.Policy == nil || rule.Policy.ProcessTreeFilter == nil ||
			!rule.Policy.ProcessTreeFilter.Enabled() {
			continue
		}
		g, ok := treeGroups[rule.Policy.Name]
		if !ok {
			continue
		}
		// The table's rule bitmaps are single u64 words: a tree-filtered rule at ID >= 64
		// cannot be represented and has NO userland fallback either - silently skipping it
		// (SetBit over-shifts to a no-op) would drop the tree filter entirely. Hard error.
		if rule.ID >= 64 {
			return table, errfmt.Errorf(
				"event %d: tree-filtered rule of policy %q got overflow rule ID %d (tree filters support rule IDs 0-63)",
				eventID, rule.Policy.Name, rule.ID)
		}
		v := perGroup[g]
		bitwise.SetBit(&v, rule.ID)
		perGroup[g] = v
	}

	// Fill the fixed-size groups array in stable order.
	gidxs := make([]uint8, 0, len(perGroup))
	for g := range perGroup {
		gidxs = append(gidxs, g)
	}
	sort.Slice(gidxs, func(i, j int) bool { return gidxs[i] < gidxs[j] })

	if len(gidxs) > maxTreeGroupsPerEvent {
		return table, errfmt.Errorf(
			"event %d is selected by %d process-tree groups; max %d per event",
			eventID, len(gidxs), maxTreeGroupsPerEvent)
	}

	for _, g := range gidxs {
		table.Groups[table.NumGroups] = treeGroupRules{Group: g, Rules: perGroup[g]}
		table.NumGroups++
	}

	return table, nil
}

// maxProcTreeWalkDepth bounds the startup ancestry walk (guards against /proc cycles from
// pid reuse); deeper than any realistic process tree, so effectively unbounded.
const maxProcTreeWalkDepth = 1024

// seedProcTreeMembership writes the initial per-process tree membership as an eq_t keyed by
// host_pid, with bits indexed by tree GROUP (policy): equals_in_rules bit g for processes
// under an "=" (include) root of group g, key_used_in_rules bit g for processes under any
// root of group g. All of a policy's roots fold into its group bit, so the number of roots
// is unbounded. Both the named root pids and their already-running descendants are seeded
// (matching the prior per-policy model); descendants that appear later inherit via the
// kernel fork-time propagation in sched_process_fork.
func (pm *PolicyManager) seedProcTreeMembership(bpfModule *bpf.Module) error {
	treeGroups, err := pm.computeTreeGroups()
	if err != nil {
		return err
	}
	if len(treeGroups) == 0 {
		return nil
	}

	// Build the eq_t contribution of each ROOT pid: equals+key_used for "=" (include) roots,
	// key_used only for "!=" (exclude) roots. A pid may be a root in several policies/groups.
	rootEq := make(map[uint32]*ruleBitmap)
	contrib := func(pid uint32, g uint8, equal bool) {
		rb := rootEq[pid]
		if rb == nil {
			rb = &ruleBitmap{}
			rootEq[pid] = rb
		}
		bitwise.SetBit(&rb.keyUsedInRules, uint(g))
		if equal {
			bitwise.SetBit(&rb.equalsInRules, uint(g))
		}
	}
	for name, policy := range pm.policies {
		if policy == nil || policy.ProcessTreeFilter == nil || !policy.ProcessTreeFilter.Enabled() {
			continue
		}
		g := treeGroups[name]
		eq := policy.ProcessTreeFilter.Equalities()
		for pid := range eq.Equal {
			contrib(pid, g, true)
		}
		for pid := range eq.NotEqual {
			contrib(pid, g, false)
		}
	}

	membershipMap, err := bpfModule.GetMap(ProcTreeMembershipMap)
	if err != nil {
		return errfmt.WrapError(err)
	}
	writeEq := func(pid uint32, rb *ruleBitmap) error {
		key := pid
		val := make([]byte, ruleBitmapSize)
		binary.LittleEndian.PutUint64(val[0:8], rb.equalsInRules)
		binary.LittleEndian.PutUint64(val[8:16], rb.keyUsedInRules)
		if err := membershipMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&val[0])); err != nil {
			return errfmt.WrapError(err)
		}
		return nil
	}

	// Seed the named root pids first, so a root that is ALSO a descendant of another policy's
	// root still gets its own contribution as the base (the descendant pass below then ORs in
	// the inherited ancestry - it must not overwrite/substitute).
	pids, err := listProcPids()
	if err != nil {
		logger.Warnw("tree: could not enumerate /proc for descendant seeding", "error", err)
		// Roots are still seeded below from rootEq alone.
		pids = nil
	}

	// For each live process compute its FULL membership in one pass: its own root contribution
	// (if it is a named root) OR'd with every root ANCESTOR's contribution. A root that is also
	// a descendant thus keeps both bits, which the previous "roots verbatim, skip roots in the
	// descendant walk" split silently dropped.
	seeded := make(map[uint32]bool, len(pids))
	for _, pid := range pids {
		acc := ruleBitmap{}
		if rb, ok := rootEq[pid]; ok { // this pid's own root contribution
			acc.equalsInRules |= rb.equalsInRules
			acc.keyUsedInRules |= rb.keyUsedInRules
		}
		cur := pid
		for depth := 0; depth < maxProcTreeWalkDepth; depth++ {
			ppid, ok := getPPid(cur)
			if !ok {
				break
			}
			// Check the ancestor BEFORE the init cutoff: pid 1 itself can be a root
			// (tree=1 means "everything").
			if rb, ok := rootEq[ppid]; ok {
				acc.equalsInRules |= rb.equalsInRules
				acc.keyUsedInRules |= rb.keyUsedInRules
			}
			if ppid <= 1 {
				break
			}
			cur = ppid
		}
		if acc.equalsInRules != 0 || acc.keyUsedInRules != 0 {
			if err := writeEq(pid, &acc); err != nil {
				return err
			}
			seeded[pid] = true
		}
	}

	// A named root that is not currently in /proc (already exited, or the enumeration failed)
	// still needs its own contribution seeded so a matching pid reappearing under it inherits
	// correctly via fork-time propagation.
	for pid, rb := range rootEq {
		if seeded[pid] {
			continue
		}
		if err := writeEq(pid, rb); err != nil {
			return err
		}
	}
	return nil
}

// sweepRetiredGroupBits clears retired tree/follow group bits from the kernel's per-process
// state, then releases the quarantined indices for reuse. Without this, a NEW policy assigned
// a freed index would inherit the REMOVED policy's per-process memberships (whole wrong
// subtrees matching). Best-effort per entry: the kernel mutates these maps concurrently
// (fork-time propagation), so a child forked from a stale parent mid-sweep can briefly keep a
// stale bit - bounded residue, cleared the next time the entry is rewritten. Sweep failures
// keep the indices quarantined (retried on the next push) rather than risking reuse.
func (pm *PolicyManager) sweepRetiredGroupBits(bpfModule *bpf.Module) {
	// Tree membership: eq_t (equals, key_used) keyed by host pid.
	if mask := pm.treeGroupAlloc.pendingMask(); mask != 0 {
		if err := sweepMaskFromEqMap(bpfModule, ProcTreeMembershipMap, mask); err != nil {
			logger.Warnw("tree: sweeping retired group bits failed; indices stay quarantined", "error", err)
		} else {
			pm.treeGroupAlloc.sweepDone()
		}
	}

	// Follow membership: u64 follow_in_scopes inside proc_info_t (offset 8), keyed by host pid.
	if mask := pm.followGroupAlloc.pendingMask(); mask != 0 {
		if err := sweepMaskFromProcInfoFollow(bpfModule, mask); err != nil {
			logger.Warnw("follow: sweeping retired group bits failed; indices stay quarantined", "error", err)
		} else {
			pm.followGroupAlloc.sweepDone()
		}
	}
}

// sweepMaskFromEqMap masks the given bits off both eq_t words of every entry in a
// pid-keyed eq_t map, deleting entries that become empty.
func sweepMaskFromEqMap(bpfModule *bpf.Module, mapName string, mask uint64) error {
	m, err := bpfModule.GetMap(mapName)
	if err != nil {
		return errfmt.WrapError(err)
	}

	var keys []uint32
	it := m.Iterator()
	for it.Next() {
		keys = append(keys, binary.LittleEndian.Uint32(it.Key()))
	}
	// A partial iteration must NOT be reported as a completed sweep: the caller releases the
	// quarantined group indices only on success, so an aborted sweep that returned nil would
	// hand out an index whose bits are still live in unseen entries.
	if err := it.Err(); err != nil {
		return errfmt.WrapError(err)
	}
	for _, pid := range keys {
		k := pid
		val, err := m.GetValue(unsafe.Pointer(&k))
		if err != nil || len(val) < ruleBitmapSize {
			continue // entry vanished mid-sweep
		}
		equals := binary.LittleEndian.Uint64(val[0:8]) &^ mask
		keyUsed := binary.LittleEndian.Uint64(val[8:16]) &^ mask
		if equals == 0 && keyUsed == 0 {
			_ = m.DeleteKey(unsafe.Pointer(&k))
			continue
		}
		binary.LittleEndian.PutUint64(val[0:8], equals)
		binary.LittleEndian.PutUint64(val[8:16], keyUsed)
		if err := m.Update(unsafe.Pointer(&k), unsafe.Pointer(&val[0])); err != nil {
			return errfmt.WrapError(err)
		}
	}
	return nil
}

// sweepMaskFromProcInfoFollow masks the given bits off proc_info.follow_in_scopes (u64 at
// offset 8) of every proc_info_map entry.
func sweepMaskFromProcInfoFollow(bpfModule *bpf.Module, mask uint64) error {
	m, err := bpfModule.GetMap(ProcInfoMap)
	if err != nil {
		return errfmt.WrapError(err)
	}

	var keys []uint32
	it := m.Iterator()
	for it.Next() {
		keys = append(keys, binary.LittleEndian.Uint32(it.Key()))
	}
	// See sweepMaskFromEqMap: an aborted iteration must not be reported as a full sweep.
	if err := it.Err(); err != nil {
		return errfmt.WrapError(err)
	}
	for _, pid := range keys {
		k := pid
		val, err := m.GetValue(unsafe.Pointer(&k))
		if err != nil || len(val) < 16 {
			continue
		}
		follow := binary.LittleEndian.Uint64(val[8:16])
		if follow&mask == 0 {
			continue
		}
		binary.LittleEndian.PutUint64(val[8:16], follow&^mask)
		if err := m.Update(unsafe.Pointer(&k), unsafe.Pointer(&val[0])); err != nil {
			return errfmt.WrapError(err)
		}
	}
	return nil
}

// listProcPids returns the host pids of all processes currently in /proc.
func listProcPids() ([]uint32, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	pids := make([]uint32, 0, len(entries))
	for _, e := range entries {
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue // non-numeric /proc entry
		}
		pids = append(pids, uint32(pid))
	}
	return pids, nil
}

// getPPid returns the parent host pid of pid (false if it can't be read).
func getPPid(pid uint32) (uint32, bool) {
	if pid > math.MaxInt32 {
		return 0, false // cannot represent as int32 for the proc API (not a valid pid)
	}
	status, err := proc.NewProcStatusFields(int32(pid), []proc.StatusField{proc.PPid})
	if err != nil {
		return 0, false
	}
	ppid := status.GetPPid()
	if ppid < 0 {
		return 0, false
	}
	return uint32(ppid), true
}

// computeFollowGroups assigns a stable group index (bit position in a process's follow
// membership, proc_info.follow_in_scopes) to each policy that has follow=true. follow has
// no per-value explosion (one bit per policy), so it is kept as a plain u64 membership;
// the cap is 64 concurrently-live policies-using-follow. Indices are STABLE across runtime
// add/remove (see groupAllocator - follow bits persist in kernel per-process state).
// Exceeding the cap is a hard error (never silent): a dropped follow group means a process
// silently stops being followed.
func (pm *PolicyManager) computeFollowGroups() (map[string]uint8, error) {
	current := make(map[string]bool)
	names := make([]string, 0)
	for name, policy := range pm.policies {
		if policy != nil && policy.Follow {
			current[name] = true
			names = append(names, name)
		}
	}
	sort.Strings(names)

	pm.followGroupAlloc.reconcile(current)

	groups := make(map[string]uint8, len(names))
	for _, name := range names {
		g, err := pm.followGroupAlloc.getOrAssign(name)
		if err != nil {
			return nil, errfmt.Errorf("follow filter groups: %v", err)
		}
		groups[name] = g
	}
	return groups, nil
}

// computeFollowRuleTable builds the per-event follow rule table (reuses treeRuleTable): for
// each of the event's rules whose policy has follow=true, record the rule under its policy's
// follow-group. The kernel uses this both to mark a process as followed when a follow rule
// matches and to force-match an already-followed process's events. Exceeding
// maxTreeGroupsPerEvent is a hard error (never a silent truncation).
func (pm *PolicyManager) computeFollowRuleTable(
	eventID events.ID, followGroups map[string]uint8,
) (treeRuleTable, error) {
	var table treeRuleTable

	eventRules, ok := pm.rules[eventID]
	if !ok {
		return table, nil
	}

	perGroup := make(map[uint8]uint64) // follow-group -> rule bitmap
	for _, rule := range eventRules.Rules {
		if rule.Policy == nil || !rule.Policy.Follow {
			continue
		}
		g, ok := followGroups[rule.Policy.Name]
		if !ok {
			continue
		}
		// Same single-word constraint as computeTreeRuleTable: an overflow rule ID would be
		// silently dropped (no kernel representation, no userland fallback). Hard error.
		if rule.ID >= 64 {
			return table, errfmt.Errorf(
				"event %d: follow rule of policy %q got overflow rule ID %d (follow supports rule IDs 0-63)",
				eventID, rule.Policy.Name, rule.ID)
		}
		v := perGroup[g]
		bitwise.SetBit(&v, rule.ID)
		perGroup[g] = v
	}

	gidxs := make([]uint8, 0, len(perGroup))
	for g := range perGroup {
		gidxs = append(gidxs, g)
	}
	sort.Slice(gidxs, func(i, j int) bool { return gidxs[i] < gidxs[j] })

	if len(gidxs) > maxTreeGroupsPerEvent {
		return table, errfmt.Errorf(
			"event %d is selected by %d follow groups; max %d per event",
			eventID, len(gidxs), maxTreeGroupsPerEvent)
	}

	for _, g := range gidxs {
		table.Groups[table.NumGroups] = treeGroupRules{Group: g, Rules: perGroup[g]}
		table.NumGroups++
	}

	return table, nil
}

// ScopeFiltersConfig mirrors the C struct scope_filters_config (scope_filters_config_t).
// Order of fields is important, as it is used as a value for the EventsConfigMap BPF map.
// Field order MUST match C scope_filters_config_t exactly. ContStarted/ProcTree/
// Follow are re-added for parity, in the same positions as the C struct.
type scopeFiltersConfig struct {
	UIDFilterEnabled         uint64
	PIDFilterEnabled         uint64
	MntNsFilterEnabled       uint64
	PidNsFilterEnabled       uint64
	UtsNsFilterEnabled       uint64
	CommFilterEnabled        uint64
	CgroupIdFilterEnabled    uint64
	ContFilterEnabled        uint64
	NewContFilterEnabled     uint64
	ContStartedFilterEnabled uint64
	NewPidFilterEnabled      uint64
	ProcTreeFilterEnabled    uint64
	BinPathFilterEnabled     uint64
	FollowFilterEnabled      uint64

	UIDFilterMatchIfKeyMissing         uint64
	PIDFilterMatchIfKeyMissing         uint64
	MntNsFilterMatchIfKeyMissing       uint64
	PidNsFilterMatchIfKeyMissing       uint64
	UtsNsFilterMatchIfKeyMissing       uint64
	CommFilterMatchIfKeyMissing        uint64
	CgroupIdFilterMatchIfKeyMissing    uint64
	ContFilterMatchIfKeyMissing        uint64
	NewContFilterMatchIfKeyMissing     uint64
	ContStartedFilterMatchIfKeyMissing uint64
	NewPidFilterMatchIfKeyMissing      uint64
	ProcTreeFilterMatchIfKeyMissing    uint64
	BinPathFilterMatchIfKeyMissing     uint64
}

// treeGroupRules / treeRuleTable mirror C tree_group_rules_t / tree_rule_table_t.
const maxTreeGroupsPerEvent = 8

type treeGroupRules struct {
	Group uint8
	_     [7]uint8
	Rules uint64
}

type treeRuleTable struct {
	NumGroups uint32
	_         uint32
	Groups    [maxTreeGroupsPerEvent]treeGroupRules
}

// extendedScopeFiltersConfig supports overflow rules (ID > 64) using bitmap arrays
type extendedScopeFiltersConfig struct {
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

// effectiveMatchIfMissing returns the "match if key missing" flag of the FIRST enabled scope source
// (policy, else detector, else per-rule). A disabled/empty filter's MatchIfKeyMissing() is vacuously
// true, so the flag MUST come from the source that actually enabled the dimension - otherwise a
// detector- or per-rule-scoped rule (empty policy filter) would inherit a spurious match-if-missing and
// match every key-missing event (e.g. a per-rule executable= or uid= rule matching the wrong binary/uid).
func effectiveMatchIfMissing(policyEnabled, policyMIM, detEnabled, detMIM, perRuleEnabled, perRuleMIM bool) bool {
	switch {
	case policyEnabled:
		return policyMIM
	case detEnabled:
		return detMIM
	case perRuleEnabled:
		return perRuleMIM
	}
	return false
}

// computeScopeFiltersConfig computes the per-dimension "enabled" and "match-if-key-missing" bitmaps for an
// event's rules. This drives BOTH the kernel scope config (computeBPFScopeFiltersConfig extracts rules
// 0-63 into events_config_map) and the userland overflow evaluation (matchOverflowRules, rules >= 64), so
// it must mark a dimension enabled whenever processRuleScopeFilters pushes a value for it.
func (pm *PolicyManager) computeScopeFiltersConfig(eventID events.ID) extendedScopeFiltersConfig {
	cfg := extendedScopeFiltersConfig{}

	eventRules, ok := pm.rules[eventID]
	if !ok {
		return cfg
	}

	// For each kernel-representable dimension the effective filter is the policy scope, else the
	// detector-declared scope (rule.DetectorScopeFilter), else the rule's per-rule scope
	// (rule.Data.ScopeFilter) - matching processRuleScopeFilters. matchPolicies ANDs the per-rule scope
	// in user space as a backstop, and covers dimensions the kernel cannot represent.
	for _, rule := range eventRules.Rules {
		if rule.Policy == nil {
			continue
		}

		ruleID := rule.ID
		perRule := ruleDataScope(rule)
		ds := rule.DetectorScopeFilter

		// comm uses the shared effective-source resolver (policy/detector/per-rule) so the enabled config
		// here cannot disagree with the map values written by processRuleScopeFilters. container is not
		// pushed per-rule (see processRuleScopeFilters), so it only falls back to the detector scope.
		commFilter := effectiveScopeComm(rule)
		utsFilter := effectiveScopeUTS(rule)
		contFilter := rule.Policy.ContFilter
		contStartedFilter := rule.Policy.ContStartedFilter
		if ds := rule.DetectorScopeFilter; ds != nil {
			if !contFilter.Enabled() {
				contFilter = ds.Container()
			}
			if !contStartedFilter.Enabled() {
				contStartedFilter = ds.ContainerStarted()
			}
		}
		// Per-rule container scope (rule `filters:`): container/container-started are a config-only bool
		// (no value map), so folding them here is all that is needed to push them to the kernel.
		// matchPolicies still ANDs rule.Data.ScopeFilter as a backstop.
		if perRule != nil {
			if !contFilter.Enabled() && perRule.Container().Enabled() {
				contFilter = perRule.Container()
			}
			if !contStartedFilter.Enabled() && perRule.ContainerStarted().Enabled() {
				contStartedFilter = perRule.ContainerStarted()
			}
		}

		// Enabled filters bitmap array (policy, else detector, else per-rule scope).
		if rule.Policy.UIDFilter.Enabled() {
			bitwise.SetBitInArray(&cfg.UIDFilterEnabled, ruleID)
		} else if ds := rule.DetectorScopeFilter; ds != nil && ds.UID().Enabled() {
			bitwise.SetBitInArray(&cfg.UIDFilterEnabled, ruleID)
		} else if perRule != nil && perRule.UID().Enabled() {
			bitwise.SetBitInArray(&cfg.UIDFilterEnabled, ruleID)
		}
		if rule.Policy.PIDFilter.Enabled() {
			bitwise.SetBitInArray(&cfg.PIDFilterEnabled, ruleID)
		} else if ds := rule.DetectorScopeFilter; ds != nil && ds.PID().Enabled() {
			bitwise.SetBitInArray(&cfg.PIDFilterEnabled, ruleID)
		} else if perRule != nil && perRule.PID().Enabled() {
			bitwise.SetBitInArray(&cfg.PIDFilterEnabled, ruleID)
		}
		if rule.Policy.MntNSFilter.Enabled() {
			bitwise.SetBitInArray(&cfg.MntNsFilterEnabled, ruleID)
		} else if ds := rule.DetectorScopeFilter; ds != nil && ds.MntNS().Enabled() {
			bitwise.SetBitInArray(&cfg.MntNsFilterEnabled, ruleID)
		} else if perRule != nil && perRule.MntNS().Enabled() {
			bitwise.SetBitInArray(&cfg.MntNsFilterEnabled, ruleID)
		}
		if rule.Policy.PidNSFilter.Enabled() {
			bitwise.SetBitInArray(&cfg.PidNsFilterEnabled, ruleID)
		} else if ds := rule.DetectorScopeFilter; ds != nil && ds.PidNS().Enabled() {
			bitwise.SetBitInArray(&cfg.PidNsFilterEnabled, ruleID)
		} else if perRule != nil && perRule.PidNS().Enabled() {
			bitwise.SetBitInArray(&cfg.PidNsFilterEnabled, ruleID)
		}
		if utsFilter.Enabled() {
			bitwise.SetBitInArray(&cfg.UtsNsFilterEnabled, ruleID)
		}
		if commFilter.Enabled() {
			bitwise.SetBitInArray(&cfg.CommFilterEnabled, ruleID)
		}
		if rule.Policy.ContIDFilter.Enabled() {
			bitwise.SetBitInArray(&cfg.CgroupIdFilterEnabled, ruleID)
		}
		if contFilter.Enabled() {
			bitwise.SetBitInArray(&cfg.ContFilterEnabled, ruleID)
		}
		if rule.Policy.NewContFilter.Enabled() {
			bitwise.SetBitInArray(&cfg.NewContFilterEnabled, ruleID)
		}
		if contStartedFilter.Enabled() {
			bitwise.SetBitInArray(&cfg.ContStartedFilterEnabled, ruleID)
		}
		if rule.Policy.NewPidFilter.Enabled() {
			bitwise.SetBitInArray(&cfg.NewPidFilterEnabled, ruleID)
		}
		if rule.Policy.ProcessTreeFilter.Enabled() {
			bitwise.SetBitInArray(&cfg.ProcTreeFilterEnabled, ruleID)
		}
		if rule.Policy.BinaryFilter.Enabled() {
			bitwise.SetBitInArray(&cfg.BinPathFilterEnabled, ruleID)
		} else if ds := rule.DetectorScopeFilter; ds != nil && ds.Binary().Enabled() {
			bitwise.SetBitInArray(&cfg.BinPathFilterEnabled, ruleID)
		} else if perRule != nil && perRule.Binary().Enabled() {
			bitwise.SetBitInArray(&cfg.BinPathFilterEnabled, ruleID)
		}
		if rule.Policy.Follow {
			bitwise.SetBitInArray(&cfg.FollowFilterEnabled, ruleID)
		}

		// MatchIfKeyMissing bitmap array. Taken from the FIRST enabled source (policy/detector/per-rule)
		// so an empty policy filter's vacuous MatchIfKeyMissing()==true is never inherited by a detector-
		// or per-rule-scoped rule (see effectiveMatchIfMissing).
		if effectiveMatchIfMissing(
			rule.Policy.UIDFilter.Enabled(), rule.Policy.UIDFilter.MatchIfKeyMissing(),
			ds != nil && ds.UID().Enabled(), ds != nil && ds.UID().MatchIfKeyMissing(),
			perRule != nil && perRule.UID().Enabled(), perRule != nil && perRule.UID().MatchIfKeyMissing(),
		) {
			bitwise.SetBitInArray(&cfg.UIDFilterMatchIfKeyMissing, ruleID)
		}
		if effectiveMatchIfMissing(
			rule.Policy.PIDFilter.Enabled(), rule.Policy.PIDFilter.MatchIfKeyMissing(),
			ds != nil && ds.PID().Enabled(), ds != nil && ds.PID().MatchIfKeyMissing(),
			perRule != nil && perRule.PID().Enabled(), perRule != nil && perRule.PID().MatchIfKeyMissing(),
		) {
			bitwise.SetBitInArray(&cfg.PIDFilterMatchIfKeyMissing, ruleID)
		}
		if effectiveMatchIfMissing(
			rule.Policy.MntNSFilter.Enabled(), rule.Policy.MntNSFilter.MatchIfKeyMissing(),
			ds != nil && ds.MntNS().Enabled(), ds != nil && ds.MntNS().MatchIfKeyMissing(),
			perRule != nil && perRule.MntNS().Enabled(), perRule != nil && perRule.MntNS().MatchIfKeyMissing(),
		) {
			bitwise.SetBitInArray(&cfg.MntNsFilterMatchIfKeyMissing, ruleID)
		}
		if effectiveMatchIfMissing(
			rule.Policy.PidNSFilter.Enabled(), rule.Policy.PidNSFilter.MatchIfKeyMissing(),
			ds != nil && ds.PidNS().Enabled(), ds != nil && ds.PidNS().MatchIfKeyMissing(),
			perRule != nil && perRule.PidNS().Enabled(), perRule != nil && perRule.PidNS().MatchIfKeyMissing(),
		) {
			bitwise.SetBitInArray(&cfg.PidNsFilterMatchIfKeyMissing, ruleID)
		}
		if utsFilter.MatchIfKeyMissing() {
			bitwise.SetBitInArray(&cfg.UtsNsFilterMatchIfKeyMissing, ruleID)
		}
		if commFilter.MatchIfKeyMissing() {
			bitwise.SetBitInArray(&cfg.CommFilterMatchIfKeyMissing, ruleID)
		}
		if rule.Policy.ContIDFilter.MatchIfKeyMissing() {
			bitwise.SetBitInArray(&cfg.CgroupIdFilterMatchIfKeyMissing, ruleID)
		}
		if contFilter.MatchIfKeyMissing() {
			bitwise.SetBitInArray(&cfg.ContFilterMatchIfKeyMissing, ruleID)
		}
		if rule.Policy.NewContFilter.MatchIfKeyMissing() {
			bitwise.SetBitInArray(&cfg.NewContFilterMatchIfKeyMissing, ruleID)
		}
		if contStartedFilter.MatchIfKeyMissing() {
			bitwise.SetBitInArray(&cfg.ContStartedFilterMatchIfKeyMissing, ruleID)
		}
		if rule.Policy.NewPidFilter.MatchIfKeyMissing() {
			bitwise.SetBitInArray(&cfg.NewPidFilterMatchIfKeyMissing, ruleID)
		}
		if rule.Policy.ProcessTreeFilter.MatchIfKeyMissing() {
			bitwise.SetBitInArray(&cfg.ProcTreeFilterMatchIfKeyMissing, ruleID)
		}
		// Binary folds ALL enabled sources into one kernel filter (combinedScopeBinary), so its
		// match-if-missing is the combined filter's: AND of the enabled sources' flags (identical
		// to effectiveMatchIfMissing when a single source is enabled).
		if combinedScopeBinaryMatchIfMissing(rule) {
			bitwise.SetBitInArray(&cfg.BinPathFilterMatchIfKeyMissing, ruleID)
		}
	}

	return cfg
}

// computeBPFScopeFiltersConfig computes the scope filters config for eBPF (rules 0-63 only)
// by extracting the first 64 bits from the full scope config
func (pm *PolicyManager) computeBPFScopeFiltersConfig(eventID events.ID) scopeFiltersConfig {
	extendedCfg := pm.computeScopeFiltersConfig(eventID)

	// Extract first 64 bits (index 0) from each bitmap array for eBPF
	cfg := scopeFiltersConfig{
		UIDFilterEnabled:         getFirstBitmap(extendedCfg.UIDFilterEnabled),
		PIDFilterEnabled:         getFirstBitmap(extendedCfg.PIDFilterEnabled),
		MntNsFilterEnabled:       getFirstBitmap(extendedCfg.MntNsFilterEnabled),
		PidNsFilterEnabled:       getFirstBitmap(extendedCfg.PidNsFilterEnabled),
		UtsNsFilterEnabled:       getFirstBitmap(extendedCfg.UtsNsFilterEnabled),
		CommFilterEnabled:        getFirstBitmap(extendedCfg.CommFilterEnabled),
		CgroupIdFilterEnabled:    getFirstBitmap(extendedCfg.CgroupIdFilterEnabled),
		ContFilterEnabled:        getFirstBitmap(extendedCfg.ContFilterEnabled),
		NewContFilterEnabled:     getFirstBitmap(extendedCfg.NewContFilterEnabled),
		ContStartedFilterEnabled: getFirstBitmap(extendedCfg.ContStartedFilterEnabled),
		NewPidFilterEnabled:      getFirstBitmap(extendedCfg.NewPidFilterEnabled),
		ProcTreeFilterEnabled:    getFirstBitmap(extendedCfg.ProcTreeFilterEnabled),
		BinPathFilterEnabled:     getFirstBitmap(extendedCfg.BinPathFilterEnabled),
		FollowFilterEnabled:      getFirstBitmap(extendedCfg.FollowFilterEnabled),

		UIDFilterMatchIfKeyMissing:         getFirstBitmap(extendedCfg.UIDFilterMatchIfKeyMissing),
		PIDFilterMatchIfKeyMissing:         getFirstBitmap(extendedCfg.PIDFilterMatchIfKeyMissing),
		MntNsFilterMatchIfKeyMissing:       getFirstBitmap(extendedCfg.MntNsFilterMatchIfKeyMissing),
		PidNsFilterMatchIfKeyMissing:       getFirstBitmap(extendedCfg.PidNsFilterMatchIfKeyMissing),
		UtsNsFilterMatchIfKeyMissing:       getFirstBitmap(extendedCfg.UtsNsFilterMatchIfKeyMissing),
		CommFilterMatchIfKeyMissing:        getFirstBitmap(extendedCfg.CommFilterMatchIfKeyMissing),
		CgroupIdFilterMatchIfKeyMissing:    getFirstBitmap(extendedCfg.CgroupIdFilterMatchIfKeyMissing),
		ContFilterMatchIfKeyMissing:        getFirstBitmap(extendedCfg.ContFilterMatchIfKeyMissing),
		NewContFilterMatchIfKeyMissing:     getFirstBitmap(extendedCfg.NewContFilterMatchIfKeyMissing),
		ContStartedFilterMatchIfKeyMissing: getFirstBitmap(extendedCfg.ContStartedFilterMatchIfKeyMissing),
		NewPidFilterMatchIfKeyMissing:      getFirstBitmap(extendedCfg.NewPidFilterMatchIfKeyMissing),
		ProcTreeFilterMatchIfKeyMissing:    getFirstBitmap(extendedCfg.ProcTreeFilterMatchIfKeyMissing),
		BinPathFilterMatchIfKeyMissing:     getFirstBitmap(extendedCfg.BinPathFilterMatchIfKeyMissing),
	}

	return cfg
}

// getFirstBitmap extracts the first uint64 from a bitmap array (rules 0-63)
// Returns 0 if the array is empty
func getFirstBitmap(bitmapArray []uint64) uint64 {
	if len(bitmapArray) == 0 {
		return 0
	}
	return bitmapArray[0]
}

// updateUIntFilterBPF updates the BPF maps for the given uint filter map.
func (pm *PolicyManager) updateUIntFilterBPF(
	bpfModule *bpf.Module,
	filterMap map[filterVersionKey]map[uint64][]ruleBitmap,
	innerMapName string,
	outerMapName string,
) error {
	for vKey, innerMap := range filterMap {
		// Skip if no rules exist for this version/event
		if len(innerMap) == 0 {
			continue
		}

		// Get or create inner map
		bpfMap, _, err := pm.createAndUpdateInnerMap(bpfModule, innerMapName, outerMapName, vKey)
		if err != nil {
			return fmt.Errorf("creating/getting inner map for version %d event %d: %w",
				vKey.Version, vKey.EventID, err)
		}

		for key, bitmaps := range innerMap {
			// Check if there are bitmaps for this key
			if len(bitmaps) == 0 {
				continue
			}

			// Update only the first bitmap (first 64 rules)
			bitmap := bitmaps[0]

			// Convert the uint64 key to []byte
			keyBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(keyBytes, uint32(key))
			keyPointer := unsafe.Pointer(&keyBytes[0])

			// Convert the ruleBitmap to []byte
			bitmapBytes := make([]byte, ruleBitmapSize)
			binary.LittleEndian.PutUint64(bitmapBytes[0:8], bitmap.equalsInRules)
			binary.LittleEndian.PutUint64(bitmapBytes[8:16], bitmap.keyUsedInRules)
			valuePointer := unsafe.Pointer(&bitmapBytes[0])

			// Update the BPF map
			if err := bpfMap.Update(keyPointer, valuePointer); err != nil {
				return errfmt.WrapError(err)
			}
		}
	}

	return nil
}

// updateStringFilterBPF updates the BPF maps for the given string filter map.
func (pm *PolicyManager) updateStringFilterBPF(
	bpfModule *bpf.Module,
	filterMap map[filterVersionKey]map[string][]ruleBitmap,
	innerMapName string,
	outerMapName string,
) error {
	for vKey, innerMap := range filterMap {
		// Skip if no rules exist for this version/event
		if len(innerMap) == 0 {
			continue
		}

		// Get or create inner map
		bpfMap, _, err := pm.createAndUpdateInnerMap(bpfModule, innerMapName, outerMapName, vKey)
		if err != nil {
			return fmt.Errorf("creating/getting inner map for version %d event %d: %w",
				vKey.Version, vKey.EventID, err)
		}

		for key, bitmaps := range innerMap {
			// Check if there are bitmaps for this key
			if len(bitmaps) == 0 {
				continue
			}

			// Update only the first bitmap (first 64 rules)
			bitmap := bitmaps[0]

			byteStr := make([]byte, maxBpfStrFilterSize)
			copy(byteStr, key)
			keyPointer := unsafe.Pointer(&byteStr[0])

			bitmapBytes := make([]byte, ruleBitmapSize)
			binary.LittleEndian.PutUint64(bitmapBytes[0:8], bitmap.equalsInRules)
			binary.LittleEndian.PutUint64(bitmapBytes[8:16], bitmap.keyUsedInRules)
			valuePointer := unsafe.Pointer(&bitmapBytes[0])

			// Update the BPF map
			if err := bpfMap.Update(keyPointer, valuePointer); err != nil {
				return errfmt.WrapError(err)
			}
		}
	}

	return nil
}

// updateBinaryFilterBPF updates the BPF maps for the given binary filter map.
func (pm *PolicyManager) updateBinaryFilterBPF(
	bpfModule *bpf.Module,
	filterMap map[filterVersionKey]map[filters.NSBinary][]ruleBitmap,
	innerMapName string,
	outerMapName string,
) error {
	for vKey, innerMap := range filterMap {
		// Skip if no rules exist for this version/event
		if len(innerMap) == 0 {
			continue
		}

		// Get or create inner map
		bpfMap, _, err := pm.createAndUpdateInnerMap(bpfModule, innerMapName, outerMapName, vKey)
		if err != nil {
			return fmt.Errorf("creating/getting inner map for version %d event %d: %w",
				vKey.Version, vKey.EventID, err)
		}

		for key, bitmaps := range innerMap {
			// Check if there are bitmaps for this key
			if len(bitmaps) == 0 {
				continue
			}

			// Update only the first bitmap (first 64 rules)
			bitmap := bitmaps[0]

			if len(key.Path) > maxBpfBinPathSize {
				return filters.InvalidValue(key.Path)
			}

			binBytes := make([]byte, bpfBinFilterSize)
			if key.MntNS == 0 {
				// if no mount namespace given, bpf map key is only the path
				copy(binBytes, key.Path)
			} else {
				// otherwise, key is composed of the mount namespace and the path
				binary.LittleEndian.PutUint32(binBytes, key.MntNS)
				copy(binBytes[4:], key.Path)
			}
			keyPointer := unsafe.Pointer(&binBytes[0])

			bitmapBytes := make([]byte, ruleBitmapSize)
			binary.LittleEndian.PutUint64(bitmapBytes[0:8], bitmap.equalsInRules)
			binary.LittleEndian.PutUint64(bitmapBytes[8:16], bitmap.keyUsedInRules)
			valuePointer := unsafe.Pointer(&bitmapBytes[0])

			// Update the BPF map
			if err := bpfMap.Update(keyPointer, valuePointer); err != nil {
				return errfmt.WrapError(err)
			}
		}
	}

	return nil
}

// updateStringDataFilterLPMBPF updates the BPF maps for the given kernel data LPM filter map.
func (pm *PolicyManager) updateStringDataFilterLPMBPF(
	bpfModule *bpf.Module,
	filterMap map[filterVersionKey]map[string][]ruleBitmap,
	innerMapName string,
	outerMapName string,
) error {
	for vKey, innerMap := range filterMap {
		// Skip if no rules exist for this version/event
		if len(innerMap) == 0 {
			continue
		}

		// Get or create inner map
		bpfMap, _, err := pm.createAndUpdateInnerMap(bpfModule, innerMapName, outerMapName, vKey)
		if err != nil {
			return fmt.Errorf("creating/getting inner map for version %d event %d: %w",
				vKey.Version, vKey.EventID, err)
		}

		for key, bitmaps := range innerMap {
			// Check if there are bitmaps for this key
			if len(bitmaps) == 0 {
				continue
			}

			// Update only the first bitmap (first 64 rules)
			bitmap := bitmaps[0]

			// Ensure the string length is within the maximum allowed limit,
			// excluding the NULL terminator.
			if len(key) > maxBpfDataFilterStrSize-1 {
				return filters.InvalidValueMax(key, maxBpfDataFilterStrSize-1)
			}

			// key is composed of: prefixlen and a string
			// multiply by 8 to convert prefix length from bytes to bits for LPM Trie
			keyBytes := make([]byte, bpfDataFilterStrSize)
			prefixlen := len(key) * 8
			binary.LittleEndian.PutUint32(keyBytes, uint32(prefixlen))
			copy(keyBytes[4:], key)
			keyPointer := unsafe.Pointer(&keyBytes[0])

			bitmapBytes := make([]byte, ruleBitmapSize)
			binary.LittleEndian.PutUint64(bitmapBytes[0:8], bitmap.equalsInRules)
			binary.LittleEndian.PutUint64(bitmapBytes[8:16], bitmap.keyUsedInRules)
			valuePointer := unsafe.Pointer(&bitmapBytes[0])

			// Update the BPF map
			if err := bpfMap.Update(keyPointer, valuePointer); err != nil {
				return errfmt.WrapError(err)
			}
		}
	}

	return nil
}

// updateStringDataFilterBPF updates the BPF maps for the given kernel data filter map.
func (pm *PolicyManager) updateStringDataFilterBPF(
	bpfModule *bpf.Module,
	filterMap map[filterVersionKey]map[string][]ruleBitmap,
	innerMapName string,
	outerMapName string,
) error {
	for vKey, innerMap := range filterMap {
		// Skip if no rules exist for this version/event
		if len(innerMap) == 0 {
			continue
		}

		// Get or create inner map
		bpfMap, _, err := pm.createAndUpdateInnerMap(bpfModule, innerMapName, outerMapName, vKey)
		if err != nil {
			return fmt.Errorf("creating/getting inner map for version %d event %d: %w",
				vKey.Version, vKey.EventID, err)
		}

		for key, bitmaps := range innerMap {
			// Check if there are bitmaps for this key
			if len(bitmaps) == 0 {
				continue
			}

			// Update only the first bitmap (first 64 rules)
			bitmap := bitmaps[0]

			// Ensure the string length is within the maximum allowed limit,
			// excluding the NULL terminator
			if len(key) > maxBpfDataFilterStrSize-1 {
				return filters.InvalidValueMax(key, maxBpfDataFilterStrSize-1)
			}

			keyBytes := make([]byte, maxBpfDataFilterStrSize)
			copy(keyBytes, key) // string
			keyPointer := unsafe.Pointer(&keyBytes[0])

			bitmapBytes := make([]byte, ruleBitmapSize)
			binary.LittleEndian.PutUint64(bitmapBytes[0:8], bitmap.equalsInRules)
			binary.LittleEndian.PutUint64(bitmapBytes[8:16], bitmap.keyUsedInRules)
			valuePointer := unsafe.Pointer(&bitmapBytes[0])

			// Update the BPF map
			if err := bpfMap.Update(keyPointer, valuePointer); err != nil {
				return errfmt.WrapError(err)
			}
		}
	}

	return nil
}

// innerMapRef tracks a created (version, event) inner filter map together with the outer map
// holding its FD, so stale generations can be reaped (outer entry deleted + FD closed) once a
// newer version replaces them.
type innerMapRef struct {
	innerMap *bpf.BPFMapLow
	outer    string
	vKey     filterVersionKey
}

// createAndUpdateInnerMap creates a new inner map and updates the outer map with it.
// It returns the created map, its name and any error encountered.
//
// A cache hit (same version + event) returns the existing map: versions are monotonic per
// event (never reused after remove+re-add), so a hit means the event's rules are unchanged
// and the map already holds the same keys. Known limitation: values resolved OUTSIDE the
// rules (container-id -> cgroup-id) can drift while the version stands; those keys are only
// refreshed when the event's rules change.
func (pm *PolicyManager) createAndUpdateInnerMap(
	bpfModule *bpf.Module,
	innerMapName string,
	outerMapName string,
	vKey filterVersionKey,
) (*bpf.BPFMapLow, string, error) {
	// Check if map already exists
	newInnerMapName := fmt.Sprintf("%s_%d_%d", innerMapName, vKey.Version, vKey.EventID)
	if ref, ok := pm.bpfInnerMaps[newInnerMapName]; ok {
		return ref.innerMap, newInnerMapName, nil
	}

	// Create new inner map
	newInnerMap, newInnerMapName, err := createNewInnerMapEventId(bpfModule, innerMapName, vKey.Version, vKey.EventID)
	if err != nil {
		return nil, "", errfmt.WrapError(err)
	}

	// Update outer map
	if err := updateOuterMapWithEventId(bpfModule, outerMapName, vKey, newInnerMap); err != nil {
		_ = syscall.Close(newInnerMap.FileDescriptor())
		return nil, "", errfmt.WrapError(err)
	}

	// Store map reference
	pm.bpfInnerMaps[newInnerMapName] = innerMapRef{innerMap: newInnerMap, outer: outerMapName, vKey: vKey}

	return newInnerMap, newInnerMapName, nil
}

// reapStaleInnerMaps deletes the outer-map entries and closes the FDs of filter inner maps
// whose generation can no longer be referenced. It retains, per event, the version now in the
// kernel (pm.pushedVersions, just updated) and the version that was in the kernel before this
// push (prevPushed) - an in-flight kernel program that read the previous events_config may still
// be doing filter-map lookups against that generation for one program-execution window. It must
// key off the ACTUAL pushed versions, not {cur, cur-1} arithmetic on the rules version: a
// single UpdatePolicy bumps the rules version by +2 (remove+add), so cur-1 is a version that
// never reached the kernel while the generation the kernel actually used (cur-2) would be reaped
// out from under those programs. A removed event keeps its last generation one extra cycle
// (still in prevPushed) and is reaped on the next push. Without reaping, every runtime policy
// change leaks kernel memory and FDs, and the outer maps eventually fill (E2BIG). Called at the
// end of a successful updateBPF, under pm.mu.
func (pm *PolicyManager) reapStaleInnerMaps(bpfModule *bpf.Module, prevPushed map[events.ID]uint16) {
	for name, ref := range pm.bpfInnerMaps {
		eid := events.ID(ref.vKey.EventID)
		if cur, ok := pm.pushedVersions[eid]; ok && ref.vKey.Version == cur {
			continue // the version currently live in the kernel
		}
		if prev, ok := prevPushed[eid]; ok && ref.vKey.Version == prev {
			continue // the version the kernel used before this push (in-flight grace)
		}
		outerMap, err := bpfModule.GetMap(ref.outer)
		if err != nil {
			continue // keep the ref; retry next push
		}
		k := ref.vKey
		// ENOENT is fine: an entry may never have been written for a dimension with no values.
		if err := outerMap.DeleteKey(unsafe.Pointer(&k)); err != nil && !errors.Is(err, syscall.ENOENT) {
			// The kernel still references the inner map through this outer entry. If we closed
			// our fd and dropped the ref now, the entry would be orphaned forever (Go loses the
			// only handle) - a permanent leak that eventually hits E2BIG, exactly what the reaper
			// prevents. Keep the ref and retry on the next push instead.
			logger.Debugw("Reaping stale filter map: outer delete failed, keeping ref for retry",
				"outer", ref.outer, "version", ref.vKey.Version, "event", ref.vKey.EventID, "error", err)
			continue
		}
		_ = syscall.Close(ref.innerMap.FileDescriptor())
		delete(pm.bpfInnerMaps, name)
	}
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
	// GetBTFFDByID returns a NEW fd each call; the created map holds its own BTF reference, so
	// this one must be closed or it leaks per inner-map creation (thousands per ApplyPolicy at
	// scale = version × event × dimension) - the exact fd exhaustion the reaper exists to bound.
	defer func() { _ = syscall.Close(int(btfFD)) }()

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
func populateProcInfoMap(bpfModule *bpf.Module, filterMap map[filterVersionKey]map[filters.NSBinary][]ruleBitmap) error {
	procInfoMap, err := bpfModule.GetMap(ProcInfoMap)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// The kernel's proc_info_t is LARGER than the Go mirror (it has a trailing file_info_t
	// interpreter the kernel owns). Work on full-value buffers so an Update never reads past
	// the Go struct and never zeroes the kernel-owned tail.
	goSize := int(unsafe.Sizeof(procInfo{}))
	valueSize := procInfoMap.ValueSize()
	if valueSize < goSize {
		return errfmt.Errorf("proc_info map value size %d smaller than the userspace mirror %d", valueSize, goSize)
	}

	binsProcs, err := proc.GetAllBinaryProcs()
	if err != nil {
		return errfmt.WrapError(err)
	}

	for _, innerMap := range filterMap {
		for bin := range innerMap {
			procs := binsProcs[bin.Path]
			for _, p := range procs {
				// Read-modify-write: a runtime re-push (ApplyPolicy/RemovePolicy) must NOT
				// reset kernel-maintained state - new_proc feeds the new-pid filter and
				// follow_in_scopes the follow filter; zeroing them here would stop following
				// already-marked subtrees after any runtime policy change.
				value := make([]byte, valueSize)
				if existing, err := procInfoMap.GetValue(unsafe.Pointer(&p)); err == nil && len(existing) == valueSize {
					copy(value, existing)
				}

				info := procInfo{
					newProc:        value[0] != 0,                           // preserved (new_proc, offset 0)
					followPolicies: binary.LittleEndian.Uint64(value[8:16]), // preserved (follow_in_scopes, offset 8)
					mntNS:          bin.MntNS,
					binNoMnt:       0, // always 0, see bin_no_mnt in tracee.bpf.c
				}
				copy(info.binaryBytes[:], bin.Path)
				copy(value[:goSize], unsafe.Slice((*byte)(unsafe.Pointer(&info)), goSize))

				if err := procInfoMap.Update(unsafe.Pointer(&p), unsafe.Pointer(&value[0])); err != nil {
					return errfmt.WrapError(err)
				}
			}
		}
	}

	return nil
}
