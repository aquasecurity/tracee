package policy

import (
	"sort"
	"sync"
	"sync/atomic"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/common/bitwise"
	"github.com/aquasecurity/tracee/common/capabilities"
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/datastores/container"
	"github.com/aquasecurity/tracee/pkg/datastores/dns"
	"github.com/aquasecurity/tracee/pkg/datastores/process"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/data"
	"github.com/aquasecurity/tracee/pkg/events/dependencies"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/pcaps"
)

type ManagerConfig struct {
	DNSStoreConfig     dns.Config
	ProcessStoreConfig process.ProcTreeConfig
	ArtifactsConfig    config.ArtifactsConfig
	HeartbeatEnabled   bool
}

// Manager is responsible for managing all loaded policies and generating lists of rules grouped by event ID.
type PolicyManager struct {
	policies        map[string]*Policy       // Map of policies by name
	rules           map[events.ID]EventRules // Map of rules by event ID
	bootstrapPolicy *Policy                  // Holds the bootstrap policy
	evtsDepsManager *dependencies.Manager
	bpfInnerMaps    map[string]innerMapRef // Live (version, event) filter inner maps; reaped per generation. TODO: move this to ebpf related code
	// lastRulesVersion keeps each event's highest rules version ever handed out, surviving the
	// event's removal from pm.rules. Versions must NEVER be reused: a (version, event) key
	// aliases kernel inner filter maps, and re-issuing one after remove+re-add would resurrect
	// a stale map's keys for the new, unrelated rules (false matches).
	lastRulesVersion map[events.ID]uint16
	// pendingEventRemovals records events the dependency manager removed (SubscribeRemove
	// callback) while a rules generation was being built on a temp map: the callback deletes
	// from the LIVE pm.rules, and committing the temp map would silently resurrect them.
	// Applied and cleared by commitRules.
	pendingEventRemovals []events.ID
	// treeGroupAlloc/followGroupAlloc hand out STABLE per-policy group bit positions for the
	// kernel's per-process tree/follow membership state (see groupAllocator).
	treeGroupAlloc   *groupAllocator
	followGroupAlloc *groupAllocator
	// treeRootSig[policyName] digests a tree policy's root-pid set from the last push, so a
	// surviving policy that changed its roots can have its group bit swept + reassigned.
	treeRootSig map[string]uint64
	// pushedVersions[eventID] is the rules version currently written to events_config_map (and
	// mirrored in exportedFMaps). Updated only inside updateBPF, so it - unlike rules versions,
	// which advance at mutation time - always matches what the kernel and exportedFMaps hold.
	pushedVersions map[events.ID]uint16
	mu             sync.RWMutex // Read/Write Mutex to protect concurrent access
	cfg            ManagerConfig
	fMaps          *filterMaps
	exportedFMaps  *FilterMaps // cached read-only export of fMaps for the overflow matcher (rebuilt per updateBPF)
	disabledAny    atomic.Bool // fast gate: set once any rule is disabled, so the hot path can skip the disabled-rules lookup
	// snap is the immutable, atomically-published view of the per-event read state (rules + exported filter
	// maps). The event hot path Loads it once and reads without taking pm.mu; writers rebuild and Store it
	// under pm.mu after every mutation (see publishSnapshot). Never nil after NewManager.
	snap atomic.Pointer[Snapshot]
	// detectorScopeFilters holds, per detector OUTPUT event, the scope filters the detector declared
	// for each required base event (Requirements.Events[].ScopeFilters). Phase 2 pushes them onto the
	// base events' dependency rules (EventRule.DetectorScopeFilter). Keyed detectorOutputID -> baseID.
	// Set via SetDetectorScopeFilters (after detectors register); RecomputeRules then threads them in.
	// nil = none.
	detectorScopeFilters map[events.ID]map[events.ID]*filters.ScopeFilter
	// detectorDataFilters is the data-filter analogue of detectorScopeFilters
	// (Requirements.Events[].DataFilters), pushed onto EventRule.DetectorDataFilter. Same keying.
	detectorDataFilters map[events.ID]map[events.ID]*filters.DataFilter
	// ruleIDAlloc gives each rule a STABLE per-event ID that persists across runtime add/remove, so an event's
	// kernel-computed matched-rules bitmap (using the layout at generation) still resolves correctly when
	// userland reads it after a concurrent policy change. Without it, RecomputeRules renumbered rule IDs by
	// name-sort on every change. Keyed per event; survives RecomputeRules. See stable-rule-IDs design.
	ruleIDAlloc map[events.ID]*ruleIDAllocator
}

// ruleKey is the stable identity of a rule within an event, used to keep its ID constant across recomputes. A
// user rule is identified by its policy name; a dependency rule by its (policy, top-consumer event) chain -
// both captured by (policy name, RuleData.EventID), since a user rule's RuleData.EventID is the event itself
// while a dependency rule's is the consumer that pulled it in.
type ruleKey struct {
	policy  string
	chainID events.ID
}

// ruleIDAllocator hands out stable per-event rule IDs. A known key keeps its ID across recomputes; a retired
// key's ID is reused (smallest-first) to keep IDs dense - so IDs stay < 64 whenever the active count is, and
// the kernel's single-u64 fast path is preserved. Not safe for concurrent use; callers hold pm.mu.
type ruleIDAllocator struct {
	byKey map[ruleKey]uint
	used  map[uint]bool
}

func newRuleIDAllocator() *ruleIDAllocator {
	return &ruleIDAllocator{byKey: make(map[ruleKey]uint), used: make(map[uint]bool)}
}

// getOrAssign returns the key's existing ID, or assigns it the smallest free ID (reusing retired IDs).
func (a *ruleIDAllocator) getOrAssign(k ruleKey) uint {
	if id, ok := a.byKey[k]; ok {
		return id
	}
	id := uint(0)
	for a.used[id] {
		id++
	}
	a.byKey[k] = id
	a.used[id] = true
	return id
}

// retirePolicy frees the IDs of all rules belonging to the named policy (called when the policy is removed),
// so a later rule can reuse them.
func (a *ruleIDAllocator) retirePolicy(policyName string) {
	for k, id := range a.byKey {
		if k.policy == policyName {
			delete(a.byKey, k)
			delete(a.used, id)
		}
	}
}

// assignStableRuleIDs rewrites every rule's ID from the persistent per-event allocator (so IDs stay constant
// across runtime add/remove) and rebuilds the per-event fields derived from IDs: ruleIDToEventRule, rulesCount,
// hasOverflow and containerFilteredRules. Called at the end of every rules rebuild, under pm.mu. Rules are
// visited in their existing order (name-sorted user rules, then dependency rules), so a fresh manager still
// hands out 0,1,2… exactly as before - only runtime add/remove now preserves existing IDs. A key is
// (policy name, RuleData.EventID): a user rule's EventID is the event itself, a dependency rule's is the
// consumer that pulled it in, so both are stable across recomputes.
func (pm *PolicyManager) assignStableRuleIDs(rules map[events.ID]EventRules) {
	for eventID, er := range rules {
		alloc := pm.ruleIDAlloc[eventID]
		if alloc == nil {
			alloc = newRuleIDAllocator()
			pm.ruleIDAlloc[eventID] = alloc
		}
		er.ruleIDToEventRule = make(map[uint]*EventRule, len(er.Rules))
		er.containerFilteredRules = nil
		var maxID uint
		haveRule := false
		for _, rule := range er.Rules {
			if rule == nil || rule.Policy == nil || rule.Data == nil {
				continue
			}
			id := alloc.getOrAssign(ruleKey{policy: rule.Policy.Name, chainID: rule.Data.EventID})
			rule.ID = id
			er.ruleIDToEventRule[id] = rule
			if !haveRule || id > maxID {
				maxID, haveRule = id, true
			}
			if rule.Policy.ContainerFilterEnabled() {
				idx := int(id / 64)
				for len(er.containerFilteredRules) <= idx {
					er.containerFilteredRules = append(er.containerFilteredRules, 0)
				}
				bitwise.SetBit(&er.containerFilteredRules[idx], uint(id%64))
			}
		}
		if haveRule {
			er.rulesCount = maxID + 1 // sized to cover the highest ID; retired IDs may leave gaps (gap bits carry no rule)
		} else {
			er.rulesCount = 0
		}
		// Overflow means a LIVE rule sits at ID >= 64 (needs userland evaluation). Deriving it
		// from rulesCount would pin an event in overflow mode after its high IDs retire (the
		// count keeps covering the historical maximum until the allocator compacts).
		er.hasOverflow = false
		var liveRules []uint64
		for id := range er.ruleIDToEventRule {
			if id >= 64 {
				er.hasOverflow = true
			}
			bitwise.SetBitInArray(&liveRules, id)
		}
		// Cache the live-rules bitmap: it is the "all rules" candidate set the net-event and
		// overflow decode paths seed from (GetAllRulesBitmap), recomputed there per event. Store
		// it once here (it is a pure function of this generation's rule IDs, computed anyway for
		// the prune below) so those hot paths do a single copy instead of a map iteration.
		er.allRulesBitmap = liveRules
		// Prune DisableRule bits whose rule retired: IDs are reused, so a stale disabled bit
		// would silently disable an unrelated future rule occupying the same position.
		for i := range er.disabledRules {
			if i < len(liveRules) {
				er.disabledRules[i] &= liveRules[i]
			} else {
				er.disabledRules[i] = 0
			}
		}
		rules[eventID] = er
	}
}

// retireRuleIDs frees every rule ID assigned to the named policy across all events (called when the policy is
// removed), so the IDs become available for reuse.
func (pm *PolicyManager) retireRuleIDs(policyName string) {
	for _, alloc := range pm.ruleIDAlloc {
		alloc.retirePolicy(policyName)
	}
}

// EventRules holds information about a specific event.
type EventRules struct {
	Rules                  []*EventRule        // List of rules associated with this event
	UserlandRules          []*EventRule        // List of rules with userland filters enabled
	enabled                bool                // Flag indicating whether the event is enabled. TODO: move to events manager
	rulesVersion           uint16              // Version of the rules for this event (for future updates)
	rulesCount             uint                // Highest rule ID + 1 (bitmap width); retired IDs leave gaps, so it can exceed the live rule count
	ruleIDToEventRule      map[uint]*EventRule // Map from RuleID to EventRule for fast lookup
	containerFilteredRules []uint64            // Bitmaps to track container-filtered rules
	disabledRules          []uint64            // Bitmap of rules disabled at runtime (EnableRule/DisableRule)
	allRulesBitmap         []uint64            // Cached "all live rules" candidate set (see GetAllRulesBitmap); rebuilt by assignStableRuleIDs
	hasOverflow            bool                // True when a LIVE rule has ID >= 64: beyond the kernel's u64 matched-rules bitmap
}

type RuleSelectionType int

const (
	NotSelected RuleSelectionType = iota
	SelectedByUser
	SelectedByDependency
	SelectedByBootstrap
)

// EventRule represents a single rule within an event's rule set.
type EventRule struct {
	ID            uint              // Unique ID of the rule within the event - used for bitmap position
	Data          *RuleData         // Data associated with the rule
	Policy        *Policy           // Reference to the policy where the rule was defined
	SelectionType RuleSelectionType // How the rule was selected: by user, by dependency, or by bootstrap policy
	DerivedRuleID uint              // For dependency rules, ID of the rule that caused the dependency
	// DetectorScopeFilter is an optional, rule-local scope filter ANDed on top of Data.ScopeFilter.
	// Phase 2 uses it to push a detector's per-base-event scope declaration (Requirements.Events[])
	// onto the base event's dependency rule WITHOUT giving it its own RuleData (which would break the
	// shared-pointer derive mapping in GetDerivedEventMatchedRules). nil for ordinary rules.
	DetectorScopeFilter *filters.ScopeFilter
	// DetectorDataFilter is the data-filter analogue of DetectorScopeFilter: a rule-local data filter
	// for a detector's per-base-event data declaration. Unlike Data.DataFilter (which belongs to the
	// dependent/derived event's schema and is not applied to a dependency rule's base event), this one
	// IS on the base event's schema, so matchPolicies applies it to the base event's args. nil for
	// ordinary rules.
	DetectorDataFilter *filters.DataFilter
}

// IsDependency reports whether this rule was attached because the event is a
// (transitive) dependency of another rule's event, rather than being selected
// directly. Dependency rules are SCOPE-ONLY: their RuleData is shared with the
// originating (dependent/derived) rule, so its data and return-value filters are
// specific to THAT event's schema and must not be applied to this (base) event -
// doing so would wrongly drop base events and break derivations. Their data/ret
// filters are instead applied when the dependent/derived event itself is matched.
func (r *EventRule) IsDependency() bool {
	return r.SelectionType == SelectedByDependency
}

// SetDetectorScopeFilters installs the per-detector, per-base-event scope filters that Phase 2
// pushes onto base events' dependency rules (EventRule.DetectorScopeFilter). Consulted by rule
// building, so set it before RecomputeRules (as tracee does after detector registration). Keyed
// detectorOutputID -> baseID.
func (pm *PolicyManager) SetDetectorScopeFilters(m map[events.ID]map[events.ID]*filters.ScopeFilter) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.detectorScopeFilters = m
}

// SetDetectorDataFilters installs the per-detector, per-base-event data filters that Phase 2 pushes
// onto base events' dependency rules (EventRule.DetectorDataFilter). Consulted by rule building, so
// set it before RecomputeRules (as tracee does after detector registration). Keyed detOut -> baseID.
func (pm *PolicyManager) SetDetectorDataFilters(m map[events.ID]map[events.ID]*filters.DataFilter) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.detectorDataFilters = m
}

func NewManager(
	cfg ManagerConfig,
	evtsDepsManager *dependencies.Manager,
	initialPolicies ...*Policy,
) (*PolicyManager, error) {
	if evtsDepsManager == nil {
		panic("evtDepsManager is nil")
	}

	pm := &PolicyManager{
		policies:         make(map[string]*Policy),
		rules:            make(map[events.ID]EventRules),
		evtsDepsManager:  evtsDepsManager,
		bpfInnerMaps:     make(map[string]innerMapRef),
		lastRulesVersion: make(map[events.ID]uint16),
		pushedVersions:   make(map[events.ID]uint16),
		treeGroupAlloc:   newGroupAllocator(64),
		followGroupAlloc: newGroupAllocator(64),
		treeRootSig:      make(map[string]uint64),
		mu:               sync.RWMutex{},
		cfg:              cfg,
		ruleIDAlloc:      make(map[events.ID]*ruleIDAllocator),
	}

	// Subscribe to event removals to clean up policy rules when events become unavailable
	// (e.g., due to missing kernel symbol dependencies)
	evtsDepsManager.SubscribeRemove(
		dependencies.EventNodeType,
		func(node interface{}) []dependencies.Action {
			eventNode, ok := node.(*dependencies.EventNode)
			if !ok {
				logger.Errorw("Got node from type not requested")
				return nil
			}

			pm.removeEventFromRules(eventNode.GetID())

			return nil
		})

	// Create and add the bootstrap policy with conditional rules
	pm.bootstrapPolicy = createBootstrapPolicy(cfg)
	if err := pm.AddPolicy(pm.bootstrapPolicy); err != nil {
		return nil, errfmt.Errorf("failed to add bootstrap policy: %s", err)
	}

	// Add initial policies in name-sorted order. Rule IDs are now assignment-order-stable (they no longer
	// renumber on add/remove), so sorting the initial load makes a fresh config produce name-sorted,
	// load-order-independent rule IDs - preserving reproducibility/log-correlation for the common case.
	// Runtime AddPolicy/RemovePolicy after this keep existing IDs and hand new rules the smallest free ID.
	sortedInitial := make([]*Policy, len(initialPolicies))
	copy(sortedInitial, initialPolicies)
	sort.Slice(sortedInitial, func(i, j int) bool { return sortedInitial[i].Name < sortedInitial[j].Name })
	for _, p := range sortedInitial {
		if err := pm.AddPolicy(p); err != nil {
			logger.Errorw("failed to add initial policy", "error", err)
		}
	}

	// TODO: update required capabilities on policy addition/removal
	if err := pm.updateCapsForSelectedEvents(); err != nil {
		return nil, errfmt.Errorf("failed to set required capabilitis: %v", err)
	}

	return pm, nil
}

func (pm *PolicyManager) removeEventFromRules(evtID events.ID) {
	logger.Debugw("Remove event from rules", "event", events.Core.GetDefinitionByID(evtID).GetName())
	delete(pm.rules, evtID)
	// When a rules generation is being built on a temp map (add/remove/recompute), deleting
	// from the live map alone is not enough - the commit would resurrect the event. Record it
	// so commitRules re-applies the removal to the generation being committed.
	pm.pendingEventRemovals = append(pm.pendingEventRemovals, evtID)
	// Publish so the lock-free read snapshot reflects the removal. This is the deps-manager SubscribeRemove
	// callback: it fires under AddPolicy's write lock (runtime) or single-threaded at init (attachProbes,
	// which runs after the last publish and removes events whose probe failed to attach). Without this, a
	// removed event stays in the snapshot and keeps matching - e.g. a failed_attach event still emitted.
	// publishSnapshot does not take pm.mu, so it is safe in both call contexts (no deadlock, no new race).
	pm.publishSnapshot()
}

// commitRules installs a rebuilt rules generation, first re-applying any event removals the
// dependency manager signaled while the generation was being built (see removeEventFromRules).
// Callers must hold pm.mu (write) and should have cleared pendingEventRemovals when they
// started building (stale entries from a previous, already-applied removal must not delete a
// legitimately re-added event).
func (pm *PolicyManager) commitRules(tempRules map[events.ID]EventRules) {
	for _, evtID := range pm.pendingEventRemovals {
		delete(tempRules, evtID)
	}
	pm.pendingEventRemovals = nil
	pm.rules = tempRules
}

// createBootstrapPolicy creates the bootstrap policy with rules based on the provided configuration.
// bootsrap policy is an internal policy to ensure essential events are always selected.
func createBootstrapPolicy(cfg ManagerConfig) *Policy {
	rules := make(map[events.ID]RuleData)

	// Helper function to create RuleData with default filters
	newRuleData := func(eventID events.ID) RuleData {
		return RuleData{
			EventID:     eventID,
			DataFilter:  filters.NewDataFilter(),
			RetFilter:   filters.NewIntFilter(),
			ScopeFilter: filters.NewScopeFilter(),
		}
	}

	// Always-selected events:
	rules[events.SchedProcessExec] = newRuleData(events.SchedProcessExec)
	rules[events.SchedProcessFork] = newRuleData(events.SchedProcessFork)
	rules[events.SchedProcessExit] = newRuleData(events.SchedProcessExit)

	// Control Plane Events
	rules[events.SignalCgroupMkdir] = newRuleData(events.SignalCgroupMkdir)
	rules[events.SignalCgroupRmdir] = newRuleData(events.SignalCgroupRmdir)

	// Control Plane Process Tree Events
	pipeEvts := func() {
		rules[events.SchedProcessFork] = newRuleData(events.SchedProcessFork)
		rules[events.SchedProcessExec] = newRuleData(events.SchedProcessExec)
		rules[events.SchedProcessExit] = newRuleData(events.SchedProcessExit)
	}
	signalEvts := func() {
		rules[events.SignalSchedProcessFork] = newRuleData(events.SignalSchedProcessFork)
		rules[events.SignalSchedProcessExec] = newRuleData(events.SignalSchedProcessExec)
		rules[events.SignalSchedProcessExit] = newRuleData(events.SignalSchedProcessExit)
	}

	switch cfg.ProcessStoreConfig.Source {
	case process.SourceBoth:
		pipeEvts()
		signalEvts()
	case process.SourceSignals:
		signalEvts()
	case process.SourceEvents:
		pipeEvts()
	}

	// DNS Cache events
	if cfg.DNSStoreConfig.Enable {
		rules[events.NetPacketDNS] = newRuleData(events.NetPacketDNS)
	}

	// Heartbeat event
	if cfg.HeartbeatEnabled {
		rules[events.SignalHeartbeat] = newRuleData(events.SignalHeartbeat)
	}

	// Capture events (selected based on configuration)
	if cfg.ArtifactsConfig.Exec {
		rules[events.CaptureExec] = newRuleData(events.CaptureExec)
	}
	if cfg.ArtifactsConfig.FileWrite.Capture {
		rules[events.CaptureFileWrite] = newRuleData(events.CaptureFileWrite)
	}
	if cfg.ArtifactsConfig.FileRead.Capture {
		rules[events.CaptureFileRead] = newRuleData(events.CaptureFileRead)
	}
	if cfg.ArtifactsConfig.Module {
		rules[events.CaptureModule] = newRuleData(events.CaptureModule)
	}
	if cfg.ArtifactsConfig.Mem {
		rules[events.CaptureMem] = newRuleData(events.CaptureMem)
	}
	if cfg.ArtifactsConfig.Bpf {
		rules[events.CaptureBpf] = newRuleData(events.CaptureBpf)
	}
	if pcaps.PcapsEnabled(cfg.ArtifactsConfig.Net) {
		rules[events.CaptureNetPacket] = newRuleData(events.CaptureNetPacket)
	}

	// Create policy with initialized filters
	p := NewPolicy()
	p.Name = "__internal_bootstrap__"
	p.Rules = rules

	return p
}

func (pm *PolicyManager) updateCapsForSelectedEvents() error {
	// Update capabilities rings with all events dependencies

	caps := capabilities.GetInstance()
	for id := range pm.rules {
		if !events.Core.IsDefined(id) {
			return errfmt.Errorf("event %d is not defined", id)
		}
		depsNode, err := pm.evtsDepsManager.GetEvent(id)
		if err == nil {
			deps := depsNode.GetDependencies()
			evtCaps := deps.GetCapabilities()
			err = caps.BaseRingAdd(evtCaps.GetBase()...)
			if err != nil {
				return errfmt.WrapError(err)
			}
			err = caps.BaseRingAdd(evtCaps.GetEBPF()...)
			if err != nil {
				return errfmt.WrapError(err)
			}
		}
	}

	return nil
}

// AddPolicyOption is a functional option for the AddPolicy method.
type AddPolicyOption func(*addPolicyOptions)

// addPolicyOptions contains the options for adding a policy.
type addPolicyOptions struct {
	override bool
}

// WithOverride is an AddPolicyOption that allows overriding an existing policy.
func WithOverride() AddPolicyOption {
	return func(opts *addPolicyOptions) {
		opts.override = true
	}
}

// AddPolicy adds a new policy or updates an existing policy in the PolicyManager.
func (pm *PolicyManager) AddPolicy(policy *Policy, opts ...AddPolicyOption) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if err := pm.addPolicyLocked(policy, opts...); err != nil {
		return err
	}
	pm.publishSnapshot()
	return nil
}

// addPolicyLocked implements AddPolicy. The caller must hold pm.mu (write). Split out so UpdatePolicy can
// compose it with removePolicyLocked under a single lock.
func (pm *PolicyManager) addPolicyLocked(policy *Policy, opts ...AddPolicyOption) error {
	if policy == nil {
		return PolicyNilError()
	}

	options := addPolicyOptions{
		override: false, // Default behavior: no override
	}
	for _, opt := range opts {
		opt(&options)
	}

	if _, exists := pm.policies[policy.Name]; exists && !options.override {
		return PolicyAlreadyExistsError(policy.Name)
	}

	pm.pendingEventRemovals = nil // start fresh accounting for this rebuild (see commitRules)

	// Create a temporary copy of the relevant parts of the PolicyManager's state
	tempPolicies := make(map[string]*Policy)
	for k, v := range pm.policies {
		tempPolicies[k] = v
	}
	// Deep-copy every event's rules so a failed add can be discarded without touching live state.
	// updateRulesForEvent and addTransitiveDependencyRules mutate reused dependency rules in place, so a
	// shallow copy is unsafe. Runs on init and every runtime add/remove/update, but never per-event (runtime
	// changes are operator-rare), so the cost is negligible.
	tempRules := make(map[events.ID]EventRules)
	for k, v := range pm.rules {
		tempRules[k] = deepCopyEventRules(v)
	}

	// Perform operations on the temporary copies
	tempPolicies[policy.Name] = policy // Add or update the policy

	// Update event selection in the dependency manager
	// This should be done for all selected events BEFORE updating EventRules (done below)
	for eventID := range policy.Rules {
		// Select event
		_, err := pm.evtsDepsManager.SelectEvent(eventID)
		if err != nil {
			eventName := events.Core.GetDefinitionByID(eventID).GetName()
			return SelectEventError(eventName)
		}
	}

	// Update EventRules for each event affected by the policy
	for eventID := range policy.Rules {
		if err := pm.updateRulesForEvent(eventID, tempRules, tempPolicies); err != nil {
			return errfmt.WrapError(err)
		}
	}

	// If all operations are successful, commit the changes to the actual PolicyManager
	pm.assignStableRuleIDs(tempRules) // keep rule IDs constant across add/remove (runtime-safe attribution)
	pm.policies = tempPolicies
	pm.commitRules(tempRules)

	return nil
}

// RecomputeRules rebuilds every event's EventRules from the current policy set. It is used at startup
// after detectors register and SetDetectorScopeFilters is set, so the detector scope filters (unknown
// at initial policy load) get threaded onto the base events' dependency rules by
// addTransitiveDependencyRules. It does not change the policy set or re-select events (they are
// already selected in the dependency manager). It is also the groundwork for future runtime policy
// changes, which will rebuild + re-push under this same lock.
func (pm *PolicyManager) RecomputeRules() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.pendingEventRemovals = nil // start fresh accounting for this rebuild (see commitRules)

	tempPolicies := make(map[string]*Policy, len(pm.policies))
	for k, v := range pm.policies {
		tempPolicies[k] = v
	}

	// Collect the events selected by any policy, in a stable order for deterministic rule IDs.
	selected := make(map[events.ID]struct{})
	for _, p := range tempPolicies {
		for eventID := range p.Rules {
			selected[eventID] = struct{}{}
		}
	}
	eventIDs := make([]events.ID, 0, len(selected))
	for eventID := range selected {
		eventIDs = append(eventIDs, eventID)
	}
	sort.Slice(eventIDs, func(i, j int) bool { return eventIDs[i] < eventIDs[j] })

	tempRules := make(map[events.ID]EventRules)
	for _, eventID := range eventIDs {
		// Unlike AddPolicy, RecomputeRules does not SelectEvent (that would double-count the
		// selection). So it must tolerate an event whose dependency node was cancelled after the
		// initial selection - e.g. an unsatisfiable ksymbol/probe/event dependency with no fallback.
		// Such an event has no node in the dependency manager and simply gets no rules, matching the
		// graceful-degradation the deps manager already applied; erroring here would abort Init.
		if _, err := pm.evtsDepsManager.GetEvent(eventID); err != nil {
			continue
		}
		if err := pm.updateRulesForEvent(eventID, tempRules, tempPolicies); err != nil {
			return errfmt.WrapError(err)
		}
	}

	pm.assignStableRuleIDs(tempRules) // keep rule IDs constant across add/remove (runtime-safe attribution)
	pm.commitRules(tempRules)
	pm.publishSnapshot()
	return nil
}

// RemovePolicy removes a policy from the PolicyManager.
func (pm *PolicyManager) RemovePolicy(policyName string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if err := pm.removePolicyLocked(policyName); err != nil {
		return err
	}
	pm.publishSnapshot()
	return nil
}

// removePolicyLocked implements RemovePolicy. The caller must hold pm.mu (write). Split out so UpdatePolicy
// can compose it with addPolicyLocked under a single lock.
func (pm *PolicyManager) removePolicyLocked(policyName string) error {
	if pm.bootstrapPolicy != nil && policyName == pm.bootstrapPolicy.Name {
		return errfmt.Errorf("cannot remove bootstrap policy")
	}

	policyToRemove, exists := pm.policies[policyName]
	if !exists {
		return PolicyNotFoundByNameError(policyName)
	}

	pm.pendingEventRemovals = nil // start fresh accounting for this rebuild (see commitRules)

	// Create temporary copies for rollback
	tempPolicies := make(map[string]*Policy)
	for k, v := range pm.policies {
		tempPolicies[k] = v
	}
	// Deep-copy every event's rules so a failed removal can be discarded without touching live state (see
	// addPolicyLocked for why a shallow copy is unsafe). Operator-rare, so the cost is negligible.
	tempRules := make(map[events.ID]EventRules)
	for k, v := range pm.rules {
		tempRules[k] = deepCopyEventRules(v)
	}

	// Perform operations on the temporary copies
	delete(tempPolicies, policyName) // Remove the policy

	// Every event carrying ANY of the policy's rules must be rebuilt: the directly-selected
	// ones (user rules) and every event holding one of its DEPENDENCY rules (bases of derived/
	// detector chains). updateRulesForEvent keeps only dependency rules whose chain is still
	// alive, so the removed policy's rules disappear from all of them.
	affected := make(map[events.ID]bool, len(policyToRemove.Rules))
	for eventID := range policyToRemove.Rules {
		affected[eventID] = true
	}
	for eventID, er := range tempRules {
		for _, rule := range er.Rules {
			if rule.Policy != nil && rule.Policy.Name == policyName {
				affected[eventID] = true
				break
			}
		}
	}
	affectedIDs := make([]events.ID, 0, len(affected))
	for eventID := range affected {
		affectedIDs = append(affectedIDs, eventID)
	}
	sort.Slice(affectedIDs, func(i, j int) bool { return affectedIDs[i] < affectedIDs[j] })

	// Rebuild while every event node still exists in the dependency manager: unselecting
	// first could cascade node removals and fail the rebuild midway.
	for _, eventID := range affectedIDs {
		if err := pm.updateRulesForEvent(eventID, tempRules, tempPolicies); err != nil {
			return errfmt.WrapError(err)
		}
	}

	// Drop events left with no rules at all: nothing selects them and no chain needs them.
	// An event that keeps DEPENDENCY rules stays even if the removed policy was the only one
	// selecting it directly - deleting it would break other policies' derived events by
	// destroying their base's rule table (their bitmap mapping resolves through it).
	for _, eventID := range affectedIDs {
		if er, ok := tempRules[eventID]; ok && len(er.Rules) == 0 {
			delete(tempRules, eventID)
		}
	}

	// Release the removed policy's direct selections in the dependency manager (only for
	// events no remaining policy selects directly; a dependency-needed event's node survives
	// via its consumers' dependency edges). May cascade node removals, which fire the
	// SubscribeRemove callback - its removals are re-applied to this generation at commit.
	for eventID := range policyToRemove.Rules {
		stillSelected := false
		for _, p := range tempPolicies {
			if _, ok := p.Rules[eventID]; ok {
				stillSelected = true
				break
			}
		}
		if !stillSelected {
			pm.evtsDepsManager.UnselectEvent(eventID)
		}
	}

	// Commit the changes to the actual PolicyManager. Retire the removed policy's rule IDs first (freeing them
	// for reuse), then re-stamp the survivors' stable IDs. Both run only after the rebuild succeeded, so a
	// mid-rebuild failure (which rolls back) never leaves the allocator inconsistent with pm.rules.
	pm.retireRuleIDs(policyName)
	pm.assignStableRuleIDs(tempRules)
	pm.policies = tempPolicies
	pm.commitRules(tempRules)

	return nil
}

// UpdatePolicy atomically replaces an existing policy (by name). Unlike RemovePolicy+AddPolicy, the whole
// change happens under one lock, so readers never see the policy absent. It is a locked remove then add; a
// failed add rolls both maps back.
//
// Per-rule DisableRule toggles on the policy's events reset, since the rules are rebuilt and their
// bitmap-position IDs shift (same as AddPolicy). A mid-update error does not roll back the dependency-manager
// selections (same non-transactionality as AddPolicy) and only arises from undefined events or unsatisfiable
// dependencies.
//
// Userland only: the caller (Tracee.ApplyPolicy) re-pushes the kernel filter maps via populateFilterMaps. The
// gRPC ApplyPolicy/RemovePolicy RPCs expose the full runtime flow.
func (pm *PolicyManager) UpdatePolicy(policy *Policy) error {
	if policy == nil {
		return PolicyNilError()
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if _, exists := pm.policies[policy.Name]; !exists {
		return PolicyNotFoundByNameError(policy.Name)
	}

	// removePolicyLocked/addPolicyLocked replace pm.policies/pm.rules wholesale (never mutate them in
	// place), so retaining the originals is enough to roll back a failed add.
	origPolicies, origRules := pm.policies, pm.rules

	if err := pm.removePolicyLocked(policy.Name); err != nil {
		return errfmt.WrapError(err)
	}
	if err := pm.addPolicyLocked(policy); err != nil {
		pm.policies, pm.rules = origPolicies, origRules
		pm.publishSnapshot() // restore the snapshot to the pre-update state
		return errfmt.WrapError(err)
	}

	// Single publish for the whole update, so readers never observe the intermediate remove.
	pm.publishSnapshot()
	return nil
}

// Snapshot is an immutable, atomically-published view of the per-event read state. Readers Load it once and
// read without locking; writers rebuild and Store it (publishSnapshot) under pm.mu after every mutation. The
// rules map is a fresh copy per publish, so later in-place map writes (toggles, delete) cannot mutate a
// published snapshot; the EventRules and their slices are replaced-not-mutated by writers (see the
// copy-on-write in setRuleEnabled and updateRulesForEvent), so sharing them is safe for lock-free readers.
//
// Runtime-swap correctness: the pipeline captures one Snapshot per event at decode (LoadSnapshot) and threads
// it through every stage (see PipelineEvent.RulesSnapshot), so all reads for an event resolve against one
// consistent version even if a runtime policy change publishes a newer snapshot mid-flight. Retention is
// automatic: an in-flight event holds a pointer to its Snapshot, so the GC keeps that version alive until the
// last event of it drains. The PolicyManager.GetXxx wrappers below read the latest snapshot for non-pipeline
// callers. All Snapshot read methods are safe on a nil receiver (they return the empty defaults).
type Snapshot struct {
	rules         map[events.ID]EventRules
	exportedFMaps *FilterMaps
	// pushedVersions[eventID] is the rules version currently written to the kernel
	// events_config_map for that event - i.e. the version exportedFMaps (the userland mirror)
	// is keyed at. It is captured together with exportedFMaps, so the two are ALWAYS the same
	// generation even when rules is a newer generation (the window between a manager mutation
	// and the kernel push). The net-event userland scope pass keys exportedFMaps by THIS, not
	// by the current rules version, so it narrows by the scope actually in the kernel.
	pushedVersions map[events.ID]uint16
}

// publishSnapshot rebuilds the read snapshot from the current rules + exported filter maps and atomically
// stores it. The caller must hold pm.mu (write). Call it from the public mutation entry points AFTER the
// mutation completes - not from the *Locked helpers - so a compound op like UpdatePolicy publishes exactly
// once and readers never observe its intermediate state.
func (pm *PolicyManager) publishSnapshot() {
	rules := make(map[events.ID]EventRules, len(pm.rules))
	for k, v := range pm.rules {
		rules[k] = v
	}
	// pushedVersions is captured together with exportedFMaps (both are pm fields updated only
	// inside updateBPF), so a snapshot's exported maps and their version keys are always the
	// same generation - even when rules is newer (mutation published before the kernel push).
	pushed := make(map[events.ID]uint16, len(pm.pushedVersions))
	for k, v := range pm.pushedVersions {
		pushed[k] = v
	}
	pm.snap.Store(&Snapshot{rules: rules, exportedFMaps: pm.exportedFMaps, pushedVersions: pushed})
}

// GetPushedVersion returns the rules version currently in the kernel (and in exportedFMaps) for
// the event, or the event's current rules version as a fallback when nothing has been pushed yet
// (init, before the first updateBPF - there are no in-flight events then). Used by the net-event
// userland scope pass to key exportedFMaps consistently with the kernel.
func (s *Snapshot) GetPushedVersion(eventID events.ID) uint16 {
	if v, ok := s.pushedVersions[eventID]; ok {
		return v
	}
	return s.GetRulesVersion(eventID)
}

// LoadSnapshot returns the current lock-free read snapshot. The pipeline calls it once per event at decode and
// threads the handle through the stages so every read for that event resolves against one consistent version.
func (pm *PolicyManager) LoadSnapshot() *Snapshot {
	return pm.snap.Load()
}

// eventRules returns the event's EventRules from this snapshot. Safe on a nil receiver.
func (s *Snapshot) eventRules(eventID events.ID) (EventRules, bool) {
	if s == nil {
		return EventRules{}, false
	}
	er, ok := s.rules[eventID]
	return er, ok
}

// deepCopyEventRules creates a deep copy of an EventRules struct.
func deepCopyEventRules(original EventRules) EventRules {
	copied := EventRules{
		rulesVersion: original.rulesVersion,
		rulesCount:   original.rulesCount,
		// containerFilteredRules and disabledRules MUST be copied, not shared: a rebuild
		// (assignStableRuleIDs prunes disabledRules in place; addTransitiveDependencyRules
		// SetBits containerFilteredRules in place) would otherwise mutate the backing array
		// of every already-published Snapshot — a data race on the lock-free read path and a
		// retroactive change to in-flight events' attribution. publishSnapshot copies only the
		// map, so these slice headers are what alias into live snapshots.
		containerFilteredRules: append([]uint64(nil), original.containerFilteredRules...),
		disabledRules:          append([]uint64(nil), original.disabledRules...),
		enabled:                original.enabled,
		Rules:                  make([]*EventRule, len(original.Rules)),
		UserlandRules:          make([]*EventRule, len(original.UserlandRules)),
		ruleIDToEventRule:      make(map[uint]*EventRule, len(original.ruleIDToEventRule)),
	}

	// Deep copy Rules
	for i, rule := range original.Rules {
		copied.Rules[i] = &EventRule{
			ID:                  rule.ID,
			Data:                rule.Data,   // Data pointers can be shared
			Policy:              rule.Policy, // Policy pointers can be shared
			SelectionType:       rule.SelectionType,
			DerivedRuleID:       rule.DerivedRuleID,
			DetectorScopeFilter: rule.DetectorScopeFilter, // shared pointer, ok
			DetectorDataFilter:  rule.DetectorDataFilter,  // shared pointer, ok
		}
	}

	// Deep copy UserlandRules
	for i, rule := range original.UserlandRules {
		copied.UserlandRules[i] = &EventRule{
			ID:                  rule.ID,
			Data:                rule.Data,   // Data pointers can be shared
			Policy:              rule.Policy, // Policy pointers can be shared
			SelectionType:       rule.SelectionType,
			DerivedRuleID:       rule.DerivedRuleID,
			DetectorScopeFilter: rule.DetectorScopeFilter, // shared pointer, ok
			DetectorDataFilter:  rule.DetectorDataFilter,  // shared pointer, ok
		}
	}

	// Deep copy ruleIDToEventRule
	for k, v := range original.ruleIDToEventRule {
		// Find the corresponding rule in the copied.Rules slice
		for _, copiedRule := range copied.Rules {
			if copiedRule.ID == v.ID {
				copied.ruleIDToEventRule[k] = copiedRule
				break
			}
		}
	}

	return copied
}

// updateRulesForEvent rebuilds the EventRules for the given eventID in the tempRules map.
// It gathers applicable rules from tempPolicies, assigns RuleIDs, and increments the rules version.
func (pm *PolicyManager) updateRulesForEvent(eventID events.ID, tempRules map[events.ID]EventRules, tempPolicies map[string]*Policy) error {
	if !events.Core.IsDefined(eventID) {
		return errfmt.Errorf("event %d is not defined", eventID)
	}
	if tempRules == nil || tempPolicies == nil {
		return errfmt.Errorf("nil maps provided")
	}

	var rules, userlandRules, existingDepRules []*EventRule
	ruleIDToEventRule := make(map[uint]*EventRule)
	ruleIDCounter := uint(0)
	var containerFilteredRules []uint64

	// Versions are MONOTONIC per event, surviving remove+re-add (lastRulesVersion): a reused
	// (version, event) key would alias the kernel inner filter maps of the retired generation
	// and resurrect its stale keys for unrelated new rules. uint16 wrap after 65535 rebuilds
	// of one event is tolerated - generations that old are long reaped.
	rulesVersion := pm.lastRulesVersion[eventID]
	enabled := true      // Default to true for new rules
	hasOverflow := false // Initialize hasOverflow flag
	var disabledRules []uint64

	if existingEventRules, ok := tempRules[eventID]; ok {
		if existingEventRules.rulesVersion > rulesVersion {
			rulesVersion = existingEventRules.rulesVersion
		}
		enabled = existingEventRules.enabled // Preserve existing enabled state
		// Preserve runtime DisableRule state: rule IDs are stable (assignStableRuleIDs), so the
		// bitmap stays meaningful for surviving rules. Dropping it here would silently re-enable
		// OTHER policies' disabled rules whenever any policy change touches the same event.
		// assignStableRuleIDs prunes bits whose rule retired, so a reused ID starts enabled.
		disabledRules = existingEventRules.disabledRules

		// Save existing dependency rules (created by rules with event that depend on this event),
		// but only those whose chain is still ALIVE: the owning policy must still exist and must
		// still select the consumer event that pulled this dependency in (Data.EventID). Nothing
		// else rebuilds dependency rules on this event, so without this filter a removed (or
		// retargeted) policy's dependency rules would survive here forever - keeping its rule
		// IDs registered and its filters pushed to the kernel.
		for _, rule := range existingEventRules.Rules {
			if rule.SelectionType != SelectedByDependency {
				continue
			}
			if rule.Policy == nil || rule.Data == nil {
				continue
			}
			owner, ok := tempPolicies[rule.Policy.Name]
			if !ok {
				continue
			}
			if _, ok := owner.Rules[rule.Data.EventID]; !ok {
				continue
			}
			existingDepRules = append(existingDepRules, rule)
		}
	}

	eventNode, err := pm.evtsDepsManager.GetEvent(eventID)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Gather rules from all policies that apply to this event. Iterate in a stable, name-sorted
	// order so rule IDs (bitmap positions) are deterministic across runs: Go map iteration is
	// randomized, which would otherwise make each policy's rule ID vary run to run, hurting
	// reproducibility, log correlation and test stability.
	policyNames := make([]string, 0, len(tempPolicies))
	for name := range tempPolicies {
		policyNames = append(policyNames, name)
	}
	sort.Strings(policyNames)
	for _, policyName := range policyNames {
		policy := tempPolicies[policyName]
		ruleData, ok := policy.Rules[eventID]
		if !ok {
			continue // This policy doesn't have rules for this event
		}

		rule := &EventRule{
			ID:            ruleIDCounter,
			Data:          &ruleData,
			Policy:        policy,
			SelectionType: SelectedByUser,
		}

		if policy == pm.bootstrapPolicy {
			rule.SelectionType = SelectedByBootstrap
		}

		rules = append(rules, rule)
		ruleIDToEventRule[ruleIDCounter] = rule
		ruleIDCounter++

		// Add dependency rules for this specific rule
		if err := pm.addTransitiveDependencyRules(eventNode, tempRules, make(map[events.ID]bool), 0, rule, nil, nil); err != nil {
			return errfmt.WrapError(err)
		}

		// Update containerFilteredRules bitmap
		if policy.ContainerFilterEnabled() {
			bitmapIndex := rule.ID / 64
			bitOffset := rule.ID % 64

			// Ensure containerFilteredRules has enough bitmaps
			for len(containerFilteredRules) <= int(bitmapIndex) {
				containerFilteredRules = append(containerFilteredRules, 0)
			}

			bitwise.SetBit(&containerFilteredRules[bitmapIndex], uint(bitOffset))
		}

		// Update userlandFilterableRules bitmap
		if isRuleFilterableInUserland(rule) {
			userlandRules = append(userlandRules, rule)
		}
	}

	// Add remaining dependency rules to the final rules list, and re-add the scope-only ones to
	// userlandRules. addTransitiveDependencyRules adds them on first creation, but this rebuild
	// path starts userlandRules empty, so omitting them here would skip their userland scope
	// re-check (silently dropping kernel-unrepresentable scope dimensions on the base event).
	for _, depRule := range existingDepRules {
		rules = append(rules, depRule)
		ruleIDToEventRule[ruleIDCounter] = depRule
		depRule.ID = ruleIDCounter
		ruleIDCounter++
		if isRuleFilterableInUserland(depRule) {
			userlandRules = append(userlandRules, depRule)
		}
	}

	// Set hasOverflow when a rule with ID >= 64 exists (more than 64 total rules): the kernel's
	// single-u64 matched_rules bitmap only represents IDs 0-63. Exactly 64 rules (IDs 0-63) still
	// fit, so the boundary is strictly greater than 64.
	if ruleIDCounter > 64 {
		hasOverflow = true
	}

	// Update the EventRules for the event in the temporary map
	pm.lastRulesVersion[eventID] = rulesVersion + 1
	tempRules[eventID] = EventRules{
		Rules:                  rules,
		UserlandRules:          userlandRules,
		ruleIDToEventRule:      ruleIDToEventRule,
		rulesVersion:           rulesVersion + 1,
		rulesCount:             ruleIDCounter,
		containerFilteredRules: containerFilteredRules,
		disabledRules:          disabledRules,
		enabled:                enabled,
		hasOverflow:            hasOverflow,
	}

	return nil
}

// addTransitiveDependencyRules recursively adds dependency rules for the given event and all its transitive dependencies.
func (pm *PolicyManager) addTransitiveDependencyRules(
	eventNode *dependencies.EventNode,
	tempRules map[events.ID]EventRules,
	visited map[events.ID]bool,
	depth int,
	parentRule *EventRule,
	inheritedDetectorScope *filters.ScopeFilter,
	inheritedDetectorData *filters.DataFilter,
) error {
	const maxDepth = 5

	if depth > maxDepth {
		return errfmt.Errorf("max dependency depth exceeded")
	}

	eventID := eventNode.GetID()
	if visited[eventID] {
		return errfmt.Errorf("circular dependency detected")
	}
	visited[eventID] = true
	defer delete(visited, eventID)

	for _, depID := range eventNode.GetDependencies().GetIDs() {
		// Phase 2: the detector scope for this dependency edge is an explicit declaration for the
		// (eventNode -> depID) edge (when eventNode is a detector output), else the scope inherited
		// from an ancestor detector edge, so it propagates down to the transitive kernel base.
		depDetectorScope := inheritedDetectorScope
		if perBase, ok := pm.detectorScopeFilters[eventNode.GetID()]; ok {
			if s := perBase[depID]; s != nil {
				depDetectorScope = s
			}
		}
		// Same for the detector's declared data filter on this dependency edge.
		depDetectorData := inheritedDetectorData
		if perBase, ok := pm.detectorDataFilters[eventNode.GetID()]; ok {
			if d := perBase[depID]; d != nil {
				depDetectorData = d
			}
		}

		eventRules, ok := tempRules[depID]
		if !ok {
			eventRules = EventRules{
				Rules:             make([]*EventRule, 0),
				UserlandRules:     make([]*EventRule, 0),
				ruleIDToEventRule: make(map[uint]*EventRule),
				enabled:           true,
			}
		}

		// A dependency rule for this (policy, chain) may already exist - added earlier in this
		// same walk, or carried over from the previous generation via existingDepRules. Match
		// on the LOGICAL chain key (policy name + consumer event, i.e. Data.EventID - the same
		// key the stable-ID allocator uses), NOT on Data pointer identity: every rebuild
		// creates a fresh RuleData for the same chain, so pointer matching would append a
		// duplicate rule on every runtime policy change (unbounded growth under churn).
		var existingChainRule *EventRule
		for _, existingRule := range eventRules.Rules {
			if existingRule.SelectionType == SelectedByDependency &&
				existingRule.Policy != nil && parentRule.Policy != nil &&
				existingRule.Policy.Name == parentRule.Policy.Name &&
				existingRule.Data != nil && parentRule.Data != nil &&
				existingRule.Data.EventID == parentRule.Data.EventID {
				existingChainRule = existingRule
				break
			}
		}

		if existingChainRule != nil {
			// Refresh the surviving rule's chain pointers so it keeps resolving against the
			// CURRENT consumer rule: GetDerivedEventMatchedRules matches chains by shared
			// RuleData pointer, and the stale generation's pointer no longer appears anywhere.
			existingChainRule.Data = parentRule.Data
			existingChainRule.Policy = parentRule.Policy
			existingChainRule.DerivedRuleID = parentRule.ID
			existingChainRule.DetectorScopeFilter = depDetectorScope
			existingChainRule.DetectorDataFilter = depDetectorData
		} else {
			// Create dependency rule using parent's data and policy context
			// This allows tracking which rule/policy caused this dependency
			rule := &EventRule{
				ID:                  eventRules.rulesCount,
				Data:                parentRule.Data,
				Policy:              parentRule.Policy,
				SelectionType:       SelectedByDependency,
				DerivedRuleID:       parentRule.ID,
				DetectorScopeFilter: depDetectorScope,
				DetectorDataFilter:  depDetectorData,
			}

			eventRules.Rules = append(eventRules.Rules, rule)
			eventRules.ruleIDToEventRule[rule.ID] = rule

			// Add to userland rules if parent has userland filters
			if isRuleFilterableInUserland(rule) {
				eventRules.UserlandRules = append(eventRules.UserlandRules, rule)
			}

			// Update container filter bitmap if parent has container filters
			if rule.Policy.ContainerFilterEnabled() {
				bitmapIndex := rule.ID / 64
				bitOffset := rule.ID % 64

				// Ensure containerFilteredRules has enough bitmaps
				for len(eventRules.containerFilteredRules) <= int(bitmapIndex) {
					eventRules.containerFilteredRules = append(eventRules.containerFilteredRules, 0)
				}

				bitwise.SetBit(&eventRules.containerFilteredRules[bitmapIndex], uint(bitOffset))
			}

			eventRules.rulesCount++
			tempRules[depID] = eventRules
		}

		depNode, err := pm.evtsDepsManager.GetEvent(depID)
		if err != nil {
			return err
		}

		// Recursively add dependency rules for the dependencies of the dependency
		if err := pm.addTransitiveDependencyRules(depNode, tempRules, visited, depth+1, parentRule, depDetectorScope, depDetectorData); err != nil {
			return err
		}
	}

	return nil
}

// isRuleFilterableInUserland checks if a rule is filterable in userland.
func isRuleFilterableInUserland(rule *EventRule) bool {
	if rule == nil {
		return false
	}

	// Dependency rules are scope-only (see EventRule.IsDependency): their data and
	// return-value filters belong to the dependent/derived event's schema and are not
	// applied to this base event, so they don't make the base rule userland-filterable.
	isDep := rule.IsDependency()

	// A Phase-2 detector scope filter (rule-local, ANDed with Data.ScopeFilter) is workload-level
	// and makes the rule userland-filterable regardless of dependency status.
	if rule.DetectorScopeFilter != nil && rule.DetectorScopeFilter.Enabled() {
		return true
	}

	// A Phase-2 detector data filter (rule-local) is on the base event's own schema, so it makes the
	// rule userland-filterable regardless of dependency status (unlike Data.DataFilter, which belongs
	// to the dependent/derived event).
	if rule.DetectorDataFilter != nil && rule.DetectorDataFilter.Enabled() {
		return true
	}

	// Check rule.Data and its filters
	if rule.Data != nil {
		// Scope filters are workload-level and apply to every rule, dependency or not.
		if rule.Data.ScopeFilter != nil && rule.Data.ScopeFilter.Enabled() {
			return true
		}
		// TODO: if kernel filter is enabled for the data filter, don't consider it filterable in userland
		if !isDep &&
			((rule.Data.DataFilter != nil && rule.Data.DataFilter.Enabled()) ||
				(rule.Data.RetFilter != nil && rule.Data.RetFilter.Enabled())) {
			return true
		}
	}

	// Check policy-level filters
	if rule.Policy != nil {
		if (rule.Policy.UIDFilter != nil && rule.Policy.UIDFilter.Enabled()) &&
			((rule.Policy.UIDFilter.Minimum() != filters.GetUnsetMin[uint32]()) ||
				(rule.Policy.UIDFilter.Maximum() != filters.GetUnsetMax[uint32]())) {
			return true
		}

		if rule.Policy.PIDFilter != nil && rule.Policy.PIDFilter.Enabled() &&
			((rule.Policy.PIDFilter.Minimum() != filters.GetUnsetMin[uint32]()) ||
				(rule.Policy.PIDFilter.Maximum() != filters.GetUnsetMax[uint32]())) {
			return true
		}
	}

	return false
}

// lookupPolicyByName returns a policy by name.
func (pm *PolicyManager) LookupPolicyByName(name string) (*Policy, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if p, ok := pm.policies[name]; ok {
		return p, nil
	}

	return nil, PolicyNotFoundByNameError(name)
}

// ListPolicyNames returns the names of all user-facing policies (excluding the internal bootstrap policy),
// sorted. Reads pm.policies under the read lock (policies are not part of the lock-free event snapshot).
func (pm *PolicyManager) ListPolicyNames() []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	names := make([]string, 0, len(pm.policies))
	for name := range pm.policies {
		if pm.bootstrapPolicy != nil && name == pm.bootstrapPolicy.Name {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// GetRules returns the Rules slice for a given event ID.
//
// Warning: This function returns a direct reference to the internal Rules slice.
// While the implementation ensures that the returned slice will not be modified
// directly, it may be replaced entirely by concurrent updates to the PolicyManager.
// The caller MUST NOT modify the returned slice and should be aware that the
// slice may become stale if the PolicyManager's state is changed concurrently.
// It is the caller's responsibility to ensure that they are not relying on
// the slice to remain unchanged across calls to AddPolicy, RemovePolicy, or
// any other function that might update the PolicyManager's rules.
func (s *Snapshot) GetRules(eventID events.ID) []*EventRule {
	eventRules, ok := s.eventRules(eventID)
	if !ok {
		return nil // Or return an empty slice: []*EventRule{}
	}

	return eventRules.Rules
}

// GetRules reads the latest snapshot; see (*Snapshot).GetRules.
func (pm *PolicyManager) GetRules(eventID events.ID) []*EventRule {
	return pm.snap.Load().GetRules(eventID)
}

// GetUserlandRules returns the UserlandRules slice for a given event ID.
//
// Warning: This function returns a direct reference to the internal UserlandRules slice.
// While the implementation ensures that the returned slice will not be modified
// directly, it may be replaced entirely by concurrent updates to the PolicyManager.
// The caller MUST NOT modify the returned slice and should be aware that the
// slice may become stale if the PolicyManager's state is changed concurrently.
// It is the caller's responsibility to ensure that they are not relying on
// the slice to remain unchanged across calls to AddPolicy, RemovePolicy, or
// any other function that might update the PolicyManager's rules.
func (s *Snapshot) GetUserlandRules(eventID events.ID) []*EventRule {
	eventRules, ok := s.eventRules(eventID)
	if !ok {
		return nil // Or return an empty slice: []*EventRule{}
	}

	return eventRules.UserlandRules
}

// GetUserlandRules reads the latest snapshot; see (*Snapshot).GetUserlandRules.
func (pm *PolicyManager) GetUserlandRules(eventID events.ID) []*EventRule {
	return pm.snap.Load().GetUserlandRules(eventID)
}

// GetFilterMaps returns the cached read-only export of the filter maps for the userland
// overflow rules matcher. The export is built once per updateBPF (see buildExportedFilterMaps),
// not per call, because it is read on the event hot path. The returned value is immutable
// (replaced, never mutated), so callers may read it without holding the lock.
func (s *Snapshot) GetFilterMaps() *FilterMaps {
	if s == nil {
		return nil
	}
	return s.exportedFMaps
}

// GetFilterMaps reads the latest snapshot; see (*Snapshot).GetFilterMaps.
func (pm *PolicyManager) GetFilterMaps() *FilterMaps {
	return pm.snap.Load().GetFilterMaps()
}

// buildExportedFilterMaps converts the internal filterMaps into the exported, read-only
// FilterMaps consumed by the userland overflow matcher. The caller must hold pm.mu (write).
func buildExportedFilterMaps(fMaps *filterMaps) *FilterMaps {
	if fMaps == nil {
		return nil
	}

	// Convert internal filterMaps to exported FilterMaps
	exported := &FilterMaps{
		UIDFilters:                 make(map[FilterVersionKey]map[uint64][]RuleBitmap),
		PIDFilters:                 make(map[FilterVersionKey]map[uint64][]RuleBitmap),
		MntNsFilters:               make(map[FilterVersionKey]map[uint64][]RuleBitmap),
		PidNsFilters:               make(map[FilterVersionKey]map[uint64][]RuleBitmap),
		CgroupFilters:              make(map[FilterVersionKey]map[uint64][]RuleBitmap),
		UTSFilters:                 make(map[FilterVersionKey]map[string][]RuleBitmap),
		CommFilters:                make(map[FilterVersionKey]map[string][]RuleBitmap),
		BinaryFilters:              make(map[FilterVersionKey]map[filters.NSBinary][]RuleBitmap),
		ExtendedScopeFilterConfigs: make(map[FilterVersionKey]ExtendedScopeFiltersConfig),
	}

	// Convert UID filters
	for k, v := range fMaps.uidFilters {
		exported.UIDFilters[FilterVersionKey(k)] = convertUint64RuleBitmaps(v)
	}

	// Convert PID filters
	for k, v := range fMaps.pidFilters {
		exported.PIDFilters[FilterVersionKey(k)] = convertUint64RuleBitmaps(v)
	}

	// Convert Mount NS filters
	for k, v := range fMaps.mntNSFilters {
		exported.MntNsFilters[FilterVersionKey(k)] = convertUint64RuleBitmaps(v)
	}

	// Convert PID NS filters
	for k, v := range fMaps.pidNSFilters {
		exported.PidNsFilters[FilterVersionKey(k)] = convertUint64RuleBitmaps(v)
	}

	// Convert Cgroup filters
	for k, v := range fMaps.cgroupIdFilters {
		exported.CgroupFilters[FilterVersionKey(k)] = convertUint64RuleBitmaps(v)
	}

	// Convert UTS filters
	for k, v := range fMaps.utsFilters {
		exported.UTSFilters[FilterVersionKey(k)] = convertStringRuleBitmaps(v)
	}

	// Convert Comm filters
	for k, v := range fMaps.commFilters {
		exported.CommFilters[FilterVersionKey(k)] = convertStringRuleBitmaps(v)
	}

	// Convert Binary filters (consumed by the userland post-proctree overflow narrowing)
	for k, v := range fMaps.binaryFilters {
		exported.BinaryFilters[FilterVersionKey(k)] = convertBinaryRuleBitmaps(v)
	}

	// Convert Extended Scope Filter Configs
	for vKey, cfg := range fMaps.extendedScopeFilterConfigs {
		exported.ExtendedScopeFilterConfigs[FilterVersionKey(vKey)] = ExtendedScopeFiltersConfig(cfg)
	}

	return exported
}

// Helper function to convert uint64 rule bitmaps
func convertUint64RuleBitmaps(input map[uint64][]ruleBitmap) map[uint64][]RuleBitmap {
	output := make(map[uint64][]RuleBitmap)
	for k, v := range input {
		output[k] = convertRuleBitmapSlice(v)
	}
	return output
}

// Helper function to convert string rule bitmaps
func convertStringRuleBitmaps(input map[string][]ruleBitmap) map[string][]RuleBitmap {
	output := make(map[string][]RuleBitmap)
	for k, v := range input {
		output[k] = convertRuleBitmapSlice(v)
	}
	return output
}

func convertBinaryRuleBitmaps(input map[filters.NSBinary][]ruleBitmap) map[filters.NSBinary][]RuleBitmap {
	output := make(map[filters.NSBinary][]RuleBitmap)
	for k, v := range input {
		output[k] = convertRuleBitmapSlice(v)
	}
	return output
}

// Helper function to convert ruleBitmap slice to RuleBitmap slice
func convertRuleBitmapSlice(input []ruleBitmap) []RuleBitmap {
	output := make([]RuleBitmap, len(input))
	for i, rb := range input {
		output[i] = RuleBitmap{
			EqualsInRules:  rb.equalsInRules,
			KeyUsedInRules: rb.keyUsedInRules,
		}
	}
	return output
}

// GetContainerFilteredRulesBitmap returns a bitmap where each bit represents a rule
// for the given event ID, and the bit is set if the corresponding rule has
// container filtering enabled.
func (s *Snapshot) GetContainerFilteredRulesBitmap(eventID events.ID) []uint64 {
	eventRules, ok := s.eventRules(eventID)
	if !ok {
		return []uint64{0} // No rules for this event, return an empty bitmap
	}

	return eventRules.containerFilteredRules
}

// GetContainerFilteredRulesBitmap reads the latest snapshot; see (*Snapshot).GetContainerFilteredRulesBitmap.
func (pm *PolicyManager) GetContainerFilteredRulesBitmap(eventID events.ID) []uint64 {
	return pm.snap.Load().GetContainerFilteredRulesBitmap(eventID)
}

// GetMatchedRulesInfo processes a bitmap array of matched rule IDs for a given event and returns
// a list of policy names corresponding to the matched rules that have the Emit flag set.
// Supports rules with ID > 64 through bitmap arrays.
func (s *Snapshot) GetMatchedRulesInfo(eventID events.ID, matchedRuleIDsBitmap []uint64) []string {
	var matchedPolicyNames []string

	eventRules, ok := s.eventRules(eventID)
	if !ok {
		return matchedPolicyNames
	}

	for ruleID := uint(0); ruleID < eventRules.rulesCount; ruleID++ {
		// Check if this rule is matched using bitmap array utilities
		if !bitwise.HasBitInArray(matchedRuleIDsBitmap, ruleID) {
			continue
		}

		rule, ok := eventRules.ruleIDToEventRule[ruleID]
		if !ok {
			// With stable rule IDs a removed rule's ID is retired and may leave a gap below rulesCount. An
			// event still in the perf buffer when its matched rule was removed carries that (now-retired) bit;
			// skipping it here is correct (the rule no longer exists, so it must not be attributed). This is
			// an expected transient during a runtime policy removal - hence Debug, not Error. A persistent
			// occurrence for a live rule would still indicate a real bitmap/rules mismatch.
			logger.Debugw("Skipping retired/unknown ruleID in GetMatchedRulesInfo",
				"eventID", eventID,
				"ruleID", ruleID,
				"note", "bitmap bit has no rule in this version (retired ID or in-flight removal)",
			)
			continue
		}

		if rule.SelectionType == SelectedByUser {
			matchedPolicyNames = append(matchedPolicyNames, rule.Policy.Name)
		}
	}

	return matchedPolicyNames
}

// GetMatchedRulesInfo reads the latest snapshot; see (*Snapshot).GetMatchedRulesInfo.
func (pm *PolicyManager) GetMatchedRulesInfo(eventID events.ID, matchedRuleIDsBitmap []uint64) []string {
	return pm.snap.Load().GetMatchedRulesInfo(eventID, matchedRuleIDsBitmap)
}

func (s *Snapshot) GetDerivedEventMatchedRules(
	derivedEventID events.ID,
	baseEventID events.ID,
	baseMatchedRulesBitmap []uint64,
) []uint64 {
	if s == nil {
		return []uint64{}
	}
	baseEventRules, ok := s.rules[baseEventID]
	if !ok {
		return []uint64{}
	}
	derivedEventRules, ok := s.rules[derivedEventID]
	if !ok {
		return []uint64{}
	}

	var derivedMatchedRules []uint64

	for ruleID := uint(0); ruleID < baseEventRules.rulesCount; ruleID++ {
		// For rules >= 64, only process if event has overflow
		if ruleID >= 64 && !baseEventRules.hasOverflow {
			continue
		}

		// Check if this rule is matched in the base event using bitmap array
		if !bitwise.HasBitInArray(baseMatchedRulesBitmap, ruleID) {
			continue
		}

		baseRule, ok := baseEventRules.ruleIDToEventRule[ruleID]
		if !ok || baseRule.SelectionType != SelectedByDependency || baseRule.Data == nil {
			continue
		}

		// The base event's matched dependency rule belongs to a chain identified by its
		// shared RuleData pointer (addTransitiveDependencyRules gives every rule in a chain
		// the same RuleData, and deepCopyEventRules preserves the pointer). Map the match to
		// the derived event's rule on the SAME chain. That rule may be the final
		// user-selected rule (single-level derivation, where Data.EventID == derivedEventID)
		// or an intermediate dependency rule (multi-level chains, e.g. a detector consuming a
		// derived event, where the dependency rules carry the top consumer's Data.EventID).
		// Keying on Data.EventID alone would miss the intermediate levels and drop the event.
		for _, derivedRule := range derivedEventRules.Rules {
			if derivedRule.Data == baseRule.Data {
				bitwise.SetBitInArray(&derivedMatchedRules, derivedRule.ID)
			}
		}
	}

	return derivedMatchedRules
}

// GetDerivedEventMatchedRules reads the latest snapshot; see (*Snapshot).GetDerivedEventMatchedRules.
func (pm *PolicyManager) GetDerivedEventMatchedRules(
	derivedEventID events.ID,
	baseEventID events.ID,
	baseMatchedRulesBitmap []uint64,
) []uint64 {
	return pm.snap.Load().GetDerivedEventMatchedRules(derivedEventID, baseEventID, baseMatchedRulesBitmap)
}

// IsEventEnabled checks if an event is currently enabled.
func (s *Snapshot) IsEventEnabled(eventID events.ID) bool {
	eventRules, ok := s.eventRules(eventID)
	if !ok {
		return false // Event not found, consider it disabled
	}

	return eventRules.enabled
}

// IsEventEnabled reads the latest snapshot; see (*Snapshot).IsEventEnabled.
func (pm *PolicyManager) IsEventEnabled(eventID events.ID) bool {
	return pm.snap.Load().IsEventEnabled(eventID)
}

// EnableRule re-enables the named policy's rule(s) for the given event at runtime.
func (pm *PolicyManager) EnableRule(policyName string, eventID events.ID) error {
	return pm.setRuleEnabled(policyName, eventID, true)
}

// DisableRule disables the named policy's rule(s) for the given event at runtime: the rule
// stops matching (its events are no longer emitted for that policy) while the event still
// flows for its other rules. Userland-only - the kernel still evaluates/submits the event;
// a kernel-side submit_for_rules rebuild (to also stop kernel work) is a future optimization.
// Lost on policy reload (runtime toggle, not persisted).
func (pm *PolicyManager) DisableRule(policyName string, eventID events.ID) error {
	return pm.setRuleEnabled(policyName, eventID, false)
}

// setRuleEnabled toggles the disabled-bit for every rule of policyName on eventID. It rebuilds
// the disabledRules bitmap copy-on-write (never mutates the shared slice in place) so in-flight
// matchers reading the old snapshot stay race-free, matching the manager's reload pattern.
func (pm *PolicyManager) setRuleEnabled(policyName string, eventID events.ID, enable bool) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	eventRules, ok := pm.rules[eventID]
	if !ok {
		return errfmt.Errorf("event %d has no rules", eventID)
	}

	newDisabled := make([]uint64, len(eventRules.disabledRules))
	copy(newDisabled, eventRules.disabledRules)

	found := false
	for _, rule := range eventRules.Rules {
		if rule.Policy == nil || rule.Policy.Name != policyName {
			continue
		}
		found = true
		if enable {
			bitwise.ClearBitInArray(&newDisabled, rule.ID)
		} else {
			bitwise.SetBitInArray(&newDisabled, rule.ID)
		}
	}
	if !found {
		return errfmt.Errorf("policy %q has no rule for event %d", policyName, eventID)
	}

	eventRules.disabledRules = newDisabled
	pm.rules[eventID] = eventRules
	if !enable {
		pm.disabledAny.Store(true) // open the hot-path gate (stays open; re-enabling is rare)
	}
	pm.publishSnapshot()
	return nil
}

// AnyRulesDisabled reports (lock-free) whether any rule has ever been disabled at runtime.
// Used to skip the disabled-rules lookup on the event hot path in the common case.
func (pm *PolicyManager) AnyRulesDisabled() bool {
	return pm.disabledAny.Load()
}

// GetDisabledRules returns the bitmap of rules disabled at runtime for the event (nil if
// none). The returned slice is immutable (replaced, never mutated in place), so callers may
// read it without holding the lock.
func (s *Snapshot) GetDisabledRules(eventID events.ID) []uint64 {
	eventRules, ok := s.eventRules(eventID)
	if !ok {
		return nil
	}
	return eventRules.disabledRules
}

// GetDisabledRules reads the latest snapshot; see (*Snapshot).GetDisabledRules.
func (pm *PolicyManager) GetDisabledRules(eventID events.ID) []uint64 {
	return pm.snap.Load().GetDisabledRules(eventID)
}

// EnableEvent enables a specific event in the PolicyManager.
// It assumes that the eventID is always valid.
func (pm *PolicyManager) EnableEvent(eventID events.ID) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	eventRules := pm.rules[eventID]
	eventRules.enabled = true
	pm.rules[eventID] = eventRules
	pm.publishSnapshot()
}

// DisableEvent disables a specific event in the PolicyManager.
// It assumes that the eventID is always valid.
func (pm *PolicyManager) DisableEvent(eventID events.ID) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	eventRules := pm.rules[eventID]
	eventRules.enabled = false
	pm.rules[eventID] = eventRules
	pm.publishSnapshot()
}

// GetSelectedEvents returns a slice of all the event IDs that are currently selected
// either directly by a policy or as a dependency.
func (s *Snapshot) GetSelectedEvents() []events.ID {
	if s == nil {
		return nil
	}
	selectedEvents := make([]events.ID, 0, len(s.rules))
	for evt := range s.rules {
		selectedEvents = append(selectedEvents, evt)
	}

	return selectedEvents
}

// GetSelectedEvents reads the latest snapshot; see (*Snapshot).GetSelectedEvents.
func (pm *PolicyManager) GetSelectedEvents() []events.ID {
	return pm.snap.Load().GetSelectedEvents()
}

// IsEventSelected checks if an event is selected by any policy, either directly or as a dependency.
func (s *Snapshot) IsEventSelected(eventID events.ID) bool {
	_, ok := s.eventRules(eventID)
	return ok
}

// IsEventSelected reads the latest snapshot; see (*Snapshot).IsEventSelected.
func (pm *PolicyManager) IsEventSelected(eventID events.ID) bool {
	return pm.snap.Load().IsEventSelected(eventID)
}

// HasOverflowRules checks if the specified event has more than 64 rules
func (s *Snapshot) HasOverflowRules(eventID events.ID) bool {
	eventRules, ok := s.eventRules(eventID)
	if !ok {
		return false // Event not found, no overflow
	}

	return eventRules.hasOverflow
}

// HasOverflowRules reads the latest snapshot; see (*Snapshot).HasOverflowRules.
func (pm *PolicyManager) HasOverflowRules(eventID events.ID) bool {
	return pm.snap.Load().HasOverflowRules(eventID)
}

// GetRulesCount returns the total number of rules for the event (0 if none). Used by the
// userland overflow matcher to mask off bit positions beyond the real rules.
func (s *Snapshot) GetRulesCount(eventID events.ID) uint {
	eventRules, ok := s.eventRules(eventID)
	if !ok {
		return 0
	}

	return eventRules.rulesCount
}

// GetRulesCount reads the latest snapshot; see (*Snapshot).GetRulesCount.
func (pm *PolicyManager) GetRulesCount(eventID events.ID) uint {
	return pm.snap.Load().GetRulesCount(eventID)
}

// GetRulesVersion returns the rules version of the event's rule set in THIS snapshot (0 if the
// event has no rules). Userland re-evaluation of kernel scope filters against the snapshot's
// exported filter maps must key them by this version - not by the version stamped in a kernel
// event context, which for socket-bound net events reflects socket-creation time and can be stale.
func (s *Snapshot) GetRulesVersion(eventID events.ID) uint16 {
	eventRules, ok := s.eventRules(eventID)
	if !ok {
		return 0
	}

	return eventRules.rulesVersion
}

// GetAllRulesBitmap returns a []uint64 bitmap with a bit set for every LIVE rule ID of the event
// - the userland equivalent of the kernel's submit_for_rules, used to seed the net-event and
// overflow decode paths. A retired rule ID leaves a gap (no bit) so downstream never treats a
// gap as a live rule. Returns a FRESH copy each call: callers (matchOverflowRules,
// narrowNetBaseEventScope) mutate the returned slice in place, so it must not alias the cached
// bitmap shared by every published snapshot.
func (s *Snapshot) GetAllRulesBitmap(eventID events.ID) []uint64 {
	eventRules, ok := s.eventRules(eventID)
	if !ok || len(eventRules.allRulesBitmap) == 0 {
		return nil
	}
	return append([]uint64(nil), eventRules.allRulesBitmap...)
}

// GetAllRulesBitmap reads the latest snapshot; see (*Snapshot).GetAllRulesBitmap.
func (pm *PolicyManager) GetAllRulesBitmap(eventID events.ID) []uint64 {
	return pm.snap.Load().GetAllRulesBitmap(eventID)
}

// ShouldEmitEvent checks if an event has at least one rule that was explicitly
// selected by a user (not a dependency or bootstrap rule), indicating that the event
// should be emitted.
func (s *Snapshot) ShouldEmitEvent(eventID events.ID) bool {
	eventRules, ok := s.eventRules(eventID)
	if !ok {
		return false // Event not found or no rules defined, not emitted
	}

	for _, rule := range eventRules.Rules {
		if rule.SelectionType == SelectedByUser {
			return true // Found at least one rule explicitly selected by the user
		}
	}

	return false // No rules were explicitly selected by the user
}

// ShouldEmitEvent reads the latest snapshot; see (*Snapshot).ShouldEmitEvent.
func (pm *PolicyManager) ShouldEmitEvent(eventID events.ID) bool {
	return pm.snap.Load().ShouldEmitEvent(eventID)
}

// GetAllMatchedRulesBitmap returns a bitmap array with a bit set for every LIVE rule of the
// event (all rules considered matched). Like GetAllRulesBitmap it returns a fresh copy of the
// cached bitmap; it differs only in returning an empty (non-nil) slice when the event has no
// rules, which its caller relies on.
func (s *Snapshot) GetAllMatchedRulesBitmap(eventID events.ID) []uint64 {
	eventRules, ok := s.eventRules(eventID)
	if !ok || len(eventRules.allRulesBitmap) == 0 {
		return []uint64{}
	}
	return append([]uint64(nil), eventRules.allRulesBitmap...)
}

// GetAllMatchedRulesBitmap reads the latest snapshot; see (*Snapshot).GetAllMatchedRulesBitmap.
func (pm *PolicyManager) GetAllMatchedRulesBitmap(eventID events.ID) []uint64 {
	return pm.snap.Load().GetAllMatchedRulesBitmap(eventID)
}

func (pm *PolicyManager) UpdateBPF(
	bpfModule *bpf.Module,
	cts *container.Manager,
	eventsFields map[events.ID][]data.DecodeAs,
) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if err := pm.updateBPF(bpfModule, cts, eventsFields); err != nil {
		return err
	}
	pm.publishSnapshot() // exportedFMaps was rebuilt; refresh the read snapshot
	return nil
}
