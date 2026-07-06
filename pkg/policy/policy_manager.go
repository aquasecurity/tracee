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
	bpfInnerMaps    map[string]*bpf.BPFMapLow // TODO: move this to ebpf related code
	mu              sync.RWMutex              // Read/Write Mutex to protect concurrent access
	cfg             ManagerConfig
	fMaps           *filterMaps
	exportedFMaps   *FilterMaps // cached read-only export of fMaps for the overflow matcher (rebuilt per updateBPF)
	disabledAny     atomic.Bool // fast gate: set once any rule is disabled, so the hot path can skip the disabled-rules lookup
	// snap is the immutable, atomically-published view of the per-event read state (rules + exported filter
	// maps). The event hot path Loads it once and reads without taking pm.mu; writers rebuild and Store it
	// under pm.mu after every mutation (see publishSnapshot). Never nil after NewManager.
	snap atomic.Pointer[policySnapshot]
	// detectorScopeFilters holds, per detector OUTPUT event, the scope filters the detector declared
	// for each required base event (Requirements.Events[].ScopeFilters). Phase 2 pushes them onto the
	// base events' dependency rules (EventRule.DetectorScopeFilter). Keyed detectorOutputID -> baseID.
	// Set via SetDetectorScopeFilters (after detectors register); RecomputeRules then threads them in.
	// nil = none.
	detectorScopeFilters map[events.ID]map[events.ID]*filters.ScopeFilter
	// detectorDataFilters is the data-filter analogue of detectorScopeFilters
	// (Requirements.Events[].DataFilters), pushed onto EventRule.DetectorDataFilter. Same keying.
	detectorDataFilters map[events.ID]map[events.ID]*filters.DataFilter
}

// EventRules holds information about a specific event.
type EventRules struct {
	Rules                  []*EventRule        // List of rules associated with this event
	UserlandRules          []*EventRule        // List of rules with userland filters enabled
	enabled                bool                // Flag indicating whether the event is enabled. TODO: move to events manager
	rulesVersion           uint16              // Version of the rules for this event (for future updates)
	rulesCount             uint                // The total number of rules for this event
	ruleIDToEventRule      map[uint]*EventRule // Map from RuleID to EventRule for fast lookup
	containerFilteredRules []uint64            // Bitmaps to track container-filtered rules
	disabledRules          []uint64            // Bitmap of rules disabled at runtime (EnableRule/DisableRule)
	hasOverflow            bool                // Flag to indicate if there are more than 64 rules
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
		policies:        make(map[string]*Policy),
		rules:           make(map[events.ID]EventRules),
		evtsDepsManager: evtsDepsManager,
		bpfInnerMaps:    make(map[string]*bpf.BPFMapLow),
		mu:              sync.RWMutex{},
		cfg:             cfg,
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

	for _, p := range initialPolicies {
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

// version returns the version of the Policies.
func (pm *PolicyManager) version() uint16 {
	return 1
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

	// Create a temporary copy of the relevant parts of the PolicyManager's state
	tempPolicies := make(map[string]*Policy)
	for k, v := range pm.policies {
		tempPolicies[k] = v
	}
	// TODO (scoped apply, deferred): this deep-copies EVERY event's rules on every add/remove/update, but only
	// the policy's events and their transitive dependencies actually change. The deep copy is load-bearing for
	// correctness today - updateRulesForEvent mutates reused dependency rules' IDs in place (depRule.ID = ...)
	// and addTransitiveDependencyRules modifies dependency events - so it cannot just become a shallow copy. A
	// scoped version would shallow-copy the map and copy-on-write each EventRules only right before it is
	// touched (updateRulesForEvent's existingDepRules reuse + addTransitiveDependencyRules' recursion). This is
	// init + runtime shared machinery, but the win is architectural, not perf: the path is never per-event
	// (init is one-time; runtime policy changes are operator-rare), so the deep copy is negligible. Fold it into
	// the runtime write-path build-out (kernel re-push + versioned snapshot retention), where the apply path's
	// blast radius is already being reasoned about. See docs/runtime-policy-change.md.
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
	pm.policies = tempPolicies
	pm.rules = tempRules

	// TODO: Notify listeners (if any) about the policy change

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

	pm.rules = tempRules
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

	// Create temporary copies for rollback
	tempPolicies := make(map[string]*Policy)
	for k, v := range pm.policies {
		tempPolicies[k] = v
	}
	// TODO (scoped apply, deferred): deep-copies every event's rules; only the removed policy's events + their
	// transitive deps change. See the fuller note in addPolicyLocked and docs/runtime-policy-change.md.
	tempRules := make(map[events.ID]EventRules)
	for k, v := range pm.rules {
		tempRules[k] = deepCopyEventRules(v)
	}

	// Perform operations on the temporary copies
	delete(tempPolicies, policyName) // Remove the policy

	// Update event selection in the dependency manager
	// This should be done for all selected events BEFORE updating EventRules (done below)
	for eventID := range policyToRemove.Rules {
		// Check if the event is still selected by any remaining policy
		isSelected := false
		for _, p := range tempPolicies {
			if _, ok := p.Rules[eventID]; ok {
				isSelected = true
				break
			}
		}

		// Only unselect the event if it's not selected by any other policy
		if !isSelected {
			pm.evtsDepsManager.UnselectEvent(eventID)
			delete(tempRules, eventID) // Remove unselected event from tempRules
		}
	}

	// Update EventRules for each event affected by the policy
	for eventID := range policyToRemove.Rules {
		// Skip if event was unselected
		if _, ok := tempRules[eventID]; !ok {
			continue
		}
		if err := pm.updateRulesForEvent(eventID, tempRules, tempPolicies); err != nil {
			return errfmt.WrapError(err)
		}
	}

	// Commit the changes to the actual PolicyManager
	pm.policies = tempPolicies
	pm.rules = tempRules

	// TODO: Notify listeners (if any) about the policy removal

	return nil
}

// UpdatePolicy atomically replaces an existing policy (matched by name) with a new definition. It is the
// runtime "update" op: unlike a separate RemovePolicy + AddPolicy, the whole change happens under a single
// lock, so concurrent readers never observe a window in which the policy is absent. It is implemented as a
// locked remove followed by a locked add, reusing their event-selection and rule-recomputation logic; on
// failure of the add, the policy and rule maps are restored to their pre-update values.
//
// Note: per-rule disable toggles (DisableRule) on the policy's events reset, because the rules are rebuilt
// and their IDs (bitmap positions) shift - the same behavior AddPolicy already has. The event-dependency
// manager's selections are not rolled back on a mid-update error (the same pre-existing non-transactionality
// as AddPolicy); such errors only arise from undefined events or unsatisfiable dependencies.
//
// TODO (runtime write path, deferred): this only updates the USERLAND rules + snapshot. The kernel filter
// maps (comm/uid/binary/..., submit_for_rules, event config) still hold the old policy until UpdateBPF
// re-pushes them, so a complete runtime change is UpdatePolicy followed by UpdateBPF(bpfModule, cts, fields).
// Both exist; what is missing is the control-plane trigger that orchestrates them - extend the existing gRPC
// TraceeService (api/v1beta1/tracee.proto) with ApplyPolicy(upsert)/RemovePolicy/List over its unix socket
// and replace the k8s reconciler's restartDaemonSet with a hot ApplyPolicy call. (Blocked here: protoc is not
// available to regenerate the stubs.) See docs/runtime-policy-change.md.
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

// policySnapshot is an immutable, atomically-published view of the per-event read state. Readers Load it
// once and read without locking; writers rebuild and Store it (publishSnapshot) under pm.mu after every
// mutation. The rules map is a fresh copy per publish, so later in-place map writes (toggles, delete) cannot
// mutate a published snapshot; the EventRules and their slices are replaced-not-mutated by writers (see the
// copy-on-write in setRuleEnabled and updateRulesForEvent), so sharing them is safe for lock-free readers.
//
// TODO (runtime-swap correctness, deferred to the write-path build-out):
//   - Per-event single Load: today each accessor Loads snap independently, so the 8+ reads for one event
//     could straddle a mid-event publish (each Load is atomic, but the set is not). Expose a Snapshot() handle
//     the pipeline Loads once per event and threads through the matchers, so an event reads one consistent
//     version. (Rare today - writers are init/operator-driven - but a real gap once runtime swaps happen.)
//   - Versioned retention: an in-flight event was tagged by the kernel with its rules_version; its
//     MatchedRules positions refer to that version's rule IDs. Keep version->snapshot and read by the event's
//     RulesVersion, retaining old versions until in-flight events of that version drain. Only matters once the
//     write path swaps versions at runtime; see docs/runtime-policy-change.md.
type policySnapshot struct {
	rules         map[events.ID]EventRules
	exportedFMaps *FilterMaps
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
	pm.snap.Store(&policySnapshot{rules: rules, exportedFMaps: pm.exportedFMaps})
}

// eventRulesSnap returns the event's EventRules from the current lock-free snapshot.
func (pm *PolicyManager) eventRulesSnap(eventID events.ID) (EventRules, bool) {
	s := pm.snap.Load()
	if s == nil {
		return EventRules{}, false
	}
	er, ok := s.rules[eventID]
	return er, ok
}

// deepCopyEventRules creates a deep copy of an EventRules struct.
func deepCopyEventRules(original EventRules) EventRules {
	copied := EventRules{
		rulesVersion:           original.rulesVersion,
		rulesCount:             original.rulesCount,
		containerFilteredRules: original.containerFilteredRules,
		disabledRules:          original.disabledRules,
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

	rulesVersion := uint16(0)
	enabled := true      // Default to true for new rules
	hasOverflow := false // Initialize hasOverflow flag

	if existingEventRules, ok := tempRules[eventID]; ok {
		rulesVersion = existingEventRules.rulesVersion
		enabled = existingEventRules.enabled // Preserve existing enabled state

		// Save existing dependency rules (created by rules with event that depend on this event)
		for _, rule := range existingEventRules.Rules {
			if rule.SelectionType == SelectedByDependency {
				existingDepRules = append(existingDepRules, rule)
			}
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
	tempRules[eventID] = EventRules{
		Rules:                  rules,
		UserlandRules:          userlandRules,
		ruleIDToEventRule:      ruleIDToEventRule,
		rulesVersion:           rulesVersion + 1,
		rulesCount:             ruleIDCounter,
		containerFilteredRules: containerFilteredRules,
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

		// Check if dependency rule already exists
		dependencyRuleExists := false
		for _, existingRule := range eventRules.Rules {
			if existingRule.SelectionType == SelectedByDependency &&
				existingRule.Policy == parentRule.Policy &&
				existingRule.Data == parentRule.Data {
				dependencyRuleExists = true
				break
			}
		}

		if !dependencyRuleExists {
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
func (pm *PolicyManager) GetRules(eventID events.ID) []*EventRule {
	eventRules, ok := pm.eventRulesSnap(eventID)
	if !ok {
		return nil // Or return an empty slice: []*EventRule{}
	}

	return eventRules.Rules
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
func (pm *PolicyManager) GetUserlandRules(eventID events.ID) []*EventRule {
	eventRules, ok := pm.eventRulesSnap(eventID)
	if !ok {
		return nil // Or return an empty slice: []*EventRule{}
	}

	return eventRules.UserlandRules
}

// GetFilterMaps returns the cached read-only export of the filter maps for the userland
// overflow rules matcher. The export is built once per updateBPF (see buildExportedFilterMaps),
// not per call, because it is read on the event hot path. The returned value is immutable
// (replaced, never mutated), so callers may read it without holding the lock.
func (pm *PolicyManager) GetFilterMaps() *FilterMaps {
	if s := pm.snap.Load(); s != nil {
		return s.exportedFMaps
	}
	return nil
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
		ContainerFilters:           make(map[FilterVersionKey]map[string][]RuleBitmap),
		ExtendedScopeFilterConfigs: make(map[events.ID]ExtendedScopeFiltersConfig),
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

	// Convert Container filters
	for k, v := range fMaps.containerFilters {
		exported.ContainerFilters[FilterVersionKey(k)] = convertStringRuleBitmaps(v)
	}

	// Convert Extended Scope Filter Configs
	for eventID, cfg := range fMaps.extendedScopeFilterConfigs {
		exported.ExtendedScopeFilterConfigs[eventID] = ExtendedScopeFiltersConfig(cfg)
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
func (pm *PolicyManager) GetContainerFilteredRulesBitmap(eventID events.ID) []uint64 {
	eventRules, ok := pm.eventRulesSnap(eventID)
	if !ok {
		return []uint64{0} // No rules for this event, return an empty bitmap
	}

	return eventRules.containerFilteredRules
}

// GetMatchedRulesInfo processes a bitmap array of matched rule IDs for a given event and returns
// a list of policy names corresponding to the matched rules that have the Emit flag set.
// Supports rules with ID > 64 through bitmap arrays.
func (pm *PolicyManager) GetMatchedRulesInfo(eventID events.ID, matchedRuleIDsBitmap []uint64) []string {
	var matchedPolicyNames []string

	eventRules, ok := pm.eventRulesSnap(eventID)
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
			// This should ideally not happen, as it indicates an inconsistency
			// between the bitmap generated by BPF and the rules in EventRules.
			logger.Errorw("Inconsistency detected in GetMatchedRulesInfo",
				"eventID", eventID,
				"ruleID", ruleID,
				"possibleCause", "Bitmap includes a ruleID not present in EventRules",
			)
			continue
		}

		if rule.SelectionType == SelectedByUser {
			matchedPolicyNames = append(matchedPolicyNames, rule.Policy.Name)
		}
	}

	return matchedPolicyNames
}

func (pm *PolicyManager) GetDerivedEventMatchedRules(
	derivedEventID events.ID,
	baseEventID events.ID,
	baseMatchedRulesBitmap []uint64,
) []uint64 {
	s := pm.snap.Load()
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

// IsEventEnabled checks if an event is currently enabled.
func (pm *PolicyManager) IsEventEnabled(eventID events.ID) bool {
	eventRules, ok := pm.eventRulesSnap(eventID)
	if !ok {
		return false // Event not found, consider it disabled
	}

	return eventRules.enabled
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
func (pm *PolicyManager) GetDisabledRules(eventID events.ID) []uint64 {
	eventRules, ok := pm.eventRulesSnap(eventID)
	if !ok {
		return nil
	}
	return eventRules.disabledRules
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
func (pm *PolicyManager) GetSelectedEvents() []events.ID {
	s := pm.snap.Load()
	if s == nil {
		return nil
	}
	selectedEvents := make([]events.ID, 0, len(s.rules))
	for evt := range s.rules {
		selectedEvents = append(selectedEvents, evt)
	}

	return selectedEvents
}

// IsEventSelected checks if an event is selected by any policy, either directly or as a dependency.
func (pm *PolicyManager) IsEventSelected(eventID events.ID) bool {
	_, ok := pm.eventRulesSnap(eventID)
	return ok
}

// HasOverflowRules checks if the specified event has more than 64 rules
func (pm *PolicyManager) HasOverflowRules(eventID events.ID) bool {
	eventRules, ok := pm.eventRulesSnap(eventID)
	if !ok {
		return false // Event not found, no overflow
	}

	return eventRules.hasOverflow
}

// GetRulesCount returns the total number of rules for the event (0 if none). Used by the
// userland overflow matcher to mask off bit positions beyond the real rules.
func (pm *PolicyManager) GetRulesCount(eventID events.ID) uint {
	eventRules, ok := pm.eventRulesSnap(eventID)
	if !ok {
		return 0
	}

	return eventRules.rulesCount
}

// GetAllRulesBitmap returns a []uint64 bitmap with every rule bit set for the event (bits
// 0..rulesCount-1) - the userland equivalent of the kernel's submit_for_rules. It seeds the
// match for a detector's OUTPUT event against its own rules when the base event's bitmap did
// not carry the output's chain bit (direct-input detectors, see detectEvents). matchPoliciesProto
// only narrows a bitmap, so without a seed an emitted output would always be dropped.
func (pm *PolicyManager) GetAllRulesBitmap(eventID events.ID) []uint64 {
	eventRules, ok := pm.eventRulesSnap(eventID)
	if !ok || eventRules.rulesCount == 0 {
		return nil
	}

	n := eventRules.rulesCount
	words := (n + 63) / 64
	bitmap := make([]uint64, words)
	for w := range bitmap {
		bitmap[w] = ^uint64(0)
	}
	if rem := n % 64; rem != 0 {
		bitmap[words-1] = (uint64(1) << rem) - 1
	}
	return bitmap
}

// ShouldEmitEvent checks if an event has at least one rule that was explicitly
// selected by a user (not a dependency or bootstrap rule), indicating that the event
// should be emitted.
func (pm *PolicyManager) ShouldEmitEvent(eventID events.ID) bool {
	eventRules, ok := pm.eventRulesSnap(eventID)
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

// GetAllMatchedRulesBitmap returns a bitmap array where all bits corresponding to
// rules for the given event ID are set, indicating that all rules are considered
// matched. Supports overflow rules (ID > 64).
func (pm *PolicyManager) GetAllMatchedRulesBitmap(eventID events.ID) []uint64 {
	eventRules, ok := pm.eventRulesSnap(eventID)
	if !ok {
		return []uint64{} // No rules for this event, return an empty bitmap array
	}

	var allRulesBitmap []uint64
	for ruleID := uint(0); ruleID < eventRules.rulesCount; ruleID++ {
		bitwise.SetBitInArray(&allRulesBitmap, ruleID)
	}

	return allRulesBitmap
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
