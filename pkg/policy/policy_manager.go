package policy

import (
	"sync"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/dnscache"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/dependencies"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/pcaps"
	"github.com/aquasecurity/tracee/pkg/proctree"
	"github.com/aquasecurity/tracee/pkg/utils"
)

const (
	dependencyRuleID = uint8(63) // Rule ID reserved for dependency rules
	maxRulesPerEvent = uint8(63)
)

type ManagerConfig struct {
	DNSCacheConfig dnscache.Config
	ProcTreeConfig proctree.ProcTreeConfig
	CaptureConfig  config.CaptureConfig
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
}

// EventData holds information about a specific event.
type EventRules struct {
	Rules                  []*EventRule         // List of rules associated with this event
	UserlandRules          []*EventRule         // List of rules with userland filters enabled
	enabled                bool                 // Flag indicating whether the event is enabled
	rulesVersion           uint32               // Version of the rules for this event (for future updates)
	rulesCount             uint8                // The total number of rules for this event
	ruleIDToEventRule      map[uint8]*EventRule // Map from RuleID to EventRule for fast lookup
	containerFilteredRules uint64               // Bitmap to track container-filtered rules
}

// EventRule represents a single rule within an event's rule set.
type EventRule struct {
	ID               uint8     // Unique ID of the rule within the event (0-63) - used for bitmap position
	Data             *RuleData // Data associated with the rule
	Policy           *Policy   // Reference to the policy where the rule was defined
	Emit             bool      // Flag to indicate whether the event should be emitted or not
	IsDependencyRule bool      // Flag to indicate that this rule is a dependency rule
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
		mu:              sync.RWMutex{},
		cfg:             cfg,
	}

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

	switch cfg.ProcTreeConfig.Source {
	case proctree.SourceBoth:
		pipeEvts()
		signalEvts()
	case proctree.SourceSignals:
		signalEvts()
	case proctree.SourceEvents:
		pipeEvts()
	}

	// DNS Cache events
	if cfg.DNSCacheConfig.Enable {
		rules[events.NetPacketDNS] = newRuleData(events.NetPacketDNS)
	}

	// Capture events (selected based on configuration)
	if cfg.CaptureConfig.Exec {
		rules[events.CaptureExec] = newRuleData(events.CaptureExec)
	}
	if cfg.CaptureConfig.FileWrite.Capture {
		rules[events.CaptureFileWrite] = newRuleData(events.CaptureFileWrite)
	}
	if cfg.CaptureConfig.FileRead.Capture {
		rules[events.CaptureFileRead] = newRuleData(events.CaptureFileRead)
	}
	if cfg.CaptureConfig.Module {
		rules[events.CaptureModule] = newRuleData(events.CaptureModule)
	}
	if cfg.CaptureConfig.Mem {
		rules[events.CaptureMem] = newRuleData(events.CaptureMem)
	}
	if cfg.CaptureConfig.Bpf {
		rules[events.CaptureBpf] = newRuleData(events.CaptureBpf)
	}
	if pcaps.PcapsEnabled(cfg.CaptureConfig.Net) {
		rules[events.CaptureNetPacket] = newRuleData(events.CaptureNetPacket)
	}

	return &Policy{
		Name:  "__internal_bootstrap__",
		Rules: rules,
	}
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
	if policy == nil {
		return PolicyNilError()
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

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

// RemovePolicy removes a policy from the PolicyManager.
func (pm *PolicyManager) RemovePolicy(policyName string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	policyToRemove, exists := pm.policies[policyName]
	if !exists {
		return PolicyNotFoundByNameError(policyName)
	}

	// Create temporary copies for rollback
	tempPolicies := make(map[string]*Policy)
	for k, v := range pm.policies {
		tempPolicies[k] = v
	}
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
		}
	}

	// Update EventRules for each event affected by the policy
	for eventID := range policyToRemove.Rules {
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

// deepCopyEventRules creates a deep copy of an EventRules struct.
func deepCopyEventRules(original EventRules) EventRules {
	copied := EventRules{
		rulesVersion:           original.rulesVersion,
		rulesCount:             original.rulesCount,
		containerFilteredRules: original.containerFilteredRules,
		Rules:                  make([]*EventRule, len(original.Rules)),
		UserlandRules:          make([]*EventRule, len(original.UserlandRules)),
		ruleIDToEventRule:      make(map[uint8]*EventRule, len(original.ruleIDToEventRule)),
	}

	// Deep copy Rules
	for i, rule := range original.Rules {
		copied.Rules[i] = &EventRule{
			ID:               rule.ID,
			Data:             rule.Data,   // Data pointers can be shared
			Policy:           rule.Policy, // Policy pointers can be shared
			Emit:             rule.Emit,
			IsDependencyRule: rule.IsDependencyRule,
		}
	}

	// Deep copy UserlandRules
	for i, rule := range original.UserlandRules {
		copied.UserlandRules[i] = &EventRule{
			ID:               rule.ID,
			Data:             rule.Data,   // Data pointers can be shared
			Policy:           rule.Policy, // Policy pointers can be shared
			Emit:             rule.Emit,
			IsDependencyRule: rule.IsDependencyRule,
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

	var rules, userlandRules []*EventRule
	ruleIDToEventRule := make(map[uint8]*EventRule)
	ruleIDCounter := uint8(0)
	var containerFilteredRules uint64

	rulesVersion := uint32(0)
	if existingEventRules, ok := tempRules[eventID]; ok {
		rulesVersion = existingEventRules.rulesVersion
	}

	// Gather rules from all policies that apply to this event
	for _, policy := range tempPolicies {
		ruleData, ok := policy.Rules[eventID]
		if !ok {
			continue // This policy doesn't have rules for this event
		}

		// Check if ruleIDCounter exceeds maximum (62 because 63 is reserved for dependency rules)
		if ruleIDCounter >= maxRulesPerEvent {
			eventName := events.Core.GetDefinitionByID(eventID).GetName()
			return TooManyRulesForEventError(eventName)
		}

		eventRule := &EventRule{
			ID:     ruleIDCounter,
			Data:   &ruleData,
			Policy: policy,
			Emit:   policy != pm.bootstrapPolicy,
		}

		rules = append(rules, eventRule)
		ruleIDToEventRule[ruleIDCounter] = eventRule

		// Update containerFilteredRules bitmap
		if policy.ContainerFilterEnabled() {
			containerFilteredRules |= 1 << ruleIDCounter
		}

		// Update userlandFilterableRules bitmap
		if isRuleFilterableInUserland(eventRule) {
			userlandRules = append(userlandRules, eventRule)
		}

		ruleIDCounter++
	}

	// Add dependency rules (with ruleId 63)
	eventNode, err := pm.evtsDepsManager.GetEvent(eventID)
	if err != nil {
		return errfmt.WrapError(err)
	}

	if len(eventNode.GetDependents()) > 0 {
		// Add a dependency rule if it doesn't exist
		if _, depRuleExists := ruleIDToEventRule[dependencyRuleID]; !depRuleExists {
			eventRule := &EventRule{
				ID:               dependencyRuleID,
				Data:             nil,
				Policy:           nil,
				Emit:             false, // Ensure that dependency events are never emitted
				IsDependencyRule: true,  // Mark the rule as a dependency rule
			}
			rules = append(rules, eventRule)
			ruleIDToEventRule[dependencyRuleID] = eventRule
		}
	}

	// Recursively add dependency rules for all transitive dependencies
	if err := pm.addTransitiveDependencyRules(eventNode, tempRules, make(map[events.ID]bool), 0); err != nil {
		return errfmt.WrapError(err)
	}

	// Update the EventRules for the event in the temporary map
	tempRules[eventID] = EventRules{
		Rules:                  rules,
		UserlandRules:          userlandRules,
		ruleIDToEventRule:      ruleIDToEventRule,
		rulesVersion:           rulesVersion + 1,
		rulesCount:             ruleIDCounter,
		containerFilteredRules: containerFilteredRules,
	}

	return nil
}

// addTransitiveDependencyRules recursively adds dependency rules for the given event and all its transitive dependencies.
func (pm *PolicyManager) addTransitiveDependencyRules(
	eventNode *dependencies.EventNode,
	tempRules map[events.ID]EventRules,
	visited map[events.ID]bool,
	depth int,
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
		eventRules, ok := tempRules[depID]
		if !ok {
			eventRules = EventRules{}
		}

		if _, depRuleExists := eventRules.ruleIDToEventRule[dependencyRuleID]; !depRuleExists {
			eventRule := &EventRule{
				ID:               dependencyRuleID,
				Data:             nil,
				Policy:           nil,
				Emit:             false, // Ensure that dependency events are never emitted
				IsDependencyRule: true,  // Mark the rule as a dependency rule
			}
			eventRules.Rules = append(eventRules.Rules, eventRule)
			eventRules.ruleIDToEventRule[dependencyRuleID] = eventRule

			tempRules[depID] = eventRules
		}

		depNode, err := pm.evtsDepsManager.GetEvent(depID)
		if err != nil {
			return err
		}

		// Recursively add dependency rules for the dependencies of the dependency
		if err := pm.addTransitiveDependencyRules(depNode, tempRules, visited, depth+1); err != nil {
			return err
		}
	}

	return nil
}

// isRuleFilterableInUserland checks if a rule is filterable in userland.
func isRuleFilterableInUserland(rule *EventRule) bool {
	// Check filters under RuleData
	if rule.Data.DataFilter.Enabled() ||
		rule.Data.RetFilter.Enabled() ||
		rule.Data.ScopeFilter.Enabled() {
		return true
	}

	// Check policy-level filters (UID and PID)
	p := rule.Policy
	if p.UIDFilter.Enabled() &&
		((p.UIDFilter.Minimum() != filters.MinNotSetUInt) ||
			(p.UIDFilter.Maximum() != filters.MaxNotSetUInt)) {
		return true
	}

	if p.PIDFilter.Enabled() &&
		((p.PIDFilter.Minimum() != filters.MinNotSetUInt) ||
			(p.PIDFilter.Maximum() != filters.MaxNotSetUInt)) {
		return true
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
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	eventRules, ok := pm.rules[eventID]
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
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	eventRules, ok := pm.rules[eventID]
	if !ok {
		return nil // Or return an empty slice: []*EventRule{}
	}

	return eventRules.UserlandRules
}

// GetContainerFilteredRulesBitmap returns a bitmap where each bit represents a rule
// for the given event ID, and the bit is set if the corresponding rule has
// container filtering enabled.
func (pm *PolicyManager) GetContainerFilteredRulesBitmap(eventID events.ID) uint64 {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	eventRules, ok := pm.rules[eventID]
	if !ok {
		return 0 // No rules for this event, return an empty bitmap
	}

	return eventRules.containerFilteredRules
}

// GetMatchedRulesInfo processes a bitmap of matched rule IDs for a given event and returns:
// 1. A modified bitmap where the bits corresponding to matched rules with the Emit flag set are cleared.
// 2. A list of policy names corresponding to the matched rules that have the Emit flag set.
func (pm *PolicyManager) GetMatchedRulesInfo(eventID events.ID, matchedRuleIDsBitmap uint64) (uint64, []string) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var matchedPolicyNames []string

	eventRules, ok := pm.rules[eventID]
	if !ok {
		return 0, matchedPolicyNames
	}

	for ruleID := uint8(0); ruleID < eventRules.rulesCount; ruleID++ {
		if (matchedRuleIDsBitmap>>ruleID)&1 == 1 { // Check if the bit corresponding to ruleID is set in the bitmap
			rule, ok := eventRules.ruleIDToEventRule[ruleID]
			if !ok {
				// This should ideally not happen, as it indicates an inconsistency
				// between the bitmap generated by BPF and the rules in EventRules.
				logger.Errorw("Inconsistency detected in GetMatchedRulesInfo",
					"eventID", eventID,
					"ruleID", ruleID,
					"matchedRuleIDsBitmap", matchedRuleIDsBitmap,
					"possibleCause", "Bitmap from BPF includes a ruleID not present in EventRules",
				)
				continue
			}

			if rule.Emit {
				matchedPolicyNames = append(matchedPolicyNames, rule.Policy.Name)
			} else {
				utils.ClearBit(&matchedRuleIDsBitmap, uint(rule.ID))
			}
		}
	}

	return matchedRuleIDsBitmap, matchedPolicyNames
}

// IsEventEnabled checks if an event is currently enabled.
func (pm *PolicyManager) IsEventEnabled(eventID events.ID) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	eventRules, ok := pm.rules[eventID]
	if !ok {
		return false // Event not found, consider it disabled
	}

	return eventRules.enabled
}

// EnableEvent enables a specific event in the PolicyManager.
// It assumes that the eventID is always valid.
func (pm *PolicyManager) EnableEvent(eventID events.ID) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	eventRules := pm.rules[eventID]
	eventRules.enabled = true
	pm.rules[eventID] = eventRules
}

// DisableEvent disables a specific event in the PolicyManager.
// It assumes that the eventID is always valid.
func (pm *PolicyManager) DisableEvent(eventID events.ID) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	eventRules := pm.rules[eventID]
	eventRules.enabled = false
	pm.rules[eventID] = eventRules
}

// GetSelectedEvents returns a slice of all the event IDs that are currently selected
// either directly by a policy or as a dependency.
func (pm *PolicyManager) GetSelectedEvents() []events.ID {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	selectedEvents := make([]events.ID, 0, len(pm.rules))
	for evt := range pm.rules {
		selectedEvents = append(selectedEvents, evt)
	}

	return selectedEvents
}

// IsEventSelected checks if an event is selected by any policy, either directly or as a dependency.
func (pm *PolicyManager) IsEventSelected(eventID events.ID) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	_, ok := pm.rules[eventID]
	return ok
}

// IsEventEmitted checks if an event has at least one rule with the Emit flag set to true,
// indicating that the event was explicitly selected by a policy and should be emitted.
func (pm *PolicyManager) IsEventEmitted(eventID events.ID) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	eventRules, ok := pm.rules[eventID]
	if !ok {
		return false // Event not found or no rules defined, not emitted
	}

	for _, rule := range eventRules.Rules {
		if rule.Emit {
			return true // Found at least one rule with Emit set to true
		}
	}

	return false // No rules have Emit set to true
}

// GetAllMatchedRulesBitmap returns a bitmap where all bits corresponding to
// rules for the given event ID are set, indicating that all rules are considered
// matched.
func (pm *PolicyManager) GetAllMatchedRulesBitmap(eventID events.ID) uint64 {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	eventRules, ok := pm.rules[eventID]
	if !ok {
		return 0 // No rules for this event, return an empty bitmap
	}

	var allRulesBitmap uint64
	for ruleID := uint8(0); ruleID < eventRules.rulesCount; ruleID++ {
		allRulesBitmap |= 1 << ruleID
	}

	return allRulesBitmap
}

func (pm *PolicyManager) UpdateBPF(
	bpfModule *bpf.Module,
	cts *containers.Containers,
	eventsFields map[events.ID][]bufferdecoder.ArgType,
	createNewMaps bool,
	updateProcTree bool,
) (*PoliciesConfig, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	return pm.updateBPF(bpfModule, cts, eventsFields, createNewMaps, updateProcTree)
}
