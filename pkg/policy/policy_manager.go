package policy

import (
	"sync"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/dnscache"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/data"
	"github.com/aquasecurity/tracee/pkg/events/dependencies"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/pcaps"
	"github.com/aquasecurity/tracee/pkg/proctree"
	"github.com/aquasecurity/tracee/pkg/utils"
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
	fMaps           *filterMaps
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
	if pm.bootstrapPolicy != nil && policyName == pm.bootstrapPolicy.Name {
		return errfmt.Errorf("cannot remove bootstrap policy")
	}

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

// deepCopyEventRules creates a deep copy of an EventRules struct.
func deepCopyEventRules(original EventRules) EventRules {
	copied := EventRules{
		rulesVersion:           original.rulesVersion,
		rulesCount:             original.rulesCount,
		containerFilteredRules: original.containerFilteredRules,
		enabled:                original.enabled,
		Rules:                  make([]*EventRule, len(original.Rules)),
		UserlandRules:          make([]*EventRule, len(original.UserlandRules)),
		ruleIDToEventRule:      make(map[uint]*EventRule, len(original.ruleIDToEventRule)),
	}

	// Deep copy Rules
	for i, rule := range original.Rules {
		copied.Rules[i] = &EventRule{
			ID:            rule.ID,
			Data:          rule.Data,   // Data pointers can be shared
			Policy:        rule.Policy, // Policy pointers can be shared
			SelectionType: rule.SelectionType,
			DerivedRuleID: rule.DerivedRuleID,
		}
	}

	// Deep copy UserlandRules
	for i, rule := range original.UserlandRules {
		copied.UserlandRules[i] = &EventRule{
			ID:            rule.ID,
			Data:          rule.Data,   // Data pointers can be shared
			Policy:        rule.Policy, // Policy pointers can be shared
			SelectionType: rule.SelectionType,
			DerivedRuleID: rule.DerivedRuleID,
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

	// Gather rules from all policies that apply to this event
	for _, policy := range tempPolicies {
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
		if err := pm.addTransitiveDependencyRules(eventNode, tempRules, make(map[events.ID]bool), 0, rule); err != nil {
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

			utils.SetBit(&containerFilteredRules[bitmapIndex], uint(bitOffset))
		}

		// Update userlandFilterableRules bitmap
		if isRuleFilterableInUserland(rule) {
			userlandRules = append(userlandRules, rule)
		}
	}

	// Add remaining dependency rules to final rules list
	for _, depRule := range existingDepRules {
		rules = append(rules, depRule)
		ruleIDToEventRule[ruleIDCounter] = depRule
		depRule.ID = ruleIDCounter
		ruleIDCounter++
	}

	// Update hasOverflow flag if necessary
	// Set overflow when the next rule would have ID >= 64 (more than 64 total rules)
	if ruleIDCounter >= 64 {
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
				ID:            eventRules.rulesCount,
				Data:          parentRule.Data,
				Policy:        parentRule.Policy,
				SelectionType: SelectedByDependency,
				DerivedRuleID: parentRule.ID,
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

				utils.SetBit(&eventRules.containerFilteredRules[bitmapIndex], uint(bitOffset))
			}

			eventRules.rulesCount++
			tempRules[depID] = eventRules
		}

		depNode, err := pm.evtsDepsManager.GetEvent(depID)
		if err != nil {
			return err
		}

		// Recursively add dependency rules for the dependencies of the dependency
		if err := pm.addTransitiveDependencyRules(depNode, tempRules, visited, depth+1, parentRule); err != nil {
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

	// Check rule.Data and its filters
	if rule.Data != nil {
		// TODO: if kernel filter is enabled for the data filter, don't consider it filterable in userland
		if (rule.Data.DataFilter != nil && rule.Data.DataFilter.Enabled()) ||
			(rule.Data.RetFilter != nil && rule.Data.RetFilter.Enabled()) ||
			(rule.Data.ScopeFilter != nil && rule.Data.ScopeFilter.Enabled()) {
			return true
		}
	}

	// Check policy-level filters
	if rule.Policy != nil {
		if (rule.Policy.UIDFilter != nil && rule.Policy.UIDFilter.Enabled()) &&
			((rule.Policy.UIDFilter.Minimum() != filters.MinNotSetUInt) ||
				(rule.Policy.UIDFilter.Maximum() != filters.MaxNotSetUInt)) {
			return true
		}

		if rule.Policy.PIDFilter != nil && rule.Policy.PIDFilter.Enabled() &&
			((rule.Policy.PIDFilter.Minimum() != filters.MinNotSetUInt) ||
				(rule.Policy.PIDFilter.Maximum() != filters.MaxNotSetUInt)) {
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

// GetFilterMaps returns the computed filter maps for use by the overflow rules matcher.
func (pm *PolicyManager) GetFilterMaps() *FilterMaps {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if pm.fMaps == nil {
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
	for k, v := range pm.fMaps.uidFilters {
		exported.UIDFilters[FilterVersionKey(k)] = convertUint64RuleBitmaps(v)
	}

	// Convert PID filters
	for k, v := range pm.fMaps.pidFilters {
		exported.PIDFilters[FilterVersionKey(k)] = convertUint64RuleBitmaps(v)
	}

	// Convert Mount NS filters
	for k, v := range pm.fMaps.mntNSFilters {
		exported.MntNsFilters[FilterVersionKey(k)] = convertUint64RuleBitmaps(v)
	}

	// Convert PID NS filters
	for k, v := range pm.fMaps.pidNSFilters {
		exported.PidNsFilters[FilterVersionKey(k)] = convertUint64RuleBitmaps(v)
	}

	// Convert Cgroup filters
	for k, v := range pm.fMaps.cgroupIdFilters {
		exported.CgroupFilters[FilterVersionKey(k)] = convertUint64RuleBitmaps(v)
	}

	// Convert UTS filters
	for k, v := range pm.fMaps.utsFilters {
		exported.UTSFilters[FilterVersionKey(k)] = convertStringRuleBitmaps(v)
	}

	// Convert Comm filters
	for k, v := range pm.fMaps.commFilters {
		exported.CommFilters[FilterVersionKey(k)] = convertStringRuleBitmaps(v)
	}

	// Convert Container filters
	for k, v := range pm.fMaps.containerFilters {
		exported.ContainerFilters[FilterVersionKey(k)] = convertStringRuleBitmaps(v)
	}

	// Convert Extended Scope Filter Configs
	for eventID, cfg := range pm.fMaps.extendedScopeFilterConfigs {
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
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	eventRules, ok := pm.rules[eventID]
	if !ok {
		return []uint64{0} // No rules for this event, return an empty bitmap
	}

	return eventRules.containerFilteredRules
}

// GetMatchedRulesInfo processes a bitmap array of matched rule IDs for a given event and returns
// a list of policy names corresponding to the matched rules that have the Emit flag set.
// Supports rules with ID > 64 through bitmap arrays.
func (pm *PolicyManager) GetMatchedRulesInfo(eventID events.ID, matchedRuleIDsBitmap []uint64) []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var matchedPolicyNames []string

	eventRules, ok := pm.rules[eventID]
	if !ok {
		return matchedPolicyNames
	}

	for ruleID := uint(0); ruleID < eventRules.rulesCount; ruleID++ {
		// Check if this rule is matched using bitmap array utilities
		if !utils.HasBitInArray(matchedRuleIDsBitmap, ruleID) {
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
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	baseEventRules, ok := pm.rules[baseEventID]
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
		if !utils.HasBitInArray(baseMatchedRulesBitmap, ruleID) {
			continue
		}

		baseRule, ok := baseEventRules.ruleIDToEventRule[ruleID]
		if !ok || baseRule.SelectionType != SelectedByDependency {
			continue
		}

		// Check if this dependency rule is for our derived event
		if baseRule.Data.EventID == derivedEventID {
			// Set the bit for the derived rule using bitmap array utilities
			utils.SetBitInArray(&derivedMatchedRules, baseRule.DerivedRuleID)
		}
	}

	return derivedMatchedRules
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

// HasOverflowRules checks if the specified event has more than 64 rules
func (pm *PolicyManager) HasOverflowRules(eventID events.ID) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	eventRules, ok := pm.rules[eventID]
	if !ok {
		return false // Event not found, no overflow
	}

	return eventRules.hasOverflow
}

// ShouldEmitEvent checks if an event has at least one rule that was explicitly
// selected by a user (not a dependency or bootstrap rule), indicating that the event
// should be emitted.
func (pm *PolicyManager) ShouldEmitEvent(eventID events.ID) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	eventRules, ok := pm.rules[eventID]
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
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	eventRules, ok := pm.rules[eventID]
	if !ok {
		return []uint64{} // No rules for this event, return an empty bitmap array
	}

	var allRulesBitmap []uint64
	for ruleID := uint(0); ruleID < eventRules.rulesCount; ruleID++ {
		utils.SetBitInArray(&allRulesBitmap, ruleID)
	}

	return allRulesBitmap
}

func (pm *PolicyManager) UpdateBPF(
	bpfModule *bpf.Module,
	cts *containers.Manager,
	eventsFields map[events.ID][]data.DecodeAs,
) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	return pm.updateBPF(bpfModule, cts, eventsFields)
}
