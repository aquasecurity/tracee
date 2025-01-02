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

type ManagerConfig struct {
	DNSCacheConfig dnscache.Config
	ProcTreeConfig proctree.ProcTreeConfig
	CaptureConfig  config.CaptureConfig
}

// Manager is responsible for managing all loaded policies and generating lists of rules grouped by event ID.
type PolicyManager struct {
	policies        map[string]*Policy       // Map of policies by name
	rules           map[events.ID]EventRules // Map of rules by event ID
	evtsDepsManager *dependencies.Manager
	bpfInnerMaps    map[string]*bpf.BPFMapLow // TODO: we don't really need this here... Remove it
	mu              sync.RWMutex              // Read/Write Mutex to protect concurrent access
	cfg             ManagerConfig
	// TODO: Rules that depend on other events should add entries to the event's rules array they depend on
}

// EventData holds information about a specific event.
type EventRules struct {
	Rules                  []*EventRule         // List of rules associated with this event
	UserlandRules          []*EventRule         // List of rules with userland filters enabled
	enabled                bool                 // Flag indicating whether the event is enabled
	rulesVersion           uint32               // Version of the rules for this event (for future updates)
	ruleIDCounter          uint8                // Counter to generate unique rule IDs within the event, limited to 64 rules
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

	for _, p := range initialPolicies {
		if err := pm.AddPolicy(p); err != nil {
			logger.Errorw("failed to add initial policy", "error", err)
		}
	}

	if err := pm.initialize(); err != nil {
		return nil, errfmt.Errorf("failed to initialize policy manager: %s", err)
	}

	return pm, nil
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

	// Update EventRules for each event affected by the policy
	for eventID := range policy.Rules {
		// Select event
		_, err := pm.evtsDepsManager.SelectEvent(eventID)
		if err != nil {
			eventName := events.Core.GetDefinitionByID(eventID).GetName()
			return SelectEventError(eventName)
		}

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

	// Update EventRules for each event affected by the policy
	for eventID := range policyToRemove.Rules {
		if err := pm.updateRulesForEvent(eventID, tempRules, tempPolicies); err != nil {
			return errfmt.WrapError(err)
		}

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
		ruleIDCounter:          original.ruleIDCounter,
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
	// Gather rules from all policies that apply to this event
	var userlandRules []*EventRule
	ruleIDToEventRule := make(map[uint8]*EventRule)
	ruleIDCounter := uint8(0)
	var containerFilteredRules uint64

	// Create a new EventRules with ruleIDCounter initialized to 0
	eventRules := EventRules{
		ruleIDCounter: 0,
		rulesVersion:  0, // Also initialize rulesVersion for a new event
	}

	var rules []*EventRule

	for _, policy := range tempPolicies {
		ruleData, ok := policy.Rules[eventID]
		if !ok {
			continue // This policy doesn't have rules for this event
		}

		// Check if ruleIDCounter exceeds maximum (62 because 63 is reserved for dependency rules)
		if ruleIDCounter >= 63 {
			eventName := events.Core.GetDefinitionByID(eventID).GetName()
			return TooManyRulesForEventError(eventName)
		}

		eventRule := &EventRule{
			ID:     ruleIDCounter,
			Data:   &ruleData,
			Policy: policy,
			Emit:   true,
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

		// Add dependency rules (with ruleId 63)
		eventNode, err := pm.evtsDepsManager.GetEvent(eventID)
		if err != nil {
			return errfmt.WrapError(err)
		}

		for _, depID := range eventNode.GetDependencies().GetIDs() {
			if err := addDependencyRule(depID, tempRules); err != nil {
				return errfmt.Errorf("failed to add dependency rule for event %d", depID)
			}
		}

		ruleIDCounter++
	}

	// Update the EventRules for the event in the temporary map
	tempRules[eventID] = EventRules{
		Rules:                  rules,
		UserlandRules:          userlandRules,
		ruleIDToEventRule:      ruleIDToEventRule,
		rulesVersion:           eventRules.rulesVersion + 1,
		ruleIDCounter:          ruleIDCounter,
		containerFilteredRules: containerFilteredRules,
	}

	return nil
}

// addDependencyRule adds a special dependency rule for the given event ID at RuleID 63
// as the last element of the EventRules.Rules slice.
func addDependencyRule(eventID events.ID, tempRules map[events.ID]EventRules) error {
	eventRules, ok := tempRules[eventID]
	if !ok {
		eventRules = EventRules{
			ruleIDCounter: 0,
			rulesVersion:  0,
		}
	}

	// Check if a dependency rule already exists (it should always be the last one)
	if len(eventRules.Rules) > 0 && eventRules.Rules[len(eventRules.Rules)-1].IsDependencyRule {
		return nil // Dependency rule already exists
	}

	// Create the EventRule for the dependency at RuleID 63
	eventRule := &EventRule{
		ID:               63,
		Data:             nil,
		Policy:           nil,
		Emit:             false, // Ensure that dependency events are never emitted
		IsDependencyRule: true,  // Mark the rule as a dependency rule
	}

	// Add the rule to the appropriate slices
	eventRules.Rules = append(eventRules.Rules, eventRule)
	eventRules.ruleIDToEventRule[63] = eventRule

	// Update the EventRules in the temporary map
	tempRules[eventID] = eventRules

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

	for ruleID := uint8(0); ruleID < eventRules.ruleIDCounter; ruleID++ {
		if (matchedRuleIDsBitmap>>ruleID)&1 == 1 { // Check if the bit corresponding to ruleID is set in the bitmap
			rule, ok := eventRules.ruleIDToEventRule[ruleID]
			if !ok {
				// This should ideally not happen, as it indicates an inconsistency
				// between the bitmap generated by BPF and the rules in EventRules.
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

// IsEnabled tests if an event, or a policy per event is enabled (in the future it will also check if a policy is enabled)
// TODO: add metrics about an event being enabled/disabled, or a policy being enabled/disabled?
func (pm *PolicyManager) IsEnabled(matchedRules uint64, id events.ID) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return pm.isEventEnabled(id)
}

// IsEventEnabled returns true if a given event policy is enabled for a given rule
func (pm *PolicyManager) IsEventEnabled(id events.ID) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return pm.isEventEnabled(id)
}

// not synchronized, use IsEventEnabled instead
func (pm *PolicyManager) isEventEnabled(eventID events.ID) bool {
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

func (pm *PolicyManager) EventsSelected() []events.ID {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	eventsSelected := make([]events.ID, 0, len(pm.rules))
	for evt := range pm.rules {
		eventsSelected = append(eventsSelected, evt)
	}

	return eventsSelected
}

func (pm *PolicyManager) IsEventSelected(id events.ID) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	_, ok := pm.rules[id]
	return ok
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
	for ruleID := uint8(0); ruleID < eventRules.ruleIDCounter; ruleID++ {
		allRulesBitmap |= 1 << ruleID
	}

	return allRulesBitmap
}

// eventFlags is a struct that holds the flags of an event.
type eventFlags struct {
	// requiredBySignature indicates if the event is required by a signature event.
	requiredBySignature bool

	// enabled indicates if the event is enabled.
	// It is *NOT* computed on policies updates, so its value remains the same
	// until changed via the API.
	enabled bool

	// TODO: consider adding rules version here - this value will be taken from here when populating events config map, just like rulesToSubmit
	rulesVersion uint8
	// Question: should rulesVersion be under per-event config (map in bpf) - if so, where is it being populated?
	// TODO: consider moving above requiredBySignature and enabled to be under the same place where we put rulesVersion
}

//
// constructor
//

type eventFlagsOption func(*eventFlags)

func eventFlagsWithSubmit(submit uint64) eventFlagsOption {
	return func(es *eventFlags) {
		es.rulesToSubmit = submit
	}
}

func eventFlagsWithEmit(emit uint64) eventFlagsOption {
	return func(es *eventFlags) {
		es.rulesToEmit = emit
	}
}

func eventFlagsWithRequiredBySignature(required bool) eventFlagsOption {
	return func(es *eventFlags) {
		es.requiredBySignature = required
	}
}

func eventFlagsWithEnabled(enabled bool) eventFlagsOption {
	return func(es *eventFlags) {
		es.enabled = enabled
	}
}

func newEventFlags(options ...eventFlagsOption) *eventFlags {
	// default values
	ef := &eventFlags{
		rulesToSubmit:       0,
		rulesToEmit:         0,
		requiredBySignature: false,
		enabled:             false,
	}

	// apply options
	for _, option := range options {
		option(ef)
	}

	return ef
}

// AddDependencyEventToRules adds for management an event that is a dependency of other events.
// The difference from selected events is that it doesn't affect its eviction.
func (pm *PolicyManager) addDependencyEventToRules(evtID events.ID, dependentEvts []events.ID) {
	var newSubmit uint64
	var reqBySig bool

	for _, dependentEvent := range dependentEvts {
		currentFlags, ok := pm.rules[dependentEvent]
		if ok {
			newSubmit |= currentFlags.rulesToSubmit
			reqBySig = reqBySig || events.Core.GetDefinitionByID(dependentEvent).IsSignature()
		}
	}

	pm.addEventFlags(
		evtID,
		newEventFlags(
			eventFlagsWithSubmit(newSubmit),
			eventFlagsWithRequiredBySignature(reqBySig),
			eventFlagsWithEnabled(true),
		),
	)
}

func (pm *PolicyManager) addEventFlags(id events.ID, selectedFlags *eventFlags) {
	currentFlags, ok := pm.rules[id]
	if ok {
		currentFlags.rulesToSubmit |= selectedFlags.rulesToSubmit
		currentFlags.rulesToEmit |= selectedFlags.rulesToEmit
		currentFlags.requiredBySignature = selectedFlags.requiredBySignature
		currentFlags.enabled = selectedFlags.enabled
		return
	}

	pm.rules[id] = newEventFlags(
		eventFlagsWithSubmit(selectedFlags.rulesToSubmit),
		eventFlagsWithEmit(selectedFlags.rulesToEmit),
		eventFlagsWithRequiredBySignature(selectedFlags.requiredBySignature),
		eventFlagsWithEnabled(selectedFlags.enabled),
	)
}

func (pm *PolicyManager) addDependenciesToRulesRecursive(eventNode *dependencies.EventNode) {
	eventID := eventNode.GetID()
	for _, dependencyEventID := range eventNode.GetDependencies().GetIDs() {
		pm.addDependencyEventToRules(dependencyEventID, []events.ID{eventID})
		dependencyNode, err := pm.evtsDepsManager.GetEvent(dependencyEventID)
		if err == nil {
			pm.addDependenciesToRulesRecursive(dependencyNode)
		}
	}
}

func (pm *PolicyManager) selectEvent(eventID events.ID, selectedState *eventFlags) {
	pm.addEventFlags(eventID, selectedState)
	eventNode, err := pm.evtsDepsManager.SelectEvent(eventID)
	if err != nil {
		logger.Errorw("Event selection failed",
			"event", events.Core.GetDefinitionByID(eventID).GetName())
		return
	}

	pm.addDependenciesToRulesRecursive(eventNode)
}

func (pm *PolicyManager) removeEventFromRules(evtID events.ID) {
	logger.Debugw("Remove event from rules", "event", events.Core.GetDefinitionByID(evtID).GetName())
	delete(pm.events, evtID)
}

// TODO: we can move the following selection functions to be part of the policies compute phase
func (pm *PolicyManager) selectMandatoryEvents() {
	// Initialize events state with mandatory events (TODO: review this need for sched exec)

	pm.selectEvent(events.SchedProcessFork, newEventFlags())
	pm.selectEvent(events.SchedProcessExec, newEventFlags())
	pm.selectEvent(events.SchedProcessExit, newEventFlags())

	// Control Plane Events

	pm.selectEvent(events.SignalCgroupMkdir, newEventFlags(eventFlagsWithSubmit(PolicyAll)))
	pm.selectEvent(events.SignalCgroupRmdir, newEventFlags(eventFlagsWithSubmit(PolicyAll)))
}

func (pm *PolicyManager) selectConfiguredEvents() {
	// Control Plane Process Tree Events

	pipeEvts := func() {
		pm.selectEvent(events.SchedProcessFork, newEventFlags(eventFlagsWithSubmit(PolicyAll)))
		pm.selectEvent(events.SchedProcessExec, newEventFlags(eventFlagsWithSubmit(PolicyAll)))
		pm.selectEvent(events.SchedProcessExit, newEventFlags(eventFlagsWithSubmit(PolicyAll)))
	}
	signalEvts := func() {
		pm.selectEvent(events.SignalSchedProcessFork, newEventFlags(eventFlagsWithSubmit(PolicyAll)))
		pm.selectEvent(events.SignalSchedProcessExec, newEventFlags(eventFlagsWithSubmit(PolicyAll)))
		pm.selectEvent(events.SignalSchedProcessExit, newEventFlags(eventFlagsWithSubmit(PolicyAll)))
	}

	switch pm.cfg.ProcTreeConfig.Source {
	case proctree.SourceBoth:
		pipeEvts()
		signalEvts()
	case proctree.SourceSignals:
		signalEvts()
	case proctree.SourceEvents:
		pipeEvts()
	}

	// DNS Cache events

	if pm.cfg.DNSCacheConfig.Enable {
		pm.selectEvent(events.NetPacketDNS, newEventFlags(eventFlagsWithSubmit(PolicyAll)))
	}

	// Pseudo events added by capture (if enabled by the user)

	getCaptureEventsFlags := func(cfg config.CaptureConfig) map[events.ID]*eventFlags {
		captureEvents := make(map[events.ID]*eventFlags)

		// INFO: All capture events should be placed, at least for now, to all matched policies, or else
		// the event won't be set to matched policy in eBPF and should_submit() won't submit the capture
		// event to userland.

		if cfg.Exec {
			captureEvents[events.CaptureExec] = newEventFlags(eventFlagsWithSubmit(PolicyAll))
		}
		if cfg.FileWrite.Capture {
			captureEvents[events.CaptureFileWrite] = newEventFlags(eventFlagsWithSubmit(PolicyAll))
		}
		if cfg.FileRead.Capture {
			captureEvents[events.CaptureFileRead] = newEventFlags(eventFlagsWithSubmit(PolicyAll))
		}
		if cfg.Module {
			captureEvents[events.CaptureModule] = newEventFlags(eventFlagsWithSubmit(PolicyAll))
		}
		if cfg.Mem {
			captureEvents[events.CaptureMem] = newEventFlags(eventFlagsWithSubmit(PolicyAll))
		}
		if cfg.Bpf {
			captureEvents[events.CaptureBpf] = newEventFlags(eventFlagsWithSubmit(PolicyAll))
		}
		if pcaps.PcapsEnabled(cfg.Net) {
			captureEvents[events.CaptureNetPacket] = newEventFlags(eventFlagsWithSubmit(PolicyAll))
		}

		return captureEvents
	}

	for id, flags := range getCaptureEventsFlags(pm.cfg.CaptureConfig) {
		pm.selectEvent(id, flags)
	}
}

func (pm *PolicyManager) selectUserEvents() {
	// Events selected by the user
	userEvents := make(map[events.ID]*eventFlags)

	// TODO: fix to match what we need
	for _, p := range pm.policies {
		//pId := p.ID
		for eId := range p.Rules {
			ef, ok := userEvents[eId]
			if !ok {
				ef = newEventFlags(eventFlagsWithEnabled(true))
				userEvents[eId] = ef
			}

			//ef.enableEmission(pId)
			//ef.enableSubmission(pId)
		}
	}

	for id, flags := range userEvents {
		pm.selectEvent(id, flags)
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

func (pm *PolicyManager) initialize() error {
	pm.selectMandatoryEvents()
	pm.selectConfiguredEvents()
	pm.selectUserEvents()
	err := pm.updateCapsForSelectedEvents()
	if err != nil {
		return errfmt.WrapError(err)
	}

	return nil
}

//
// Rules
//

func (pm *PolicyManager) IsRequiredBySignature(id events.ID) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	flags, ok := pm.rules[id]
	if !ok {
		return false
	}

	return flags.requiredBySignature
}

func (pm *PolicyManager) EventsToSubmit() []events.ID {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	eventsToSubmit := []events.ID{}
	for evt, flags := range pm.rules {
		if flags.rulesToSubmit != 0 {
			eventsToSubmit = append(eventsToSubmit, evt)
		}
	}

	return eventsToSubmit
}

func (pm *PolicyManager) IsEventToSubmit(id events.ID) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	flags, ok := pm.rules[id]
	if !ok {
		return false
	}

	return flags.rulesToSubmit != 0
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
