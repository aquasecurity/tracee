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
type Manager struct {
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
	Rules             []*EventRule         // List of rules associated with this event
	UserlandRules     []*EventRule         // List of rules with userland filters enabled
	enabled           bool                 // Flag indicating whether the event is enabled
	rulesVersion      uint32               // Version of the rules for this event (for future updates)
	ruleIDCounter     uint8                // Counter to generate unique rule IDs within the event, limited to 64 rules
	ruleIDToEventRule map[uint8]*EventRule // Map from RuleID to EventRule for fast lookup
}

// EventRule represents a single rule within an event's rule set.
type EventRule struct {
	RuleID   uint8     // Unique ID of the rule within the event (0-63) - used for bitmap position
	RuleData *RuleData // Data associated with the rule
	Policy   *Policy   // Reference to the policy where the rule was defined
	Emit     bool      // Flag to indicate whether the event should be emitted or not // TODO: Consider using an enum or custom type for actions
}

func NewManager(
	cfg ManagerConfig,
	evtsDepsManager *dependencies.Manager,
	initialPolicies ...*Policy,
) (*Manager, error) {
	if evtsDepsManager == nil {
		panic("evtDepsManager is nil")
	}

	m := &Manager{
		policies:        make(map[string]*Policy),
		rules:           make(map[events.ID]EventRules),
		evtsDepsManager: evtsDepsManager,
		mu:              sync.RWMutex{},
		cfg:             cfg,
	}

	for _, p := range initialPolicies {
		if err := m.addPolicy(p); err != nil {
			logger.Errorw("failed to add initial policy", "error", err)
		}
	}

	if err := m.initialize(); err != nil {
		return nil, errfmt.Errorf("failed to initialize policy manager: %s", err)
	}

	return m, nil
}

// version returns the version of the Policies.
func (m *Manager) version() uint16 {
	return 1
}

// addPolicy adds a policy.
func (m *Manager) addPolicy(p *Policy) error {
	if p == nil {
		return PolicyNilError()
	}
	if _, ok := m.policies[p.Name]; ok {
		return PolicyAlreadyExistsError(p.Name)
	}

	m.policies[p.Name] = p

	m.computeRules()

	return nil
}

// setPolicy sets a policy.
func (m *Manager) setPolicy(p *Policy) error {
	if p == nil {
		return PolicyNilError()
	}

	// TODO: we can merge set and add together to avoid code duplication
	m.policies[p.Name] = p

	m.computeRules()

	return nil
}

// removePolicy removes a policy by name.
func (m *Manager) removePolicy(name string) error {
	p, ok := m.policies[name]
	if !ok {
		return PolicyNotFoundByNameError(name)
	}

	delete(m.policies, p.Name)

	m.computeRules()

	return nil
}

// compute recalculates values, updates flags, fills the reduced userland map,
// and sets the related bitmap that is used to prevent the iteration of the entire map.
//
// It must be called at every runtime policies changes.
func (m *Manager) compute() {
	ps.updateContainerFilterEnabled()
	ps.updateUserlandRules()
}

func (m *Manager) updateContainerFilterEnabled() {
	ps.containerFiltersEnabled = 0

	for _, p := range ps.allFromMap() {
		if p.ContainerFilterEnabled() {
			utils.SetBit(&ps.containerFiltersEnabled, uint(p.ID))
		}
	}
}

// updateUserlandRules sets the userlandRules list.
func (m *Manager) updateUserlandRules() {
	userlandList := []*Policy{}

	for _, p := range ps.allFromMap() {
		if p == nil {
			continue
		}

		hasUserlandFilters := false
		uidFilterableInUserland := false
		pidFilterableInUserland := false

		if p.UIDFilter.Enabled() &&
			((p.UIDFilter.Minimum() != filters.MinNotSetUInt) ||
				(p.UIDFilter.Maximum() != filters.MaxNotSetUInt)) {
			uidFilterableInUserland = true
		}

		if p.PIDFilter.Enabled() &&
			((p.PIDFilter.Minimum() != filters.MinNotSetUInt) ||
				(p.PIDFilter.Maximum() != filters.MaxNotSetUInt)) {
			pidFilterableInUserland = true
		}

		// Check filters under Rules
		for _, rule := range p.Rules {
			if rule.DataFilter.Enabled() ||
				rule.RetFilter.Enabled() ||
				rule.ScopeFilter.Enabled() {
				hasUserlandFilters = true
				break
			}
		}

		// Check other filters
		if hasUserlandFilters || uidFilterableInUserland || pidFilterableInUserland {
			// add policy to userland list
			userlandList = append(userlandList, p)
		}
	}

	ps.userlandRules = userlandList
}

// lookupPolicyByName returns a policy by name.
func (m *Manager) lookupPolicyByName(name string) (*Policy, error) {
	if p, ok := m.policies[name]; ok {
		return p, nil
	}

	return nil, PolicyNotFoundByNameError(name)
}

// matchedPolicyNames returns a list of matched policy names based on
// the given matched bitmap.
func (m *Manager) matchedPolicyNames(matched uint64) []string {
	names := []string{}

	// TODO: this will take event id and matched rules bitmap, and map to policies in userspace
	// for _, p := range ps.allFromMap() {
	// 	if utils.HasBit(matched, uint(p.ID)) {
	// 		names = append(names, p.Name)
	// 	}
	// }

	return names
}

// allPoliciesFromMap returns a map of allFromMap policies by ID.
// When iterating, the order is not guaranteed.
func (m *Manager) allPoliciesFromMap() map[string]*Policy {
	return m.policies
}

func (m *Manager) subscribeDependencyHandlers() {
	// TODO: As dynamic event addition or removal becomes a thing, we should subscribe all the watchers
	// before selecting them. There is no reason to select the event in the New function anyhow.
	m.evtsDepsManager.SubscribeAdd(
		dependencies.EventNodeType,
		func(node interface{}) []dependencies.Action {
			eventNode, ok := node.(*dependencies.EventNode)
			if !ok {
				logger.Errorw("Got node from type not requested")
				return nil
			}

			m.addDependencyEventToRules(eventNode.GetID(), eventNode.GetDependents())

			return nil
		})
	m.evtsDepsManager.SubscribeRemove(
		dependencies.EventNodeType,
		func(node interface{}) []dependencies.Action {
			eventNode, ok := node.(*dependencies.EventNode)
			if !ok {
				logger.Errorw("Got node from type not requested")
				return nil
			}

			m.removeEventFromRules(eventNode.GetID())

			return nil
		})
}

// AddDependencyEventToRules adds for management an event that is a dependency of other events.
// The difference from selected events is that it doesn't affect its eviction.
func (m *Manager) addDependencyEventToRules(evtID events.ID, dependentEvts []events.ID) {
	var newSubmit uint64
	var reqBySig bool

	for _, dependentEvent := range dependentEvts {
		currentFlags, ok := m.events[dependentEvent]
		if ok {
			newSubmit |= currentFlags.rulesToSubmit
			reqBySig = reqBySig || events.Core.GetDefinitionByID(dependentEvent).IsSignature()
		}
	}

	m.addEventFlags(
		evtID,
		newEventFlags(
			eventFlagsWithSubmit(newSubmit),
			eventFlagsWithRequiredBySignature(reqBySig),
			eventFlagsWithEnabled(true),
		),
	)
}

func (m *Manager) addEventFlags(id events.ID, selectedFlags *eventFlags) {
	currentFlags, ok := m.events[id]
	if ok {
		currentFlags.rulesToSubmit |= selectedFlags.rulesToSubmit
		currentFlags.rulesToEmit |= selectedFlags.rulesToEmit
		currentFlags.requiredBySignature = selectedFlags.requiredBySignature
		currentFlags.enabled = selectedFlags.enabled
		return
	}

	m.rules[id] = newEventFlags(
		eventFlagsWithSubmit(selectedFlags.rulesToSubmit),
		eventFlagsWithEmit(selectedFlags.rulesToEmit),
		eventFlagsWithRequiredBySignature(selectedFlags.requiredBySignature),
		eventFlagsWithEnabled(selectedFlags.enabled),
	)
}

func (m *Manager) addDependenciesToRulesRecursive(eventNode *dependencies.EventNode) {
	eventID := eventNode.GetID()
	for _, dependencyEventID := range eventNode.GetDependencies().GetIDs() {
		m.addDependencyEventToRules(dependencyEventID, []events.ID{eventID})
		dependencyNode, err := m.evtsDepsManager.GetEvent(dependencyEventID)
		if err == nil {
			m.addDependenciesToRulesRecursive(dependencyNode)
		}
	}
}

func (m *Manager) selectEvent(eventID events.ID, selectedState *eventFlags) {
	m.addEventFlags(eventID, selectedState)
	eventNode, err := m.evtsDepsManager.SelectEvent(eventID)
	if err != nil {
		logger.Errorw("Event selection failed",
			"event", events.Core.GetDefinitionByID(eventID).GetName())
		return
	}

	m.addDependenciesToRulesRecursive(eventNode)
}

func (m *Manager) removeEventFromRules(evtID events.ID) {
	logger.Debugw("Remove event from rules", "event", events.Core.GetDefinitionByID(evtID).GetName())
	delete(m.events, evtID)
}

// TODO: we can move the following selection functions to be part of the policies compute phase
func (m *Manager) selectMandatoryEvents() {
	// Initialize events state with mandatory events (TODO: review this need for sched exec)

	m.selectEvent(events.SchedProcessFork, newEventFlags())
	m.selectEvent(events.SchedProcessExec, newEventFlags())
	m.selectEvent(events.SchedProcessExit, newEventFlags())

	// Control Plane Events

	m.selectEvent(events.SignalCgroupMkdir, newEventFlags(eventFlagsWithSubmit(PolicyAll)))
	m.selectEvent(events.SignalCgroupRmdir, newEventFlags(eventFlagsWithSubmit(PolicyAll)))
}

func (m *Manager) selectConfiguredEvents() {
	// Control Plane Process Tree Events

	pipeEvts := func() {
		m.selectEvent(events.SchedProcessFork, newEventFlags(eventFlagsWithSubmit(PolicyAll)))
		m.selectEvent(events.SchedProcessExec, newEventFlags(eventFlagsWithSubmit(PolicyAll)))
		m.selectEvent(events.SchedProcessExit, newEventFlags(eventFlagsWithSubmit(PolicyAll)))
	}
	signalEvts := func() {
		m.selectEvent(events.SignalSchedProcessFork, newEventFlags(eventFlagsWithSubmit(PolicyAll)))
		m.selectEvent(events.SignalSchedProcessExec, newEventFlags(eventFlagsWithSubmit(PolicyAll)))
		m.selectEvent(events.SignalSchedProcessExit, newEventFlags(eventFlagsWithSubmit(PolicyAll)))
	}

	switch m.cfg.ProcTreeConfig.Source {
	case proctree.SourceBoth:
		pipeEvts()
		signalEvts()
	case proctree.SourceSignals:
		signalEvts()
	case proctree.SourceEvents:
		pipeEvts()
	}

	// DNS Cache events

	if m.cfg.DNSCacheConfig.Enable {
		m.selectEvent(events.NetPacketDNS, newEventFlags(eventFlagsWithSubmit(PolicyAll)))
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

	for id, flags := range getCaptureEventsFlags(m.cfg.CaptureConfig) {
		m.selectEvent(id, flags)
	}
}

func (m *Manager) selectUserEvents() {
	// Events selected by the user
	userEvents := make(map[events.ID]*eventFlags)

	// TODO: fix to match what we need
	for _, p := range m.ps.policies {
		pId := p.ID
		for eId := range p.Rules {
			ef, ok := userEvents[eId]
			if !ok {
				ef = newEventFlags(eventFlagsWithEnabled(true))
				userEvents[eId] = ef
			}

			ef.enableEmission(pId)
			ef.enableSubmission(pId)
		}
	}

	for id, flags := range userEvents {
		m.selectEvent(id, flags)
	}
}

func (m *Manager) updateCapsForSelectedEvents() error {
	// Update capabilities rings with all events dependencies

	caps := capabilities.GetInstance()
	for id := range m.events {
		if !events.Core.IsDefined(id) {
			return errfmt.Errorf("event %d is not defined", id)
		}
		depsNode, err := m.evtsDepsManager.GetEvent(id)
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

func (m *Manager) initialize() error {
	m.subscribeDependencyHandlers()
	m.selectMandatoryEvents()
	m.selectConfiguredEvents()
	m.selectUserEvents()
	err := m.updateCapsForSelectedEvents()
	if err != nil {
		return errfmt.WrapError(err)
	}

	return nil
}

// TODO: all below functions is related to API - consider moving to a new file

// IsEnabled tests if a event, or a policy per event is enabled (in the future it will also check if a policy is enabled)
// TODO: add metrics about an event being enabled/disabled, or a policy being enabled/disabled?
func (m *Manager) IsEnabled(matchedRules uint64, id events.ID) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.isEventEnabled(id) {
		return false
	}

	return m.isRuleEnabled(matchedRules, id)
}

// IsRuleEnabled returns true if a given event policy is enabled for a given rule
func (m *Manager) IsRuleEnabled(matchedRules uint64, id events.ID) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.isRuleEnabled(matchedRules, id)
}

// not synchronized, use IsRuleEnabled instead
func (m *Manager) isRuleEnabled(matchedRules uint64, id events.ID) bool {
	flags, ok := m.events[id]
	if !ok {
		return false
	}

	return flags.rulesToEmit&matchedRules != 0
}

// IsEventEnabled returns true if a given event policy is enabled for a given rule
func (m *Manager) IsEventEnabled(id events.ID) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.isEventEnabled(id)
}

// not synchronized, use IsEventEnabled instead
func (m *Manager) isEventEnabled(id events.ID) bool {
	flags, ok := m.events[id]
	if !ok {
		return false
	}

	return flags.enabled
}

// EnableEvent enables a given event
func (m *Manager) EnableEvent(id events.ID) {
	m.mu.Lock()
	defer m.mu.Unlock()

	flags, ok := m.events[id]
	if !ok {
		m.events[id] = newEventFlags(
			eventFlagsWithEnabled(true),
		)
		return
	}

	flags.enableEvent()
}

// DisableEvent disables a given event
func (m *Manager) DisableEvent(id events.ID) {
	m.mu.Lock()
	defer m.mu.Unlock()

	flags, ok := m.events[id]
	if !ok {
		m.events[id] = newEventFlags(
			eventFlagsWithEnabled(false),
		)
		return
	}

	flags.disableEvent()
}

//
// Rules
//

func (m *Manager) IsRequiredBySignature(id events.ID) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	flags, ok := m.events[id]
	if !ok {
		return false
	}

	return flags.requiredBySignature
}

func (m *Manager) MatchEvent(id events.ID, matched uint64) uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	flags, ok := m.events[id]
	if !ok {
		return 0
	}

	return flags.rulesToEmit & matched
}

func (m *Manager) MatchEventInAnyPolicy(id events.ID) uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	flags, ok := m.events[id]
	if !ok {
		return 0
	}

	return flags.rulesToEmit | flags.rulesToSubmit
}

func (m *Manager) EventsSelected() []events.ID {
	m.mu.RLock()
	defer m.mu.RUnlock()

	eventsSelected := make([]events.ID, 0, len(m.events))
	for evt := range m.events {
		eventsSelected = append(eventsSelected, evt)
	}

	return eventsSelected
}

func (m *Manager) IsEventSelected(id events.ID) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, ok := m.events[id]
	return ok
}

func (m *Manager) EventsToSubmit() []events.ID {
	m.mu.RLock()
	defer m.mu.RUnlock()

	eventsToSubmit := []events.ID{}
	for evt, flags := range m.events {
		if flags.rulesToSubmit != 0 {
			eventsToSubmit = append(eventsToSubmit, evt)
		}
	}

	return eventsToSubmit
}

func (m *Manager) IsEventToEmit(id events.ID) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	flags, ok := m.events[id]
	if !ok {
		return false
	}

	return flags.rulesToEmit != 0
}

func (m *Manager) IsEventToSubmit(id events.ID) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	flags, ok := m.events[id]
	if !ok {
		return false
	}

	return flags.rulesToSubmit != 0
}

//
// Policies methods made available by Manager.
// Some are transitive (tidying), some are not.
//

func (m *Manager) CreateUserlandIterator() utils.Iterator[*Policy] {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// The returned iterator is not thread-safe since its underlying data is not a copy.
	// A possible solution would be to use the snapshot mechanism with timestamps instead
	// of version numbers.
	return m.ps.createUserlandIterator()
}

func (m *Manager) CreateAllIterator() utils.Iterator[*Policy] {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// The returned iterator is not thread-safe since its underlying data is not a copy.
	// A possible solution would be to use the snapshot mechanism with timestamps instead
	// of version numbers.
	return m.ps.createAllIterator()
}

func (m *Manager) FilterableInUserland() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.ps.userlandRules) != 0
}

func (m *Manager) WithContainerFilterEnabled() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// TODO: we should return rules bitmap where container filters are enabled
	//return m.ps.withContainerFilterEnabled()
}

func (m *Manager) MatchedNames(matched uint64) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.ps.matchedNames(matched)
}

func (m *Manager) LookupByName(name string) (*Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.ps.lookupByName(name)
}

func (m *Manager) UpdateBPF(
	bpfModule *bpf.Module,
	cts *containers.Containers,
	eventsFields map[events.ID][]bufferdecoder.ArgType,
	createNewMaps bool,
	updateProcTree bool,
) (*PoliciesConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.ps.updateBPF(bpfModule, cts, m.rules, eventsFields, createNewMaps, updateProcTree)
}
