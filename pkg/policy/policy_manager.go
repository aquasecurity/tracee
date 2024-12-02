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

// Manager is a thread-safe struct that manages the enabled policies for each rule
type Manager struct {
	mu              sync.RWMutex
	cfg             ManagerConfig
	evtsDepsManager *dependencies.Manager
	ps              *policies
	rules           map[events.ID]*eventFlags
}

func NewManager(
	cfg ManagerConfig,
	depsManager *dependencies.Manager,
	initialPolicies ...*Policy,
) (*Manager, error) {
	if depsManager == nil {
		panic("evtDepsManager is nil")
	}

	ps := NewPolicies()
	for _, p := range initialPolicies {
		if err := ps.set(p); err != nil {
			logger.Errorw("failed to set initial policy", "error", err)
		}
	}

	m := &Manager{
		mu:              sync.RWMutex{},
		cfg:             cfg,
		evtsDepsManager: depsManager,
		ps:              ps,
		rules:           make(map[events.ID]*eventFlags),
	}

	if err := m.initialize(); err != nil {
		return nil, errfmt.Errorf("failed to initialize policy manager: %s", err)
	}

	return m, nil
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
// The difference from chosen events is that it doesn't affect its eviction.
func (m *Manager) addDependencyEventToRules(evtID events.ID, dependentEvts []events.ID) {
	var newSubmit uint64
	var reqBySig bool

	for _, dependentEvent := range dependentEvts {
		currentFlags, ok := m.rules[dependentEvent]
		if ok {
			newSubmit |= currentFlags.policiesSubmit
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

func (m *Manager) addEventFlags(id events.ID, chosenFlags *eventFlags) {
	currentFlags, ok := m.rules[id]
	if ok {
		currentFlags.policiesSubmit |= chosenFlags.policiesSubmit
		currentFlags.policiesEmit |= chosenFlags.policiesEmit
		currentFlags.requiredBySignature = chosenFlags.requiredBySignature
		currentFlags.enabled = chosenFlags.enabled
		return
	}

	m.rules[id] = newEventFlags(
		eventFlagsWithSubmit(chosenFlags.policiesSubmit),
		eventFlagsWithEmit(chosenFlags.policiesEmit),
		eventFlagsWithRequiredBySignature(chosenFlags.requiredBySignature),
		eventFlagsWithEnabled(chosenFlags.enabled),
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

func (m *Manager) selectEvent(eventID events.ID, chosenState *eventFlags) {
	m.addEventFlags(eventID, chosenState)
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
	delete(m.rules, evtID)
}

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
	// Events chosen by the user
	userEvents := make(map[events.ID]*eventFlags)

	for _, p := range m.ps.policiesList {
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
	for id := range m.rules {
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

// IsEnabled tests if a event, or a policy per event is enabled (in the future it will also check if a policy is enabled)
// TODO: add metrics about an event being enabled/disabled, or a policy being enabled/disabled?
func (m *Manager) IsEnabled(matchedPolicies uint64, id events.ID) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.isEventEnabled(id) {
		return false
	}

	return m.isRuleEnabled(matchedPolicies, id)
}

// IsRuleEnabled returns true if a given event policy is enabled for a given rule
func (m *Manager) IsRuleEnabled(matchedPolicies uint64, id events.ID) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.isRuleEnabled(matchedPolicies, id)
}

// not synchronized, use IsRuleEnabled instead
func (m *Manager) isRuleEnabled(matchedPolicies uint64, id events.ID) bool {
	flags, ok := m.rules[id]
	if !ok {
		return false
	}

	return flags.policiesEmit&matchedPolicies != 0
}

// IsEventEnabled returns true if a given event policy is enabled for a given rule
func (m *Manager) IsEventEnabled(id events.ID) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.isEventEnabled(id)
}

// not synchronized, use IsEventEnabled instead
func (m *Manager) isEventEnabled(id events.ID) bool {
	flags, ok := m.rules[id]
	if !ok {
		return false
	}

	return flags.enabled
}

// EnableRule enables a rule for a given event policy
func (m *Manager) EnableRule(policyId int, id events.ID) error {
	if !isIDInRange(policyId) {
		return PoliciesOutOfRangeError(policyId)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	flags, ok := m.rules[id]
	if !ok {
		// if you enabling/disabling a rule for an event that
		// was not enabled/disabled yet, we assume the event should be enabled
		flags = newEventFlags(
			eventFlagsWithEnabled(true),
		)
		m.rules[id] = flags
	}

	flags.enableEmission(policyId)

	return nil
}

// DisableRule disables a rule for a given event policy
func (m *Manager) DisableRule(policyId int, id events.ID) error {
	if !isIDInRange(policyId) {
		return PoliciesOutOfRangeError(policyId)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	flags, ok := m.rules[id]
	if !ok {
		// if you enabling/disabling a rule for an event that
		// was not enabled/disabled yet, we assume the event should be enabled
		flags = newEventFlags(
			eventFlagsWithEnabled(true),
		)
		m.rules[id] = flags
	}

	flags.disableEmission(policyId)

	return nil
}

// EnableEvent enables a given event
func (m *Manager) EnableEvent(id events.ID) {
	m.mu.Lock()
	defer m.mu.Unlock()

	flags, ok := m.rules[id]
	if !ok {
		m.rules[id] = newEventFlags(
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

	flags, ok := m.rules[id]
	if !ok {
		m.rules[id] = newEventFlags(
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

	flags, ok := m.rules[id]
	if !ok {
		return false
	}

	return flags.requiredBySignature
}

func (m *Manager) MatchEvent(id events.ID, matched uint64) uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	flags, ok := m.rules[id]
	if !ok {
		return 0
	}

	return flags.policiesEmit & matched
}

func (m *Manager) MatchEventInAnyPolicy(id events.ID) uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	flags, ok := m.rules[id]
	if !ok {
		return 0
	}

	return (flags.policiesEmit | flags.policiesSubmit) & PolicyAll
}

func (m *Manager) EventsSelected() []events.ID {
	m.mu.RLock()
	defer m.mu.RUnlock()

	eventsSelected := make([]events.ID, 0, len(m.rules))
	for evt := range m.rules {
		eventsSelected = append(eventsSelected, evt)
	}

	return eventsSelected
}

func (m *Manager) IsEventSelected(id events.ID) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, ok := m.rules[id]
	return ok
}

func (m *Manager) EventsToSubmit() []events.ID {
	m.mu.RLock()
	defer m.mu.RUnlock()

	eventsToSubmit := []events.ID{}
	for evt, flags := range m.rules {
		if flags.policiesSubmit != 0 {
			eventsToSubmit = append(eventsToSubmit, evt)
		}
	}

	return eventsToSubmit
}

func (m *Manager) IsEventToEmit(id events.ID) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	flags, ok := m.rules[id]
	if !ok {
		return false
	}

	return flags.policiesEmit != 0
}

func (m *Manager) IsEventToSubmit(id events.ID) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	flags, ok := m.rules[id]
	if !ok {
		return false
	}

	return flags.policiesSubmit != 0
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

	return m.ps.filterableInUserland
}

func (m *Manager) WithContainerFilterEnabled() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.ps.withContainerFilterEnabled()
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
