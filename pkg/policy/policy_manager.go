package policy

import (
	"sync"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/dnscache"
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

// PolicyManager is a thread-safe struct that manages the enabled policies for each rule
type PolicyManager struct {
	mu              sync.RWMutex
	cfg             ManagerConfig
	evtsDepsManager *dependencies.Manager
	ps              *policies
	rules           map[events.ID]*eventFlags
}

func NewPolicyManager(
	cfg ManagerConfig,
	evtsDepsManager *dependencies.Manager,
	policies ...*Policy,
) *PolicyManager {
	if evtsDepsManager == nil {
		panic("evtsDepsManager is nil")
	}

	ps := NewPolicies()
	for _, p := range policies {
		if err := ps.set(p); err != nil {
			logger.Errorw("failed to set policy", "error", err)
		}
	}

	pm := &PolicyManager{
		mu:              sync.RWMutex{},
		cfg:             cfg,
		evtsDepsManager: evtsDepsManager,
		ps:              ps,
		rules:           make(map[events.ID]*eventFlags),
	}

	// TODO: As dynamic event addition or removal becomes a thing, we should subscribe all the watchers
	// before selecting them. There is no reason to select the event in the New function anyhow.
	pm.evtsDepsManager.SubscribeAdd(
		dependencies.EventNodeType,
		func(node interface{}) []dependencies.Action {
			eventNode, ok := node.(*dependencies.EventNode)
			if !ok {
				logger.Errorw("Got node from type not requested")
				return nil
			}
			pm.addDependencyEventToRules(eventNode.GetID(), eventNode.GetDependents())
			return nil
		})

	pm.evtsDepsManager.SubscribeRemove(
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

	// Initialize events state with mandatory events (TODO: review this need for sched exec)

	pm.selectEvent(events.SchedProcessFork, newEventFlags())
	pm.selectEvent(events.SchedProcessExec, newEventFlags())
	pm.selectEvent(events.SchedProcessExit, newEventFlags())

	// Control Plane Events

	pm.selectEvent(events.SignalCgroupMkdir, newEventFlags(eventFlagsWithSubmit(PolicyAll)))
	pm.selectEvent(events.SignalCgroupRmdir, newEventFlags(eventFlagsWithSubmit(PolicyAll)))

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

	// DNS Cache events

	if pm.cfg.DNSCacheConfig.Enable {
		pm.selectEvent(events.NetPacketDNS, newEventFlags(eventFlagsWithSubmit(PolicyAll)))
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

	// Pseudo events added by capture (if enabled by the user)

	for id, flags := range getCaptureEventsFlags(cfg.CaptureConfig) {
		pm.selectEvent(id, flags)
	}

	// Events chosen by the user

	for _, p := range pm.ps.policiesList {
		for e := range p.EventsToTrace {
			var submit, emit uint64
			if _, ok := pm.rules[e]; ok {
				submit = pm.rules[e].policiesSubmit
				emit = pm.rules[e].policiesEmit
			}
			utils.SetBit(&submit, uint(p.ID))
			utils.SetBit(&emit, uint(p.ID))
			pm.selectEvent(
				e,
				newEventFlags(
					eventFlagsWithSubmit(submit),
					eventFlagsWithEmit(emit),
					eventFlagsWithEnabled(true),
				),
			)

			// pm.EnableRule(p.ID, e)
		}
	}

	caps := capabilities.GetInstance()

	for id := range pm.rules {
		if !events.Core.IsDefined(id) {
			logger.Errorw("Event is not defined", "event", id)
		}
		depsNode, err := pm.evtsDepsManager.GetEvent(id)
		if err == nil {
			deps := depsNode.GetDependencies()
			evtCaps := deps.GetCapabilities()
			err = caps.BaseRingAdd(evtCaps.GetBase()...)
			if err != nil {
				logger.Errorw("Failed to add base capabilities", "event", id, "error", err)
			}
			err = caps.BaseRingAdd(evtCaps.GetEBPF()...)
			if err != nil {
				logger.Errorw("Failed to add eBPF capabilities", "event", id, "error", err)
			}
		}
	}

	return pm
}

func getCaptureEventsFlags(cfg config.CaptureConfig) map[events.ID]*eventFlags {
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

func (pm *PolicyManager) addEventFlags(id events.ID, chosenFlags *eventFlags) {
	currentFlags, ok := pm.rules[id]
	if ok {
		// if already exists, turn on the corresponding bits and keep the rest
		currentFlags.policiesSubmit |= chosenFlags.policiesSubmit
		currentFlags.policiesEmit |= chosenFlags.policiesEmit
		// currentFlags.signature = chosenFlags.signature
		// currentFlags.enabled = chosenFlags.enabled
		return
	}

	pm.rules[id] = newEventFlags(
		eventFlagsWithSubmit(chosenFlags.policiesSubmit),
		eventFlagsWithEmit(chosenFlags.policiesEmit),
		eventFlagsWithEnabled(chosenFlags.enabled),
		eventFlagsWithSignature(chosenFlags.signature),
	)
}

// AddDependencyEventToRules adds for management an event that is a dependency of other events.
// The difference from chosen events is that it doesn't affect its eviction.
func (pm *PolicyManager) addDependencyEventToRules(evtID events.ID, dependentEvts []events.ID) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	var newSubmit uint64

	for _, dependentEvent := range dependentEvts {
		currentFlags, ok := pm.rules[dependentEvent]
		if ok {
			newSubmit |= currentFlags.policiesSubmit
		}
	}
	pm.addEventFlags(
		evtID,
		newEventFlags(
			eventFlagsWithSubmit(newSubmit),
			eventFlagsWithSignature(events.Core.GetDefinitionByID(evtID).IsSignature()),
		),
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

func (pm *PolicyManager) selectEvent(eventID events.ID, chosenState *eventFlags) {
	pm.addEventFlags(eventID, chosenState)
	eventNode, err := pm.evtsDepsManager.SelectEvent(eventID)
	if err != nil {
		logger.Errorw("Event selection failed",
			"event", events.Core.GetDefinitionByID(eventID).GetName())
		return
	}
	pm.addDependenciesToRulesRecursive(eventNode)
}

func (pm *PolicyManager) removeEventFromRules(evtID events.ID) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	logger.Debugw("Remove event from rules", "event", events.Core.GetDefinitionByID(evtID).GetName())
	delete(pm.rules, evtID)
}

//

func (pm *PolicyManager) MatchEvent(id events.ID, matched uint64) uint64 {
	pm.mu.RLock()
	flags, ok := pm.rules[id]
	pm.mu.RUnlock()

	if !ok {
		return 0
	}

	return flags.policiesEmit & matched
}

func (pm *PolicyManager) EventsToTrace() []events.ID {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	eventsToTrace := make([]events.ID, 0, len(pm.rules))
	for evt := range pm.rules {
		eventsToTrace = append(eventsToTrace, evt)
	}

	return eventsToTrace
}

func (pm *PolicyManager) EventsToSubmit() []events.ID {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	eventsToSubmit := []events.ID{}
	for evt, flags := range pm.rules {
		if flags.policiesSubmit != 0 {
			eventsToSubmit = append(eventsToSubmit, evt)
		}
	}

	return eventsToSubmit
}

func (pm *PolicyManager) IsEventToTrace(id events.ID) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	_, ok := pm.rules[id]
	return ok
}

func (pm *PolicyManager) IsEventToEmit(id events.ID) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	flags, ok := pm.rules[id]
	if !ok {
		return false
	}

	return flags.policiesEmit != 0
}

func (pm *PolicyManager) IsEventToSubmit(id events.ID) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	flags, ok := pm.rules[id]
	if !ok {
		return false
	}

	return flags.policiesSubmit != 0
}

// IsEnabled tests if a event, or a policy per event is enabled (in the future it will also check if a policy is enabled)
// TODO: add metrics about an event being enabled/disabled, or a policy being enabled/disabled?
func (pm *PolicyManager) IsEnabled(matchedPolicies uint64, id events.ID) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if !pm.isEventEnabled(id) {
		return false
	}

	return pm.isRuleEnabled(matchedPolicies, id)
}

// IsRuleEnabled returns true if a given event policy is enabled for a given rule
func (pm *PolicyManager) IsRuleEnabled(matchedPolicies uint64, id events.ID) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return pm.isRuleEnabled(matchedPolicies, id)
}

// not synchronized, use IsRuleEnabled instead
func (pm *PolicyManager) isRuleEnabled(matchedPolicies uint64, id events.ID) bool {
	flags, ok := pm.rules[id]
	if !ok {
		return false
	}

	return flags.policiesEmit&matchedPolicies != 0
}

// IsEventEnabled returns true if a given event policy is enabled for a given rule
func (pm *PolicyManager) IsEventEnabled(id events.ID) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return pm.isEventEnabled(id)
}

// not synchronized, use IsEventEnabled instead
func (pm *PolicyManager) isEventEnabled(id events.ID) bool {
	flags, ok := pm.rules[id]
	if !ok {
		return false
	}

	return flags.enabled
}

// EnableRule enables a rule for a given event policy
func (pm *PolicyManager) EnableRule(policyId int, id events.ID) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	flags, ok := pm.rules[id]
	if !ok {
		// if you enabling/disabling a rule for an event that
		// was not enabled/disabled yet, we assume the event should be enabled
		flags = newEventFlags(
			eventFlagsWithEnabled(true),
		)
		pm.rules[id] = flags
	}

	flags.enableEmission(policyId)
}

// DisableRule disables a rule for a given event policy
func (pm *PolicyManager) DisableRule(policyId int, id events.ID) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	flags, ok := pm.rules[id]
	if !ok {
		// if you enabling/disabling a rule for an event that
		// was not enabled/disabled yet, we assume the event should be enabled
		flags = newEventFlags(
			eventFlagsWithEnabled(true),
		)
		pm.rules[id] = flags
	}

	flags.disableEmission(policyId)
}

// EnableEvent enables a given event
func (pm *PolicyManager) EnableEvent(id events.ID) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	flags, ok := pm.rules[id]
	if !ok {
		pm.rules[id] = newEventFlags(
			eventFlagsWithEnabled(true),
		)
		return
	}

	flags.enableEvent()
}

// DisableEvent disables a given event
func (pm *PolicyManager) DisableEvent(id events.ID) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	flags, ok := pm.rules[id]
	if !ok {
		pm.rules[id] = newEventFlags(
			eventFlagsWithEnabled(false),
		)
		return
	}

	flags.disableEvent()
}

//
// Policies methods made available by PolicyManager.
// Some are transitive (tidying), some are not.
//

func (pm *PolicyManager) CreateUserlandIterator() utils.Iterator[*Policy] {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// The returned iterator is not thread-safe since its underlying data is not a copy.
	// A possible solution would be to use the snapshot mechanism with timestamps instead
	// of version numbers.
	return pm.ps.createUserlandIterator()
}

func (pm *PolicyManager) CreateAllIterator() utils.Iterator[*Policy] {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// The returned iterator is not thread-safe since its underlying data is not a copy.
	// A possible solution would be to use the snapshot mechanism with timestamps instead
	// of version numbers.
	return pm.ps.createAllIterator()
}

func (pm *PolicyManager) FilterableInUserland(bitmap uint64) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return (bitmap & pm.ps.filterInUserland()) != 0
}

func (pm *PolicyManager) WithContainerFilterEnabled() uint64 {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return pm.ps.withContainerFilterEnabled()
}

func (pm *PolicyManager) MatchedNames(matched uint64) []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return pm.ps.matchedNames(matched)
}

func (pm *PolicyManager) LookupByName(name string) (*Policy, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return pm.ps.lookupByName(name)
}

func (pm *PolicyManager) UpdateBPF(
	bpfModule *bpf.Module,
	cts *containers.Containers,
	eventsParams map[events.ID][]bufferdecoder.ArgType,
	createNewMaps bool,
	updateProcTree bool,
) (*PoliciesConfig, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	return pm.ps.updateBPF(bpfModule, cts, pm.rules, eventsParams, createNewMaps, updateProcTree)
}
