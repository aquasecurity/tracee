package policy

import (
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/pcaps"
	"github.com/aquasecurity/tracee/pkg/proctree"
	"github.com/aquasecurity/tracee/pkg/utils"
)

// computeEventsStates computes the events states based on the policies and its configuration.
func (ps *Policies) computeEventsStates() {
	evtsStates := newEventsStates()

	// Initialize events states with mandatory events (TODO: review this need for sched exec)

	evtsStates.set(events.SchedProcessFork, newEventStates())
	evtsStates.set(events.SchedProcessExec, newEventStates())
	evtsStates.set(events.SchedProcessExit, newEventStates())

	// Control Plane Events

	evtsStates.set(events.SignalCgroupMkdir, submitAllPolicies)
	evtsStates.set(events.SignalCgroupRmdir, submitAllPolicies)

	// Control Plane Process Tree Events

	pipeEvts := func() {
		evtsStates.set(events.SchedProcessFork, submitAllPolicies)
		evtsStates.set(events.SchedProcessExec, submitAllPolicies)
		evtsStates.set(events.SchedProcessExit, submitAllPolicies)
	}
	signalEvts := func() {
		evtsStates.set(events.SignalSchedProcessFork, submitAllPolicies)
		evtsStates.set(events.SignalSchedProcessExec, submitAllPolicies)
		evtsStates.set(events.SignalSchedProcessExit, submitAllPolicies)
	}

	// DNS Cache events

	if ps.config.DNSCacheConfig {
		evtsStates.set(events.NetPacketDNS, submitAllPolicies)
	}

	switch ps.config.ProcTreeSource {
	case proctree.SourceBoth:
		pipeEvts()
		signalEvts()
	case proctree.SourceSignals:
		signalEvts()
	case proctree.SourceEvents:
		pipeEvts()
	}

	// Pseudo events added by capture (if enabled by the user)

	for eventID, eCfg := range ps.getCaptureEventsList().getAll() {
		evtsStates.set(eventID, eCfg)
	}

	// Events chosen by the user

	for p := range ps.filterEnabledPoliciesMap {
		for e := range p.EventsToTrace {
			var submit, emit uint64
			if evtStates, ok := evtsStates.GetOk(e); ok {
				submit = evtStates.GetSubmit()
				emit = evtStates.GetEmit()
			}
			utils.SetBit(&submit, uint(p.ID))
			utils.SetBit(&emit, uint(p.ID))
			evtsStates.set(
				e,
				newEventStates(
					eventStatesWithSubmit(submit),
					eventStatesWithEmit(emit),
				),
			)
		}
	}

	// Handle all essential events dependencies

	for id, states := range evtsStates.getAll() {
		handleEventsDependencies(evtsStates, id, states)
	}

	// Finally, replace the events states with the computed ones

	ps.evtsStates = evtsStates
}

// handleEventsDependencies handles all events dependencies recursively.
func handleEventsDependencies(
	evtsStates *eventsStates,
	givenEvtId events.ID,
	givenEvtStates eventStates,
) {
	givenEventDefinition := events.Core.GetDefinitionByID(givenEvtId)

	for _, depEventId := range givenEventDefinition.GetDependencies().GetIDs() {
		depEventStates, ok := evtsStates.GetOk(depEventId)
		if !ok {
			depEventStates = eventStates{}
			handleEventsDependencies(evtsStates, depEventId, givenEvtStates)
		}

		// Make sure dependencies are submitted if the given event is submitted.
		depEvtSubmit := depEventStates.GetSubmit() | givenEvtStates.GetSubmit()
		evtsStates.set(
			depEventId,
			newEventStates(
				eventStatesWithSubmit(depEvtSubmit),
				eventStatesWithEmit(depEventStates.GetEmit()),
			),
		)
	}
}

// getCaptureEventsList sets events used to capture data.
func (ps *Policies) getCaptureEventsList() *eventsStates {
	captureEvents := newEventsStates()

	// INFO: All capture events should be placed, at least for now, to all matched policies, or else
	// the event won't be set to matched policy in eBPF and should_submit() won't submit the capture
	// event to userland.

	if ps.config.Capture.Exec {
		captureEvents.set(events.CaptureExec, submitAllPolicies)
	}
	if ps.config.Capture.FileWrite.Capture {
		captureEvents.set(events.CaptureFileWrite, submitAllPolicies)
	}
	if ps.config.Capture.FileRead.Capture {
		captureEvents.set(events.CaptureFileRead, submitAllPolicies)
	}
	if ps.config.Capture.Module {
		captureEvents.set(events.CaptureModule, submitAllPolicies)
	}
	if ps.config.Capture.Mem {
		captureEvents.set(events.CaptureMem, submitAllPolicies)
	}
	if ps.config.Capture.Bpf {
		captureEvents.set(events.CaptureBpf, submitAllPolicies)
	}
	if pcaps.PcapsEnabled(ps.config.Capture.Net) {
		captureEvents.set(events.CaptureNetPacket, submitAllPolicies)
	}

	return captureEvents
}
