package policy

import (
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/pcaps"
	"github.com/aquasecurity/tracee/pkg/proctree"
	"github.com/aquasecurity/tracee/pkg/utils"
)

// computeEventsFlags computes the events flags based on the policies and its configuration.
func (ps *Policies) computeEventsFlags() {
	evtsFlags := newEventsFlags()

	// Initialize events flags with mandatory events (TODO: review this need for sched exec)

	evtsFlags.set(events.SchedProcessFork, newEventFlags())
	evtsFlags.set(events.SchedProcessExec, newEventFlags())
	evtsFlags.set(events.SchedProcessExit, newEventFlags())

	// Control Plane Events

	evtsFlags.set(events.SignalCgroupMkdir, submitAllPolicies)
	evtsFlags.set(events.SignalCgroupRmdir, submitAllPolicies)

	// Control Plane Process Tree Events

	pipeEvts := func() {
		evtsFlags.set(events.SchedProcessFork, submitAllPolicies)
		evtsFlags.set(events.SchedProcessExec, submitAllPolicies)
		evtsFlags.set(events.SchedProcessExit, submitAllPolicies)
	}
	signalEvts := func() {
		evtsFlags.set(events.SignalSchedProcessFork, submitAllPolicies)
		evtsFlags.set(events.SignalSchedProcessExec, submitAllPolicies)
		evtsFlags.set(events.SignalSchedProcessExit, submitAllPolicies)
	}

	// DNS Cache events

	if ps.config.DNSCacheConfig {
		evtsFlags.set(events.NetPacketDNS, submitAllPolicies)
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
		evtsFlags.set(eventID, eCfg)
	}

	// Events chosen by the user

	for p := range ps.filterEnabledPoliciesMap {
		for e := range p.EventsToTrace {
			var submit, emit uint64
			if evtFlags, ok := evtsFlags.GetOk(e); ok {
				submit = evtFlags.GetSubmit()
				emit = evtFlags.GetEmit()
			}
			utils.SetBit(&submit, uint(p.ID))
			utils.SetBit(&emit, uint(p.ID))
			evtsFlags.set(
				e,
				newEventFlags(
					eventFlagsWithSubmit(submit),
					eventFlagsWithEmit(emit),
				),
			)
		}
	}

	// Handle all essential events dependencies

	for id, flags := range evtsFlags.getAll() {
		handleEventsDependencies(evtsFlags, id, flags)
	}

	// Finally, replace the events flags with the computed ones

	ps.evtsFlags = evtsFlags
}

// handleEventsDependencies handles all events dependencies recursively.
func handleEventsDependencies(
	evtsFlags *eventsFlags,
	givenEvtId events.ID,
	givenEvtFlags eventFlags,
) {
	givenEventDefinition := events.Core.GetDefinitionByID(givenEvtId)

	for _, depEventId := range givenEventDefinition.GetDependencies().GetIDs() {
		depEventFlags, ok := evtsFlags.GetOk(depEventId)
		if !ok {
			depEventFlags = eventFlags{}
			handleEventsDependencies(evtsFlags, depEventId, givenEvtFlags)
		}

		// Make sure dependencies are submitted if the given event is submitted.
		depEvtSubmit := depEventFlags.GetSubmit() | givenEvtFlags.GetSubmit()
		evtsFlags.set(
			depEventId,
			newEventFlags(
				eventFlagsWithSubmit(depEvtSubmit),
				eventFlagsWithEmit(depEventFlags.GetEmit()),
				eventFlagsWithReqBySignature(givenEventDefinition.IsSignature()),
			),
		)
	}
}

// getCaptureEventsList sets events used to capture data.
func (ps *Policies) getCaptureEventsList() *eventsFlags {
	captureEvents := newEventsFlags()

	// INFO: All capture events should be placed, at least for now, to all matched policies, or else
	// the event won't be set to matched policy in eBPF and should_submit() won't submit the capture
	// event to userland.

	if ps.config.CaptureExec {
		captureEvents.set(events.CaptureExec, submitAllPolicies)
	}
	if ps.config.CaptureFileWrite {
		captureEvents.set(events.CaptureFileWrite, submitAllPolicies)
	}
	if ps.config.CaptureFileRead {
		captureEvents.set(events.CaptureFileRead, submitAllPolicies)
	}
	if ps.config.CaptureModule {
		captureEvents.set(events.CaptureModule, submitAllPolicies)
	}
	if ps.config.CaptureMem {
		captureEvents.set(events.CaptureMem, submitAllPolicies)
	}
	if ps.config.CaptureBpf {
		captureEvents.set(events.CaptureBpf, submitAllPolicies)
	}
	if pcaps.PcapsEnabled(ps.config.CaptureNet) {
		captureEvents.set(events.CaptureNetPacket, submitAllPolicies)
	}

	return captureEvents
}
