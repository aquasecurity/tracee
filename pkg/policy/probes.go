package policy

import (
	"github.com/aquasecurity/tracee/pkg/cgroup"
	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
)

// AttachProbes attaches selected events probes to their respective eBPF progs
func (ps *Policies) AttachProbes(probeGroup *probes.ProbeGroup, cgroups *cgroup.Cgroups) error {
	var err error

	// TODO: On Snapshot pruning, we should check which probes are not used for
	// any snapshot and detach them.

	// Get probe dependencies for a given event ID
	getProbeDeps := func(id events.ID) []events.Probe {
		return events.Core.GetDefinitionByID(id).GetDependencies().GetProbes()
	}

	ps.rwmu.Lock()
	defer ps.rwmu.Unlock()

	// Get the list of probes to attach for each event being traced.
	probesToEvents := make(map[events.Probe][]events.ID)
	for id := range ps.eventsStates().getAll() {
		if !events.Core.IsDefined(id) {
			continue
		}
		for _, probeDep := range getProbeDeps(id) {
			probesToEvents[probeDep] = append(probesToEvents[probeDep], id)
		}
	}

	// Attach probes to their respective eBPF programs or cancel events if a required probe is missing.
	for probe, evtsIDs := range probesToEvents {
		err = probeGroup.Attach(probe.GetHandle(), cgroups) // attach bpf program to probe
		if err != nil {
			for _, evtID := range evtsIDs {
				evtName := events.Core.GetDefinitionByID(evtID).GetName()
				if probe.IsRequired() {
					logger.Warnw(
						"Cancelling event and its dependencies because of missing probe",
						"missing probe", probe.GetHandle(), "event", evtName,
						"error", err,
					)
					ps.eventsStates().cancelEventAndAllDeps(evtID)
				} else {
					logger.Debugw(
						"Failed to attach non-required probe for event",
						"event", evtName,
						"probe", probe.GetHandle(), "error", err,
					)
				}
			}
		}
	}

	return nil
}
