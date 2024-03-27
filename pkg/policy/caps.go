package policy

import (
	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
)

// UpdateCapabilitiesRings updates the capabilities rings based on the policies events states.
func (pm *PolicyManager) UpdateCapabilitiesRings(policies Policies) error {
	// NOTE: This only adds capabilities from events that are defined in the policies.
	// TODO: On the Snapshot pruning, we should check which capabilities are not used
	// for any snapshot and remove them from the capabilities rings.

	caps := capabilities.GetInstance()

	ps, ok := policies.(Policies)
	if !ok {
		return errfmt.Errorf("invalid policies type")
	}

	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	for id := range ps.EventsFlags().GetAll() {
		if !events.Core.IsDefined(id) {
			return errfmt.Errorf("event %d is not defined", id)
		}
		evtCaps := events.Core.GetDefinitionByID(id).GetDependencies().GetCapabilities()
		err := caps.BaseRingAdd(evtCaps.GetBase()...)
		if err != nil {
			return errfmt.WrapError(err)
		}
		err = caps.BaseRingAdd(evtCaps.GetEBPF()...)
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}
