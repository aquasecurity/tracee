package events

import "github.com/aquasecurity/tracee/pkg/ebpf/probes"

//
// Dependencies: Probes
//

// SetProbes sets the probes to a new given set (thread-safe).
func (d *Dependencies) SetProbes(prbs []*Probe) {
	d.probesLock.Lock()
	defer d.probesLock.Unlock()

	// delete all previous probes
	for k := range d.probes {
		delete(d.probes, k)
	}

	d.addProbes(prbs)
}

// GetProbes returns a slice copy of instanced probes (thread-safe).
func (d *Dependencies) GetProbes() []*Probe {
	d.probesLock.RLock()
	defer d.probesLock.RUnlock()

	a := []*Probe{}
	for _, v := range d.probes {
		a = append(a, v)
	}

	return a
}

// AddProbe adds a probe dependency to the event (thread-safe).
func (d *Dependencies) AddProbe(probe *Probe) {
	d.probesLock.Lock()
	defer d.probesLock.Unlock()

	d.probes[probe.GetHandle()] = probe
}

// AddProbes adds probes dependencies to the event (thread-safe).
func (d *Dependencies) AddProbes(prbs []*Probe) {
	d.probesLock.Lock()
	defer d.probesLock.Unlock()

	d.addProbes(prbs)
}

// DelProbe removes a probe dependency from the event (thread-safe).
func (d *Dependencies) DelProbe(handle probes.Handle) {
	d.probesLock.Lock()
	defer d.probesLock.Unlock()

	delete(d.probes, handle)
}

// DelProbes removes probes dependencies from the event (thread-safe).
func (d *Dependencies) DelProbes(handle []probes.Handle) {
	d.probesLock.Lock()
	defer d.probesLock.Unlock()

	for _, e := range handle {
		delete(d.probes, e)
	}
}

// addProbes adds probes dependencies to the event (no locking).
func (d *Dependencies) addProbes(prbs []*Probe) {
	for _, p := range prbs {
		d.probes[p.GetHandle()] = p
	}
}
