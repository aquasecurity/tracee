package dependencies

import (
	"golang.org/x/exp/slices"

	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
	"github.com/aquasecurity/tracee/pkg/events"
)

type ProbeNode struct {
	handle     probes.Handle
	dependents []events.ID
}

func NewProbeNode(handle probes.Handle, dependents []events.ID) *ProbeNode {
	return &ProbeNode{
		handle:     handle,
		dependents: dependents,
	}
}

func (hn *ProbeNode) GetHandle() probes.Handle {
	return hn.handle
}

func (hn *ProbeNode) GetDependents() []events.ID {
	return slices.Clone(hn.dependents)
}

func (hn *ProbeNode) addDependent(dependent events.ID) {
	if !slices.Contains(hn.dependents, dependent) {
		hn.dependents = append(hn.dependents, dependent)
	}
}

func (hn *ProbeNode) removeDependent(dependent events.ID) {
	for i, d := range hn.dependents {
		if d == dependent {
			hn.dependents = append(hn.dependents[:i], hn.dependents[i+1:]...)
			break
		}
	}
}
