package policy

import (
	"golang.org/x/exp/maps"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/utils"
)

type Policy struct {
	ID                int
	Name              string
	EventsToTrace     map[events.ID]string
	UIDFilter         *filters.UIntFilter[uint32]
	PIDFilter         *filters.UIntFilter[uint32]
	NewPidFilter      *filters.BoolFilter
	MntNSFilter       *filters.UIntFilter[uint64]
	PidNSFilter       *filters.UIntFilter[uint64]
	UTSFilter         *filters.StringFilter
	CommFilter        *filters.StringFilter
	ContFilter        *filters.BoolFilter
	NewContFilter     *filters.BoolFilter
	ContIDFilter      *filters.StringFilter
	RetFilter         *filters.RetFilter
	ArgFilter         *filters.ArgFilter
	ContextFilter     *filters.ContextFilter
	ProcessTreeFilter *filters.ProcessTreeFilter
	BinaryFilter      *filters.BinaryFilter
	Follow            bool
}

func NewPolicy() *Policy {
	return &Policy{
		ID:                0,
		Name:              "",
		EventsToTrace:     map[events.ID]string{},
		UIDFilter:         filters.NewUInt32Filter(),
		PIDFilter:         filters.NewUInt32Filter(),
		NewPidFilter:      filters.NewBoolFilter(),
		MntNSFilter:       filters.NewUIntFilter(),
		PidNSFilter:       filters.NewUIntFilter(),
		UTSFilter:         filters.NewStringFilter(),
		CommFilter:        filters.NewStringFilter(),
		ContFilter:        filters.NewBoolFilter(),
		NewContFilter:     filters.NewBoolFilter(),
		ContIDFilter:      filters.NewStringFilter(),
		RetFilter:         filters.NewRetFilter(),
		ArgFilter:         filters.NewArgFilter(),
		ContextFilter:     filters.NewContextFilter(),
		ProcessTreeFilter: filters.NewProcessTreeFilter(),
		BinaryFilter:      filters.NewBinaryFilter(),
		Follow:            false,
	}
}

// ContainerFilterEnabled returns true when the policy has at least one container filter type enabled
func (p *Policy) ContainerFilterEnabled() bool {
	return (p.ContFilter.Enabled() && p.ContFilter.Value()) ||
		(p.NewContFilter.Enabled() && p.NewContFilter.Value()) ||
		p.ContIDFilter.Enabled()
}

func (p *Policy) Clone() utils.Cloner {
	if p == nil {
		return nil
	}

	n := NewPolicy()

	n.ID = p.ID
	n.Name = p.Name
	maps.Copy(n.EventsToTrace, p.EventsToTrace)
	n.UIDFilter = p.UIDFilter.Clone().(*filters.UIntFilter[uint32])
	n.PIDFilter = p.PIDFilter.Clone().(*filters.UIntFilter[uint32])
	n.NewPidFilter = p.NewPidFilter.Clone().(*filters.BoolFilter)
	n.MntNSFilter = p.MntNSFilter.Clone().(*filters.UIntFilter[uint64])
	n.PidNSFilter = p.PidNSFilter.Clone().(*filters.UIntFilter[uint64])
	n.UTSFilter = p.UTSFilter.Clone().(*filters.StringFilter)
	n.CommFilter = p.CommFilter.Clone().(*filters.StringFilter)
	n.ContFilter = p.ContFilter.Clone().(*filters.BoolFilter)
	n.NewContFilter = p.NewContFilter.Clone().(*filters.BoolFilter)
	n.ContIDFilter = p.ContIDFilter.Clone().(*filters.StringFilter)
	n.RetFilter = p.RetFilter.Clone().(*filters.RetFilter)
	n.ArgFilter = p.ArgFilter.Clone().(*filters.ArgFilter)
	n.ContextFilter = p.ContextFilter.Clone().(*filters.ContextFilter)
	n.ProcessTreeFilter = p.ProcessTreeFilter.Clone().(*filters.ProcessTreeFilter)
	n.BinaryFilter = p.BinaryFilter.Clone().(*filters.BinaryFilter)
	n.Follow = p.Follow

	return n
}
