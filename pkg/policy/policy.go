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
	DataFilter        *filters.DataFilter
	ScopeFilter       *filters.ScopeFilter
	ProcessTreeFilter *filters.ProcessTreeFilter
	BinaryFilter      *filters.BinaryFilter
	Follow            bool
}

// Compile-time check to ensure that Policy implements the Cloner interface
var _ utils.Cloner[*Policy] = &Policy{}

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
		UTSFilter:         filters.NewStringFilter(nil),
		CommFilter:        filters.NewStringFilter(nil),
		ContFilter:        filters.NewBoolFilter(),
		NewContFilter:     filters.NewBoolFilter(),
		ContIDFilter:      filters.NewStringFilter(nil),
		RetFilter:         filters.NewRetFilter(),
		DataFilter:        filters.NewDataFilter(),
		ScopeFilter:       filters.NewScopeFilter(),
		ProcessTreeFilter: filters.NewProcessTreeFilter(),
		BinaryFilter:      filters.NewBinaryFilter(),
		Follow:            false,
	}
}

// ContainerFilterEnabled returns true if the policy has at least one container filter type enabled.
func (p *Policy) ContainerFilterEnabled() bool {
	return (p.ContFilter.Enabled() && p.ContFilter.Value()) ||
		(p.NewContFilter.Enabled() && p.NewContFilter.Value()) ||
		p.ContIDFilter.Enabled()
}

func (p *Policy) Clone() *Policy {
	if p == nil {
		return nil
	}

	n := NewPolicy()

	n.ID = p.ID
	n.Name = p.Name
	maps.Copy(n.EventsToTrace, p.EventsToTrace)
	n.UIDFilter = p.UIDFilter.Clone()
	n.PIDFilter = p.PIDFilter.Clone()
	n.NewPidFilter = p.NewPidFilter.Clone()
	n.MntNSFilter = p.MntNSFilter.Clone()
	n.PidNSFilter = p.PidNSFilter.Clone()
	n.UTSFilter = p.UTSFilter.Clone()
	n.CommFilter = p.CommFilter.Clone()
	n.ContFilter = p.ContFilter.Clone()
	n.NewContFilter = p.NewContFilter.Clone()
	n.ContIDFilter = p.ContIDFilter.Clone()
	n.RetFilter = p.RetFilter.Clone()
	n.DataFilter = p.DataFilter.Clone()
	n.ScopeFilter = p.ScopeFilter.Clone()
	n.ProcessTreeFilter = p.ProcessTreeFilter.Clone()
	n.BinaryFilter = p.BinaryFilter.Clone()
	n.Follow = p.Follow

	return n
}
