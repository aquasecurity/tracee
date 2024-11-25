package policy

import (
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/utils"
)

type Policy struct {
	ID                int
	Name              string
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
	ProcessTreeFilter *filters.ProcessTreeFilter
	BinaryFilter      *filters.BinaryFilter
	Follow            bool
	Rules             map[events.ID]RuleData
}

type RuleData struct {
	EventID     events.ID
	ScopeFilter *filters.ScopeFilter
	DataFilter  *filters.DataFilter
	RetFilter   *filters.IntFilter[int64]
}

// Compile-time check to ensure that Policy implements the Cloner interface
var _ utils.Cloner[*Policy] = &Policy{}

func NewPolicy() *Policy {
	return &Policy{
		ID:                0,
		Name:              "",
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
		ProcessTreeFilter: filters.NewProcessTreeFilter(),
		BinaryFilter:      filters.NewBinaryFilter(),
		Follow:            false,
		Rules:             map[events.ID]RuleData{},
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
	n.ProcessTreeFilter = p.ProcessTreeFilter.Clone()
	n.BinaryFilter = p.BinaryFilter.Clone()
	n.Follow = p.Follow
	for eID, ruleData := range p.Rules {
		n.Rules[eID] = RuleData{
			EventID:     ruleData.EventID,
			ScopeFilter: ruleData.ScopeFilter.Clone(),
			DataFilter:  ruleData.DataFilter.Clone(),
			RetFilter:   ruleData.RetFilter.Clone(),
		}
	}

	return n
}
