package policy

import (
	"golang.org/x/exp/maps"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/utils"
)

type PolicyBuilder interface {
	utils.Cloner

	GetID() int
	GetName() string
	SetEventToTrace(id events.ID, name string)
	IsEventToTrace(id events.ID) bool
	ContainerFilterEnabled() bool
	UIDFilter() *filters.UIntFilter[uint32]
	PIDFilter() *filters.UIntFilter[uint32]
	NewPidFilter() *filters.BoolFilter
	MntNSFilter() *filters.UIntFilter[uint64]
	PidNSFilter() *filters.UIntFilter[uint64]
	UTSFilter() *filters.StringFilter
	CommFilter() *filters.StringFilter
	ContFilter() *filters.BoolFilter
	NewContFilter() *filters.BoolFilter
	ContIDFilter() *filters.StringFilter
	RetFilter() *filters.RetFilter
	ArgFilter() *filters.ArgFilter
	ContextFilter() *filters.ContextFilter
	ProcessTreeFilter() *filters.ProcessTreeFilter
	BinaryFilter() *filters.BinaryFilter
	SetFollow(bool)
	Follow() bool
}

type Policy interface {
	utils.Cloner

	GetID() int
	GetName() string
	IsEventToTrace(id events.ID) bool
	ContainerFilterEnabled() bool
	UIDFilter() *filters.UIntFilter[uint32]
	PIDFilter() *filters.UIntFilter[uint32]
	NewPidFilter() *filters.BoolFilter
	MntNSFilter() *filters.UIntFilter[uint64]
	PidNSFilter() *filters.UIntFilter[uint64]
	UTSFilter() *filters.StringFilter
	CommFilter() *filters.StringFilter
	ContFilter() *filters.BoolFilter
	NewContFilter() *filters.BoolFilter
	ContIDFilter() *filters.StringFilter
	RetFilter() *filters.RetFilter
	ArgFilter() *filters.ArgFilter
	ContextFilter() *filters.ContextFilter
	ProcessTreeFilter() *filters.ProcessTreeFilter
	BinaryFilter() *filters.BinaryFilter
	Follow() bool
	CreateEventsToTraceIterator() utils.Iterator[events.ID]
}

type policy struct {
	id            int
	name          string
	eventsToTrace map[events.ID]string

	uidFilter         *filters.UIntFilter[uint32]
	pidFilter         *filters.UIntFilter[uint32]
	newPidFilter      *filters.BoolFilter
	mntNSFilter       *filters.UIntFilter[uint64]
	pidNSFilter       *filters.UIntFilter[uint64]
	utsFilter         *filters.StringFilter
	commFilter        *filters.StringFilter
	contFilter        *filters.BoolFilter
	newContFilter     *filters.BoolFilter
	contIDFilter      *filters.StringFilter
	retFilter         *filters.RetFilter
	argFilter         *filters.ArgFilter
	contextFilter     *filters.ContextFilter
	processTreeFilter *filters.ProcessTreeFilter
	binaryFilter      *filters.BinaryFilter
	follow            bool
}

func NewPolicyBuilder(id int, name string) PolicyBuilder {
	return &policy{
		id:                id,
		name:              name,
		eventsToTrace:     map[events.ID]string{},
		uidFilter:         filters.NewUInt32Filter(),
		pidFilter:         filters.NewUInt32Filter(),
		newPidFilter:      filters.NewBoolFilter(),
		mntNSFilter:       filters.NewUIntFilter(),
		pidNSFilter:       filters.NewUIntFilter(),
		utsFilter:         filters.NewStringFilter(),
		commFilter:        filters.NewStringFilter(),
		contFilter:        filters.NewBoolFilter(),
		newContFilter:     filters.NewBoolFilter(),
		contIDFilter:      filters.NewStringFilter(),
		retFilter:         filters.NewRetFilter(),
		argFilter:         filters.NewArgFilter(),
		contextFilter:     filters.NewContextFilter(),
		processTreeFilter: filters.NewProcessTreeFilter(),
		binaryFilter:      filters.NewBinaryFilter(),
		follow:            false,
	}
}

func (p *policy) SetEventToTrace(id events.ID, name string) {
	p.eventsToTrace[id] = name
}

func (p *policy) GetID() int {
	return p.id
}

func (p *policy) GetName() string {
	return p.name
}

func (p *policy) IsEventToTrace(id events.ID) bool {
	_, ok := p.eventsToTrace[id]
	return ok
}

// ContainerFilterEnabled returns true when the policy has at least one container filter type enabled
func (p *policy) ContainerFilterEnabled() bool {
	return (p.ContFilter().Enabled() && p.ContFilter().Value()) ||
		(p.NewContFilter().Enabled() && p.NewContFilter().Value()) ||
		p.ContIDFilter().Enabled()
}

func (p *policy) CreateEventsToTraceIterator() utils.Iterator[events.ID] {
	it := &EventsToTraceIterator{
		eventsToTrace: make([]events.ID, 0, len(p.eventsToTrace)),
		index:         0,
	}

	for k := range p.eventsToTrace {
		it.eventsToTrace = append(it.eventsToTrace, k)
	}

	return it
}

func (p *policy) UIDFilter() *filters.UIntFilter[uint32] {
	return p.uidFilter
}

func (p *policy) PIDFilter() *filters.UIntFilter[uint32] {
	return p.pidFilter
}

func (p *policy) NewPidFilter() *filters.BoolFilter {
	return p.newPidFilter
}

func (p *policy) MntNSFilter() *filters.UIntFilter[uint64] {
	return p.mntNSFilter
}

func (p *policy) PidNSFilter() *filters.UIntFilter[uint64] {
	return p.pidNSFilter
}

func (p *policy) UTSFilter() *filters.StringFilter {
	return p.utsFilter
}

func (p *policy) CommFilter() *filters.StringFilter {
	return p.commFilter
}

func (p *policy) ContFilter() *filters.BoolFilter {
	return p.contFilter
}

func (p *policy) NewContFilter() *filters.BoolFilter {
	return p.newContFilter
}

func (p *policy) ContIDFilter() *filters.StringFilter {
	return p.contIDFilter
}

func (p *policy) RetFilter() *filters.RetFilter {
	return p.retFilter
}

func (p *policy) ArgFilter() *filters.ArgFilter {
	return p.argFilter
}

func (p *policy) ContextFilter() *filters.ContextFilter {
	return p.contextFilter
}

func (p *policy) ProcessTreeFilter() *filters.ProcessTreeFilter {
	return p.processTreeFilter
}

func (p *policy) BinaryFilter() *filters.BinaryFilter {
	return p.binaryFilter
}

func (p *policy) SetFollow(follow bool) {
	p.follow = follow
}

func (p *policy) Follow() bool {
	return p.follow
}

// EventsToTraceIterator is an iterator for the events to trace
type EventsToTraceIterator struct {
	eventsToTrace []events.ID
	index         int
}

func (i *EventsToTraceIterator) HasNext() bool {
	return i.index < len(i.eventsToTrace)
}

func (i *EventsToTraceIterator) GetNext() events.ID {
	if i.HasNext() {
		e := i.eventsToTrace[i.index]
		i.index++
		return e
	}

	return events.Undefined
}

func (p *policy) Clone() utils.Cloner {
	if p == nil {
		return nil
	}

	n := NewPolicyBuilder(p.id, p.name).(*policy)

	maps.Copy(n.eventsToTrace, p.eventsToTrace)
	n.uidFilter = p.UIDFilter().Clone().(*filters.UIntFilter[uint32])
	n.pidFilter = p.PIDFilter().Clone().(*filters.UIntFilter[uint32])
	n.newPidFilter = p.NewPidFilter().Clone().(*filters.BoolFilter)
	n.mntNSFilter = p.MntNSFilter().Clone().(*filters.UIntFilter[uint64])
	n.pidNSFilter = p.PidNSFilter().Clone().(*filters.UIntFilter[uint64])
	n.utsFilter = p.UTSFilter().Clone().(*filters.StringFilter)
	n.commFilter = p.CommFilter().Clone().(*filters.StringFilter)
	n.contFilter = p.ContFilter().Clone().(*filters.BoolFilter)
	n.newContFilter = p.NewContFilter().Clone().(*filters.BoolFilter)
	n.contIDFilter = p.ContIDFilter().Clone().(*filters.StringFilter)
	n.retFilter = p.RetFilter().Clone().(*filters.RetFilter)
	n.argFilter = p.ArgFilter().Clone().(*filters.ArgFilter)
	n.contextFilter = p.ContextFilter().Clone().(*filters.ContextFilter)
	n.processTreeFilter = p.ProcessTreeFilter().Clone().(*filters.ProcessTreeFilter)
	n.binaryFilter = p.BinaryFilter().Clone().(*filters.BinaryFilter)
	n.follow = p.follow

	return n
}
