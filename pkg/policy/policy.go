package policy

import (
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
)

const (
	UIDFilterMap         = "uid_filter"
	PIDFilterMap         = "pid_filter"
	MntNSFilterMap       = "mnt_ns_filter"
	PidNSFilterMap       = "pid_ns_filter"
	UTSFilterMap         = "uts_ns_filter"
	CommFilterMap        = "comm_filter"
	ProcessTreeFilterMap = "process_tree_map"
	CgroupIdFilterMap    = "cgroup_id_filter"
	ContIdFilter         = "cont_id_filter"
	BinaryFilterMap      = "binary_filter"
	ProcInfoMap          = "proc_info_map"
)

type Policy struct {
	ID                int
	Name              string
	EventsToTrace     map[events.ID]string
	UIDFilter         *filters.BPFUIntFilter[uint32]
	PIDFilter         *filters.BPFUIntFilter[uint32]
	NewPidFilter      *filters.BoolFilter
	MntNSFilter       *filters.BPFUIntFilter[uint64]
	PidNSFilter       *filters.BPFUIntFilter[uint64]
	UTSFilter         *filters.BPFStringFilter
	CommFilter        *filters.BPFStringFilter
	ContFilter        *filters.BoolFilter
	NewContFilter     *filters.BoolFilter
	ContIDFilter      *filters.ContainerFilter
	RetFilter         *filters.RetFilter
	ArgFilter         *filters.ArgFilter
	ContextFilter     *filters.ContextFilter
	ProcessTreeFilter *filters.ProcessTreeFilter
	BinaryFilter      *filters.BPFBinaryFilter
	Follow            bool
}

func NewPolicy() *Policy {
	return &Policy{
		ID:                0,
		Name:              "",
		EventsToTrace:     map[events.ID]string{},
		UIDFilter:         filters.NewBPFUInt32Filter(UIDFilterMap),
		PIDFilter:         filters.NewBPFUInt32Filter(PIDFilterMap),
		NewPidFilter:      filters.NewBoolFilter(),
		MntNSFilter:       filters.NewBPFUIntFilter(MntNSFilterMap),
		PidNSFilter:       filters.NewBPFUIntFilter(PidNSFilterMap),
		UTSFilter:         filters.NewBPFStringFilter(UTSFilterMap),
		CommFilter:        filters.NewBPFStringFilter(CommFilterMap),
		ContFilter:        filters.NewBoolFilter(),
		NewContFilter:     filters.NewBoolFilter(),
		ContIDFilter:      filters.NewContainerFilter(CgroupIdFilterMap),
		RetFilter:         filters.NewRetFilter(),
		ArgFilter:         filters.NewArgFilter(),
		ContextFilter:     filters.NewContextFilter(),
		ProcessTreeFilter: filters.NewProcessTreeFilter(ProcessTreeFilterMap),
		BinaryFilter:      filters.NewBPFBinaryFilter(BinaryFilterMap, ProcInfoMap),
		Follow:            false,
	}
}

const MaxPolicies = 64

func isIDInRange(id int) bool {
	return id >= 0 && id < MaxPolicies
}
