package ebpf

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
)

type Filter struct {
	EventsToTrace     []events.ID
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
