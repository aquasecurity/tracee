package ebpf

import (
	"fmt"
	"net"
	"strings"

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
	BinaryFilter      *filters.BPFStringFilter
	Follow            bool
	NetFilter         *NetIfaces
}

type NetIfaces struct {
	Ifaces []string
}

func (filter *NetIfaces) Parse(operatorAndValues string) error {
	ifaces := strings.Split(operatorAndValues, ",")
	filter.Ifaces = ifaces
	for _, iface := range ifaces {
		if _, err := net.InterfaceByName(iface); err != nil {
			return fmt.Errorf("invalid network interface: %s", iface)
		}
		_, found := filter.Find(iface)
		// if the interface is not already in the interface list, we want to add it
		if !found {
			filter.Ifaces = append(filter.Ifaces, iface)
		}
	}

	return nil
}

func (ifaces *NetIfaces) Find(iface string) (int, bool) {
	for idx, currIface := range ifaces.Ifaces {
		if currIface == iface {
			return idx, true
		}
	}

	return -1, false
}

func (ifaces *NetIfaces) Interfaces() []string {
	if ifaces.Ifaces == nil {
		ifaces.Ifaces = []string{}
	}
	return ifaces.Ifaces
}
