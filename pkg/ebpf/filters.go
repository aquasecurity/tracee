package ebpf

import (
	"fmt"
	"net"
	"strings"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
)

const MaxFilterScopes = 32

type FilterScope struct {
	ID                uint32
	EventsToTrace     []events.ID
	UIDFilter         *filters.UIntFilter
	PIDFilter         *filters.UIntFilter
	NewPidFilter      *filters.BoolFilter
	MntNSFilter       *filters.UIntFilter
	PidNSFilter       *filters.UIntFilter
	UTSFilter         *filters.StringFilter
	CommFilter        *filters.StringFilter
	ContFilter        *filters.BoolFilter
	NewContFilter     *filters.BoolFilter
	ContIDFilter      *filters.ContIDFilter
	RetFilter         *filters.RetFilter
	ArgFilter         *filters.ArgFilter
	ProcessTreeFilter *filters.ProcessTreeFilter
	Follow            bool
	NetFilter         *NetIfaces
}

func (fs *FilterScope) HasContainerFilterEnabled() bool {
	return (fs.ContFilter.Enabled && fs.ContFilter.Value) ||
		(fs.NewContFilter.Enabled && fs.NewContFilter.Value) ||
		fs.ContIDFilter.Enabled
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
