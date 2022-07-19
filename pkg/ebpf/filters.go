package ebpf

import (
	"fmt"
	"net"
	"strings"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
)

type Filter struct {
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
	NetFilter         *IfaceFilter
}

type IfaceFilter struct {
	InterfacesToTrace []string
}

func (filter *IfaceFilter) Parse(operatorAndValues string) error {
	return ParseIface(operatorAndValues, &filter.InterfacesToTrace)
}

func ParseIface(operatorAndValues string, ifacesList *[]string) error {
	ifaces := strings.Split(operatorAndValues, ",")
	for _, iface := range ifaces {
		if _, err := net.InterfaceByName(iface); err != nil {
			return fmt.Errorf("invalid network interface: %s", iface)
		}
		_, err := findInList(iface, ifacesList)
		// if the interface is not already in the interface list, we want to add it
		if err != nil {
			*ifacesList = append(*ifacesList, iface)
		}
	}

	return nil
}
