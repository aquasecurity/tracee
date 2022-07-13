package ebpf

import (
	"fmt"
	"math"
	"net"
	"strings"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/types/protocol"
)

const (
	uidLess uint32 = iota
	uidGreater
	pidLess
	pidGreater
	mntNsLess
	mntNsGreater
	pidNsLess
	pidNsGreater
)

// Set default inequality values
// val<0 and val>math.MaxUint64 should never be used by the user as they give an empty set
const (
	LessNotSetUint    uint64 = 0
	GreaterNotSetUint uint64 = math.MaxUint64
	LessNotSetInt     int64  = math.MinInt64
	GreaterNotSetInt  int64  = math.MaxInt64
)

type Filter struct {
	EventsToTrace     []events.ID
	UIDFilter         *filters.BPFUintFilter
	PIDFilter         *filters.BPFUintFilter
	NewPidFilter      *filters.BoolFilter
	MntNSFilter       *filters.BPFUintFilter
	PidNSFilter       *filters.BPFUintFilter
	UTSFilter         *filters.BPFStringFilter
	CommFilter        *filters.BPFStringFilter
	ContFilter        *filters.BoolFilter
	NewContFilter     *filters.BoolFilter
	ContIDFilter      *filters.ContainersFilter
	RetFilter         *filters.RetFilter
	ArgFilter         *filters.ArgFilter
	ContextFilter     *filters.ContextFilter
	ProcessTreeFilter *filters.ProcessTreeFilter
	Follow            *filters.BoolFilter
	NetFilter         *NetIfaces
}

func IsValidFilterField(field string) bool {
	if strings.Contains(field, ".") {
		parts := strings.Split(field, ".")
		first := parts[0]
		if _, ok := events.Definitions.GetID(first); !ok && first != "container" && first != "pid" {
			return false
		}
		return true
	}

	switch field {
	case "comm", "processName", "container", "container.new", "event", "set", "pid", "pid.new", "uts", "uid", "follow", "mntns", "pidns", "net":
		return true
	}

	return false
}

func buildFilterError(filterName string, err error) error {
	return fmt.Errorf("failed to build %s filter: %s", filterName, err)
}

func ParseProtocolFilters(filterRequests []protocol.Filter) (Filter, error) {
	filter := Filter{
		UIDFilter:     &filters.BPFUintFilter{UIntFilter: filters.NewUInt32Filter()},
		PIDFilter:     &filters.BPFUintFilter{UIntFilter: filters.NewUInt32Filter()},
		NewPidFilter:  filters.NewBoolFilter(),
		MntNSFilter:   &filters.BPFUintFilter{UIntFilter: filters.NewUIntFilter()},
		PidNSFilter:   &filters.BPFUintFilter{UIntFilter: filters.NewUIntFilter()},
		UTSFilter:     &filters.BPFStringFilter{StringFilter: filters.NewStringFilter()},
		CommFilter:    &filters.BPFStringFilter{StringFilter: filters.NewStringFilter()},
		ContFilter:    filters.NewBoolFilter(),
		NewContFilter: filters.NewBoolFilter(),
		ContIDFilter:  &filters.ContainersFilter{StringFilter: filters.NewStringFilter()},
		RetFilter: &filters.RetFilter{
			Filters: make(map[events.ID]*filters.IntFilter),
		},
		ArgFilter: &filters.ArgFilter{
			Filters: make(map[events.ID]map[string]*filters.StringFilter),
		},
		ContextFilter: filters.NewContextFilter(),
		ProcessTreeFilter: &filters.ProcessTreeFilter{
			PIDs: make(map[uint32]bool),
		},
		EventsToTrace: []events.ID{},
		NetFilter:     &NetIfaces{},
		Follow:        filters.NewBoolFilter(),
	}

	eventFilter := filters.NewStringFilter()
	setFilter := filters.NewStringFilter()

	for _, filterReq := range filterRequests {
		field := filterReq.Field
		if strings.HasSuffix(field, ".retval") {
			err := filter.RetFilter.Add(filterReq)
			if err != nil {
				return Filter{}, buildFilterError("ret", err)
			}
			defer filter.RetFilter.Enable()
			continue
		}
		if strings.Contains(field, ".context") {
			err := filter.ContextFilter.Add(filterReq)
			if err != nil {
				return Filter{}, buildFilterError("context", err)
			}
			defer filter.ContextFilter.Enable()
			continue
		}

		if strings.Contains(field, ".") {
			err := filter.ArgFilter.Add(filterReq)
			if err != nil {
				return Filter{}, buildFilterError("arg", err)
			}
			defer filter.ArgFilter.Enable()
			continue
		}

		switch field {
		case "comm", "processName":
			err := filter.CommFilter.Add(filterReq)
			if err != nil {
				return Filter{}, buildFilterError("com", err)
			}
			defer filter.CommFilter.Enable()
			continue
		case "container":
			err := filter.ContFilter.Add(filterReq)
			if err != nil {
				return Filter{}, buildFilterError("container", err)
			}
			defer filter.ContFilter.Enable()

			continue
		case "container.new":
			err := filter.NewContFilter.Add(filterReq)
			if err != nil {
				return Filter{}, buildFilterError("new container", err)
			}
			defer filter.NewContFilter.Enable()

			continue
		case "event":
			err := eventFilter.Add(filterReq)
			if err != nil {
				return Filter{}, buildFilterError("event", err)
			}
			continue
		case "set":
			err := setFilter.Add(filterReq)
			if err != nil {
				return Filter{}, buildFilterError("set", err)
			}
			continue
		case "pid":
			err := filter.PIDFilter.Add(filterReq)
			if err != nil {
				return Filter{}, buildFilterError("pid", err)
			}
			defer filter.PIDFilter.Enable()
			continue
		case "pid.new":
			err := filter.NewPidFilter.Add(filterReq)
			if err != nil {
				return Filter{}, buildFilterError("new pid", err)
			}
			defer filter.NewPidFilter.Enable()
			continue
		case "uts":
			err := filter.UTSFilter.Add(filterReq)
			if err != nil {
				return Filter{}, buildFilterError("uts", err)
			}
			defer filter.UTSFilter.Enable()
			continue
		case "uid":
			err := filter.UIDFilter.Add(filterReq)
			if err != nil {
				return Filter{}, buildFilterError("uid", err)
			}
			defer filter.UIDFilter.Enable()
			continue
		case "follow":
			err := filter.Follow.Add(filterReq)
			if err != nil {
				return Filter{}, buildFilterError("follow", err)
			}
			continue
		case "mntns":
			err := filter.MntNSFilter.Add(filterReq)
			if err != nil {
				return Filter{}, buildFilterError("mntns", err)
			}
			defer filter.MntNSFilter.Enable()
			continue
		case "pidns":
			err := filter.PidNSFilter.Add(filterReq)
			if err != nil {
				return Filter{}, buildFilterError("pidns", err)
			}
			defer filter.PidNSFilter.Enable()
			continue
		case "net":
			err := filter.NetFilter.Add(filterReq)
			if err != nil {
				return Filter{}, buildFilterError("net", err)
			}
		}

	}

	eventsNameToID := events.Definitions.NamesToIDs()
	// remove internal events since they shouldn't be accesible by users
	for event, id := range eventsNameToID {
		if events.Definitions.Get(id).Internal {
			delete(eventsNameToID, event)
		}
	}

	eventsToTrace, err := prepareEventsToTrace(eventFilter, setFilter, eventsNameToID)

	if err != nil {
		return Filter{}, err
	}

	filter.EventsToTrace = eventsToTrace

	return filter, nil

}

func prepareEventsToTrace(eventFilter *filters.StringFilter, setFilter *filters.StringFilter, eventsNameToID map[string]events.ID) ([]events.ID, error) {
	res := []events.ID{}
	setsToTrace := []string{}

	setFilter.Enable()

	setsToEvents := make(map[string][]events.ID)
	for id, event := range events.Definitions.Events() {
		for _, set := range event.Sets {
			setsToEvents[set] = append(setsToEvents[set], id)
		}
	}

	for set := range setsToEvents {
		if setFilter.Filter(set) {
			setsToTrace = append(setsToTrace, set)
		}
	}

	eventsToTrace := eventFilter.Equals()
	excludeEvents := eventFilter.NotEquals()
	isExcluded := make(map[events.ID]bool)

	for _, name := range excludeEvents {
		// Handle event prefixes with wildcards
		if strings.HasSuffix(name, "*") {
			found := false
			prefix := name[:len(name)-1]
			for event, id := range eventsNameToID {
				if strings.HasPrefix(event, prefix) {
					isExcluded[id] = true
					found = true
				}
			}
			if !found {
				return nil, fmt.Errorf("invalid event to exclude: %s", name)
			}
		} else {
			id, ok := eventsNameToID[name]
			if !ok {
				return nil, fmt.Errorf("invalid event to exclude: %s", name)
			}
			isExcluded[id] = true
		}
	}

	for _, name := range eventsToTrace {
		// Handle event prefixes with wildcards
		if strings.HasSuffix(name, "*") {
			var ids []events.ID
			found := false
			prefix := name[:len(name)-1]
			for event, id := range eventsNameToID {
				if strings.HasPrefix(event, prefix) {
					ids = append(ids, id)
					found = true
				}
			}
			if !found {
				return nil, fmt.Errorf("invalid event to trace: %s", name)
			}
			res = append(res, ids...)
		} else {
			id, ok := eventsNameToID[name]
			if !ok {
				return nil, fmt.Errorf("invalid event to trace: %s", name)
			}
			res = append(res, id)
		}
	}

	if len(eventsToTrace) == 0 && len(setsToTrace) == 0 {
		setsToTrace = append(setsToTrace, "default")
	}

	for _, set := range setsToTrace {
		setEvents, ok := setsToEvents[set]
		if !ok {
			return nil, fmt.Errorf("invalid set to trace: %s", set)
		}
		res = append(res, setEvents...)
	}
	return res, nil
}

type NetIfaces struct {
	Ifaces []string
}

func (ifaces *NetIfaces) Add(filterReq protocol.Filter) error {
	arr := filterReq.Value
	vals := make([]string, len(filterReq.Value))
	for i := 0; i < len(arr); i++ {
		val := arr[i]
		valStr, ok := val.(string)
		if !ok {
			return fmt.Errorf("failed to add to filter: invalid value")
		}
		vals[i] = valStr
	}
	for _, val := range vals {
		err := ifaces.add(val, filters.Operator(filterReq.Operator))
		if err != nil {
			return fmt.Errorf("failed to add to filter: %s", err)
		}
	}
	return nil
}

func (ifaces *NetIfaces) add(val string, op filters.Operator) error {
	if op == filters.Equal {
		if _, err := net.InterfaceByName(val); err != nil {
			return fmt.Errorf("invalid network interface: %s", val)
		}
		if _, found := ifaces.Find(val); found {
			return nil
		}
		ifaces.Ifaces = append(ifaces.Ifaces, val)
		return nil
	}
	return filters.UnsupportedOperator(op)
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

//for backwards compat
func (ifaces *NetIfaces) Parse(operatorAndValues string) error {
	ifaceList := strings.Split(operatorAndValues, ",")
	for _, iface := range ifaceList {
		err := ifaces.add(iface, filters.Equal)
		if err != nil {
			return err
		}
	}

	return nil
}
