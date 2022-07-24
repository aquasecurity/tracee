package ebpf

import (
	"fmt"
	"net"
	"strings"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/types/protocol"
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
)

type Filter struct {
	EventsToTrace     []events.ID
	UIDFilter         *filters.BPFUIntFilter
	PIDFilter         *filters.BPFUIntFilter
	NewPidFilter      *filters.BoolFilter
	MntNSFilter       *filters.BPFUIntFilter
	PidNSFilter       *filters.BPFUIntFilter
	UTSFilter         *filters.BPFStringFilter
	CommFilter        *filters.BPFStringFilter
	ContainerFilter   *filters.ContainerFilter
	NewContFilter     *filters.BoolFilter
	RetFilter         *filters.RetFilter
	ArgFilter         *filters.ArgFilter
	ProcessTreeFilter *filters.ProcessTreeFilter
	Follow            bool
	NetFilter         *NetIfaces
}

func IsValidFilterField(field string) bool {
	if strings.Contains(field, ".") {
		parts := strings.Split(field, ".")
		first := parts[0]
		if _, ok := events.Definitions.GetID(first); !ok {
			return false
		}
		return true
	}

	switch field {
	case "comm", "processName", "container", "container/new", "event", "set", "pid", "pid/new", "uts", "uid", "follow", "mntns", "pidns", "net":
		return true
	}

	return false
}

func buildFilterError(filterName string, err error) error {
	return fmt.Errorf("failed to build %s filter: %s", filterName, err)
}

func ParseProtocolFilters(filterRequests []protocol.Filter) (Filter, error) {
	// aggregate protocol.Filter by "topics" (inner filters in tracee)
	const (
		retval      = "retval"
		args        = "args"
		event       = "event"
		comm        = "comm"
		container   = "container"
		newcont     = "newcont"
		containerid = "containerid"
		set         = "set"
		pid         = "pid"
		newpid      = "newpid"
		uts         = "uts"
		uid         = "uid"
		follow      = "follow"
		mntns       = "mntns"
		pidns       = "pidns"
		net         = "net"
	)
	filterMap := map[string][]protocol.Filter{
		retval:    {},
		args:      {},
		event:     {},
		comm:      {},
		container: {},
		newcont:   {},
		set:       {},
		pid:       {},
		newpid:    {},
		uts:       {},
		follow:    {},
		mntns:     {},
		pidns:     {},
		net:       {},
	}

	for _, filterReq := range filterRequests {
		field := filterReq.Field
		if strings.HasSuffix(field, ".retval") {
			filterMap[retval] = append(filterMap[retval], filterReq)
			continue
		}

		if strings.Contains(field, ".") {
			filterMap[args] = append(filterMap[args], filterReq)
			continue
		}

		switch field {
		case "comm", "processName":
			filterMap[comm] = append(filterMap[comm], filterReq)
		case "container":
			filterMap[container] = append(filterMap[container], filterReq)
		case "container/new":
			filterMap[newcont] = append(filterMap[newcont], filterReq)
			// if new container filter is set as false we need to change to container mode
			if filterReq.Operator == protocol.NotEqual {
				filterMap[container] = append(filterMap[container], protocol.EqualFilter("container", true))
			}
		case "event":
			filterMap[event] = append(filterMap[event], filterReq)
		case "set":
			filterMap[set] = append(filterMap[set], filterReq)
		case "pid":
			filterMap[pid] = append(filterMap[pid], filterReq)
		case "pid/new":
			filterMap[newpid] = append(filterMap[newpid], filterReq)
		case "uts":
			filterMap[uts] = append(filterMap[uts], filterReq)
		case "uid":
			filterMap[uid] = append(filterMap[uid], filterReq)
		case "follow":
			filterMap[follow] = append(filterMap[follow], filterReq)
		case "mntns":
			filterMap[mntns] = append(filterMap[mntns], filterReq)
		case "pidns":
			filterMap[pidns] = append(filterMap[pidns], filterReq)
		case "net":
			filterMap[net] = append(filterMap[net], filterReq)
		}

	}

	// setup eventsToTrace
	eventsNameToID := events.Definitions.NamesToIDs()
	// remove internal events since they shouldn't be accesible by users
	for event, id := range eventsNameToID {
		if events.Definitions.Get(id).Internal {
			delete(eventsNameToID, event)
		}
	}

	eventFilter, err := filters.NewStringFilter(filterMap[event]...)
	if err != nil {
		return Filter{}, buildFilterError(event, err)
	}
	setFilter, err := filters.NewStringFilter(filterMap[set]...)
	if err != nil {
		return Filter{}, buildFilterError(set, err)
	}

	// both filters must be enabled for prepare logic to work
	eventFilter.Enable()
	setFilter.Enable()
	eventsToTrace, err := prepareEventsToTrace(eventFilter, setFilter, eventsNameToID)

	if err != nil {
		return Filter{}, err
	}

	// setup the other filters
	uidFilter, err := filters.NewBPFUInt32Filter(UIDFilterMap, filterMap[uid]...)
	if err != nil {
		return Filter{}, buildFilterError(uid, err)
	}
	pidFilter, err := filters.NewBPFUInt32Filter(PIDFilterMap, filterMap[pid]...)
	if err != nil {
		return Filter{}, buildFilterError(pid, err)
	}
	newPidFilter, err := filters.NewBoolFilter(filterMap[newpid]...)
	if err != nil {
		return Filter{}, buildFilterError(newpid, err)
	}
	mntnsFilter, err := filters.NewBPFUInt32Filter(MntNSFilterMap, filterMap[mntns]...)
	if err != nil {
		return Filter{}, buildFilterError(mntns, err)
	}
	pidnsFilter, err := filters.NewBPFUInt32Filter(PidNSFilterMap, filterMap[pidns]...)
	if err != nil {
		return Filter{}, buildFilterError(pidns, err)
	}
	utsFilter, err := filters.NewBPFStringFilter(UTSFilterMap, filterMap[uts]...)
	if err != nil {
		return Filter{}, buildFilterError(uts, err)
	}
	commFilter, err := filters.NewBPFStringFilter(CommFilterMap, filterMap[comm]...)
	if err != nil {
		return Filter{}, buildFilterError(comm, err)
	}
	newContFilter, err := filters.NewBoolFilter(filterMap[newcont]...)
	if err != nil {
		return Filter{}, buildFilterError(newcont, err)
	}
	containerFilter, err := filters.NewContainerFilter(CgroupIdFilterMap, filterMap[container]...)
	if err != nil {
		return Filter{}, buildFilterError(containerid, err)
	}
	retFilter, err := filters.NewRetFilter(filterMap[retval]...)
	if err != nil {
		return Filter{}, buildFilterError(retval, err)
	}
	argFilter, err := filters.NewArgFilter(filterMap[args]...)
	if err != nil {
		return Filter{}, buildFilterError(args, err)
	}
	followFilter, err := filters.NewBoolFilter(filterMap[follow]...)
	if err != nil {
		return Filter{}, buildFilterError(follow, err)
	}
	netFilter, err := NewNetIfaces(filterMap[net]...)
	if err != nil {
		return Filter{}, buildFilterError(net, err)
	}

	filter := Filter{
		EventsToTrace:     eventsToTrace,
		UIDFilter:         uidFilter,
		PIDFilter:         pidFilter,
		NewPidFilter:      newPidFilter,
		MntNSFilter:       mntnsFilter,
		PidNSFilter:       pidnsFilter,
		UTSFilter:         utsFilter,
		CommFilter:        commFilter,
		ContainerFilter:   containerFilter,
		NewContFilter:     newContFilter,
		RetFilter:         retFilter,
		ArgFilter:         argFilter,
		ProcessTreeFilter: filters.NewProcessTreeFilter(ProcessTreeFilterMap),
		Follow:            followFilter.Value(),
		NetFilter:         netFilter,
	}

	return filter, nil
}

func prepareEventsToTrace(eventFilter *filters.StringFilter, setFilter *filters.StringFilter, eventsNameToID map[string]events.ID) ([]events.ID, error) {
	res := []events.ID{}
	setsToTrace := []string{}

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
		for _, id := range setEvents {
			if !isExcluded[id] {
				res = append(res, id)
			}
		}
	}
	return res, nil
}

type NetIfaces struct {
	Ifaces []string
}

func NewNetIfaces(filters ...protocol.Filter) (*NetIfaces, error) {
	netIfaces := &NetIfaces{
		Ifaces: []string{},
	}

	for _, f := range filters {
		err := netIfaces.parse(f)
		if err != nil {
			return netIfaces, err
		}
	}

	return netIfaces, nil
}

func (ifaces *NetIfaces) parse(filterReq protocol.Filter) error {
	arr := filterReq.Value
	for i := 0; i < len(arr); i++ {
		val := arr[i]
		valStr, ok := val.(string)
		if !ok {
			return fmt.Errorf("failed to add to filter: invalid value")
		}
		err := ifaces.add(valStr, filters.Operator(filterReq.Operator))
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

func (filter *NetIfaces) Parse(operatorAndValues string) error {
	ifaceList := strings.Split(operatorAndValues, ",")
	for _, iface := range ifaceList {
		err := filter.add(iface, filters.Equal)
		if err != nil {
			return err
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
