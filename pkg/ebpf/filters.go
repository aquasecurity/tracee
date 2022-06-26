package ebpf

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
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
	RetFilter         *RetFilter
	ArgFilter         *ArgFilter
	ProcessTreeFilter *ProcessTreeFilter
	Follow            *filters.BoolFilter
	NetFilter         *NetIfaces
}

func IsValidFilterField(field string) bool {
	if strings.Contains(field, ".") {
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
		UIDFilter:     &filters.BPFUintFilter{UIntFilter: filters.NewUIntFilter(true)},
		PIDFilter:     &filters.BPFUintFilter{UIntFilter: filters.NewUIntFilter(true)},
		NewPidFilter:  filters.NewBoolFilter(),
		MntNSFilter:   &filters.BPFUintFilter{UIntFilter: filters.NewUIntFilter(false)},
		PidNSFilter:   &filters.BPFUintFilter{UIntFilter: filters.NewUIntFilter(false)},
		UTSFilter:     &filters.BPFStringFilter{StringFilter: filters.NewStringFilter()},
		CommFilter:    &filters.BPFStringFilter{StringFilter: filters.NewStringFilter()},
		ContFilter:    filters.NewBoolFilter(),
		NewContFilter: filters.NewBoolFilter(),
		ContIDFilter:  &filters.ContainersFilter{StringFilter: filters.NewStringFilter()},
		RetFilter: &RetFilter{
			Filters: make(map[events.ID]*filters.IntFilter),
		},
		ArgFilter: &ArgFilter{
			Filters: make(map[events.ID]map[string]*filters.StringFilter),
		},
		ProcessTreeFilter: &ProcessTreeFilter{
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

type RetFilter struct {
	Filters map[events.ID]*filters.IntFilter
	enabled bool
}

func (filter *RetFilter) Enable() {
	filter.enabled = true
	for _, f := range filter.Filters {
		f.Enable()
	}
}

func (filter *RetFilter) Disable() {
	filter.enabled = false
	for _, f := range filter.Filters {
		f.Disable()
	}
}

func (filter *RetFilter) Enabled() bool {
	return filter.enabled
}

func (filter *RetFilter) Filter(eventID events.ID, retval int64) bool {
	if !filter.enabled {
		return true
	}
	if filter, ok := filter.Filters[eventID]; ok {
		if !filter.Filter(retval) {
			return false
		}
	}
	return true
}

func (filter *RetFilter) Add(filterReq protocol.Filter) error {
	field := filterReq.Field
	parts := strings.Split(field, ".")
	if len(parts) != 2 {
		return fmt.Errorf("invalid retval filter format: %s", field)
	}
	eventName := parts[0]

	id, ok := events.Definitions.NamesToIDs()[eventName]
	if !ok {
		return fmt.Errorf("invalid retval filter event name: %s", eventName)
	}
	eventFilter := filter.Filters[id]
	if eventFilter == nil {
		eventFilter = filters.NewIntFilter(false)
	}

	err := eventFilter.Add(filterReq)
	if err != nil {
		return fmt.Errorf("failed to set ret filter: %s", err)
	}
	return nil
}

type ArgFilter struct {
	Filters map[events.ID]map[string]*filters.StringFilter // key to the first map is event id, and to the second map the argument name
	enabled bool
}

func (filter *ArgFilter) Enable() {
	filter.enabled = true
	for _, filterMap := range filter.Filters {
		for _, f := range filterMap {
			f.Enable()
		}
	}
}

func (filter *ArgFilter) Disable() {
	filter.enabled = false
	for _, filterMap := range filter.Filters {
		for _, f := range filterMap {
			f.Disable()
		}
	}
}

func (filter *ArgFilter) Enabled() bool {
	return filter.enabled
}

func (filter *ArgFilter) Filter(eventID events.ID, args []trace.Argument) bool {
	if !filter.enabled {
		return true
	}
	for argName, filter := range filter.Filters[eventID] {
		var argVal interface{}
		ok := false
		for _, arg := range args {
			if arg.Name == argName {
				argVal = arg.Value
				ok = true
				break
			}
		}
		if !ok {
			continue
		}
		// TODO: use type assertion instead of string conversion
		argValStr := fmt.Sprint(argVal)
		if !filter.Filter(argValStr) {
			return false
		}
	}
	return true
}

func (filter *ArgFilter) Add(filterReq protocol.Filter) error {
	// Event argument filter has the following format: "event.argname=argval"
	// filterName have the format event.argname, and operatorAndValues have the format "=argval"

	field := filterReq.Field
	parts := strings.Split(field, ".")
	if len(parts) != 2 {
		return fmt.Errorf("invalid format for arg filter: %s", field)
	}
	eventName := parts[0]
	argName := parts[1]

	id, ok := events.Definitions.NamesToIDs()[eventName]
	if !ok {
		return fmt.Errorf("invalid argument filter event name: %s", eventName)
	}

	eventDefinition := events.Definitions.Get(id)
	eventParams := eventDefinition.Params

	// check if argument name exists for this event
	argFound := false
	for i := range eventParams {
		if eventParams[i].Name == argName {
			argFound = true
			break
		}
	}

	if !argFound {
		return fmt.Errorf("invalid argument filter argument name: %s", argName)
	}

	// Treat operatorAndValues as a string filter to avoid code duplication
	strFilter := filters.NewStringFilter()
	strFilter.Add(filterReq)

	if _, ok := filter.Filters[id]; !ok {
		filter.Filters[id] = make(map[string]*filters.StringFilter)
	}

	if _, ok := filter.Filters[id][argName]; !ok {
		filter.Filters[id][argName] = strFilter
	}

	return nil
}

type ProcessTreeFilter struct {
	PIDs    map[uint32]bool // PIDs is a map where k=pid and v represents whether it and its descendents should be traced or not
	Enabled bool
}

func (filter *ProcessTreeFilter) Add(filterReq protocol.Filter) error {
	filter.Enabled = true

	for _, value := range filterReq.Value {
		pid, err := strconv.ParseUint(fmt.Sprint(value), 10, 32)
		if err != nil {
			return fmt.Errorf("invalid PID given to filter: %s", value)
		}
		switch filterReq.Operator {
		case protocol.Equal:
			filter.PIDs[uint32(pid)] = true
		case protocol.NotEqual:
			filter.PIDs[uint32(pid)] = false
		default:
			return fmt.Errorf("invalid operator given to tree filter %s", filterReq.Operator.String())
		}
	}

	return nil
}

func (filter *ProcessTreeFilter) InitBpf(bpfModule *bpf.Module) error {
	if !filter.Enabled {
		return nil
	}

	processTreeBPFMap, err := bpfModule.GetMap("process_tree_map")
	if err != nil {
		return fmt.Errorf("could not find bpf process_tree_map: %v", err)
	}

	procDir, err := os.Open("/proc")
	if err != nil {
		return fmt.Errorf("could not open proc dir: %v", err)
	}
	defer procDir.Close()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("could not read proc dir: %v", err)
	}

	// Iterate over each pid
	for _, entry := range entries {
		pid, err := strconv.ParseUint(entry, 10, 32)
		if err != nil {
			continue
		}
		var fn func(uint32)
		fn = func(curPid uint32) {
			stat, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/stat", curPid))
			if err != nil {
				return
			}
			// see https://man7.org/linux/man-pages/man5/proc.5.html for how to read /proc/pid/stat
			splitStat := bytes.SplitN(stat, []byte{' '}, 5)
			if len(splitStat) != 5 {
				return
			}
			ppid, err := strconv.Atoi(string(splitStat[3]))
			if err != nil {
				return
			}
			if ppid == 1 {
				return
			}

			if shouldBeTraced, ok := filter.PIDs[uint32(ppid)]; ok {
				trace := boolToUInt32(shouldBeTraced)
				processTreeBPFMap.Update(unsafe.Pointer(&pid), unsafe.Pointer(&trace))
				return
			}
			fn(uint32(ppid))
		}
		fn(uint32(pid))
	}

	for pid, shouldBeTraced := range filter.PIDs {
		trace := boolToUInt32(shouldBeTraced)
		processTreeBPFMap.Update(unsafe.Pointer(&pid), unsafe.Pointer(&trace))
	}

	return nil
}

func (filter *ProcessTreeFilter) FilterOut() bool {
	// Determine the default filter for PIDs that aren't specified with a proc tree filter
	// - If one or more '=' filters, default is '!='
	// - If one or more '!=' filters, default is '='
	// - If a mix of filters, the default is '='
	var filterIn = true
	for _, v := range filter.PIDs {
		filterIn = filterIn && v
	}
	return !filterIn
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
