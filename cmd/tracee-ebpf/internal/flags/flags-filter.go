package flags

import (
	"fmt"
	"strings"

	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events"
)

// MaxBpfStrFilterSize value should match MAX_STR_FILTER_SIZE defined in BPF code
const MaxBpfStrFilterSize = 16

func FilterHelp() string {
	return `Select which events to trace by defining trace expressions that operate on events or process metadata.
Only events that match all trace expressions will be traced (trace flags are ANDed).
The following types of expressions are supported:

Numerical expressions which compare numbers and allow the following operators: '=', '!=', '<', '>'.
Available numerical expressions: uid, pid, mntns, pidns.

String expressions which compares text and allow the following operators: '=', '!='.
Available string expressions: event, set, uts, comm, container.

Boolean expressions that check if a boolean is true and allow the following operator: '!'.
Available boolean expressions: container.

Event arguments can be accessed using 'event_name.event_arg' and provide a way to filter an event by its arguments.
Event arguments allow the following operators: '=', '!='.
Strings can be compared as a prefix if ending with '*' or as suffix if starting with '*'.

Event return value can be accessed using 'event_name.retval' and provide a way to filter an event by its return value.
Event return value expression has the same syntax as a numerical expression.

Non-boolean expressions can compare a field to multiple values separated by ','.
Multiple values are ORed if used with equals operator '=', but are ANDed if used with any other operator.

The field 'container' and 'pid' also support the special value 'new' which selects new containers or pids, respectively.

The field 'set' selects a set of events to trace according to predefined sets, which can be listed by using the 'list' flag.

The special 'follow' expression declares that not only processes that match the criteria will be traced, but also their descendants.

The field 'net' specifies which interfaces to monitor when tracing network events.
Notice that the 'net' field is mandatory when tracing network events.

Examples:
  --trace pid=new                                              | only trace events from new processes
  --trace pid=510,1709                                         | only trace events from pid 510 or pid 1709
  --trace p=510 --trace p=1709                                 | only trace events from pid 510 or pid 1709 (same as above)
  --trace container=new                                        | only trace events from newly created containers
  --trace container=ab356bc4dd554                              | only trace events from container id ab356bc4dd554
  --trace container                                            | only trace events from containers
  --trace c                                                    | only trace events from containers (same as above)
  --trace '!container'                                         | only trace events from the host
  --trace uid=0                                                | only trace events from uid 0
  --trace mntns=4026531840                                     | only trace events from mntns id 4026531840
  --trace pidns!=4026531836                                    | only trace events from pidns id not equal to 4026531840
  --trace tree=476165                                          | only trace events that descend from the process with pid 476165
  --trace tree!=5023                                           | only trace events if they do not descend from the process with pid 5023
  --trace tree=3213,5200 --trace tree!=3215                    | only trace events if they descend from 3213 or 5200, but not 3215
  --trace 'uid>0'                                              | only trace events from uids greater than 0
  --trace 'pid>0' --trace 'pid<1000'                           | only trace events from pids between 0 and 1000
  --trace 'u>0' --trace u!=1000                                | only trace events from uids greater than 0 but not 1000
  --trace event=execve,open                                    | only trace execve and open events
  --trace event=open*                                          | only trace events prefixed by "open"
  --trace event!=open*,dup*                                    | don't trace events prefixed by "open" or "dup"
  --trace set=fs                                               | trace all file-system related events
  --trace s=fs --trace e!=open,openat                          | trace all file-system related events, but not open(at)
  --trace uts!=ab356bc4dd554                                   | don't trace events from uts name ab356bc4dd554
  --trace comm=ls                                              | only trace events from ls command
  --trace close.fd=5                                           | only trace 'close' events that have 'fd' equals 5
  --trace openat.pathname=/tmp*                                | only trace 'openat' events that have 'pathname' prefixed by "/tmp"
  --trace openat.pathname!=/tmp/1,/bin/ls                      | don't trace 'openat' events that have 'pathname' equals /tmp/1 or /bin/ls
  --trace comm=bash --trace follow                             | trace all events that originated from bash or from one of the processes spawned by bash
  --trace net=docker0 			                       | trace the net events over docker0 interface


Note: some of the above operators have special meanings in different shells.
To 'escape' those operators, please use single quotes, e.g.: 'uid>0'
`
}

func PrepareFilter(filters []string) (tracee.Filter, error) {
	filter := tracee.Filter{
		UIDFilter: &tracee.UintFilter{
			Equal:    []uint64{},
			NotEqual: []uint64{},
			Less:     tracee.LessNotSetUint,
			Greater:  tracee.GreaterNotSetUint,
			Is32Bit:  true,
		},
		PIDFilter: &tracee.UintFilter{
			Equal:    []uint64{},
			NotEqual: []uint64{},
			Less:     tracee.LessNotSetUint,
			Greater:  tracee.GreaterNotSetUint,
			Is32Bit:  true,
		},
		NewPidFilter: &tracee.BoolFilter{},
		MntNSFilter: &tracee.UintFilter{
			Equal:    []uint64{},
			NotEqual: []uint64{},
			Less:     tracee.LessNotSetUint,
			Greater:  tracee.GreaterNotSetUint,
		},
		PidNSFilter: &tracee.UintFilter{
			Equal:    []uint64{},
			NotEqual: []uint64{},
			Less:     tracee.LessNotSetUint,
			Greater:  tracee.GreaterNotSetUint,
		},
		UTSFilter: &tracee.StringFilter{
			Equal:    []string{},
			NotEqual: []string{},
			Size:     MaxBpfStrFilterSize,
		},
		CommFilter: &tracee.StringFilter{
			Equal:    []string{},
			NotEqual: []string{},
			Size:     MaxBpfStrFilterSize,
		},
		ContFilter:    &tracee.BoolFilter{},
		NewContFilter: &tracee.BoolFilter{},
		ContIDFilter: &tracee.ContIDFilter{
			Equal:    []string{},
			NotEqual: []string{},
		},
		RetFilter: &tracee.RetFilter{
			Filters: make(map[events.ID]tracee.IntFilter),
		},
		ArgFilter: &tracee.ArgFilter{
			Filters: make(map[events.ID]map[string]tracee.ArgFilterVal),
		},
		ProcessTreeFilter: &tracee.ProcessTreeFilter{
			PIDs: make(map[uint32]bool),
		},
		EventsToTrace: []events.ID{},
		NetFilter: &tracee.IfaceFilter{
			InterfacesToTrace: []string{},
		},
	}

	eventFilter := &tracee.StringFilter{Equal: []string{}, NotEqual: []string{}}
	setFilter := &tracee.StringFilter{Equal: []string{}, NotEqual: []string{}}

	eventsNameToID := events.Definitions.NamesToIDs()
	// remove internal events since they shouldn't be accesible by users
	for event, id := range eventsNameToID {
		if events.Definitions.Get(id).Internal {
			delete(eventsNameToID, event)
		}
	}

	for _, f := range filters {
		filterName := f
		operatorAndValues := ""
		operatorIndex := strings.IndexAny(f, "=!<>")
		if operatorIndex > 0 {
			filterName = f[0:operatorIndex]
			operatorAndValues = f[operatorIndex:]
		}

		if strings.Contains(f, ".retval") {
			err := filter.RetFilter.Parse(filterName, operatorAndValues, eventsNameToID)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if strings.Contains(f, ".") {
			err := filter.ArgFilter.Parse(filterName, operatorAndValues, eventsNameToID)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		// The filters which are more common (container, event, pid, set, uid) can be given using a prefix of them.
		// Other filters should be given using their full name.
		// To avoid collisions between filters that share the same prefix, put the filters which should have an exact match first!
		if filterName == "comm" {
			err := filter.CommFilter.Parse(operatorAndValues)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if strings.HasPrefix("container", f) || (strings.HasPrefix("!container", f) && len(f) > 1) {
			err := filter.ContFilter.Parse(f)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if strings.HasPrefix("container", filterName) {
			if operatorAndValues == "=new" {
				filter.NewContFilter.Enabled = true
				filter.NewContFilter.Value = true
				continue
			}
			if operatorAndValues == "!=new" {
				filter.ContFilter.Enabled = true
				filter.ContFilter.Value = true
				filter.NewContFilter.Enabled = true
				filter.NewContFilter.Value = false
				continue
			}
			err := filter.ContIDFilter.Parse(operatorAndValues)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if strings.HasPrefix("event", filterName) {
			err := eventFilter.Parse(operatorAndValues)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if strings.HasPrefix(filterName, "net") {
			err := filter.NetFilter.Parse(strings.TrimPrefix(operatorAndValues, "="))
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if filterName == "mntns" {
			err := filter.MntNSFilter.Parse(operatorAndValues)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if filterName == "pidns" {
			err := filter.PidNSFilter.Parse(operatorAndValues)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if filterName == "tree" {
			err := filter.ProcessTreeFilter.Parse(operatorAndValues)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if strings.HasPrefix("pid", filterName) {
			if operatorAndValues == "=new" {
				filter.NewPidFilter.Enabled = true
				filter.NewPidFilter.Value = true
				continue
			}
			if operatorAndValues == "!=new" {
				filter.NewPidFilter.Enabled = true
				filter.NewPidFilter.Value = false
				continue
			}
			err := filter.PIDFilter.Parse(operatorAndValues)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if strings.HasPrefix("set", filterName) {
			err := setFilter.Parse(operatorAndValues)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if filterName == "uts" {
			err := filter.UTSFilter.Parse(operatorAndValues)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if strings.HasPrefix("uid", filterName) {
			err := filter.UIDFilter.Parse(operatorAndValues)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if strings.HasPrefix("follow", f) {
			filter.Follow = true
			continue
		}
		return tracee.Filter{}, fmt.Errorf("invalid filter option specified, use '--trace help' for more info")
	}

	var err error
	filter.EventsToTrace, err = prepareEventsToTrace(eventFilter, setFilter, eventsNameToID)
	if err != nil {
		return tracee.Filter{}, err
	}

	return filter, nil
}

func prepareEventsToTrace(eventFilter *tracee.StringFilter, setFilter *tracee.StringFilter, eventsNameToID map[string]events.ID) ([]events.ID, error) {
	eventFilter.Enabled = true
	eventsToTrace := eventFilter.Equal
	excludeEvents := eventFilter.NotEqual
	setsToTrace := setFilter.Equal

	var res []events.ID
	setsToEvents := make(map[string][]events.ID)
	isExcluded := make(map[events.ID]bool)
	for id, event := range events.Definitions.Events() {
		for _, set := range event.Sets {
			setsToEvents[set] = append(setsToEvents[set], id)
		}
	}
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
	if len(eventsToTrace) == 0 && len(setsToTrace) == 0 {
		setsToTrace = append(setsToTrace, "default")
	}

	res = make([]events.ID, 0, events.Definitions.Length())
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
