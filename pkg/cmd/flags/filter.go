package flags

import (
	"strings"

	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/policy"
)

func filterHelp() string {
	return `Select which events to trace by defining filter expressions that operate on events or process metadata.
Only events that match all filter expressions will be traced (filter flags are ANDed).
The following types of expressions are supported:

Numerical expressions which compare numbers and allow the following operators: '=', '!=', '<', '>'.
Available numerical expressions: uid, pid, mntns, pidns.
NOTE: Expressions containing '<' or '>' token must be escaped! This is also shown in the examples below.

String expressions which compares text and allow the following operators: '=', '!='.
Available string expressions: event, set, uts, comm, container, binary.

Boolean expressions that check if a boolean is true and allow the following operator: '!'.
Available boolean expressions: container.

Event arguments can be accessed using 'event_name.args.event_arg' and provide a way to filter an event by its arguments.
Event arguments allow the following operators: '=', '!='.
Strings can be compared as a prefix if ending with '*' or as suffix if starting with '*'.

Event return value can be accessed using 'event_name.retval' and provide a way to filter an event by its return value.
Event return value expression has the same syntax as a numerical expression.

Event context fields can be accessed using 'event_name.context.field', this can be used to filter an event by the non arguments
fields defined in the trace.Event struct.
Refer to the json tags in the trace.Event struct located in the types/trace package for the correct field names, and the event filtering
section in the documentation for a full list.

Non-boolean expressions can compare a field to multiple values separated by ','.
Multiple values are ORed if used with equals operator '=', but are ANDed if used with any other operator.

The field 'container' and 'pid' also support the special value 'new' which selects new containers or pids, respectively.

The field 'set' selects a set of events to trace according to predefined sets, which can be listed by using the 'list' flag.

The special 'follow' expression declares that not only processes that match the criteria will be traced, but also their descendants.

The field 'net' specifies which interfaces to monitor when tracing network events.
Notice that the 'net' field is mandatory when tracing network events.

Examples:
  --filter pid=new                                              | only trace events from new processes
  --filter pid=510,1709                                         | only trace events from pid 510 or pid 1709
  --filter p=510 --filter p=1709                                | only trace events from pid 510 or pid 1709 (same as above)
  --filter container=new                                        | only trace events from newly created containers
  --filter container=ab356bc4dd554                              | only trace events from container id ab356bc4dd554
  --filter container                                            | only trace events from containers
  --filter c                                                    | only trace events from containers (same as above)
  --filter '!container'                                         | only trace events from the host
  --filter uid=0                                                | only trace events from uid 0
  --filter mntns=4026531840                                     | only trace events from mntns id 4026531840
  --filter pidns!=4026531836                                    | only trace events from pidns id not equal to 4026531840
  --filter tree=476165                                          | only trace events that descend from the process with pid 476165
  --filter tree!=5023                                           | only trace events if they do not descend from the process with pid 5023
  --filter tree=3213,5200 --filter tree!=3215                   | only trace events if they descend from 3213 or 5200, but not 3215
  --filter 'uid>0'                                              | only trace events from uids greater than 0
  --filter 'pid>0' --filter 'pid<1000'                          | only trace events from pids between 0 and 1000
  --filter 'u>0' --filter u!=1000                               | only trace events from uids greater than 0 but not 1000
  --filter event=execve,open                                    | only trace execve and open events
  --filter event='open*'                                        | only trace events prefixed by "open"
  --filter event!='open*,dup*'                                  | don't trace events prefixed by "open" or "dup"
  --filter set=fs                                               | trace all file-system related events
  --filter s=fs --filter e!=open,openat                         | trace all file-system related events, but not open(at)
  --filter uts!=ab356bc4dd554                                   | don't trace events from uts name ab356bc4dd554
  --filter comm=ls                                              | only trace events from ls command
  --filter binary=/usr/bin/ls                                   | only trace events from /usr/bin/ls binary
  --filter binary=host:/usr/bin/ls                              | only trace events from /usr/bin/ls binary in the host mount namespace
  --filter binary=4026532448:/usr/bin/ls                        | only trace events from /usr/bin/ls binary in 4026532448 mount namespace
  --filter close.args.fd=5                                      | only trace 'close' events that have 'fd' equals 5
  --filter openat.args.pathname='/tmp*'                         | only trace 'openat' events that have 'pathname' prefixed by /tmp
  --filter openat.args.pathname='*shadow'                       | only trace 'openat' events that have 'pathname' suffixed by shadow
  --filter openat.args.pathname!=/tmp/1,/bin/ls                 | don't trace 'openat' events that have 'pathname' equals /tmp/1 or /bin/ls
  --filter openat.context.processName=ls                        | only trace 'openat' events that have 'processName' equal to 'ls'
  --filter security_file_open.context.container                 | only trace 'security_file_open' events coming from a container
  --filter comm=bash --filter follow                            | trace all events that originated from bash or from one of the processes spawned by bash

Note: some of the above operators have special meanings in different shells.
To 'escape' those operators, please use single quotes, e.g.: 'uid>0', '/tmp*'
`
}

func PrepareFilterMapFromFlags(filtersArr []string) (FilterMap, error) {
	// parse and store filters by policy
	filterMap := make(FilterMap)
	for _, filter := range filtersArr {
		parsed, err := parseFilterFlag(filter)
		if err != nil {
			return nil, err
		}

		policyIdx := parsed.policyIdx

		filterMap[policyIdx] = append(
			filterMap[policyIdx],
			parsed,
		)
	}

	return filterMap, nil
}

func CreatePolicies(filterMap FilterMap) (*policy.Policies, error) {
	eventsNameToID := events.Definitions.NamesToIDs()
	// remove internal events since they shouldn't be accessible by users
	for event, id := range eventsNameToID {
		if events.Definitions.Get(id).Internal {
			delete(eventsNameToID, event)
		}
	}

	policies := policy.NewPolicies()
	for _, fsFlags := range filterMap {
		p := policy.NewPolicy()
		eventFilter := cliFilter{
			Equal:    []string{},
			NotEqual: []string{},
		}
		setFilter := cliFilter{
			Equal:    []string{},
			NotEqual: []string{},
		}

		for _, filterFlag := range fsFlags {
			p.ID = filterFlag.policyIdx
			p.Name = filterFlag.policyName

			if strings.Contains(filterFlag.full, ".retval") {
				err := p.RetFilter.Parse(filterFlag.filterName, filterFlag.operatorAndValues, eventsNameToID)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.Contains(filterFlag.full, ".context") {
				err := p.ContextFilter.Parse(filterFlag.filterName, filterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.Contains(filterFlag.full, ".args") {
				err := p.ArgFilter.Parse(filterFlag.filterName, filterFlag.operatorAndValues, eventsNameToID)
				if err != nil {
					return nil, err
				}
				continue
			}

			// The filters which are more common (container, event, pid, set, uid) can be given using a prefix of them.
			// Other filters should be given using their full name.
			// To avoid collisions between filters that share the same prefix, put the filters which should have an exact match first!
			if filterFlag.filterName == "comm" {
				err := p.CommFilter.Parse(filterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if filterFlag.filterName == "binary" || filterFlag.filterName == "bin" {
				err := p.BinaryFilter.Parse(filterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.HasPrefix("container", filterFlag.filterName) {
				if filterFlag.operatorAndValues == "=new" {
					err := p.NewContFilter.Parse("new")
					if err != nil {
						return nil, err
					}
					continue
				}
				if filterFlag.operatorAndValues == "!=new" {
					err := p.ContFilter.Parse(filterFlag.filterName)
					if err != nil {
						return nil, err
					}
					err = p.NewContFilter.Parse("!new")
					if err != nil {
						return nil, err
					}
					continue
				}
				if strings.Contains(filterFlag.operatorAndValues, "=") {
					err := p.ContIDFilter.Parse(filterFlag.operatorAndValues)
					if err != nil {
						return nil, err
					}
					continue
				}
				err := p.ContFilter.Parse(filterFlag.filterName)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.HasPrefix("!container", filterFlag.filterName) {
				err := p.ContFilter.Parse(filterFlag.filterName)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.HasPrefix("event", filterFlag.filterName) {
				err := eventFilter.Parse(filterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if filterFlag.filterName == "mntns" {
				if strings.ContainsAny(filterFlag.operatorAndValues, "<>") {
					return nil, filters.InvalidExpression(filterFlag.operatorAndValues)
				}
				err := p.MntNSFilter.Parse(filterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if filterFlag.filterName == "pidns" {
				if strings.ContainsAny(filterFlag.operatorAndValues, "<>") {
					return nil, filters.InvalidExpression(filterFlag.operatorAndValues)
				}
				err := p.PidNSFilter.Parse(filterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if filterFlag.filterName == "tree" {
				err := p.ProcessTreeFilter.Parse(filterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.HasPrefix("pid", filterFlag.filterName) {
				if filterFlag.operatorAndValues == "=new" {
					if err := p.NewPidFilter.Parse("new"); err != nil {
						return nil, err
					}
					continue
				}
				if filterFlag.operatorAndValues == "!=new" {
					if err := p.NewPidFilter.Parse("!new"); err != nil {
						return nil, err
					}
					continue
				}
				err := p.PIDFilter.Parse(filterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.HasPrefix("set", filterFlag.filterName) {
				err := setFilter.Parse(filterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if filterFlag.filterName == "uts" {
				err := p.UTSFilter.Parse(filterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.HasPrefix("uid", filterFlag.filterName) {
				err := p.UIDFilter.Parse(filterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.HasPrefix("follow", filterFlag.filterName) {
				p.Follow = true
				continue
			}

			return nil, InvalidFilterOptionError(filterFlag.full)
		}

		var err error
		p.EventsToTrace, err = prepareEventsToTrace(eventFilter, setFilter, eventsNameToID)
		if err != nil {
			return nil, err
		}

		err = policies.Set(p)
		if err != nil {
			logger.Warnw("Setting policy", "error", err)
		}
	}

	if len(policies.Map()) == 0 {
		// If nothing was set, let us consider it as a single default policy
		eventFilter := cliFilter{
			Equal:    []string{},
			NotEqual: []string{},
		}
		setFilter := cliFilter{
			Equal:    []string{},
			NotEqual: []string{},
		}

		var err error
		newPolicy := policy.NewPolicy()
		newPolicy.EventsToTrace, err = prepareEventsToTrace(eventFilter, setFilter, eventsNameToID)
		if err != nil {
			return nil, err
		}

		err = policies.Add(newPolicy)
		if err != nil {
			return nil, err
		}
	}

	return policies, nil
}

func prepareEventsToTrace(
	eventFilter cliFilter, setFilter cliFilter, eventsNameToID map[string]events.ID,
) (
	map[events.ID]string, error,
) {
	eventsToTrace := eventFilter.Equal
	excludeEvents := eventFilter.NotEqual
	setsToTrace := setFilter.Equal

	var res map[events.ID]string
	setsToEvents := make(map[string][]events.ID)
	isExcluded := make(map[events.ID]bool)

	// build a map: k:set, v:eventID
	for id, event := range events.Definitions.Events() {
		for _, set := range event.Sets {
			setsToEvents[set] = append(setsToEvents[set], id)
		}
	}

	// Exclude network events from the default set if kernel v4.19.
	// Issue: https://github.com/aquasecurity/tracee/issues/1602
	// TODO: workaround until we have the feature probing mechanism
	if osInfo, err := helpers.GetOSInfo(); err == nil {
		kernel51ComparedToRunningKernel, err := osInfo.CompareOSBaseKernelRelease("5.1.0")
		if err != nil {
			logger.Errorw("Failed to compare kernel version", "error", err)
		} else {
			if kernel51ComparedToRunningKernel == helpers.KernelVersionNewer {
				id_like := osInfo.GetOSReleaseFieldValue(helpers.OS_ID_LIKE)
				if !strings.Contains(id_like, "rhel") {
					// disable network events for v4.19 kernels other than RHEL based ones
					logger.Debugw("Kernel <= v5.1, disabling network events from default set")
					for _, id := range setsToEvents["default"] {
						if id >= events.NetPacketIPv4 && id <= events.MaxUserNetID {
							isExcluded[id] = true
						}
					}
				}
			}
		}
	} else {
		logger.Errorw("Failed to get OS info", "error", err)
	}

	// mark excluded events (isExcluded) by their id
	for _, name := range excludeEvents {
		if strings.HasSuffix(name, "*") { // handle event prefixes with wildcards
			found := false
			prefix := name[:len(name)-1]
			for event, id := range eventsNameToID {
				if strings.HasPrefix(event, prefix) {
					isExcluded[id] = true
					found = true
				}
			}
			if !found {
				return nil, InvalidEventExcludeError(name)
			}
		} else {
			id, ok := eventsNameToID[name]
			if !ok {
				return nil, InvalidEventExcludeError(name)
			}
			isExcluded[id] = true
		}
	}

	// if no events were specified, add all events from the default set
	if len(eventsToTrace) == 0 && len(setsToTrace) == 0 {
		setsToTrace = append(setsToTrace, "default")
	}

	// build a map: k:eventID, v:eventName with all events to trace
	res = make(map[events.ID]string, events.Definitions.Length())
	for _, name := range eventsToTrace {
		if strings.HasSuffix(name, "*") { // handle event prefixes with wildcards
			found := false
			prefix := name[:len(name)-1]
			for event, id := range eventsNameToID {
				if strings.HasPrefix(event, prefix) && !isExcluded[id] {
					res[id] = event
					found = true
				}
			}
			if !found {
				return nil, InvalidEventError(name)
			}
		} else {
			id, ok := eventsNameToID[name]
			if !ok {
				return nil, InvalidEventError(name)
			}
			res[id] = name
		}
	}

	// add events from sets to the map containing events to trace
	for _, set := range setsToTrace {
		setEvents, ok := setsToEvents[set]
		if !ok {
			return nil, InvalidSetError(set)
		}
		for _, id := range setEvents {
			if !isExcluded[id] {
				res[id] = events.Definitions.Get(id).Name
			}
		}
	}

	return res, nil
}

type cliFilter struct {
	Equal    []string
	NotEqual []string
}

func (filter *cliFilter) Parse(operatorAndValues string) error {
	valuesString := string(operatorAndValues[1:])
	operatorString := string(operatorAndValues[0])

	if operatorString == "!" {
		if len(operatorAndValues) < 3 {
			return errfmt.Errorf("invalid operator and/or values given to filter: %s", operatorAndValues)
		}
		operatorString = operatorAndValues[0:2]
		valuesString = operatorAndValues[2:]
	}

	values := strings.Split(valuesString, ",")

	for i := range values {
		switch operatorString {
		case "=":
			filter.Equal = append(filter.Equal, values[i])
		case "!=":
			filter.NotEqual = append(filter.NotEqual, values[i])
		default:
			return errfmt.Errorf("invalid filter operator: %s", operatorString)
		}
	}

	return nil
}
