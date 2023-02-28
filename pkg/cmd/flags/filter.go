package flags

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/filterscope"
	"github.com/aquasecurity/tracee/pkg/logger"
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

Filters can also be configured within up to 64 scopes (workloads).
Events that match all filter expressions within a single scope will be filtered.
To find out which scopes an event is related to, read the bitmask in one of these ways:

- using '-o format:json', matchedScopes JSON field (in decimal)
- using '-o format:table-verbose', SCOPES column (in hexadecimal)

Examples:

  -f 42:event=sched_process_exec -f 42:binary=/usr/bin/ls      | trace in scope 42 sched_process_exec event from /usr/bin/ls binary

  -f 3:event=openat -f 3:comm=id -f 9:event=close -f 9:comm=ls - trace in scope 3 only openat event from id command
                                                               | and
                                                               - trace in scope 9 only close event from ls command

  -f 6:event=openat -f 6:comm=id -f 7:event=close -f 7:comm=id - trace in scope 6 only openat event from id command
                                                               | and
                                                               _ trace in scope 7 only close event from id command

  -f 3:event=openat -f 3:comm=id -f 9:event=close              - trace in scope 3 only openat event from id command
                                                               | and
                                                               - trace in scope 9 only close event from all

Note: some of the above operators have special meanings in different shells.
To 'escape' those operators, please use single quotes, e.g.: 'uid>0', '/tmp*'
`
}

// filterFlag holds pre-parsed filter flag fields
type filterFlag struct {
	full              string
	filterName        string
	operatorAndValues string
	scopeIdx          int
}

func parseFilterFlag(flag string) (*filterFlag, error) {
	var (
		scopeID           int // stores the parsed scope index, not its flag position
		filterName        string
		operatorAndValues string

		scopeEndIdx      int // stores ':' flag index (end of the scope value)
		filterNameIdx    int
		filterNameEndIdx int
		operatorIdx      int
		err              error
	)

	scopeEndIdx = strings.Index(flag, ":")
	operatorIdx = strings.IndexAny(flag, "=!<>")

	if scopeEndIdx == -1 && operatorIdx == -1 {
		return &filterFlag{
			full:              flag,
			filterName:        flag,
			operatorAndValues: "",
			scopeIdx:          scopeID,
		}, nil
	}

	if operatorIdx != -1 {
		operatorAndValues = flag[operatorIdx:]
		filterNameEndIdx = operatorIdx
	} else {
		operatorIdx = len(flag) - 1
		filterNameEndIdx = len(flag)
	}

	// check operators
	if len(operatorAndValues) == 1 ||
		operatorAndValues == "!=" ||
		operatorAndValues == "<=" ||
		operatorAndValues == ">=" {

		return nil, filters.InvalidExpression(flag)
	}

	if scopeEndIdx != -1 && scopeEndIdx < operatorIdx {
		// parse its ID
		scopeID, err = strconv.Atoi(flag[:scopeEndIdx])
		if err != nil {
			return nil, filters.InvalidScope(fmt.Sprintf("%s - %s", flag, err))
		}

		// now consider it as a scope index
		scopeID--
		if scopeID < 0 || scopeID > filterscope.MaxFilterScopes-1 {
			return nil, filters.InvalidScope(fmt.Sprintf("%s - scopes must be between 1 and %d", flag, filterscope.MaxFilterScopes))
		}

		filterNameIdx = scopeEndIdx + 1
	}

	if len(operatorAndValues) >= 2 &&
		operatorAndValues[0] == '!' &&
		operatorAndValues[1] != '=' {

		filterName = flag[filterNameIdx:]
		if strings.HasSuffix(filterName, "follow") ||
			strings.HasSuffix(filterName, "container") {

			return &filterFlag{
				full:              flag,
				filterName:        filterName,
				operatorAndValues: "",
				scopeIdx:          scopeID,
			}, nil
		}

		return nil, filters.InvalidExpression(flag)
	}

	// parse filter name
	filterName = flag[filterNameIdx:filterNameEndIdx]

	return &filterFlag{
		full:              flag,
		filterName:        filterName,
		operatorAndValues: operatorAndValues,
		scopeIdx:          scopeID,
	}, nil
}

func PrepareFilterScopes(filtersArr []string) (*filterscope.FilterScopes, error) {
	eventsNameToID := events.Definitions.NamesToIDs()
	// remove internal events since they shouldn't be accessible by users
	for event, id := range eventsNameToID {
		if events.Definitions.Get(id).Internal {
			delete(eventsNameToID, event)
		}
	}

	// parse and store filters by scope
	parsedMap := map[int][]*filterFlag{}
	for _, filter := range filtersArr {
		parsed, err := parseFilterFlag(filter)
		if err != nil {
			return nil, err
		}

		scopeIdx := parsed.scopeIdx
		parsedMap[scopeIdx] = append(
			parsedMap[scopeIdx],
			parsed,
		)
	}

	filterScopes := filterscope.NewFilterScopes()
	for scopeIdx, fsFlags := range parsedMap {
		filterScope := filterscope.NewFilterScope()
		eventFilter := cliFilter{
			Equal:    []string{},
			NotEqual: []string{},
		}
		setFilter := cliFilter{
			Equal:    []string{},
			NotEqual: []string{},
		}

		for _, filterFlag := range fsFlags {
			if strings.Contains(filterFlag.full, ".retval") {
				err := filterScope.RetFilter.Parse(filterFlag.filterName, filterFlag.operatorAndValues, eventsNameToID)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.Contains(filterFlag.full, ".context") {
				err := filterScope.ContextFilter.Parse(filterFlag.filterName, filterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.Contains(filterFlag.full, ".args") {
				err := filterScope.ArgFilter.Parse(filterFlag.filterName, filterFlag.operatorAndValues, eventsNameToID)
				if err != nil {
					return nil, err
				}
				continue
			}

			// The filters which are more common (container, event, pid, set, uid) can be given using a prefix of them.
			// Other filters should be given using their full name.
			// To avoid collisions between filters that share the same prefix, put the filters which should have an exact match first!
			if filterFlag.filterName == "comm" {
				err := filterScope.CommFilter.Parse(filterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if filterFlag.filterName == "binary" || filterFlag.filterName == "bin" {
				err := filterScope.BinaryFilter.Parse(filterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.HasPrefix("container", filterFlag.filterName) {
				if filterFlag.operatorAndValues == "=new" {
					err := filterScope.NewContFilter.Parse("new")
					if err != nil {
						return nil, err
					}
					continue
				}
				if filterFlag.operatorAndValues == "!=new" {
					err := filterScope.ContFilter.Parse(filterFlag.filterName)
					if err != nil {
						return nil, err
					}
					err = filterScope.NewContFilter.Parse("!new")
					if err != nil {
						return nil, err
					}
					continue
				}
				if strings.Contains(filterFlag.operatorAndValues, "=") {
					err := filterScope.ContIDFilter.Parse(filterFlag.operatorAndValues)
					if err != nil {
						return nil, err
					}
					continue
				}
				err := filterScope.ContFilter.Parse(filterFlag.filterName)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.HasPrefix("!container", filterFlag.filterName) {
				err := filterScope.ContFilter.Parse(filterFlag.filterName)
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
				err := filterScope.MntNSFilter.Parse(filterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if filterFlag.filterName == "pidns" {
				if strings.ContainsAny(filterFlag.operatorAndValues, "<>") {
					return nil, filters.InvalidExpression(filterFlag.operatorAndValues)
				}
				err := filterScope.PidNSFilter.Parse(filterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if filterFlag.filterName == "tree" {
				err := filterScope.ProcessTreeFilter.Parse(filterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.HasPrefix("pid", filterFlag.filterName) {
				if filterFlag.operatorAndValues == "=new" {
					filterScope.NewPidFilter.Parse("new")
					continue
				}
				if filterFlag.operatorAndValues == "!=new" {
					filterScope.NewPidFilter.Parse("!new")
					continue
				}
				err := filterScope.PIDFilter.Parse(filterFlag.operatorAndValues)
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
				err := filterScope.UTSFilter.Parse(filterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.HasPrefix("uid", filterFlag.filterName) {
				err := filterScope.UIDFilter.Parse(filterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.HasPrefix("follow", filterFlag.filterName) {
				filterScope.Follow = true
				continue
			}

			return nil, InvalidFilterOptionError(filterFlag.full)
		}

		var err error
		filterScope.EventsToTrace, err = prepareEventsToTrace(eventFilter, setFilter, eventsNameToID)
		if err != nil {
			return nil, err
		}

		err = filterScopes.Set(scopeIdx, filterScope)
		if err != nil {
			logger.Warn("Setting scope", "error", err)
		}
	}

	if len(filterScopes.Map()) == 0 {
		// If nothing was set, let us consider it as a single default scope
		eventFilter := cliFilter{
			Equal:    []string{},
			NotEqual: []string{},
		}
		setFilter := cliFilter{
			Equal:    []string{},
			NotEqual: []string{},
		}

		var err error
		newScope := filterscope.NewFilterScope()
		newScope.EventsToTrace, err = prepareEventsToTrace(eventFilter, setFilter, eventsNameToID)
		if err != nil {
			return nil, err
		}

		err = filterScopes.Add(newScope)
		if err != nil {
			return nil, err
		}
	}

	return filterScopes, nil
}

func prepareEventsToTrace(eventFilter cliFilter, setFilter cliFilter, eventsNameToID map[string]events.ID) (map[events.ID]string, error) {
	eventsToTrace := eventFilter.Equal
	excludeEvents := eventFilter.NotEqual
	setsToTrace := setFilter.Equal

	var res map[events.ID]string
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
	if len(eventsToTrace) == 0 && len(setsToTrace) == 0 {
		setsToTrace = append(setsToTrace, "default")
	}

	res = make(map[events.ID]string, events.Definitions.Length())
	for _, name := range eventsToTrace {
		// Handle event prefixes with wildcards
		if strings.HasSuffix(name, "*") {
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
			return logger.NewErrorf("invalid operator and/or values given to filter: %s", operatorAndValues)
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
			return logger.NewErrorf("invalid filter operator: %s", operatorString)
		}
	}

	return nil
}
