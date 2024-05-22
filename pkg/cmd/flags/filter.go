package flags

import (
	"strings"

	"github.com/aquasecurity/tracee/pkg/events"
)

func filterHelp() string {
	return `Select which events to trace by defining filter expressions that operate on some scope (workload), events or process metadata.
Only events that match all filter expressions will be traced (flags are ANDed).
The following types of expressions are supported:

Numerical expressions which compare numbers and allow the following operators: '=', '!=', '<', '>'.
Available numerical expressions: uid, pid, mntns, pidns.
NOTE: Expressions containing '<' or '>' token must be escaped! This is also shown in the examples below.

String expressions which compares text and allow the following operators: '=', '!='.
Available string expressions: uts, comm, container, executable.

Boolean expressions that check if a boolean is true and allow the following operator: '!'.
Available boolean expressions: container.

Event flag selects events or sets of events to trace according to predefined sets, which can be listed by using the 'list' flag.
Event flag uses a dash prefix to filter out events: '-'.

Event data can be accessed using 'event_name.data.event_arg' and provide a way to filter an event by its data.
Event data allow the following operators: '=', '!='.
Strings can be compared as a prefix if ending with '*' or as suffix if starting with '*'.

Event return value can be accessed using 'event_name.retval' and provide a way to filter an event by its return value.
Event return value expression has the same syntax as a numerical expression.

Event scope fields can be accessed using 'event_name.scope.field', this can be used to filter an event by the non arguments
fields defined in the trace.Event struct.
Refer to the json tags in the trace.Event struct located in the types/trace package for the correct field names, and the event filtering
section in the documentation for a full list.

Non-boolean expressions can compare a field to multiple values separated by ','.
Multiple values are ORed if used with equals operator '=', but are ANDed if used with any other operator.

The field 'container' and 'pid' also support the special value 'new' which selects new containers or pids, respectively.

The special 'follow' expression declares that not only processes that match the criteria will be traced, but also their descendants.

The field 'net' specifies which interfaces to monitor when tracing network events.
Notice that the 'net' field is mandatory when tracing network events.

Scope examples:
  --scope pid=new                                              | only trace events from new processes
  --scope pid=510,1709                                         | only trace events from pid 510 or pid 1709
  --scope p=510 --scope p=1709                                 | only trace events from pid 510 or pid 1709 (same as above)
  --scope container=new                                        | only trace events from newly created containers
  --scope container=ab356bc4dd554                              | only trace events from container id ab356bc4dd554
  --scope container                                            | only trace events from containers
  --scope c                                                    | only trace events from containers (same as above)
  --scope not-container                                        | only trace events from the host
  --scope uid=0                                                | only trace events from uid 0
  --scope mntns=4026531840                                     | only trace events from mntns id 4026531840
  --scope pidns!=4026531836                                    | only trace events from pidns id not equal to 4026531840
  --scope tree=476165                                          | only trace events that descend from the process with pid 476165
  --scope tree!=5023                                           | only trace events if they do not descend from the process with pid 5023
  --scope tree=3213,5200 --scope tree!=3215                    | only trace events if they descend from 3213 or 5200, but not 3215
  --scope 'uid>0'                                              | only trace events from uids greater than 0
  --scope 'pid>0' --scope 'pid<1000'                           | only trace events from pids between 0 and 1000
  --scope 'u>0' --scope u!=1000                                | only trace events from uids greater than 0 but not 1000
  --scope uts!=ab356bc4dd554                                   | don't trace events from uts name ab356bc4dd554
  --scope comm=ls                                              | only trace events from ls command
  --scope executable=/usr/bin/ls                               | only trace events from /usr/bin/ls executable
  --scope executable=host:/usr/bin/ls                          | only trace events from /usr/bin/ls executable in the host mount namespace
  --scope executable=4026532448:/usr/bin/ls                    | only trace events from /usr/bin/ls executable in 4026532448 mount namespace
  --scope comm=bash --scope follow                             | trace all events that originated from bash or from one of the processes spawned by bash

Event examples:
  --events execve,open                                          | only trace execve and open events
  --events 'open*'                                              | only trace events prefixed by "open"
  --events '-open*,-dup*'                                       | don't trace events prefixed by "open" or "dup"
  --events fs                                                   | trace all file-system related events
  --events fs --events -open,-openat                            | trace all file-system related events, but not open(at)
  --events close.data.fd=5                                      | only trace 'close' events that have 'fd' equals 5
  --events openat.data.pathname='/tmp*'                         | only trace 'openat' events that have 'pathname' prefixed by /tmp
  --events openat.data.pathname='*shadow'                       | only trace 'openat' events that have 'pathname' suffixed by shadow
  --events openat.data.pathname!=/tmp/1,/bin/ls                 | don't trace 'openat' events that have 'pathname' equals /tmp/1 or /bin/ls
  --events openat.scope.processName=ls                          | only trace 'openat' events that have 'processName' equal to 'ls'
  --events security_file_open.scope.container                   | only trace 'security_file_open' events coming from a container

Note: some of the above operators have special meanings in different shells.
To 'escape' those operators, please use single quotes, e.g.: 'uid>0', '/tmp*'
`
}

type eventFilter struct {
	Equal    []string
	NotEqual []string
}

func prepareEventsToTrace(eventFilter eventFilter, eventsNameToID map[string]events.ID) (map[events.ID]string, error) {
	eventsToTrace := eventFilter.Equal
	excludeEvents := eventFilter.NotEqual
	var setsToTrace []string

	var idToName map[events.ID]string
	setsToEvents := make(map[string][]events.ID)
	isExcluded := make(map[events.ID]bool)

	// build a map: k:set, v:eventID
	for _, eventDefinition := range events.Core.GetDefinitions() {
		for _, set := range eventDefinition.GetSets() {
			setsToEvents[set] = append(setsToEvents[set], eventDefinition.GetID())
		}
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
	if len(eventsToTrace) == 0 {
		setsToTrace = append(setsToTrace, "default")
	}

	// build a map: k:eventID, v:eventName with all events to trace
	idToName = make(map[events.ID]string, events.Core.Length())
	for _, name := range eventsToTrace {
		if strings.HasSuffix(name, "*") { // handle event prefixes with wildcards
			found := false
			prefix := name[:len(name)-1]
			for event, id := range eventsNameToID {
				if strings.HasPrefix(event, prefix) && !isExcluded[id] {
					idToName[id] = event
					found = true
				}
			}
			if !found {
				return nil, InvalidEventError(name)
			}
		} else {
			id, ok := eventsNameToID[name]
			if !ok {
				// no matching event - maybe it is actually a set?
				if _, ok = setsToEvents[name]; ok {
					setsToTrace = append(setsToTrace, name)
					continue
				}
				return nil, InvalidEventError(name)
			}
			idToName[id] = name
		}
	}

	// add events from sets to the map containing events to trace
	for _, set := range setsToTrace {
		setEvents := setsToEvents[set]
		for _, id := range setEvents {
			if !isExcluded[id] {
				idToName[id] = events.Core.GetDefinitionByID(id).GetName()
			}
		}
	}

	return idToName, nil
}
