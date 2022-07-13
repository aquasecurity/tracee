package flags

import (
	"fmt"
	"strings"

	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/types/protocol"
)

// MaxBpfStrFilterSize value should match MAX_STR_FILTER_SIZE defined in BPF code
const MaxBpfStrFilterSize = 16

func FilterHelp() string {
	return `Select which events to trace by defining trace expressions that operate on events or process metadata.
Only events that match all trace expressions will be traced (trace flags are ANDed).
The following types of expressions are supported:

Numerical expressions which compare numbers and allow the following operators: '=', '!=', '<', '>'.
Available numerical expressions: uid, pid, mntns, pidns.
NOTE: expressions using '<' or '>' must be escaped to work.

String expressions which compares text and allow the following operators: '=', '!='.
Available string expressions: event, set, uts, comm, container.

Boolean expressions that check if a boolean is true and allow the following operator: '!'.
Available boolean expressions: container.

Event arguments can be accessed using 'event_name.event_arg' and provide a way to filter an event by its arguments.
Event arguments allow the following operators: '=', '!='.
Strings can be compared as a prefix if ending with '*' or as suffix if starting with '*'.

Event return value can be accessed using 'event_name.retval' and provide a way to filter an event by its return value.
Event return value expression has the same syntax as a numerical expression.

Event context fields can be accessed using 'event_name.context.field', this can be used to filter an event by its standard fields.
Refer to the json field values in github.com/aquasecurity/tracee/blob/main/types/trace/trace.go and the standard filter fields for valid context fields.

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
  --trace openat.context.processName=ls                        | only trace 'openat' events that have 'processName' equal to 'ls'
  --trace security_file_open.context.container                 | only trace 'security_file_open' events coming from a container
  --trace comm=bash --trace follow                             | trace all events that originated from bash or from one of the processes spawned by bash
  --trace net=docker0 			                               | trace the net events over docker0 interface


Note: some of the above operators have special meanings in different shells.
To 'escape' those operators, please use single quotes, e.g.: 'uid>0'
`
}

func InvalidFilter(input string) error {
	return fmt.Errorf("invalid filter option \"%s\" specified, use '--trace help' for more info", input)
}
func ErrorParsingFilter(input string, err error) error {
	return fmt.Errorf("error parsing filter option \"%s\": %s, use '--trace help' for more info", input, err)
}
func InvalidArgFilter() error {
	return fmt.Errorf("invalid filter field: no value after '.' token")
}
func InvalidEventName(event string) error {
	return fmt.Errorf("invalid filter field: no event called %s", event)
}
func EmptyValueFilter() error {
	return fmt.Errorf("invalid value for filter: empty")
}

func PrepareFilter(filtersInput []string) ([]protocol.Filter, error) {
	res := []protocol.Filter{}

	for _, f := range filtersInput {
		filter, err := parseFilterString(f)
		if err != nil {
			return nil, ErrorParsingFilter(f, err)
		}
		if !tracee.IsValidFilterField(filter.Field) {
			return nil, InvalidFilter(f)
		}
		res = append(res, filter)
	}

	return res, nil
}

func parseFilterString(filterStr string) (protocol.Filter, error) {
	operatorStr := ""
	valuesStr := ""
	operatorIndex := strings.IndexAny(filterStr, "=!<>")
	filterName := ""

	//no operator found means  a bool filter
	if operatorIndex < 0 {
		filterName = filterStr
		err := validateFilterName(filterName)
		if err != nil {
			return protocol.Filter{}, err
		}
		return protocol.EqualFilter(filterName, true), nil
	}
	if operatorIndex == 0 && filterStr[0] == '!' {
		filterName = filterStr[1:]
		err := validateFilterName(filterName)
		if err != nil {
			return protocol.Filter{}, err
		}
		return protocol.EqualFilter(filterName, false), nil
	}
	if operatorIndex+1 == len(filterStr) {
		return protocol.Filter{}, EmptyValueFilter()
	}

	filterName = filterStr[0:operatorIndex]
	err := validateFilterName(filterName)
	if err != nil {
		return protocol.Filter{}, err
	}
	operatorStr = string(filterStr[operatorIndex])
	valuesStr = filterStr[operatorIndex+1:]

	//check for <= and >=
	if (filterStr[operatorIndex] == '>' || filterStr[operatorIndex] == '<') && filterStr[operatorIndex+1] == '=' {
		operatorStr = filterStr[operatorIndex : operatorIndex+2]
		valuesStr = filterStr[operatorIndex+2:]
	}
	//check for !=
	if filterStr[operatorIndex] == '!' && filterStr[operatorIndex+1] == '=' {
		operatorStr = filterStr[operatorIndex : operatorIndex+2]
		valuesStr = filterStr[operatorIndex+2:]
	}

	operator, err := operatorFromString(operatorStr)
	if err != nil {
		return protocol.Filter{}, err
	}

	// handle new value filters
	if valuesStr == "new" {
		switch operator {
		case protocol.Equal:
			return protocol.EqualFilter(fmt.Sprintf("%s.new", filterName), true), nil
		case protocol.NotEqual:
			return protocol.NotEqualFilter(fmt.Sprintf("%s.new", filterName), true), nil
		default:
			return protocol.Filter{}, fmt.Errorf("invalid operator %s for \"new\" valued filter", operator.String())
		}
	}
	valuesStr = strings.TrimSpace(valuesStr)
	if valuesStr == "" {
		return protocol.Filter{}, EmptyValueFilter()
	}
	splitVals := strings.Split(valuesStr, ",")
	values := []interface{}{}

	//parse vals to actual types
	for _, val := range splitVals {
		values = append(values, val)
	}

	return protocol.Filter{Field: filterName, Operator: operator, Value: values}, nil
}

func validateFilterName(filterName string) error {
	//if filter starts or ends with a '.' terminate for invalid syntax
	if strings.HasSuffix(filterName, ".") || strings.HasPrefix(filterName, ".") {
		return InvalidArgFilter()
	}
	return nil
}

func operatorFromString(opStr string) (protocol.FilterOperator, error) {
	switch opStr {
	case "=":
		return protocol.Equal, nil
	case "!=":
		return protocol.NotEqual, nil
	case ">":
		return protocol.Greater, nil
	case "<":
		return protocol.Lesser, nil
	case ">=":
		return protocol.GreaterEqual, nil
	case "<=":
		return protocol.LesserEqual, nil
	}
	//sanity
	return protocol.Equal, fmt.Errorf("invalid operator %s", opStr)
}
