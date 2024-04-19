---
title: TRACEE-EVENTS
section: 1
header: Tracee Events Flag Manual
date: 2024/06
...

## NAME

tracee **\-\-events** - Select which events to trace

## SYNOPSIS

tracee **\-\-events** [<event-name1(,[-]event-name2...)\> | <[-]event-name1(,set1...)\> | <set1(,[-]event-name1,[-]event-name2...)\> | <event1.data.data-field[=|!=]value\> | <event1.retval[=|!=|<|\>|<=|\>=]value\> | <event1.scope.field[=|!=|<|\>|<=|\>=]value\> | <event.scope.container\>] ...

## DESCRIPTION

The **\-\-events** flag allows you to select which events to trace by defining filters.

## FILTERS

- Event or set name: Select specific events using 'event-name1,event-name2...' or predefined event sets using 'event_set_name1,event_set_name2...'. To exclude events, prepend the event name with a dash '-': '-event-name'.

- Event data: Filter events based on their data using 'event-name.data.event_data'. The event data expression follows the syntax of a string expression.

- Event return value: Filter events based on their return value using 'event-name.retval'. The event return value expression follows the syntax of a numerical expression.

- Event scope fields: Filter events based on the non-argument fields defined in the trace.Event struct using 'event-name.scope.field'. Refer to the json tags in the trace.Event struct located in the types/trace package for the correct field names, and the event filtering section in the documentation for a full list.

## FILTER EXPRESSION

Filter expressions can be defined to operate on event options or process metadata. Only events that match all filter expressions will be traced.

Multiple flags are combined with AND logic, while multiple values within a single flag are combined with OR logic when using the equals operator '='. Multiple values can be specified using ','.

### NUMERICAL EXPRESSION OPERATORS

'=', '!=', '<', '\>', '<=', '\>='

Available for:

- return value
- scope fields

NOTE: Expressions containing '<' or '\>' tokens must be escaped!

### STRING EXPRESSION OPERATORS

'=', '!='

Available for:

- event arguments
- return value
- scope fields

Strings can be compared as a prefix if ending with '\*', or as a suffix if starting with '\*'.

NOTE: Expressions containing '\*' token must be escaped!

### EXCLUSION OPERATOR (PREPENDED)

'-'

Available only for:

- event names

## EXAMPLES

- To trace only 'execve' and 'open' events, use the following flag:

  ```console
  --events execve,open
  ```

- To trace only events prefixed by "open", use the following flag:

  ```console
  --events 'open*'
  ```

- To exclude events prefixed by "open" or "dup", use the following flag:

  ```console
  --events '-open*,-dup*'
  ```

- To trace all file-system related events, use the following flag:

  ```console
  --events fs
  ```

- To trace all file-system related events, but not 'open' or 'openat', use the following flag:

  ```console
  --events fs --events '-open,-openat'
  ```

- To trace only 'close' events that have 'fd' equal to 5, use the following flag:

  ```console
  --events close.data.fd=5
  ```

- To trace only 'openat' events that have 'pathname' prefixed by '/tmp', use the following flag:

  ```console
  --events openat.data.pathname='/tmp*'
  ```

- To trace only 'openat' events that have 'pathname' suffixed by 'shadow', use the following flag:

  ```console
  --events openat.data.pathname='*shadow'
  ```

- To exclude 'openat' events that have 'pathname' equal to '/tmp/1' or '/bin/ls', use the following flag:

  ```console
  --events openat.data.pathname!=/tmp/1,/bin/ls
  ```

- To trace only 'openat' events that have 'processName' equal to 'ls', use the following flag:

  ```console
  --events openat.scope.processName=ls
  ```

- To trace only 'security_file_open' events coming from a container, use the following flag:

  ```console
  --events security_file_open.scope.container
  ```
