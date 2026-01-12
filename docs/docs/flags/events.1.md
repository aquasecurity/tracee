--
title: TRACEE-EVENTS
section: 1
header: Tracee Events Flag Manual
date: 2024/12
...

## NAME

tracee **\-\-events** - Select which events to trace

## SYNOPSIS

tracee **\-\-events** [<event-name1(,[-]event-name2...)\> | <tag=tag1(,tag2...)\> | <event1.data.data-field[=|!=]value\> | <event1.retval[=|!=|<|\>|<=|\>=]value\> | <event1.scope.field[=|!=|<|\>|<=|\>=]value\> | <event.scope.container\>] ...

## DESCRIPTION

The **\-\-events** flag allows you to select which events to trace by defining filters.

## FILTERS

- Event name: Select specific events using 'event-name1,event-name2...'. To exclude events, prepend the event name with a dash '-': '-event-name'.

- Tag selection: Select events by tag (set) using 'tag=tag1,tag2...'. Multiple tags are combined with OR logic. Common tags include: syscalls, fs, network, proc, default.

- Detector selection by threat properties: Select detectors based on their threat metadata using 'threat.property=value'. See THREAT-BASED DETECTOR SELECTION section below.

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

Strings can be compared as a prefix if ending with '\*', or as a suffix if starting with '\*'.  If a string starts with '\*' and ends with '\*', it functions as a contains operator.

For certain event fields filtered in kernel space, the user will receive a warning if:

- String filters exceed 255 characters.
- The contains operator is used. Only exact matches, prefix, and suffix comparisons are allowed.

NOTE: Expressions containing '\*' token must be escaped!

### EXCLUSION OPERATOR (PREPENDED)

'-'

Available only for:

- event names

## THREAT-BASED DETECTOR SELECTION

Detectors can be selected based on their threat metadata properties. This allows you to enable all detectors that match specific security criteria without knowing their individual event names.

### THREAT PROPERTIES

**threat.severity** - Severity level (info, low, medium, high, critical or 0-4). Supports: =, !=, <, \>, <=, \>=

```console
--events threat.severity=critical                # Only critical threats
--events 'threat.severity>=high'                 # High and critical threats
```

**threat.mitre.technique** - MITRE ATT&CK technique ID (e.g., T1055). Supports: =, !=

```console
--events threat.mitre.technique=T1055
```

**threat.mitre.tactic** - MITRE ATT&CK tactic name (e.g., "Defense Evasion"). Supports: =, !=

```console
--events 'threat.mitre.tactic="Defense Evasion"'
```

**threat.name** - Threat name/identifier. Supports: =, !=

```console
--events threat.name=process_injection
```

Threat selection can be combined with regular events. Multiple `--events` flags are combined additively (OR logic):

```console
--events threat.severity=critical --events write    # Critical threats OR write events
--events tag=fs --events 'threat.severity>=high'    # Filesystem events OR high+ threats
```

**Note:** Detector selection based on threat properties is performed once at startup. Matching detectors are enabled; non-matching detectors are never loaded.

## TAG SELECTION

Events are categorized with tags (also known as sets). You can select all events with a specific tag:

```console
--events tag=containers       # All events tagged with "containers"
--events tag=fs               # All filesystem-related events
--events tag=detectors        # All detector events
```

Tags can be combined with other selection methods:

```console
--events tag=containers,execve            # Events with "containers" tag + execve syscall
--events tag=fs,network                   # Filesystem OR network events
--events tag=fs --events -open,-openat    # Filesystem events except open(at)
```

## EXAMPLES

- To trace only 'execve' and 'open' events, use the following flag:

  ```console
  --events execve,open
  ```

- To trace only events prefixed by "open", use the following flag:

  ```console
  --events 'open*'
  ```

- To trace all file-system related events, use the following flag:

  ```console
  --events tag=fs
  ```

- To trace all file-system related events, but not 'open' or 'openat', use the following flag:

  ```console
  --events tag=fs --events '-open,-openat'
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

- To trace only 'openat' events that have 'pathname' contains the substring 'pass', use the following flag:

  ```console
  --events openat.data.pathname='*pass*'
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

- To trace all detectors with critical severity, use the following flag:

  ```console
  --events threat.severity=critical
  ```

- To trace all detectors with high or critical severity, use the following flag:

  ```console
  --events 'threat.severity>=high'
  ```

- To trace detectors for a specific MITRE ATT&CK technique, use the following flag:

  ```console
  --events threat.mitre.technique=T1055
  ```

- To trace detectors for a specific MITRE ATT&CK tactic, use the following flag:

  ```console
  --events 'threat.mitre.tactic="Defense Evasion"'
  ```

- To combine threat-based selection with regular events, use the following flags:

  ```console
  --events write --events threat.severity=critical
  ```
