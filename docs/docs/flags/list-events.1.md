--
title: TRACEE-LIST-EVENTS
section: 1
header: Tracee List Events Command Manual
date: 2025/01
...

## NAME

tracee **list events** - List traceable events with optional filtering

## SYNOPSIS

tracee **list events** [filters...] [\-\-json]

## DESCRIPTION

The **list events** command displays all events that can be traced by Tracee, with optional filtering.

Uses the same filter syntax as **tracee \-\-events**.

## FILTER PATTERNS

**eventname**
: Exact event name match (e.g., `open`, `execve`)

**pattern\***
: Wildcard pattern match. Supports prefix (`open*`), suffix (`*write`), or contains (`*file*`)

**tag=TAG**
: Filter by tag/set (e.g., `tag=fs`, `tag=network`, `tag=syscalls`)

**tag=TAG1,TAG2**
: Filter by multiple tags with OR logic (e.g., `tag=fs,network`)

**type=TYPE**
: Filter by event type. Valid values: `syscall`, `detector`, `network`

**threat.severity=SEVERITY**
: Filter by threat severity. Valid values: `info`, `low`, `medium`, `high`, `critical`

**threat.mitre.technique=ID**
: Filter by MITRE ATT&CK technique ID (e.g., `threat.mitre.technique=T1055`)

**threat.mitre.tactic=NAME**
: Filter by MITRE ATT&CK tactic name (e.g., `threat.mitre.tactic=Execution`)

## OUTPUT FLAGS

**\-\-json**, **-j**
: Output in JSON format for scripting.

## FILTER SEMANTICS

Multiple filter arguments are combined with **AND** logic:

```console
tracee list events tag=fs threat.severity=high
# Events must have 'fs' tag AND high severity
```

Comma-separated values within a filter are combined with **OR** logic:

```console
tracee list events tag=fs,network
# Events with 'fs' OR 'network' tag
```

## EXAMPLES

- List all events:

```console
tracee list events
```

- List event by exact name:

```console
tracee list events open
```

- List events matching a pattern:

```console
tracee list events 'open*'
tracee list events '*write*'
```

- List events with a specific tag:

```console
tracee list events tag=fs
tracee list events tag=syscalls
```

- List events with multiple tags (OR):

```console
tracee list events tag=fs,network
```

- List events with multiple tags (AND):

```console
tracee list events tag=fs tag=proc
```

- List syscall events only:

```console
tracee list events type=syscall
```

- List detector events only:

```console
tracee list events type=detector
```

- List events by threat severity:

```console
tracee list events threat.severity=critical
tracee list events threat.severity=high,critical
```

- List events by MITRE technique:

```console
tracee list events threat.mitre.technique=T1055
```

- List events by MITRE tactic:

```console
tracee list events threat.mitre.tactic=Execution
```

- Combine multiple filters (AND):

```console
tracee list events tag=fs threat.severity=high
tracee list events type=detector threat.mitre.tactic=Persistence
```

- Output in JSON format:

```console
tracee list events --json
tracee list events tag=fs --json | jq '.[] | .name'
```

## SEE ALSO

tracee-list(1), tracee-list-detectors(1), tracee-list-policies(1)
