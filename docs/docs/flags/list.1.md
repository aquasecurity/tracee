--
title: TRACEE-LIST
section: 1
header: Tracee List Command Manual
date: 2026/07
...

## NAME

tracee **list** - List traceable events, detectors, or policies; inspect filtering and dependencies

## SYNOPSIS

tracee **list** \<subcommand\> [arguments...] [options]

## DESCRIPTION

The **list** command displays available events, detectors, or policies that can be used with Tracee, and inspects where an event's filters are enforced and how its dependencies resolve.

A subcommand is required.

## SUBCOMMANDS

**events** [filters...]
: List all traceable events with optional filtering. See tracee-list-events(1).

**detectors** [paths...]
: List available detectors from built-in and YAML sources. See tracee-list-detectors(1).

**policies** [paths...]
: List policies from directories or files. See tracee-list-policies(1).

**filterable** [event... | policy-path...]
: Show which event fields filter in the kernel vs user space, or analyze where a policy's selected events are filtered. See tracee-list-filterable(1).

**deps** \<event...\>
: Show an event's dependency graph (tree, mermaid, or json). See tracee-list-deps(1).

## EXAMPLES

- List all events:

```console
tracee list events
```

- List events with filters:

```console
tracee list events tag=fs
tracee list events type=detector threat.severity=critical
```

- List detectors:

```console
tracee list detectors
tracee list detectors ./my-detectors
```

- List policies:

```console
tracee list policies
tracee list policies ./my-policies
```

- Show where an event's fields filter, or analyze a policy:

```console
tracee list filterable security_file_open
tracee list filterable ./my-policies
```

- Show an event's dependency graph:

```console
tracee list deps net_packet_icmp
tracee list deps sched_process_exec --format mermaid
```

## SEE ALSO

tracee-list-events(1), tracee-list-detectors(1), tracee-list-policies(1), tracee-list-filterable(1), tracee-list-deps(1)
