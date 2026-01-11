--
title: TRACEE-LIST
section: 1
header: Tracee List Command Manual
date: 2025/01
...

## NAME

tracee **list** - List traceable events, detectors, or policies

## SYNOPSIS

tracee **list** \<subcommand\> [arguments...] [options]

## DESCRIPTION

The **list** command displays available events, detectors, or policies that can be used with Tracee.

A subcommand is required.

## SUBCOMMANDS

**events** [filters...]
: List all traceable events with optional filtering. See tracee-list-events(1).

**detectors** [paths...]
: List available detectors from built-in and YAML sources. See tracee-list-detectors(1).

**policies** [paths...]
: List policies from directories or files. See tracee-list-policies(1).

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

## SEE ALSO

tracee-list-events(1), tracee-list-detectors(1), tracee-list-policies(1)
