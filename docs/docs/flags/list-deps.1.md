--
title: TRACEE-LIST-DEPS
section: 1
header: Tracee List Deps Command Manual
date: 2026/07
...

## NAME

tracee **list deps** - Show an event's dependency graph

## SYNOPSIS

tracee **list deps** \<event\> [event...] [\-\-format FORMAT]

## DESCRIPTION

The **list deps** command shows the dependency graph of one or more events: the base events each one needs, annotated with probe and kernel-symbol dependencies.

Detector and derived events expand into the base events they consume, so this also reveals which raw events a detector chain ultimately rests on.

## OPTIONS

**\-\-format**, **-f** FORMAT
: Output format. One of:

    **tree**
    : (default) an ASCII indented tree.

    **mermaid**
    : a fenced mermaid flowchart, ready to paste into documentation.

    **json**
    : structured output for scripting.

## EXAMPLES

- Show the dependencies of a network event:

```console
tracee list deps net_packet_icmp
```

- Render a mermaid diagram:

```console
tracee list deps sched_process_exec --format mermaid
```

- Emit JSON for scripting:

```console
tracee list deps security_file_open --format json
```

- Inspect several events at once:

```console
tracee list deps net_packet_icmp security_file_open
```

## SEE ALSO

tracee-list(1), tracee-list-filterable(1), tracee-list-events(1), tracee-list-detectors(1)
