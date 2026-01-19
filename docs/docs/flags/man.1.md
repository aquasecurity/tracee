--
title: TRACEE-MAN
section: 1
header: Tracee Manual Command Manual
date: 2025/01
...

## NAME

tracee **man** - Open manual pages for tracee flags and events

## SYNOPSIS

tracee **man** \<flag\> | \<event\>

## DESCRIPTION

The **man** command provides access to detailed documentation for tracee flags and events. It displays manual pages for specific flags or events directly in your terminal.

## SUBCOMMANDS

The **man** command accepts subcommands that correspond to tracee flags:

- **artifacts**, **a** - Show manual page for the --artifacts flag
- **buffers** - Show manual page for the --buffers flag
- **capabilities**, **C** - Show manual page for the --capabilities flag
- **config**, **c** - Show manual page for the --config flag
- **detectors**, **d** - Show manual page for the --detectors flag
- **enrichment**, **E** - Show manual page for the --enrichment flag
- **events**, **e** - Show manual page for the --events flag
- **list** - Show manual page for the list command
- **list-events** - Show manual page for the list events subcommand
- **list-detectors** - Show manual page for the list detectors subcommand
- **list-policies** - Show manual page for the list policies subcommand
- **logging**, **l** - Show manual page for the --logging flag
- **output**, **o** - Show manual page for the --output flag
- **policy**, **p** - Show manual page for the --policy flag
- **scope**, **s** - Show manual page for the --scope flag
- **server** - Show manual page for the --server flag
- **signatures-dir** - Show manual page for the --signatures-dir flag
- **stores** - Show manual page for the --stores flag

## EXAMPLES

- View manual page for a flag:

```console
tracee man events
tracee man output
tracee man policy
```

- View manual page for the list command:

```console
tracee man list
```

- View manual page for list subcommands:

```console
tracee man list-events
tracee man list-detectors
tracee man list-policies
```

- Using aliases:

```console
tracee m events
tracee m e
```

## SEE ALSO

tracee(1), tracee-list(1)

