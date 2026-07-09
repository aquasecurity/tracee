--
title: TRACEE-LIST-FILTERABLE
section: 1
header: Tracee List Filterable Command Manual
date: 2026/07
...

## NAME

tracee **list filterable** - Show which event fields filter in the kernel vs user space

## SYNOPSIS

tracee **list filterable** \<event...\> [\-\-json]

tracee **list filterable** \<policy-path...\> [\-\-config FILE] [\-\-json]

tracee **list filterable** \-\-policy PATH [\-\-policy PATH...] [\-\-config FILE] [\-\-json]

## DESCRIPTION

The **list filterable** command shows where each of an event's filters is enforced.

Kernel filters drop non-matching instances **before** the event is submitted (the cheapest filtering); user-space filters run **after** submission (the event is collected, then filtered). Scope filters (**comm**, **uid**, **pid**, **mntns**, **pidns**, ...) and the **pathname** data filter are kernel-enforced; other data fields and return-value filters run in user space.

The command has two modes.

## STATIC MODE

Given one or more event names, classify each event's fields as kernel- or user-space-filterable:

```console
tracee list filterable security_file_open
tracee list filterable sched_process_exec security_file_open --json
```

## POLICY-AWARE MODE

Given a policy file or directory (detected automatically) or **\-\-policy**, the real rule set is computed - dependency expansion, bootstrap selections, cross-policy union, and overflow - and, per selected event, the report states whether in-kernel filtering is **effective**, **defeated** by a broad (unfiltered) co-selector of the same event, or lost to **overflow** (an event selected by more than 64 rules, which the kernel must submit in full). Per-policy attribution and a hint are included where relevant.

```console
tracee list filterable ./policies
tracee list filterable ./my-policy.yaml
tracee list filterable --policy ./p1.yaml --policy ./p2.yaml --json
```

## OPTIONS

**\-\-policy** PATH
: Analyze policy file(s) or director(ies) instead of listing an event's fields. Repeatable. A positional policy path is detected automatically, so this flag is optional.

**\-\-config** FILE
: A Tracee config file whose settings affect the report. The configured detectors' declared base-event scope filters are folded in, and the DNS cache force-collects **net_packet_dns**. Process-store and capture settings add only internal control-plane events (a separate perf buffer), so they do not change the report. Without **\-\-config** the policies are analyzed on their own.

**\-\-json**, **-j**
: Output in JSON format for scripting.

## EXAMPLES

- Classify a single event's fields:

```console
tracee list filterable security_file_open
```

- Classify several events as JSON:

```console
tracee list filterable sched_process_exec security_file_open --json
```

- Analyze a policy directory:

```console
tracee list filterable ./policies
```

- Analyze specific policy files:

```console
tracee list filterable --policy ./p1.yaml --policy ./p2.yaml
```

- Analyze policies in the context of a real scenario (detectors and DNS cache):

```console
tracee list filterable ./policies --config /etc/tracee/tracee.yaml
```

## SEE ALSO

tracee-list(1), tracee-list-deps(1), tracee-list-events(1), tracee-list-policies(1)
