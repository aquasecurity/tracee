--
title: TRACEE-LIST-POLICIES
section: 1
header: Tracee List Policies Command Manual
date: 2025/01
...

## NAME

tracee **list policies** - List policies from a directory

## SYNOPSIS

tracee **list policies** [paths...] [\-\-json]

## DESCRIPTION

The **list policies** command displays all policies from the specified directories or files.

Policies define what events to trace, how to filter them, and what actions to take.

## ARGUMENTS

**[paths...]**
: Directories or files to search for policies. If not specified, uses default path (/etc/tracee/policies).

## FLAGS

**\-\-json**, **-j**
: Output in JSON format for scripting.

## OUTPUT COLUMNS

**Name**
: Policy name

**Description**
: Policy description from annotations

**Scope**
: Summary of scope filters

**Rules**
: Number of rules in the policy

## EXAMPLES

- List policies from default path:

```console
tracee list policies
```

- List policies from a custom directory:

```console
tracee list policies ./my-policies
```

- List policies from multiple directories:

```console
tracee list policies ./dir1 ./dir2
```

- List a single policy file:

```console
tracee list policies ./my-policy.yaml
```

- List policies in JSON format:

```console
tracee list policies --json
```

## SEE ALSO

tracee-list(1), tracee-list-events(1), tracee-list-detectors(1), tracee-policy(1)
