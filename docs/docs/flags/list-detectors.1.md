--
title: TRACEE-LIST-DETECTORS
section: 1
header: Tracee List Detectors Command Manual
date: 2025/01
...

## NAME

tracee **list detectors** - List available detectors and shared lists

## SYNOPSIS

tracee **list detectors** [paths...] [\-\-json]

## DESCRIPTION

The **list detectors** command displays all available detectors and shared lists from built-in sources and YAML files.

Detectors analyze events and produce threat detections or derived events.

Shared lists are reusable value sets (e.g., shell binaries, sensitive paths) that YAML detectors can reference in CEL expressions.

## ARGUMENTS

**[paths...]**
: Directories or files to search for YAML detectors and lists. If not specified, uses default paths (/etc/tracee/detectors).

## FLAGS

**\-\-json**, **-j**
: Output in JSON format for scripting.

## OUTPUT

The command displays two sections:

### Detectors

**ID**
: Unique detector identifier (e.g., TRC-001, DRV-001)

**Name**
: Detector event name

**Severity**
: Threat severity level (info, low, medium, high, critical)

**Required Events**
: Events the detector needs to receive

**MITRE**
: MITRE ATT&CK technique ID if applicable

### Shared Lists

**Name**
: List variable name (uppercase snake_case, e.g., SHELL_BINARIES)

**Values**
: Number of values in the list

## JSON OUTPUT

When using `--json`, the output structure is:

```json
{
  "detectors": [
    {
      "id": "yaml-001",
      "name": "suspicious_exec",
      "severity": "HIGH",
      "required_events": ["sched_process_exec"],
      "mitre_technique": "T1059"
    }
  ],
  "lists": [
    {"name": "SHELL_BINARIES", "value_count": 6},
    {"name": "SENSITIVE_PATHS", "value_count": 12}
  ]
}
```

## EXAMPLES

- List all detectors and lists from default paths:

```console
tracee list detectors
```

- List detectors and lists from a custom directory:

```console
tracee list detectors ./my-detectors
```

- List detectors and lists from multiple directories:

```console
tracee list detectors ./dir1 ./dir2
```

- List detectors and lists in JSON format:

```console
tracee list detectors --json
```

- Filter critical detectors with jq:

```console
tracee list detectors --json | jq '.detectors[] | select(.severity == "CRITICAL")'
```

- List shared list names with jq:

```console
tracee list detectors --json | jq '.lists[].name'
```

## SEE ALSO

tracee-list(1), tracee-list-events(1), tracee-list-policies(1)
