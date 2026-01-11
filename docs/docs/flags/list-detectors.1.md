--
title: TRACEE-LIST-DETECTORS
section: 1
header: Tracee List Detectors Command Manual
date: 2025/01
...

## NAME

tracee **list detectors** - List available detectors

## SYNOPSIS

tracee **list detectors** [paths...] [\-\-json]

## DESCRIPTION

The **list detectors** command displays all available detectors from built-in sources and YAML detector files.

Detectors analyze events and produce threat detections or derived events.

## ARGUMENTS

**[paths...]**
: Directories or files to search for YAML detectors. If not specified, uses default paths (/etc/tracee/detectors).

## FLAGS

**\-\-json**, **-j**
: Output in JSON format for scripting.

## OUTPUT COLUMNS

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

## EXAMPLES

- List all detectors from default paths:

```console
tracee list detectors
```

- List detectors from a custom directory:

```console
tracee list detectors ./my-detectors
```

- List detectors from multiple directories:

```console
tracee list detectors ./dir1 ./dir2
```

- List a single detector file:

```console
tracee list detectors ./my-detector.yaml
```

- List detectors in JSON format:

```console
tracee list detectors --json
```

- List detectors and filter with jq:

```console
tracee list detectors --json | jq '.[] | select(.severity == "CRITICAL")'
```

## SEE ALSO

tracee-list(1), tracee-list-events(1), tracee-list-policies(1)
