
# `sched_debug` File Reconnaissance Detection

## Intro

The `SchedDebugRecon` signature aims to detect when the `sched_debug` file, a
file that offers insights about the CPU and ongoing processes, is read. Threat
actors could tap into this file to glean valuable information about a system's
operational dynamics.

## Description

The `sched_debug` file, commonly found at `/proc/sched_debug` and
`/sys/kernel/debug/sched/debug`, provides detailed information about the
scheduler's inner workings, including insights about the CPU and ongoing
processes.

Though it's primarily intended for debugging purposes, adversaries can exploit
it for reconnaissance, profiling the system before executing a potentially
harmful action.

## Purpose

This signature's primary purpose is to identify unauthorized or suspicious reads
on the `sched_debug` file. Recognizing such access can serve as an early
warning, flagging a possible attempt at system reconnaissance.

## Metadata

- **ID**: TRC-1029
- **Version**: 1
- **Name**: sched_debug CPU file was read
- **EventName**: sched_debug_recon
- **Description**: Detects when the `sched_debug` file is accessed for reading. Given the sensitive information this file contains, unauthorized reads could imply that an adversary is attempting to gather intelligence about the system.
- **Properties**:
  - **Severity**: 1 (Lowest threat level)
  - **Category**: discovery
  - **Technique**: Container and Resource Discovery
  - **Kubernetes_Technique**: N/A
  - **id**: attack-pattern--0470e792-32f8-46b0-a351-652bc35e9336
  - **external_id**: T1613

## Findings

If a match is detected, meaning that the `sched_debug` file is read, a `Finding`
is generated. This finding encompasses detailed metadata about the potential
threat, enabling system administrators or security professionals to take further
action if necessary.

## Events Used

This signature focuses on a single event:

- `security_file_open`: This event fires when a file is accessed. The signature
determines if the `sched_debug` file is being read by checking the file's
pathname and flags.
