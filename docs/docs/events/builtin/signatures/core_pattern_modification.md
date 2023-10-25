
# Core dumps configuration file modification detection

## Intro

The `CorePatternModification` signature detects unauthorized changes to the core
dump configuration file (`core_pattern`), an integral component within Linux
systems.

## Description

In Linux, the core dump mechanism captures the memory content of a crashed
program, typically written to disk. This aids in debugging and analyzing the
cause of the crash. The location and format of these core dumps are defined by
the `core_pattern` configuration file located within `/proc/sys/kernel/`.

Any unauthorized modification to the `core_pattern` could be indicative of an
adversary attempting to exploit kernel's core dump capabilities, particularly
for container escape maneuvers. Such techniques can allow attackers to run
arbitrary commands when a program crashes, and as such, any changes to the
`core_pattern` should be monitored closely.

The `CorePatternModification` signature specifically identifies unauthorized
attempts to modify this configuration file.

## Purpose

The primary intent of this signature is to identify and raise alerts for
unauthorized modifications to the `core_pattern` file. By keeping an eye on
alterations to this file, the system can preemptively counter attempts at
exploiting the core dump functionality, especially for container escapes or
other privilege escalation tactics.

## Metadata

- **ID**: TRC-1011
- **Version**: 1
- **Name**: Core dumps configuration file modification detected
- **EventName**: core_pattern_modification
- **Description**: The signature observes any alterations to the core dump configuration file (`core_pattern`). Any unauthorized change can be a precursor to an attacker leveraging kernel's core dump mechanisms for nefarious ends, such as container escapes.
- **Properties**:
  - **Severity**: 3 (Moderate threat level)
  - **Category**: privilege-escalation
  - **Technique**: Escape to Host
  - **Kubernetes_Technique**: N/A
  - **id**: attack-pattern--4a5b7ade-8bb5-4853-84ed-23f262002665
  - **external_id**: T1611

## Findings

Upon detecting a potential threat, the signature returns a `Finding` data
structure, which includes:

- **SigMetadata**: Metadata that offers insights about the threat based on the signature.
- **Event**: Specific details of the event that prompted the signature's activation.
- **Data**: Currently set to `nil`, indicating that there isn't any additional data linked with this structure.

## Events Used

This signature is contingent on the following event:

- `security_file_open`: This event is triggered when a file is accessed. The
signature analyzes the accessed file's pathname and associated flags to discern
if the `core_pattern` file undergoes any modification.
