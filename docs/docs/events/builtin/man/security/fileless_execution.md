---
title: TRACEE-FILELESS-EXECUTION
section: 1
header: Tracee Event Manual
---

## NAME

**fileless_execution** - fileless execution attempt detected

## DESCRIPTION

Triggered when fileless execution is detected - running processes directly from memory rather than from files on the filesystem. This security signature identifies sophisticated evasion techniques used by adversaries to escape traditional file-based detection mechanisms.

Fileless execution allows malicious actors to operate without leaving traditional file artifacts on disk, making detection more challenging through conventional security tools that focus on file system monitoring.

## SIGNATURE METADATA

- **ID**: TRC-105
- **Version**: 1
- **Severity**: 3 (Moderate to high threat level)
- **Category**: defense-evasion
- **Technique**: Reflective Code Loading
- **MITRE ATT&CK**: T1620

## EVENT SETS

**signatures**, **defense_evasion**

## DATA FIELDS

**process_info** (*object*)
: Information about the process executing from memory

**execution_context** (*object*)
: Context information about the fileless execution attempt

## DEPENDENCIES

**System Events:**

- sched_process_exec (required): Monitors process execution attempts to detect memory-based origins

## DETECTION LOGIC

The signature monitors for:

1. **Process execution events** from `sched_process_exec`
2. **Memory origin detection** - identifies when process origin is memory rather than filesystem
3. **Fileless execution patterns** - distinguishes legitimate memory execution from malicious attempts

## USE CASES

- **Advanced persistent threat (APT) detection**: Identify sophisticated attack techniques

- **Malware analysis**: Detect fileless malware execution patterns

- **Incident response**: Investigate memory-based attack techniques

- **Security monitoring**: Detect attempts to evade file-based security controls

- **Forensic analysis**: Track fileless execution during security investigations

## THREAT LANDSCAPE

Fileless execution is increasingly used by:

- **Advanced malware**: Sophisticated threats avoiding disk artifacts
- **Living-off-the-land attacks**: Using legitimate tools for malicious purposes
- **Nation-state actors**: Advanced persistent threats using evasion techniques
- **Ransomware**: Modern ransomware variants using fileless techniques

## RELATED EVENTS

- **sched_process_exec**: Primary source event for process execution monitoring
- **dynamic_code_loading**: Related code loading detection
- **process_vm_write_code_injection**: Memory-based code injection detection
- **dropped_executable**: Executable dropping detection for comparison