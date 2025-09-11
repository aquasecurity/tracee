---
title: TRACEE-ANTI-DEBUGGING
section: 1
header: Tracee Event Manual
---

## NAME

**anti_debugging** - detect anti-debugging technique usage

## DESCRIPTION

Triggered when processes employ anti-debugging techniques to thwart or block debugger efforts. This security signature detects the usage of the `ptrace` system call with the `PTRACE_TRACEME` request, which is commonly used by malware or commercial applications to deter analysis and reverse engineering.

When a process invokes `ptrace` with `PTRACE_TRACEME`, it's asking to be traced by its parent, which can be used to determine if it's currently being debugged. This technique is often employed as a defense evasion mechanism.

## SIGNATURE METADATA

- **Severity**: 3 (Moderate to high threat level)
- **MITRE ATT&CK**: Defense Evasion: Execution Guardrails
- **Tags**: linux, container

## EVENT SETS

**signatures**, **defense_evasion**

## DATA FIELDS

**ptrace_request** (*string*)
: The specific ptrace request used (typically "PTRACE_TRACEME")

**process_info** (*object*)
: Information about the process employing anti-debugging techniques

## DEPENDENCIES

**System Calls:**

- ptrace (required): Monitors ptrace system call for PTRACE_TRACEME requests

## USE CASES

- **Malware analysis**: Detect malware employing anti-debugging techniques

- **Security monitoring**: Identify programs attempting to evade analysis

- **Incident response**: Investigate processes using defense evasion techniques

- **Threat hunting**: Search for advanced evasion techniques in the environment

## DETECTION LOGIC

The signature monitors for:

1. **ptrace syscall invocation** with PTRACE_TRACEME request
2. **Process behavior analysis** to determine anti-debugging intent
3. **Context evaluation** to reduce false positives from legitimate debugging

## RELATED EVENTS

- **ptrace**: Primary system call monitored for anti-debugging attempts
- **process_vm_write_code_injection**: Related code injection detection
- **ptrace_code_injection**: Ptrace-based code injection detection