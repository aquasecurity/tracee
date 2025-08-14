---
title: TRACEE-PROC-MEM-CODE-INJECTION
section: 1
header: Tracee Event Manual
---

## NAME

**proc_mem_code_injection** - detect code injection through /proc/[pid]/mem

## DESCRIPTION

This event detects attempts to inject code into processes by writing to their memory through the /proc/[pid]/mem interface. This technique allows direct manipulation of process memory and is commonly used by attackers to inject malicious code, modify process behavior, or establish persistence.

Code injection through /proc/[pid]/mem is particularly dangerous as it allows attackers to execute arbitrary code within the context of another process, potentially bypassing security controls or escalating privileges by targeting privileged processes.

## SIGNATURE METADATA

- **ID**: TRC-1024
- **Version**: 1
- **Severity**: 3
- **Category**: defense-evasion
- **Technique**: Proc Memory
- **MITRE ID**: attack-pattern--d201d4cc-214d-4a74-a1ba-b3fa09fd4591
- **MITRE External ID**: T1055.009

## EVENT SETS

**signatures**, **default**

## DATA FIELDS

This signature event uses fields from the underlying security_file_open event:

**pathname** (*string*)
: Path to the process memory file being written

**flags** (*string*)
: File access flags indicating write attempt

**pid** (*int32*)
: Process ID performing the injection

**target_pid** (*int32*)
: Process ID being injected into

## DEPENDENCIES

- `security_file_open`: Monitor memory file write attempts

## USE CASES

- **Code injection detection**: Identify memory-based attacks

- **Process integrity**: Monitor unauthorized modifications

- **Malware detection**: Spot injection-based malware

- **Runtime protection**: Prevent unauthorized code execution

## INJECTION TECHNIQUES

Common injection methods:

- **Shellcode injection**: Writing executable code
- **Library injection**: Loading malicious libraries
- **Function hooking**: Modifying function pointers
- **Return-oriented programming**: Chain existing code
- **Thread injection**: Creating remote threads

## ATTACK VECTORS

Common malicious uses include:

- **Code execution**: Running arbitrary code
- **Process hollowing**: Replacing process memory
- **Function hooking**: Intercepting calls
- **Persistence**: Maintaining access
- **Privilege escalation**: Targeting privileged processes

## RISK ASSESSMENT

Risk factors to consider:

- **Process Context**: Runs as target process
- **Permission Bypass**: Inherits process privileges
- **Detection Evasion**: Memory-only execution
- **System Impact**: Affects critical processes

## LEGITIMATE USES

Valid memory modification scenarios:

- Debuggers
- Profilers
- Hot patching
- Runtime instrumentation

## MITIGATION

Recommended security controls:

- Process isolation
- Memory protection
- Write restrictions
- Integrity monitoring
- Behavior analysis

## RELATED EVENTS

- **proc_mem_access**: Process memory access
- **process_vm_write_inject**: Process memory writes
- **dynamic_code_loading**: Runtime code execution
- **mem_prot_alert**: Memory protection alerts
