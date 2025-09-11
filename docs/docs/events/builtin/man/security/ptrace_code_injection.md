---
title: TRACEE-PTRACE-CODE-INJECTION
section: 1
header: Tracee Event Manual
---

## NAME

**ptrace_code_injection** - ptrace-based code injection detection

## DESCRIPTION

Triggered when code injection attempts are detected using the `ptrace` system call. This security signature specifically monitors for `PTRACE_POKETEXT` and `PTRACE_POKEDATA` requests, which are commonly used to alter target process memory and inject malicious code.

Code injection through ptrace allows attackers to execute arbitrary code within the context of another process, evading detection and leveraging the permissions of the injected process. This technique is particularly dangerous as malicious operations appear to originate from legitimate processes.

## SIGNATURE METADATA

- **ID**: TRC-103
- **Version**: 1
- **Severity**: 3 (Moderate to high threat level)
- **Category**: defense-evasion
- **Technique**: Ptrace System Calls
- **MITRE ATT&CK**: T1055.008

## EVENT SETS

**signatures**, **defense_evasion**

## DATA FIELDS

**ptrace_request** (*string*)
: The specific ptrace request used (PTRACE_POKETEXT or PTRACE_POKEDATA)

**target_process** (*object*)
: Information about the process being injected into

**injector_process** (*object*)
: Information about the process performing the injection

## DEPENDENCIES

**System Events:**

- ptrace (required): Monitors ptrace system call for specific memory manipulation requests

## DETECTION LOGIC

The signature monitors for:

1. **Ptrace system calls** with specific request types
2. **PTRACE_POKETEXT requests**: Writing to target process text/code segments
3. **PTRACE_POKEDATA requests**: Writing to target process data segments
4. **Memory modification patterns**: Identifying potential code injection signatures

## USE CASES

- **Malware detection**: Identify malware using process injection techniques

- **Advanced threat hunting**: Detect sophisticated evasion mechanisms

- **Incident response**: Investigate process manipulation during security incidents

- **Security monitoring**: Detect unauthorized process memory modifications

- **Forensic analysis**: Analyze code injection techniques used in attacks

## PTRACE REQUESTS MONITORED

- **PTRACE_POKETEXT**: Write data to target process text segment (code injection)
- **PTRACE_POKEDATA**: Write data to target process data segment (data modification)

## ATTACK SCENARIOS

Common code injection scenarios:

- **Shellcode injection**: Injecting executable shellcode into target processes
- **DLL injection**: Loading malicious libraries into target processes
- **Process hollowing**: Replacing legitimate process code with malicious code
- **API hooking**: Intercepting and modifying function calls
- **Return-oriented programming**: Chaining existing code gadgets

## LEGITIMATE USE CASES

Ptrace is also used legitimately by:

- **Debuggers**: GDB, LLDB for debugging applications
- **Profilers**: Performance analysis tools
- **Security tools**: Anti-malware and monitoring software
- **System administration**: Process monitoring and management tools

## EVASION TECHNIQUES

Attackers may attempt to evade detection through:

- **Timing-based evasion**: Spacing out injection operations
- **Process selection**: Targeting specific processes less likely to be monitored
- **Small payload injection**: Injecting minimal code to avoid detection thresholds
- **Legitimate tool abuse**: Using debugging tools for malicious purposes

## MITIGATION STRATEGIES

- **Process isolation**: Use containers and sandboxing
- **Privilege restriction**: Limit ptrace capabilities through seccomp/AppArmor
- **Monitoring**: Deploy comprehensive process monitoring
- **Yama LSM**: Use Yama security module to restrict ptrace usage

## RELATED EVENTS

- **ptrace**: Primary system call monitored for injection attempts
- **process_vm_write_code_injection**: Alternative code injection detection method
- **anti_debugging**: Related anti-analysis technique detection
- **suspicious_syscall_source**: Unusual syscall source location detection