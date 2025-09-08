---
title: TRACEE-MEM-PROT-ALERT
section: 1
header: Tracee Event Manual
---

## NAME

**mem_prot_alert** - suspicious memory protection change detection

## DESCRIPTION

Triggered when memory region protection changes are detected that are suspicious for malicious activity or that expose memory to potential exploitation. This security signature identifies memory access protection changes that might enable code injection, allow dynamic code execution, or create other security vulnerabilities.

Memory protection changes are critical security indicators as they can indicate exploitation attempts, code injection, or evasion techniques. This event provides detailed alerts about specific suspicious patterns in memory protection modifications.

## SIGNATURE METADATA

- **ID**: TRC-1019
- **Version**: 1
- **Severity**: 2 (Moderate threat level)
- **Category**: defense-evasion
- **Technique**: Exploitation for Privilege Escalation
- **MITRE ATT&CK**: T1068

## EVENT SETS

**signatures**, **memory**, **defense_evasion**

## DATA FIELDS

**alert** (*uint32*)
: The specific alert identifier (parsed to meaningful string with parse-args flag)

**addr** (*trace.Pointer*)
: The start address of the memory region where the alert occurred

**len** (*uint64*)
: The length of the memory region where the alert occurred

**prot** (*integer*)
: The new access protection for the memory region

**prev_prot** (*integer*)
: The previous access protection of the memory region

**pathname** (*string*, optional)
: The path of the file related to the memory region (if file-backed)

**dev** (*uint32*, optional)
: The device of the file related to the memory region (if file-backed)

**inode** (*uint64*, optional)
: The inode of the file related to the memory region (if file-backed)

**ctime** (*uint64*, optional)
: The last change time of the file related to the memory region (if file-backed)

## DEPENDENCIES

**LSM Hooks:**

- security_mmap_addr (required): Monitors memory mapping operations for suspicious permissions
- security_file_mprotect (required): Monitors memory protection changes

**Tracepoints:**

- sys_enter (required): Extracts syscall arguments for deeper analysis

## ALERT TYPES

Current alert categories and their meanings:

**"Mmaped region with W+E permissions!"**
: Memory mapping operation creating a region with both write and execute permissions, enabling dynamic code execution

**"Protection changed to Executable!"**
: Memory region protection changed to allow execution after having different permissions previously

**"Protection changed from E to W+E!"**
: Memory region changed from execute-only to write+execute, enabling dynamic code modification and execution

**"Protection changed from W to E!"**
: Memory region changed from write-only to execute-only, potentially indicating evasion attempt after code preparation

## USE CASES

- **Exploit detection**: Identify code injection and memory corruption exploits

- **Malware analysis**: Monitor malware attempting to execute injected code

- **Incident response**: Investigate suspicious memory operations during security events

- **Vulnerability research**: Analyze exploitation techniques and memory manipulation

- **Runtime security**: Detect real-time attempts to bypass memory protections

## ATTACK SCENARIOS

Common attack patterns triggering alerts:

- **Shellcode injection**: Making heap/stack regions executable for shellcode
- **ROP/JOP preparation**: Preparing memory regions for return/jump-oriented programming
- **Process injection**: Modifying target process memory for code injection
- **Dynamic code loading**: Malware unpacking and loading additional payloads
- **JIT spraying**: Preparing just-in-time compiled code for exploitation

## MEMORY PROTECTION COMBINATIONS

Suspicious protection combinations:

- **W+E (Write+Execute)**: Most dangerous, allows dynamic code creation and execution
- **W→E transitions**: Writing code then making it executable (common in JIT but also exploits)
- **E→W+E transitions**: Adding write permissions to executable regions
- **Large anonymous W+E regions**: Unusual for legitimate applications

## LEGITIMATE SCENARIOS

Some legitimate uses that may trigger alerts:

- **JIT compilers**: Languages like Java, .NET, JavaScript with dynamic compilation
- **Dynamic code generation**: Template engines and runtime code generators
- **Debugging tools**: Debuggers modifying memory for breakpoints and analysis
- **Runtime loaders**: Dynamic library loading and symbol resolution
- **Self-modifying code**: Some legitimate applications using code modification

## EVASION TECHNIQUES

Attackers may attempt to evade detection:

- **Small region modifications**: Making small changes to avoid detection thresholds
- **Timing-based evasion**: Spacing out protection changes over time
- **Legitimate tool abuse**: Using debuggers or JIT environments for malicious purposes
- **Memory fragmentation**: Splitting malicious code across multiple regions

## MITIGATION STRATEGIES

- **DEP/NX enforcement**: Hardware-based execution prevention for data pages
- **ASLR**: Address Space Layout Randomization to complicate exploitation
- **CFI**: Control Flow Integrity to prevent ROP/JOP attacks
- **W^X policies**: Enforce write-xor-execute memory policies
- **Memory tagging**: Hardware memory tagging for exploit detection

## RELATED EVENTS

- **security_mmap_addr**: Memory mapping security checks
- **security_file_mprotect**: Memory protection change security events
- **mmap**: Memory mapping system call
- **mprotect**: Memory protection change system call