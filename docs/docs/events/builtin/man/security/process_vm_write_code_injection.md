---
title: TRACEE-PROCESS-VM-WRITE-INJECTION
section: 1
header: Tracee Event Manual
---

## NAME

**process_vm_write_inject** - detect code injection via process_vm_writev

## DESCRIPTION

This event detects potential code injection attacks using the process_vm_writev system call. This syscall allows one process to write directly into another process's memory space, which while legitimate in some cases, is also a common technique for injecting malicious code.

The event specifically monitors for cross-process memory writes where the source and destination process IDs differ, which could indicate an attempt to execute arbitrary code within the context of another process.

## SIGNATURE METADATA

- **ID**: TRC-1025
- **Version**: 1
- **Severity**: 3
- **Category**: defense-evasion
- **Technique**: Process Injection
- **MITRE ID**: attack-pattern--43e7dc91-05b2-474c-b9ac-2ed4fe101f4d
- **MITRE External ID**: T1055

## EVENT SETS

**signatures**, **default**

## DATA FIELDS

This signature event uses fields from the underlying process_vm_writev event:

**src_pid** (*int32*)
: Process ID performing the write

**dst_pid** (*int32*)
: Process ID being written to

**local_iov** (*[]iovec*)
: Source memory segments

**remote_iov** (*[]iovec*)
: Destination memory segments

**flags** (*uint32*)
: Operation flags

## DEPENDENCIES

- `process_vm_writev`: Monitor cross-process memory writes

## USE CASES

- **Code injection detection**: Identify process memory tampering

- **Process integrity**: Monitor unauthorized memory writes

- **Malware detection**: Spot injection-based malware

- **Runtime protection**: Prevent unauthorized code execution

## INJECTION TECHNIQUES

Common injection methods:

- **Direct memory writes**: Using process_vm_writev
- **Shellcode injection**: Writing executable code
- **DLL injection**: Loading malicious libraries
- **Thread injection**: Creating remote threads
- **Reflective injection**: Self-loading code

## ATTACK VECTORS

Common malicious uses include:

- **Code execution**: Running arbitrary code
- **Process hollowing**: Replacing process memory
- **DLL hijacking**: Forcing library loads
- **Credential theft**: Accessing process memory

## RISK ASSESSMENT

Risk factors to consider:

- **Process Context**: Runs as target process
- **Permission Bypass**: Inherits process privileges
- **Detection Evasion**: Blends with process activity
- **Memory Persistence**: Survives disk scans

## LEGITIMATE USES

Valid cross-process writes:

- Debuggers
- Performance profilers
- Memory analysis tools
- IPC mechanisms

## MITIGATION

Recommended security controls:

- Process isolation
- Memory protection
- ASLR enforcement
- Integrity monitoring
- Behavior analysis

## RELATED EVENTS

- **security_file_mprotect**: Memory protection changes
- **mem_prot_alert**: Memory protection alerts
- **dynamic_code_loading**: Runtime code execution
- **process_execute**: Process creation tracking
