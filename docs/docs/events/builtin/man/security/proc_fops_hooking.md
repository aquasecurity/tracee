---
title: TRACEE-PROC-FOPS-HOOKING
section: 1
header: Tracee Event Manual
---

## NAME

**proc_fops_hooking** - detect proc filesystem file operations hooking

## DESCRIPTION

This event detects malicious hooking of file operations in the proc filesystem. The proc filesystem is a pseudo-filesystem that provides an interface to kernel data structures by representing processes and system information as files. Attackers, particularly rootkits, can hook these file operations to manipulate how the system interacts with process information.

By hooking proc filesystem operations, malware can hide processes, modify system information, and interfere with system monitoring tools like ps and top. This type of manipulation often indicates kernel compromise and is a common technique used by rootkits for stealth and persistence.

## SIGNATURE METADATA

- **ID**: TRC-1020
- **Version**: 1
- **Severity**: 3
- **Category**: defense-evasion
- **Technique**: Rootkit
- **MITRE ID**: attack-pattern--0f20e3cb-245b-4a61-8a91-2d93f7cb0e9b
- **MITRE External ID**: T1014

## EVENT SETS

**signatures**, **default**

## DATA FIELDS

This signature event uses fields from the underlying hooked_proc_fops event:

**file_path** (*string*)
: Path in procfs being hooked

**fops_address** (*trace.Pointer*)
: Address of the hooked file operations structure

**hook_address** (*trace.Pointer*)
: Address of the hook function

**symbol_owner** (*string*)
: Module owning the hook function

## DEPENDENCIES

- `hooked_proc_fops`: Monitor proc filesystem operation hooks

## USE CASES

- **Rootkit detection**: Identify kernel-level malware

- **Process hiding**: Detect process manipulation attempts

- **System integrity**: Monitor kernel function hooks

- **Anti-debugging**: Identify anti-analysis techniques

## PROC FILESYSTEM

Critical aspects of procfs:

- Process information interface
- Kernel data structures
- System statistics
- Runtime configurations
- Hardware information

## ATTACK VECTORS

Common malicious uses include:

- **Process hiding**: Conceal malicious processes
- **System info manipulation**: Hide system activity
- **Anti-forensics**: Prevent analysis
- **Persistence**: Maintain kernel-level access

## RISK ASSESSMENT

Risk factors to consider:

- **Kernel Level**: Direct kernel manipulation
- **Stealth Capability**: Hides from tools
- **System Impact**: Affects all monitoring
- **Recovery Difficulty**: Complex remediation

## HOOKING TECHNIQUES

Common hooking methods:

- **Direct modification**: Change function pointers
- **Inline hooking**: Modify function code
- **Jump/trampoline**: Redirect execution
- **Table modification**: Alter operation tables

## MITIGATION

Recommended security controls:

- Kernel integrity monitoring
- Function pointer validation
- Memory protection
- Module signing
- Regular integrity checks

## RELATED EVENTS

- **hooked_syscall**: System call table hooks
- **hidden_kernel_module**: Hidden module detection
- **symbols_loaded**: Kernel symbol loading
- **ftrace_hook**: Function tracing hooks
