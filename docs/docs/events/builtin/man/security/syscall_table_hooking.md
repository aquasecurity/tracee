---
title: TRACEE-SYSCALL-TABLE-HOOKING
section: 1
header: Tracee Event Manual
---

## NAME

**syscall_hooking** - detect system call table hooking

## DESCRIPTION

This event detects malicious hooking of the system call table in the kernel. System calls (syscalls) provide the interface between user applications and the kernel, making them a critical security boundary. By hooking the syscall table, attackers can intercept, modify, or redirect system calls, potentially gaining complete control over system operations.

This type of manipulation is a common technique used by rootkits and kernel-level malware to hide their presence, intercept system operations, and maintain persistent control. The presence of syscall table hooks, especially when combined with hidden kernel modules, strongly indicates kernel compromise.

## SIGNATURE METADATA

- **ID**: TRC-1030
- **Version**: 1
- **Severity**: 3
- **Category**: defense-evasion
- **Technique**: Rootkit
- **MITRE ID**: attack-pattern--0f20e3cb-245b-4a61-8a91-2d93f7cb0e9b
- **MITRE External ID**: T1014

## EVENT SETS

**signatures**, **default**

## DATA FIELDS

This signature event uses fields from the underlying hooked_syscalls event:

**syscall_id** (*int32*)
: ID of the hooked system call

**syscall_address** (*trace.Pointer*)
: Current address of the system call handler

**original_address** (*trace.Pointer*)
: Expected address of the system call handler

**hook_owner** (*string*)
: Module responsible for the hook

## DEPENDENCIES

- `hooked_syscalls`: Monitor syscall table modifications

## USE CASES

- **Rootkit detection**: Identify kernel-level malware

- **System integrity**: Monitor kernel function hooks

- **Security monitoring**: Detect kernel compromises

- **Incident response**: Analyze kernel modifications

## SYSCALL HOOKING

Common hooking techniques:

- **Table modification**: Direct syscall table changes
- **Jump/trampoline**: Redirect execution flow
- **Inline hooking**: Modify function code
- **IDT/GDT hooks**: Interrupt table manipulation
- **VDSO/VSYSCALL**: User-space syscall interception

## ATTACK VECTORS

Common malicious uses include:

- **Process hiding**: Conceal malicious processes
- **File hiding**: Hide malware components
- **Command interception**: Modify system operations
- **Privilege escalation**: Bypass security checks

## RISK ASSESSMENT

Risk factors to consider:

- **Kernel Level**: Direct kernel manipulation
- **System-Wide**: Affects all processes
- **Persistence**: Survives user-space security
- **Stealth**: Hard to detect from userspace

## LEGITIMATE USES

Rare but valid scenarios:

- Security monitoring
- System tracing
- Performance profiling
- Debugging tools

## MITIGATION

Recommended security controls:

- Kernel integrity monitoring
- Module signing
- Secure boot
- Memory protection
- Regular integrity checks

## RELATED EVENTS

- **proc_fops_hooking**: Proc filesystem hooks
- **hidden_kernel_module**: Hidden module detection
- **ftrace_hook**: Function tracing hooks
- **hooked_syscall**: Individual syscall hooks
