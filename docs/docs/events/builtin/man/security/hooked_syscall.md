---
title: TRACEE-HOOKED-SYSCALL
section: 1
header: Tracee Event Manual
---

## NAME

**hooked_syscall** - system call hooking detection

## DESCRIPTION

Triggered when system call table hooking is detected in the Linux kernel. This event monitors the syscall table to verify that each system call points to its corresponding legitimate function symbol, helping identify kernel code modifications often used by rootkits and other malicious software.

System call hooking is a common technique used by malware to intercept and modify system calls, enabling activities such as hiding processes, files, network connections, or escalating privileges while remaining undetected by traditional monitoring tools.

This event is useful for:

- **Rootkit detection**: Identify kernel-level rootkits that hook system calls
- **System integrity monitoring**: Verify kernel code integrity
- **Security incident response**: Detect unauthorized kernel modifications

## EVENT SETS

**derived**, **security_alert**

## DATA FIELDS

**syscall_number** (*integer*)
: The system call number that was found to be hooked

**expected_address** (*string*)
: The expected memory address of the legitimate syscall function

**actual_address** (*string*)
: The actual memory address found in the syscall table

**hook_target** (*string*)
: Information about the hooking function or module if identifiable

## DEPENDENCIES

**Detection Method:**

- Uprobe-based detection on various system calls
- Kernel symbol table verification
- Syscall table integrity checking

## USE CASES

- **Rootkit detection**: Identify kernel-level malware that hooks system calls

- **System integrity monitoring**: Continuous verification of syscall table integrity

- **Incident response**: Investigate unauthorized kernel modifications

- **Security auditing**: Verify system call table consistency

- **Forensic analysis**: Detect evidence of advanced persistent threats

## DETECTION METHODOLOGY

The event performs:

1. **Syscall table scanning**: Systematic verification of syscall table entries
2. **Symbol verification**: Comparison of actual vs. expected function addresses
3. **Hook identification**: Detection of unauthorized modifications to syscall handlers
4. **Integrity validation**: Verification that syscalls point to legitimate kernel functions

## SECURITY IMPLICATIONS

System call hooking can enable:

- **Process hiding**: Malware hiding processes from system monitoring
- **File hiding**: Concealing malicious files from filesystem operations
- **Network hiding**: Hiding network connections and traffic
- **Privilege escalation**: Bypassing security controls and access restrictions
- **Anti-forensics**: Evading detection and analysis tools

## MITIGATION STRATEGIES

- **Kernel integrity protection**: Use technologies like KGDB, KASLR
- **Control Flow Integrity (CFI)**: Hardware-based protection mechanisms
- **Hypervisor-based protection**: Monitor kernel from hypervisor level
- **Regular integrity checks**: Periodic verification of critical kernel structures

## RELATED EVENTS

- **syscall_table_hooking**: Alternative detection method for syscall table modifications
- **ftrace_hook**: Function tracing hook detection
- **hidden_kernel_module**: Hidden kernel module detection
- **symbols_collision**: Symbol conflict detection