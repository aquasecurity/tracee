---
title: TRACEE-KERNEL-MODULE-LOADING
section: 1
header: Tracee Event Manual
---

## NAME

**kernel_module_loading** - kernel module loading detection

## DESCRIPTION

Triggered when kernel module loading is detected. This security signature monitors for kernel module loading activities, which can be legitimate system administration tasks or potentially malicious operations by adversaries seeking elevated privileges and stealth capabilities.

Kernel modules operate with elevated privileges and can directly interact with the operating system core. While legitimate modules extend kernel functionality, malicious modules can enable rootkits, hide processes, intercept system calls, and evade detection by operating within kernel space.

## SIGNATURE METADATA

- **ID**: TRC-1017
- **Version**: 1
- **Severity**: 2 (Moderate threat level)
- **Category**: persistence
- **Technique**: Kernel Modules and Extensions
- **MITRE ATT&CK**: T1547.006

## EVENT SETS

**signatures**, **persistence**

## DATA FIELDS

**module_info** (*object*)
: Information about the kernel module being loaded

**loading_context** (*object*)
: Context information about the module loading operation

## DEPENDENCIES

**System Events:**

- init_module (required): Monitors kernel module initialization
- security_kernel_read_file (required): Monitors kernel file read operations for "kernel-module" type files

## DETECTION LOGIC

The signature monitors for:

1. **Module initialization events** from `init_module` system calls
2. **Kernel file reading** from `security_kernel_read_file` with "kernel-module" type
3. **Loading pattern analysis** to distinguish legitimate from suspicious module loading

## USE CASES

- **Rootkit detection**: Identify malicious kernel modules used by rootkits

- **System integrity monitoring**: Track unauthorized kernel modifications

- **Incident response**: Investigate persistence mechanisms during security incidents

- **Compliance monitoring**: Ensure only authorized kernel modules are loaded

- **Forensic analysis**: Analyze kernel-level persistence techniques

## LEGITIMATE VS. MALICIOUS LOADING

**Legitimate scenarios**:

- Hardware driver installation
- System feature activation (e.g., VPN, virtualization)
- Administrative tools requiring kernel access
- Security software components

**Suspicious indicators**:

- Loading from unusual locations
- Unsigned or unknown modules
- Loading during suspicious timeframes
- Modules with obfuscated names
- Concurrent with other suspicious activities

## DETECTION CHALLENGES

- **False positives**: Legitimate administrative activities
- **Timing**: Detection after module is already loaded
- **Evasion**: Advanced modules may use anti-detection techniques
- **Context**: Distinguishing legitimate from malicious loading

## RELATED EVENTS

- **init_module**: Primary system call for module loading
- **security_kernel_read_file**: Kernel file access monitoring
- **hidden_kernel_module**: Detection of hidden modules after loading
- **module_load**: Alternative module loading detection
- **finit_module**: File-based module loading system call