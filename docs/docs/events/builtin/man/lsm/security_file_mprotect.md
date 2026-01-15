---
title: TRACEE-SECURITY-FILE-MPROTECT
section: 1
header: Tracee Event Manual
---

## NAME

**security_file_mprotect** - memory protection change security check

## DESCRIPTION

Triggered when there is an attempt to change the access protection of a memory region through the Linux Security Module (LSM) hook. This event occurs during permissions checks for operations like `mprotect` or `pkey_mprotect` system calls, capturing attempts to modify memory access permissions.

Memory protection changes are critical security events as they can indicate code injection, exploitation attempts, or legitimate application behavior like JIT compilation. The event provides detailed information about the memory addresses, protection changes, and associated files.

## EVENT SETS

**lsm_hooks**

## DATA FIELDS

**pathname** (*string*)
: The path of the file associated with the memory region (if file-backed)

**prot** (*int32*)
: The new access protection for the memory region (decoded to string if decoded-data enabled)

**ctime** (*uint64*)
: The creation time of the file associated with the memory region

**prev_prot** (*int32*)
: The previous access protection for the memory region (decoded to string if decoded-data enabled)

**addr** (*trace.Pointer*)
: The start of virtual memory address where protection change is requested

**len** (*uint64*)
: The length of the memory region to apply the new protection

**pkey** (*int32*, optional)
: The protection key used for the operation (only available for `pkey_mprotect` syscall)

## DEPENDENCIES

- `mprotect`
- `pkey_mprotect`

## USE CASES

- **Exploit detection**: Identify attempts to make data pages executable for code injection

- **JIT compilation monitoring**: Track legitimate just-in-time compilation activities

- **Memory forensics**: Analyze memory protection patterns during incident investigation

- **Security auditing**: Monitor applications making unusual memory protection changes

- **Malware analysis**: Identify malware attempting to modify memory protections

## MEMORY PROTECTION FLAGS

Common protection flags (prot values):

- **PROT_NONE (0)**: No access permissions
- **PROT_READ (1)**: Read access
- **PROT_WRITE (2)**: Write access
- **PROT_EXEC (4)**: Execute access
- **Combinations**: PROT_READ|PROT_WRITE (3), PROT_READ|PROT_EXEC (5), etc.

## SUSPICIOUS PATTERNS

Monitor for potentially malicious protection changes:

- **Making data executable**: Changing non-executable pages to executable (W→X, RW→RX)
- **Removing write protection**: Making code pages writable for modification
- **Anonymous memory execution**: Making heap/stack regions executable
- **Large memory operations**: Protecting unusually large memory regions
- **Frequent changes**: Rapid succession of protection modifications

## LEGITIMATE USE CASES

Common legitimate scenarios:

- **JIT compilers**: Java, .NET, JavaScript engines modifying code pages
- **Dynamic loaders**: Runtime library loading and symbol resolution
- **Garbage collectors**: Memory management in managed languages
- **Code generation**: Template engines and runtime code generation
- **Self-modifying code**: Some legitimate applications and libraries

## MEMORY REGIONS

Different memory region types:

- **File-backed mappings**: Memory mapped from files (pathname provided)
- **Anonymous mappings**: Heap, stack, or anonymous memory (no pathname)
- **Shared mappings**: Memory shared between processes
- **Private mappings**: Process-private memory regions

## EXPLOITATION TECHNIQUES

Memory protection changes in attacks:

- **Code injection**: Making injected shellcode executable
- **Return-oriented programming**: Preparing ROP/JOP gadget execution
- **Process hollowing**: Modifying legitimate process memory
- **DLL injection**: Preparing injected libraries for execution
- **Heap spraying**: Preparing heap memory for exploitation

## SECURITY IMPLICATIONS

Memory protection changes can enable:

- **Arbitrary code execution**: Making data regions executable
- **Defense evasion**: Bypassing DEP/NX bit protections
- **Control flow hijacking**: Preparing memory for malicious code
- **Information disclosure**: Modifying protections to read sensitive data

## RELATED EVENTS

- **mprotect**: The underlying system call for memory protection changes
- **pkey_mprotect**: Protection key-based memory protection system call
- **mem_prot_alert**: Custom signature for suspicious protection changes
- **vma_modification**: Virtual memory area modification events