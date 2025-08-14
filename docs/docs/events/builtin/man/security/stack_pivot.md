---
title: TRACEE-STACK-PIVOT
section: 1
header: Tracee Event Manual
---

## NAME

**stack_pivot** - Detects syscalls invoked with a stack pointer outside the stack region

## DESCRIPTION

The stack pivot event detects a technique commonly used in ROP (Return-Oriented Programming) exploits where the stack pointer is manipulated to point outside the legitimate stack region.

All native code execution makes use of the stack - a region of memory used for storing function-local data like parameters, return addresses, and local variables. A stack overflow vulnerability allows an attacker to write data past the end of a stack-allocated buffer, potentially overwriting other stack data including return addresses.

In ROP exploits, the attacker overwrites return addresses to chain together small code sequences called "gadgets". One limitation is the amount of data that can be written to the stack - it may not be enough for the full sequence of gadget addresses. The stack pivot technique overcomes this by using a gadget that changes the stack pointer to point to an attacker-controlled location, effectively moving the stack and allowing a longer ROP chain.

This event detects stack pivoting by checking the stack pointer at selected syscall invocations and identifying cases where it points outside the original stack region.

## EVENT SETS

**none**

## DATA FIELDS

**syscall** (*int32*)
: The syscall which was invoked while the stack pointer was outside the stack. The syscall name is parsed if the `parse-arguments` option is specified. This argument is also used as a parameter to select which syscalls should be checked.

**sp** (*trace.Pointer*)
: The stack pointer value at the time of syscall invocation

**vma_type** (*string*)
: Description of the memory region type containing the stack pointer address

**vma_start** (*trace.Pointer*)
: Start address of the memory region containing the stack pointer

**vma_size** (*uint64*)
: Size of the memory region containing the stack pointer

**vma_flags** (*uint64*)
: Memory region flags (parsed if `parse-arguments` is enabled)

## DEPENDENCIES

**Thread Tracking:**

- sched_process_fork (optional) - Used for thread stack tracking
- sched_process_exec (optional) - Used for thread stack tracking

## USE CASES

- **Exploit detection**: Detect ROP exploits that use the stack pivot technique

- **Security monitoring**: Monitor for suspicious stack pointer manipulation

- **Memory analysis**: Identify potential memory corruption exploits

## IMPLEMENTATION NOTES

The kernel manages the stack for each process's main thread, but additional threads must create and manage their own stacks. Since the kernel has no direct notion of thread stacks, Tracee tracks thread stacks by storing the memory region pointed to by the stack pointer when new threads are created.

Limitations:
- Threads created before Tracee starts are not tracked
- For untracked threads, anonymous memory regions are ignored to avoid false positives
- This may result in false negatives for legitimate thread stacks created before Tracee started

## EXAMPLE USAGE

Monitor specific syscalls for stack pivoting:
```
tracee --events stack_pivot.args.syscall=open,openat
```

## RELATED EVENTS

- **mem_prot_alert**: Memory protection alerts
- **proc_mem_code_injection**: Process memory code injection
- **process_vm_write_code_injection**: Process VM write code injection
- **ptrace_code_injection**: Ptrace-based code injection