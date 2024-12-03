# suspicious_syscall_source

## Intro

suspicious_syscall_source - An event reporting a syscall that was invoked from an unusual code location.

## Description

In most cases, all code running in a process is placed in dedicated code regions (VMAs, or Virtual Memory Areas) that are mapped from executable files that contain the code. Thus, the locations that syscalls are invoked from should be in one of these code regions.

When a syscall is invoked from an unusual location, this event is triggered. This may happen in the following scenarios:

- A shellcode is executed from the stack, the heap or an anonymous (non-file-backed) memory region.

- A packed program is executed, and is either statically linked or it calls syscalls directly (instead of using libc wrappers).

This event relies on an event parameter to specify which syscalls should be monitored, to reduce overhead. An example command line usage of this event:

`tracee --events suspicious_syscall_source.args.syscall=open,openat`.

To reduce noise in cases where code with significant syscall activity is being detected, any unique combination of process, syscall and VMA that contains the invoking code will be submitted as an event only once.

## Arguments

* `syscall`:`int`[K] - the syscall which was invoked from an unusual location. The syscall name is parsed if the `parse-arguments` option is specified. This argument is also used as a parameter to select which syscalls should be checked.
* `ip`:`void *`[K] - the address from which the syscall was invoked (instruction pointer of the instruction following the syscall instruction).
* `vma_type`:`char *`[K] - a string describing the type of the VMA which contains the code that triggered the syscall
* `vma_start`:`void *`[K] - the start address of the VMA which contains the code that triggered the syscall
* `vma_size`:`unsigned long`[K] - the size of the VMA which contains the code that triggered the syscall
* `vma_flags`:`unsigned long`[K] - the flags of the VMA which contains the code that triggered the syscall. The flag names are parsed if the `parse-arguments` option is specified.

## Hooks

### Individual syscalls

#### Type

kprobe

#### Purpose

A kprobe is placed on each syscall that was selected using a parameter for this event. The kprobe function analyzes the location from which the syscall was invoked.

## Example Use Case

Detect shellcodes.

## Issues

Unwanted events may occur in scenarios where legitimate programs run code from unusual locations. This may happen in the case of JITs that write code to anonymous VMAs. Although such code is not expected to invoke syscalls directly (instead relying on some runtime that is mapped from an executable file), exceptions may exist.
