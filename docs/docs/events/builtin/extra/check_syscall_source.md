# check_syscall_source

## Intro

check_syscall_source - An event reporting a syscall that was invoked from an unusual code location.

## Description

In most cases, all code running in a process is placed in dedicated code regions (VMAs, or Virtual Memory Areas) that are mapped from executable files that contain the code. Thus, the locations that syscalls are invoked from should be in one of these code regions.

When a syscall is invoked from an unusual location, this event is triggered. This may happen in the following scenarios:

- A shellcode is executed from the stack, the heap or an anonymous (non-file-backed) memory region.

- A packed program is executed, and is either statically linked or it calls syscalls directly (instead of using libc wrappers).

This event relies on an event filter to specify which syscalls should be monitored, to reduce overhead. An example command line usage of this event:

`tracee --events check_syscall_source.args.syscall=open,openat`.

To reduce noise in cases where code with significant syscall activity is being detected, any unique combination of process, syscall and VMA that contains the invoking code will be submitted as an event only once.

## Arguments

* `syscall`:`int`[K] - the syscall which was invoked from an unusual location. The syscall name is parsed if the `parse-arguments` option is specified.
* `ip`:`void *`[K] - the address from which the syscall was invoked (instruction pointer of the instruction following the syscall instruction).
* `is_stack`:`bool`[K] - whether the syscall was invoked from the stack. Mutually exclusive with `is_heap` and `is_anon_vma`.
* `is_heap`:`bool`[K] - whether the syscall was invoked from the heap. Mutually exclusive with `is_stack` and `is_anon_vma`.
* `is_anon_vma`:`bool`[K] - whether the syscall was invoked from an anonymous (non-file-backed) VMA. Mutually exclusive with `is_stack` and `is_heap`.

## Hooks

### sys_enter

#### Type

tracepoint

#### Purpose

Utilizes a tail call from the existing tracepoint on `sys_enter`. The called function analyzes the location from which the syscall was invoked. The analysis occurs only if a policy has selected this syscall as a filter for this event.

## Example Use Case

Detect shellcodes.

## Issues

Unwanted events may occur in scenarios where legitimate programs run code from unusual locations. This may happen in the case of JITs that write code to anonymous VMAs. Although such code is not expected to invoke syscalls directly (instead relying on some runtime that is mapped from an executable file), exceptions may exist.
