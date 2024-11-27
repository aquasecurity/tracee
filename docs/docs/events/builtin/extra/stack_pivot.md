# stack_pivot

## Intro

stack_pivot - An event reporting a syscall that was invoked while the user's stack pointer doesn't point to the stack.

## Description

All native code executed makes use of the stack, a region of memory used for storage of function-local data, like function parameters, return address, and local variables.

A stack overflow vulnerability is a security vulnerability that allows an attacker to write data past the end of a stack allocated buffer, allowing him to overwrite other stack data. This kind of vulnerability could be exploited by overwriting the function return address to a location chosen by the attacker, causing the code at that location to run when the vulnerable function returns. An attacker can write multiple return addresses to the stack such that small code sequences, called gadgets, are executed in a chain dictated by the attacker. This exploitation method is called ROP (return oriented programming).

One potential limitation of such an exploit is the amount of data the attacker is able to write to the stack - in some cases, it may not be enough to write the full sequence of gadget addresses required to achieve the attacker's goal. To overcome this limitation, the attacker can use the stack pivot technique. This technique involves a gadget that writes an attacker controlled value to the stack pointer, effectively moving the stack to a new location that the attacker is able to write to (and thus achieving a longer ROP chain).

This event attempts to detect the usage of this technique by checking the stack pointer at the invocation of selected syscalls and detecting cases where it does not point to the original stack.

This event relies on an event parameter to specify which syscalls should be monitored, to reduce overhead. An example command line usage of this event:

`tracee --events stack_pivot.args.syscall=open,openat`.

## Arguments

- `syscall`:`int`[K] - the syscall which was invoked while the stack pointer doesn't point to the orignal stack. The syscall name is parsed if the `parse-arguments` option is specified. This argument is also used as a parameter to select which syscalls should be checked.
- `sp`:`void *`[K] - the stack pointer at the time of syscall invocation
- `vma_type`:`char *`[K] - a string describing the type of the VMA which contains the address that the stack pointer points to
- `vma_start`:`void *`[K] - the start address of the VMA which contains the address that the stack pointer points to
- `vma_size`:`unsigned long`[K] - the size of the VMA which contains the address that the stack pointer points to
- `vma_flags`:`unsigned long`[K] - the flags of the VMA which contains the address that the stack pointer points to. The flag names are parsed if the `parse-arguments` option is specified.

## Hooks

### Individual syscalls

#### Type

kprobe

#### Purpose

A kprobe is placed on each syscall that was selected using a parameter for this event. The kprobe function analyzes the location pointed to by the stack pointer.

## Example Use Case

Detect ROP exploits that use the stack pivot technique.

## Issues

The kernel manages the stack for the main thread of each process, but additional threads must create and manage their own stacks. The kernel has no notion of a thread stack, so in order to detect that an address belongs to a thread stack and avoid false positives, thread stacks are tracked by tracee by storing the memory region pointed to by the stack pointer at the time of a new thread's creation. This means that threads created before tracee started are not tracked, and we have no way to differentiate between a regular anonymous memory region and one allocated for the stack in such threads. To avoid false positives, anonymous memory regions are ignored for untracked threads, which may result in false negatives.


