---
title: TRACEE-DO-SIGACTION
section: 1
header: Tracee Event Manual
---

## NAME

**do_sigaction** - Event triggered when registering new signal handler or getting information about current one

## DESCRIPTION

The **do_sigaction** event marks that an attempt to get current task signal handler or to change the signal handler of the current task for a specific signal occurred. Signal handler changes mark the change of program behavior, and might indicate an attempt to defy expected signal behavior.

This event is relevant for each syscall related to signal handling - `rt_sigaction`, `sigaction` and `signal`.

In the kernel, the handle method and the handler are united to one field. To make it more accessible to the user, Tracee splits the two apart. Normally, the value can be one of the following: `SIG_DFL`(0), `SIG_IGN`(1) or pointer to user-mode handler function. To deal with the case of a user-mode handler, the value `SIG_HND`(2) is created to specify that the method is by handler.

## EVENT SETS

**none**

## DATA FIELDS

**sig** (*int32*)
: The signal that its handler is inspected or changed

**is_sa_initialized** (*bool*)
: Is a new signal handler given. If not, this event marks only inspection of data

**sa_flags** (*uint64*)
: The flags given for the new signal handler

**sa_mask** (*uint64*)
: The mask given for the new signal handler

**sa_handle_method** (*uint8*)
: The handling method of the new signal handler

**sa_handler** (*trace.Pointer*)
: The address of the new signal handling function if method is SIG_HND

**is_old_sa_initialized** (*bool*)
: Is an old signal handler given. If given, the old signal handler will be copied back to the caller

**old_sa_flags** (*uint64*)
: The flags of the old signal handler

**old_sa_mask** (*uint64*)
: The mask of the old signal handler

**old_sa_handle_method** (*uint8*)
: The handling method of the old signal handler

**old_sa_handler** (*trace.Pointer*)
: The address of the old signal handling function if method was SIG_HND

## DEPENDENCIES

**Kernel Probe:**

- do_sigaction (required): Kernel probe on the function implementing the signal handler inspection/modification for syscalls

## USE CASES

- **Malware Detection**: Monitor signal handler modifications that could indicate process injection or evasion techniques

- **Security Analysis**: Track changes to signal handling behavior that might bypass security controls

- **Debugging**: Monitor signal handler registration during application debugging

## RELATED EVENTS

- **rt_sigaction**: Real-time signal action system call
- **sigaction**: Signal action system call
- **signal**: Signal system call