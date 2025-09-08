---
title: TRACEE-CALL-USERMODEHELPER
section: 1
header: Tracee Event Manual
---

## NAME

**call_usermodehelper** - kernel usermode helper execution monitoring

## DESCRIPTION

Triggered when the kernel executes a usermode helper program using the `call_usermodehelper` function. This mechanism allows the kernel to execute user-space programs to perform tasks such as loading firmware, handling hotplug events, or executing system utilities from kernel context.

Usermode helpers are powerful mechanisms that can be abused by attackers to execute arbitrary code with elevated privileges or to maintain persistence, making monitoring these operations important for security.

## EVENT SETS

**none**

## DATA FIELDS

**pathname** (*string*)
: The path of the usermode helper program being executed

**argv** (*[]string*)
: The argument vector passed to the helper program

**envp** (*[]string*)
: The environment variables passed to the helper program

**wait** (*int32*)
: Whether the kernel waits for the helper program to complete

## DEPENDENCIES

**Kernel Probe:**

- call_usermodehelper (required): Kernel usermode helper execution function

## USE CASES

- **System execution monitoring**: Track kernel-initiated user-space program execution

- **Security monitoring**: Detect potential abuse of usermode helpers for malicious purposes

- **Privilege escalation detection**: Monitor usermode helper execution that could indicate attacks

- **System debugging**: Debug usermode helper usage and configuration issues

- **Compliance monitoring**: Ensure usermode helper usage follows security policies

## RELATED EVENTS

- **execve**: User-space program execution events
- **do_init_module**: Kernel module loading that may trigger usermode helpers
- **Device events**: Hardware events that may trigger usermode helpers
- **Process execution events**: Related program execution and process monitoring
