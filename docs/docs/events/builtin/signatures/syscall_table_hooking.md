
# Syscall Table Hooking Detection

## Intro

The `SyscallTableHooking` signature is developed to detect malevolent hooking of
the syscall table in a system.

System calls (syscalls) serve as the pivotal bridge between user applications
and the operating system kernel. If manipulated through hooking, they grant an
adversary the capability to exert substantial control over vital system
functions.

## Description

Syscalls are essential; they act as intermediaries enabling user applications to
request services and operations from the OS kernel. A table in the kernel
catalogs these syscalls.

If a malicious actor manages to manipulate or "hook" into this table, they gain
the ability to either supplant or entirely circumvent the kernel's innate
operations. This control ranges from basic operations like reading/writing files
to advanced capabilities like influencing the system's behavior or even
rerouting its execution flow. In simple terms, an attacker could make the system
believe it's performing regular operations when it's, in fact, executing the
attacker's code.

Rootkits, notorious for deep system infiltration, often exploit syscall table
hooking. It's a strong indication that the system's kernel may have been
compromised. Furthermore, any modules hiding in the shadows, known as "hidden
modules," also hint at a deeper malfeasance and indicate an elevated threat
level.

## Purpose

The signature `SyscallTableHooking` is meticulously designed to detect instances
where the syscall table is tampered with in real-time. By spotting these hooks
early, it provides a pivotal advantage in thwarting and neutralizing potential
threats, preserving the sanctity of the kernel and the entire system.

## Metadata

- **ID**: TRC-1030
- **Version**: 1
- **Name**: Syscall table hooking detected
- **EventName**: syscall_hooking
- **Description**: It focuses on detecting unauthorized and malevolent hooking of the syscall table. This manipulation allows an attacker to exert undue control over the kernel's operations, leading to potential compromises of the entire system. Rootkits often employ this technique, making it a critical threat to detect and address.
- **Properties**:
  - **Severity**: 3 (Moderate to high threat level)
  - **Category**: defense-evasion
  - **Technique**: Rootkit
  - **Kubernetes_Technique**: N/A
  - **id**: attack-pattern--0f20e3cb-245b-4a61-8a91-2d93f7cb0e9b
  - **external_id**: T1014

## Findings

Upon discovering a malevolent hook in the syscall table, the signature generates
a `Finding` that houses:

- **SigMetadata**: This is a set of metadata outlining the nature and potential threat of the detected issue.
- **Event**: A comprehensive record of the event that spurred the detection, offering a granular look at the problem.
- **Data**: This highlights the specific syscalls that have been manipulated, giving insights into the nature and extent of the threat.

## Events Used

The signature predominantly zeroes in on the event:

- `hooked_syscalls`: This event is fired when malicious hooking of the syscall
table is detected. The signature parses this event's data to ascertain the
degree and nature of the hooking.
