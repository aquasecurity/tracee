# hooked_syscall

## Intro
`hooked_syscall` is an event that checks syscall table for any syscall hooking.

## Description
The purpose of the `hooked_syscall` event is to monitor for system call hooking in the Linux kernel. It verifies each sys call points to its corresponding sys call function symbol. This helps identify instances of kernel code modifications, often used for malicious activities such as hiding processes, files, or network connections.

## Hooks
### Various system calls
#### Type
Uprobe
#### Purpose
Detection of syscall hooking.

## Example Use Case
The `hooked_syscall` event could be used as part of a broader system integrity monitoring solution. For example, a security engineer could use it to raise alerts or run further investigations if unexpected syscall hooking activities are detected. This could aid in the early detection and mitigation of malware or rootkit infections.

```console
tracee -e hooked_syscall
```

## Issues

## Related Events

