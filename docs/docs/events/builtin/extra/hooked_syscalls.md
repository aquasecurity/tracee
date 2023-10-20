# hooked_syscalls

## Intro
`hooked_syscalls` is an event that checks the selected syscalls for any syscall hooking.

## Description
The purpose of the `hooked_syscalls` event is to monitor for system call hooking in the Linux kernel. It verifies the function pointer of the system call to ensure it lies between the etext and stext addresses. This helps identify instances of kernel code modifications, often used for malicious activities such as hiding processes, files, or network connections.

The `hooked_syscalls` event checks either user-specified syscalls or a default list of syscalls depending on the architecture of the system, with a different list for amd64 and arm64 respectively.

## Arguments
* `check_syscalls`:`[]string`[U] - the syscall checked for syscall hooking. Can be used to specify selected syscalls or use the default ones. 
The default syscalls for amd64 are:

    `read`
    `write`
    `open`
    `close`
    `ioctl`
    `socket`
    `sendto`
    `recvfrom`
    `sendmsg`
    `recvmsg`
    `execve`
    `kill`
    `getdents`
    `ptrace`
    `getdents64`
    `openat`
    `bpf`
    `execveat`

The default syscalls for arm64 are:
    `ioctl`
    `openat`
    `close`
    `getdents64`
    `read`
    `write`
    `ptrace`
    `kill`
    `socket`
    `execveat`
    `sendto`
    `recvfrom`
    `sendmsg`
    `recvmsg`
    `execve`
    `bpf`
* `hooked_syscalls`:`[]trace.HookedSymbolData` [K] - The hooked syscalls that were found along with their owners. `Hidden` owner means that the pointed function owner is not a part of the kernel modules list.
## Hooks
### Various system calls
#### Type
Uprobe
#### Purpose
Detection of syscall hooking.

## Example Use Case
The `hooked_syscalls` event could be used as part of a broader system integrity monitoring solution. For example, a security engineer could use it to raise alerts or run further investigations if unexpected syscall hooking activities are detected. This could aid in the early detection and mitigation of malware or rootkit infections.
Example:

```console
tracee -e hooked_syscalls.args.check_syscalls=<syscall>,<syscall>,...`
```

## Issues
The `check_syscalls` argument is used as a parameter to specify the syscalls to be checked. This will change in the future to be an event parameter.

## Related Events

