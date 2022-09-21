# process_execution

## Intro
process_execution - a process was executed on the system.

## Description
A new process execution was invoked.
This event enables monitoring of process executions.
This event is intended for users to gain insight into the machines' runtime operations.

## Arguments
* `relative_path`:`const char*`[K] - The process binary relative path passed to the kernel via a syscall.
* `absolute_path`:`const char*`[K] - The process binary resolved absolute path.
* `arguments`:`const char**`[K] - The process array of arguments.
* `invoked_from_kernel`:`int`[K] - A flag indicating whether the process was invoked from within the kernel.
* `last_changed`:`unsigned long`[K] - The process binary last modification time in epoch.
* `sha256`:`char *`[OPT,U,TOCTOU] - The process binary sha256 hash. optional. Will be empty if the `exec-hash` flag wasn't specified.

### Available Tags
* K - Originated from kernel-space.
* U - Originated from user space (for example, pointer to user space memory used to get it)
* TOCTOU - Vulnerable to TOCTOU (time of check, time of use)
* OPT - Optional argument - might not always be available

## Hooks
### sched_process_exec
#### Type
tracepoint.
#### Purpose
Indicates process execution.

## Example Use Case
Can be used to monitor processes life cycle on the system.

## Issues


## Related Events
sched_process_exec, process_termination