# process_execute_failed

## Intro
process_execute_failed - a failed process execution occurred.

## Description
An event marking that a process execution failure has occurred. This event helps in 
monitoring failed executions, with the ability to access (mostly - see below) kernel provided arguments.
This is a high-level event, planned to include all the failure cases of process execution, 
while providing as much as possible the arguments as used by the kernel.

## Arguments
* `path`:`const char*`[K] - the path to the file as provided by the user. 
* `binary.path`:`const char*`[K] - the binary path being executed.
* `binary.device_id`:`dev_t`[K] - the device id of the binary being executed.
* `binary.inode_number`:`unsigned long`[K] - the inode number of the binary being executed.
* `binary.ctime`:`unsigned long`[K] - the change time (ctime) of the binary being executed.
* `binary.inode_mode`:`u64`[K] - the inode mode of the binary being executed.
* `interpreter_path`:`const char*`[K] - the path to the interpreter used.
* `stdin_type`:`umode_t`[K] - the stdin type.
* `stdin_path`:`char*`[K] - the stdin path.
* `kernel_invoked`:`int`[K] - whether this execution was initiated by the kernel (or user-space).
* `environment`:`const char*const*`[U,TOCTOU] - the environment variables of this execution.
* `arguments`:`const char*const*`[U,TOCTOU] - the arguments of this execution.

## Hooks
### exec_binprm
#### Type
kprobe
#### Purpose
To retrieve the arguments of exec_binprm.
Used for kernels older than 5.8.

### exec_binprm
#### Type
kretprobe
#### Purpose
To retrieve the return value of exec_binprm and generate the event.
Used for kernels older than 5.8.

### security_bprm_creds_for_exec
#### Type
kprobe
#### Purpose
To retrieve the arguments for the event.
Relevant from kernel version 5.8 onwards, as the function was added in that kernel.

### sys_enter
#### Type
tracepoint
#### Purpose
To obtain the return code of the execution, determining whether to generate the event.
For a failed execution, an event will be generated using the information from the `security_bprm_creds_for_exec` hook.
Relevant from kernel version 5.8 onwards, matching the `security_bprm_creds_for_exec` hook.

## Example Use Case

```console
./tracee -e process_execution_failed
```

## Issues
The `exec_binprm` symbol is not available in some systems, potentially resulting in the failure to load the event in kernels older than 5.8.
For kernels older than 5.8, the event only encompasses failed executions occurring within `exec_binprm`. Other failures may occur at an earlier stage. Newer versions do not account for failures before `security_bprm_creds_for_exec`, which precedes `exec_binprm`.

## Related Events
execve,execveat,bprm_check,sched_process_exec