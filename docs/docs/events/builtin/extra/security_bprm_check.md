# security_bprm_check

## Intro
security_bprm_check - verify permissions prior to initiating the binary handler search in the execution flow.

## Description
This event signifies an attempt to execute a binary via execve or execveat, occurring just before the kernel starts searching for the specific binary handler. During this stage, numerous new process attributes are set, and although the context remains that of the pre-execution process, the event is valuable when that context holds significance. It's a preferred choice over syscall events due to its resolved path and binary details. However, if you need more extensive information and the process context is less crucial, you might find the sched_process_exec event to be a better fit.

## Arguments
* `pathname`:`const char*`[K] - the resolved path of the file executed.
* `dev`:`dev_t`[K] - the device of the executed file.
* `inode`:`unsigned long`[K] - the inode number of the executed file.
* `argv`:`const char*`[U,TOCTOU] - the arguments given by the user during execution.
* `envp`:`const char*`[U,TOCTOU,OPT] - the environment variable passed by the user during execution. Will be filled only if requested by the configuration.

## Hooks
### security_bprm_check
#### Type
LSM hook
#### Purpose
The LSM hook for the execution phase before context changing.

### sys_enter
#### Type
Tracepoint
#### Purpose
Used to save the argv of the execution from the syscall arguments.

## Related Events
`sched_process_exec`,`execve`,`execveat`