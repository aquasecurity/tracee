# process_termination

## Intro
process_termination - a process was terminated, either killed or exited cleanly.

## Description
All the process threads were exited.
This event enables monitoring of process exits.
This event is intended for users to gain insight into the machines' runtime operations.

## Arguments
* `exit_code`:`long`[K] - The process exit code.

### Available Tags
* K - Originated from kernel-space.
* U - Originated from user space (for example, pointer to user space memory used to get it)
* TOCTOU - Vulnerable to TOCTOU (time of check, time of use)
* OPT - Optional argument - might not always be available

## Hooks
### sched_process_exit
#### Type
tracepoint.
#### Purpose
Indicates thread exit. Used to determine if a process was exited.

## Example Use Case
Can be used to monitor processes life cycle on the system.

## Issues


## Related Events
sched_process_exit, process_execution