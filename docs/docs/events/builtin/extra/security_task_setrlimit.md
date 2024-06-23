# security_task_setrlimit

## Intro
security_task_setrlimit - Do a check when a task's resource limit is being set.

## Description
The event indicates a resource set of a task.
The event is triggered by the permissions check for the operation, as LSM hook.

## Arguments
* `target_host_pid`:`u32`[K] - the target host pid.
* `resource`:`int`[K] - the resource limit being changed.
* `new_rlim_cur`:`u64`[K] - the new current limit.
* `new_rlim_max`:`u64`[K] - the new maximum limit.

## Hooks
### security_task_setrlimit
#### Type
kprobe
#### Purpose
The LSM hook of setting the resource limit on a task. This hook triggers the event. 

## Example Use Case

```console
./tracee -e security_task_setrlimit
```

## Issues

## Related Events
