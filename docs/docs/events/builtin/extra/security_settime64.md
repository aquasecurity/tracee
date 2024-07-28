# security_settime64

## Intro
security_settime64 - set the system time

## Description
The event indicates a request to set the time
The event is triggered by the permissions check for the operation, as LSM hook.

## Arguments
* `tv_sec`:u64`[K] - the time in seconds.
* `tv_nsec`:`u64`[K] - the time in nanoseconds.
* `tz_minuteswest`:`int`[K] - minutes west of Greenwich
* `tz_dsttime`:`int`[K] - type of dst correction

## Hooks
### security_settime64
#### Type
kprobe
#### Purpose
The LSM hook of setting the system time. This hook triggers the event. 

## Example Use Case

```console
./tracee -e security_settime64
```

## Issues

## Related Events
