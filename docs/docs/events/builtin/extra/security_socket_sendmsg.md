# inet_sendmsg

## Intro
inet_sendmsg - set the system time

## Description
The event indicates a message send over a socket.
The event is triggered by the permissions check for the operation, as LSM hook.

## Arguments
#TODOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO

## Hooks
### inet_sendmsg
#### Type
kprobe
#### Purpose
The LSM hook purpose is to provide a mechanism for security modules to enforce security policies on socket messaging operations.
This hook triggers the event.

## Example Use Case

```console
./tracee -e inet_sendmsg
```

## Issues

## Related Events