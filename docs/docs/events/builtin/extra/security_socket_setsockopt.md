# security_socket_setsockopt

## Intro
security_socket_setsockopt - check permissions before setting the options associated with socket

## Description
The event marks that an attempt to set a socket option occurred, probably by the `setsockopt` syscall.
The event is triggered by the permissions check for the operation, as LSM hook.
The event gives insight to the socket details (which differs from the `setsockopt` syscall event, that only pass the socket fd).
However, unlike the `setsockopt` syscall event, the option value isn't passed.


## Arguments
* `sockfd`:`int`[K] - the file descriptor of the socket.
* `level`:`int`[K] - the level that the option should apply to. If the `parse-arguments` option is on, will be transformed to a string with the level name.
* `optname`:`int`[K] - the option that is set. If the `parse-arguments` option is on, will be transformed to a string with the option name.
* `local_addr`:`struct socketaddr*`[K] - the details of the socket (like socket type, local IP and port for TCP/UDP sockets, etc.).

## Hooks
### security_socket_setsockopt
#### Type
LSM Hook
#### Purpose
The LSM hook of the `setsockopt` syscall implementation.

## Related Events
`setsockopt`, `getsockopt`