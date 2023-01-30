# Tracing Scopes (workloads)

**Scopes** allow you to have more granularity and flexibility when [filtering]
events. Up to 64 scopes (workloads) can be used at the same time.

[filtering]: ./event-filtering.md

If one of your filters doesn't match, the event will be filtered out, as they
work together in a short circuit. However, you can use multiple sets of
filters, called scopes, by adding a number and a colon before the trace flags,
such as `1:`. In this way, you can have different workloads that mix different
types of filters.

The main filtering logic, *ANDed filters*, remains the same within a scope. But
the result of multi-scopes is *ORed*, which enables you to have granularity.

## Scopes matches

To determine which scopes an event is related to, you can check the **bitmask**
using:

1. `-o format:json`, via `matchedScopes` JSON field (in decimal).
1. `-o format:table-verbose`, via `SCOPES` column (in hexadecimal).

For instance, an event with the matchedScopes value of 35 (decimal), tells you
that this event matches the 1st, 2nd, and 6th scopes.


```shell
bc <<< "obase=2; 35"
```

```text
100011
^   ^^
6   21 (scope number)
```

## Examples

### Single scope (the same of not using the scope prefix)

Trace in **scope 42** `sched_process_exec` events from `/usr/bin/ls` binary:

```shell
sudo ./dist/tracee \
-t 42:event=sched_process_exec -t 42:binary=/usr/bin/ls \
-o format:table-verbose
```

```text
TIME             SCOPES            UTS_NAME          CONTAINER_ID  MNT_NS       PID_NS       UID    COMM             PID     TID     PPID    RET              EVENT                ARGS
20:09:15:041923  0000020000000000  hb                             4026531841   4026531836   1000   ls               470751  470751  470503  0                sched_process_exec   cmdpath: /usr/bin/ls, pathname: /usr/bin/ls, dev: 271581189, inode: 3933037, ctime: 1668553120490241295, inode_mode: 33261, argv: [ls --color=auto], interp: /usr/bin/ls, stdin_type: S_IFCHR, stdin_path: /dev/pts/2, invoked_from_kernel: 0
```

!!! Note
    If you don't prefix the filter, `event=sched_process_exec`, Tracee
    will consider that event to be part of **scope 1**. As a result, it can
    be omitted for single scope usage.

### Multi-scopes

#### Detached workloads

1. Trace in **scope 3** only `sched_process_exit` events from `id` command and
trace in **scope 9** only `sched_process_exit` events from `ls` command:

    ```shell
    sudo ./dist/tracee \
    -t 3:event=sched_process_exit -t 3:comm=id \
    -t 9:event=sched_process_exit -t 9:comm=ls \
    -o format:table-verbose
    ```

    ```text
    TIME             SCOPES            UTS_NAME          CONTAINER_ID  MNT_NS       PID_NS       UID    COMM             PID     TID     PPID    RET              EVENT                ARGS
    20:14:57:074270  0000000000000004  hb                             4026531841   4026531836   1000   id               471990  471990  470503  0                sched_process_exit   exit_code: 0, process_group_exit: true
    20:14:59:709468  0000000000000100  hb                             4026531841   4026531836   1000   ls               472033  472033  470503  0                sched_process_exit   exit_code: 0, process_group_exit: true
    ```

1. Trace in **scope 6** only `openat` events from `id` command and
trace in **scope 7** only `close` events from `id` command:

    ```shell
    sudo ./dist/tracee \
    -t 6:event=openat -t 6:comm=id \
    -t 7:event=close -t 7:comm=id \
    -o format:table-verbose
    ```

    ```text
    TIME             SCOPES            UTS_NAME          CONTAINER_ID  MNT_NS       PID_NS       UID    COMM             PID     TID     PPID    RET              EVENT                ARGS
    20:23:22:794235  0000000000000020  hb                             4026531841   4026531836   1000   id               473432  473432  295394  3                openat               dirfd: -100, pathname: /etc/ld.so.cache, flags: O_RDONLY|O_CLOEXEC, mode: 0
    20:23:22:794246  0000000000000040  hb                             4026531841   4026531836   1000   id               473432  473432  295394  0                close                fd: 3
    ```

1. Trace in **scope 3** only `anti_debugging` events from **all**,
trace in **scope 5** only `net_packet_icmp` events from `ping` command, and
trace in **scope 9** only `ptrace` events from **all**.

    ```shell
    sudo ./dist/tracee \
    -t 3:event=anti_debugging \
    -t 5:event=net_packet_icmp -t 5:comm=ping \
    -t 9:event=ptrace \
    -o format:table-verbose
    ```

    ```text
    TIME             SCOPES            UTS_NAME          CONTAINER_ID  MNT_NS       PID_NS       UID    COMM             PID     TID     PPID    RET              EVENT                ARGS
    20:59:54:105722  0000000000000010  hb                             4026531841   4026531836   1000   ping             480539  480539  295394  0                net_packet_icmp      src: 192.168.0.109, dst: 8.8.8.8, proto_icmp: {EchoRequest 36097 22 1}
    20:59:54:129919  0000000000000010  hb                             4026531841   4026531836   1000   ping             480539  480539  295394  0                net_packet_icmp      src: 8.8.8.8, dst: 192.168.0.109, proto_icmp: {EchoReply 38145 22 1}
    20:59:57:941107  0000000000000100  hb                             4026531841   4026531836   1000   strace           480614  480614  295394  0                ptrace               request: PTRACE_SEIZE, pid: 480615, addr: 0x0, data: 0x0
    20:59:57:941424  0000000000000100  hb                             4026531841   4026531836   1000   strace           480616  480616  480614  0                ptrace               request: PTRACE_TRACEME, pid: 0, addr: 0x0, data: 0x0
    20:59:57:941424  0000000000000004  hb                             4026531841   4026531836   1000   strace           480616  480616  480614  0                anti_debugging       request: PTRACE_TRACEME, pid: 0, addr: 0x0, data: 0x0
    ```

#### Intertwined workloads

1. Trace in **scope 3** only `sched_process_exit` events from `id` command and
trace in **scope 9** only `sched_process_exit` events from **all**:

    ```shell
    sudo ./dist/tracee \
    -t 3:event=sched_process_exit -t 3:comm=id \
    -t 9:event=sched_process_exit \
    -o format:table-verbose
    ```

    ```text
    TIME             SCOPES            UTS_NAME          CONTAINER_ID  MNT_NS       PID_NS       UID    COMM             PID     TID     PPID    RET              EVENT                ARGS
    20:26:50:435805  0000000000000100  hb                             4026531841   4026531836   1000   sleep            474130  474130  474129  0                sched_process_exit   exit_code: 0, process_group_exit: true
    20:26:50:439402  0000000000000104  hb                             4026531841   4026531836   1000   id               474129  474129  295394  0                sched_process_exit   exit_code: 0, process_group_exit: true
    20:26:50:457932  0000000000000100  hb                             4026531841   4026531836   1000   pkgfile          474162  474166  474161  0                sched_process_exit   exit_code: 0, process_group_exit: false
    ...
    ```

1. Trace in **scope 3** only `net_packet_icmp` events from containers and
trace in **scope 5** only `net_packet_icmp` events from **all**:

    ```shell
    sudo ./dist/tracee \
    -t 3:event=net_packet_icmp -t 3:container \
    -t 5:event=net_packet_icmp \
    -o format:table-verbose
    ```

    ```text
    TIME             SCOPES            UTS_NAME          CONTAINER_ID  MNT_NS       PID_NS       UID    COMM             PID/host        TID/host        PPID/host       RET              EVENT                ARGS
    22:06:47:106058  0000000000000010  hb                             4026531841   4026531836   1000   ping             902452 /902452  902452 /902452  902386 /902386  0                net_packet_icmp      src: 192.168.0.109, dst: 8.8.8.8, proto_icmp: {EchoRequest 6891 39 1}
    22:06:47:131362  0000000000000010  hb                             4026531841   4026531836   1000   ping             902452 /902452  902452 /902452  902386 /902386  0                net_packet_icmp      src: 8.8.8.8, dst: 192.168.0.109, proto_icmp: {EchoReply 8939 39 1}
    22:06:54:878971  0000000000000014  e9cf0db70635     e9cf0db70635  4026532904   4026532908   0      ping             8      /902559  8      /902559  1      /899413  0                net_packet_icmp      src: 172.17.0.2, dst: 8.8.8.8, proto_icmp: {EchoRequest 38257 8 0}
    22:06:54:902975  0000000000000014  e9cf0db70635     e9cf0db70635  4026532904   4026532908   0      ping             8      /902559  8      /902559  1      /899413  0                net_packet_icmp      src: 8.8.8.8, dst: 172.17.0.2, proto_icmp: {EchoReply 40305 8 0}
    ```

1. Trace in **scope 3** `anti_debugging` and `ptrace` events from **all**,
trace in **scope 5** only `net_packet_icmp` events from `ping` command, and
trace in **scope 9** only `ptrace` events from **all**.

    ```shell
    sudo ./dist/tracee \
    -t 3:event=anti_debugging,ptrace \
    -t 5:event=net_packet_icmp -t 5:comm=ping \
    -t 9:event=ptrace \
    -o format:table-verbose
    ```

    ```text
    TIME             SCOPES            UTS_NAME          CONTAINER_ID  MNT_NS       PID_NS       UID    COMM             PID     TID     PPID    RET              EVENT                ARGS
    22:13:20:854132  0000000000000010  hb                             4026531841   4026531836   1000   ping             903291  903291  903233  0                net_packet_icmp      src: 192.168.0.109, dst: 8.8.8.8, proto_icmp: {EchoRequest 22398 40 1}
    22:13:20:876449  0000000000000010  hb                             4026531841   4026531836   1000   ping             903291  903291  903233  0                net_packet_icmp      src: 8.8.8.8, dst: 192.168.0.109, proto_icmp: {EchoReply 24446 40 1}
    22:13:28:877929  0000000000000104  hb                             4026531841   4026531836   1000   strace           903353  903353  903233  0                ptrace               request: PTRACE_SEIZE, pid: 903354, addr: 0x0, data: 0x0
    22:13:28:878450  0000000000000104  hb                             4026531841   4026531836   1000   strace           903355  903355  903353  0                ptrace               request: PTRACE_TRACEME, pid: 0, addr: 0x0, data: 0x0
    ...
    22:13:28:878450  0000000000000004  hb                             4026531841   4026531836   1000   strace           903355  903355  903353  0                anti_debugging       request: PTRACE_TRACEME, pid: 0, addr: 0x0, data: 0x0
    ```
