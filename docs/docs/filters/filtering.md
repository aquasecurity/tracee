# Tracing Event Filtering

```console
sudo ./dist/tracee --help filter
sudo ./dist/tracee --filter xxx
```

Tracee output might become too hard to consume when tracing all the events from
a system. Luckily, Tracee has a powerful mechanism to accurately filter just the
information that is relevant to the user, the `--filter` flag.

With `--filter` command line flag you define expressions that tells
**tracee** what you are interested in based on event metadata filtering
capabilities. Only events that match given criteria will be traced.

!!! Tip
    You can filter events by most of the visible fields from Tracee events.

## Initial Example

All the examples bellow this item can be executed with the following tracee
prefix command:

```console
sudo ./dist/tracee \
    --output json \
    --filter comm=bash \
    --filter follow
    --output option:parse-arguments \
    <rest of filters>
```

This will allow you to test the filtering rules by executing a new process in
any running shell and might serve as a good indicative if your filter works as
expected.

## Filters and Operators

1. **Event** `(Operators: =, != and "follow". Prefix/Suffix: *)`

    ```text
    1) --filter event=openat
    2) --filter event=execve,open
    3) --filter event='open*'
    4) --filter event!='open*,dup*'
    5) --filter follow
    ```

    !!! Note
        The "follow" operator will make tracee follow all newly created
        child processes of the parents being filtered.

1. **Event Arguments** `(Operators: =, !=. Prefix/Suffix: *)`

    ```text
    1) --filter event=openat --filter openat.args.pathname=/etc/shadow
    2) --filter event=openat --filter openat.args.pathname='/tmp*'
    3) --filter event=openat --filter openat.args.pathname!=/tmp/1,/bin/ls
    ```

    !!! Note
        Multiple values are ORed if used with = operator  
        But ANDed if used with any other operator.

1. **Event Return Code** `(Operators: =, !=, <, >)`

    ```text
    1) --filter event=openat --filter openat.args.pathname=/etc/shadow --filter 'openat.retval>0'
    2) --filter event=openat --filter openat.args.pathname=/etc/shadow --filter 'openat.retval<0'
    ```

    !!! Tip
        Try `cat /etc/shadow` as a regular use and filter for `retval<0`.

1. **Event Context** `(Operators: vary by field)`

    ```text
    1) --filter openat.context.container --filter openat.args.pathname=/etc/shadow
    2) --filter event=openat --filter openat.context.container --filter openat.args.pathname=/etc/shadow
    ```

    !!! Note
        The following is a list of available context fields:  
        1)  "timestamp"  
        2)  "processorId"  
        3)  "p", "pid", "processId"  
        4)  "tid", "threadId"  
        5)  "ppid", "parentProcessId"  
        6)  "hostTid", "hostThreadId"  
        7)  "hostPid", "hostParentProcessId"  
        8)  "uid", "userId"  
        9)  "mntns", "mountNamespace"  
        10) "pidns", "pidNamespace"  
        11) "processName", "comm"  
        12) "hostName"  
        13) "cgroupId"  
        14) "host" (inversion of "container")  
        15) "container"  
        16) "containerId"  
        17) "containerImage"  
        18) "containerName"  
        19) "podName"  
        20) "podNamespace"  
        21) "podUid"  
        22) "syscall"  
    !!! Tip
        Open a container and try `cat /etc/shadow`.

1. **Event Sets** `(Operators: =, !=)`

    ```text
    1) --filter set=fs
    2) --filter set=lsm_hooks,network_events
    ```

    !!! Note
        Selects a set of events to tracee according to pre-defined sets which
        can be listed by using `list` command line argument.

1. **Container** `(Operators: =, != and "new". Boolean)`

    ```text
    1) --filter container # all container events
    2) --filter '!container' # events from the host only
    3) --filter container=new # containers created after tracee-ebf execution
    4) --filter container=3f93da58be3c --filter event=openat
    5) --filter container=new --filter event=openat --filter openat.args.pathname=/etc/shadow
    ```

    !!! Note
        The **new** flag allows to filter newly created containers only.  

1. **Command** `(Operators: =, !=)`

    ```text
    1) --filter comm=cat,vim,ping
    2) --filter comm!=ping
    ```

    !!! Note
        Do not use given command prefix for these examples as they're filtering
        by command name as well.

1. **Binary Path** `(Operators: =, !=)`

    ```text
    1) --filter binary=/usr/bin/ls
    2) --filter binary=host:/usr/bin/ls
    3) --filter binary=4026532448:/usr/bin/ls
    ```

    !!! Note
        1. Mount namespace id or the special "host:" prefix can be used for finer filtering
        2. Given path must be absolute; i.e starts with "/"
        3. Symbolic link paths are not supported

1. **PID** `(Operators: =, !=, <, > and "new")`

    ```text
    1) --filter pid=new # newly created events (after tracee execution)
    2) --filter pid=510,1709 # # pids 510 and 1709
    3) --filter 'pid>0' --filter pid 'pid<1000'
    4) --filter pid=2578238 --filter event=openat --filter openat.pathname=/etc/shadow --filter follow
    ```

    !!! Note
        This filter can be used to filter a specific process or thread:
        1. Providing a tgid (aka pid) will filter all threads of the process.
        2. Providing a tid (where tid != tgid) will only filter the specific thread.

1. **Process Tree**

    ```text
    1) --filter tree=476165 # events descending from process 476165
    2) --filter tree!=5023 # events that do not descend from process 5023
    ```

1. **UID** `(Operators: =, !=, <, >)`

    ```text
    1) --filter uid=0
    2) --filter 'uid>0'
    3) --filter 'uid>0' --filter uid!=1000 # do not filter root and uid=1000
    ```

1. **UTS Namespace (hostnames)** `(Operators: =, !=)`

    ```text
    1) --filter uts!=ab356bc4dd554 
    ```

1. **PID Namespace** `(Operators: =, !=)`

    ```text
    1) --filter pidns!=4026531836
    ```

1. **MOUNT Namespace** `(Operators: =, !=)`

    ```text
    1) --filter mntns=4026531840
    ```
