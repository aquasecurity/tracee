# Rules

Rules determine which events a policy should tracee. You can see all supported events on tracee with:

```
tracee -l 
```

## Events

I want to tracee events for `dropped_executable` which is a signature event, `security_file_open`,
`sched_process_exec` and the syscall `close`. 

```
name: rules events example
description: This policy shows multiple events tracing
scope:
  - global
defaultAction: log
rules:
  - event: dropped_executable
  - event: security_file_open
  - event: sched_process_exec
  - event: close
```

# Filters

Events in Tracee suport filters. Let's take a closer look at the 3 types of filters currently supported:

### Context Filters

Let's suppose I only want to trace `sched_process_exec` events that occur for the user root with a zero UID. In that case, I can modify the above policy as follows:

```
name: rules events example
description: This policy shows multiple events tracing
scope:
  - global
defaultAction: log
rules:
  - event: dropped_executable
  - event: security_file_open
  - event: sched_process_exec
    filter: 
        - uid=0
  - event: close
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

### Argument Filters

In addition, I want to filter `security_open_file` events to only track those occurring in `/tmp/*`. Here's how to set the policy:

```
name: rules events example
description: This policy shows multiple events tracing
scope:
  - global
defaultAction: log
rules:
  - event: dropped_executable
  - event: security_file_open
    filter:
        - args.pathname=/tmp/*
  - event: sched_process_exec
    filter: 
        - uid=0
  - event: close
```

### Return value Filters

Lastly, we want to use the return value filter, by only tracing the syscall `close` whenever the return value is different than zero.

```
name: rules events example
description: This policy shows multiple events tracing
scope:
  - global
defaultAction: log
rules:
  - event: dropped_executable
  - event: security_file_open
    filter:
        - args.pathname=/tmp/*
  - event: sched_process_exec
    filter: 
        - uid=0
  - event: close
    filter:
        - retval!=0
```