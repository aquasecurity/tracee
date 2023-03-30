# Rules

Rules determine which events a policy should trace. 

## Events

An event can match all occurrences of events for a specific scope, or specific events depending on its filters.
Events support three types of filters: `context`, `arguments` and `return value`. 

## Context filter

Context is data which is collected along the event. They can be filtered like:

```yaml
name: sample_context_filter
description: sample context filter
defaultAction: log
scope:
    - global
rules:
    event: sched_process_exec
    filter:
        - pid=1000
```

The context filters supported are:

#### p, pid, processId

```yaml
event: sched_process_exec
filter:
    - pid=1000
```

#### tid, threadId

```yaml
event: sched_process_exec
filter:
    - tid=13819
```

#### ppid, parentProcessId

```yaml
event: sched_process_exec
filter:
    - ppid=1000
```

#### hostTid, hostThreadId

```yaml
event: sched_process_exec
filter:
    - hostTid=1000
```

#### hostPid

```yaml
event: sched_process_exec
filter:
    - hostPid=1000
```

#### hostParentProcessId

```yaml
event: sched_process_exec
filter:
    - hostParentProcessId=1
```

#### uid, userId

```yaml
event: sched_process_exec
filter:
    - uid=0
```

#### mntns, mountNamespace

```yaml
event: sched_process_exec
filter:
    - mntns=4026531840
```

#### pidns, pidNamespace

```yaml
event: sched_process_exec
filter:
    - pidns=4026531836
```

#### comm, processName

```yaml
event: sched_process_exec
filter:
    - comm=uname
```

#### hostName

```yaml
event: sched_process_exec
filter:
    - hostName=hostname
```

#### cgroupId

```yaml
event: sched_process_exec
filter:
    - cgroupId=5247
```

#### container

```yaml
event: sched_process_exec
filter:
    - container=66c2778945e29dfd36532d63c38c2ce4ed1
```

#### containerId

```yaml
event: sched_process_exec
filter:
    - containerId=66c2778945e29dfd36532d63c38c2ce4ed1
```

#### containerImage

```yaml
event: sched_process_exec
filter:
    - containerImage=ubuntu:latest
```

#### containerName  

```yaml
event: sched_process_exec
filter:
    - containerName=test
```

#### podName

```yaml
event: sched_process_exec
filter:
    - podName=daemonset/test
```

#### podNamespace

```yaml
event: sched_process_exec
filter:
    - podNamespace=production
```

#### podUid

```yaml
event: sched_process_exec
filter:
    - podUid=66c2778945e29dfd36532d63c38c2ce4ed16a002c44cb254b8e
```

        
## Argument filter

Events have arguments, which can be filtered. 

```yaml
name: sample_argument_filter
description: sample argument filter
defaultAction: log
scope:
    - global
rules:
    event: security_file_open
    filter:
        - args.pathname=/tmp*
```

Arguments can be found on the respective event definition, in this case [security_file_open](https://github.com/aquasecurity/tracee/blob/main/pkg/events/events.goL5293-L529), or the user can test the event output in CLI before defining a policy, e.g:

```console
tracee -f e=security_file_open --output json
```

```json
{"timestamp":1680182976364916505,"threadStartTime":1680179107675006774,"processorId":0,"processId":676,"cgroupId":5247,"threadId":676,"parentProcessId":1,"hostProcessId":676,"hostThreadId":676,"hostParentProcessId":1,"userId":131,"mountNamespace":4026532574,"pidNamespace":4026531836,"processName":"systemd-oomd","hostName":"josedonizetti-x","container":{},"kubernetes":{},"eventId":"730","eventName":"security_file_open","matchedPolicies":[""],"argsNum":6,"returnValue":0,"syscall":"openat","stackAddresses":null,"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"pathname","type":"const char*","value":"/proc/meminfo"},{"name":"flags","type":"string","value":"O_RDONLY|O_LARGEFILE"},{"name":"dev","type":"dev_t","value":45},{"name":"inode","type":"unsigned long","value":4026532041},{"name":"ctime","type":"unsigned long","value":1680179108391999988},{"name":"syscall_pathname","type":"const char*","value":"/proc/meminfo"}]}
```

## Return value filter

Return values can also be filtered.

```yaml
name: sample_return_value
description: sample return filter
defaultAction: log
scope:
    - global
rules:
    event: close
    filter:
        - retval!=0
```