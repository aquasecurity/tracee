# Rules

Rules are part of the Tracee Policy, which defines which events to trace. The events that are part of a specific policy are recorded in the `rules` section of the Tracee Policy. It is possible to define multiple events within each policy.

Below are several examples on configuring events in the Tracee Policy.

## Events

Every event that is specified within the `rules` section supports three types of filters: `process`, `data` and `return value`.

### Type of Events
 
The [events](../events/index.md) section provides further information on the type of events that Tracee can track.

__rules support:__

* [Syscall events](../events/builtin/syscalls/index.md)

* [Network events](../events/builtin/network/index.md)

* [Signatures events](../events/builtin/signatures/index.md)

* [Extra events like "bpf_attach"](../events/builtin/extra/bpf_attach.md)


## Process filters

Further refinement of the policy's scope is achievable through the application of process filters:

```yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
	name: sample-process-filter
	annotations:
		description: sample process filter
spec:
	scope:
	    - global

    rules:
	    event: sched_process_exec
	    filters:
		- pid=1000
```

There are many process filters that are supported. This section includes detailed description of the common process filters options

#### p, pid, processId

```yaml
event: sched_process_exec
filters:
    - pid=1000
```

#### tid, threadId

```yaml
event: sched_process_exec
filters:
    - tid=13819
```

#### ppid, parentProcessId

```yaml
event: sched_process_exec
filters:
    - ppid=1000
```

#### hostTid, hostThreadId

```yaml
event: sched_process_exec
filters:
    - hostTid=1000
```

#### hostPid

```yaml
event: sched_process_exec
filters:
    - hostPid=1000
```

#### uid, userId

```yaml
event: sched_process_exec
filters:
    - uid=0
```

#### comm, processName

```yaml
event: sched_process_exec
filters:
    - comm=uname
```

#### hostName

```yaml
event: sched_process_exec
filters:
    - hostName=hostname
```

#### cgroupId

```yaml
event: sched_process_exec
filters:
    - cgroupId=5247
```

#### container

```yaml
event: sched_process_exec
filters:
    - container=66c2778945e29dfd36532d63c38c2ce4ed1
```

#### containerId

```yaml
event: sched_process_exec
filters:
    - containerId=66c2778945e29dfd36532d63c38c2ce4ed1
```

#### containerImage

```yaml
event: sched_process_exec
filters:
    - containerImage=ubuntu:latest
```

#### containerName  

```yaml
event: sched_process_exec
filters:
    - containerName=test
```

#### podName

```yaml
event: sched_process_exec
filters:
    - podName=daemonset/test
```

#### podNamespace

```yaml
event: sched_process_exec
filters:
    - podNamespace=production
```

#### podUid

```yaml
event: sched_process_exec
filters:
    - podUid=66c2778945e29dfd36532d63c38c2ce4ed16a002c44cb254b8e
```

        
## Data filter

Every event contain data that can be filtered.
 
For example:

```yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
	name: sample-data-filter
	annotations:
		description: sample data filter
spec:
	scope:
	    - global
	rules:
	    event: security_file_open
	    filters:
		- data.pathname=/tmp*
```

Data fields can be found on the respective event definition, in this case [security_file_open](https://github.com/aquasecurity/tracee/blob/656eb976fbb66aba54c5f306019258e436d4814a/pkg/events/core.go#L11502-L11533) - be aware of possible changes to the definition linked above, so always check the main branch.

 Or the user can test the event output in CLI before defining a policy, e.g:

```console
tracee -e security_file_open --output json
```

```json
{"timestamp":1680182976364916505,"threadStartTime":1680179107675006774,"processorId":0,"processId":676,"cgroupId":5247,"threadId":676,"parentProcessId":1,"hostProcessId":676,"hostThreadId":676,"hostParentProcessId":1,"userId":131,"mountNamespace":4026532574,"pidNamespace":4026531836,"processName":"systemd-oomd","hostName":"josedonizetti-x","container":{},"kubernetes":{},"eventId":"730","eventName":"security_file_open","matchedPolicies":[""],"argsNum":6,"returnValue":0,"syscall":"openat","stackAddresses":null,"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"pathname","type":"const char*","value":"/proc/meminfo"},{"name":"flags","type":"string","value":"O_RDONLY|O_LARGEFILE"},{"name":"dev","type":"dev_t","value":45},{"name":"inode","type":"unsigned long","value":4026532041},{"name":"ctime","type":"unsigned long","value":1680179108391999988},{"name":"syscall_pathname","type":"const char*","value":"/proc/meminfo"}]}
```

## Return value filter

Return values can also be filtered.

```yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
	name: sample-return-value
	annotations:
		description: sample return value
spec:
	scope:
	    - global
	rules:
	    event: close
	    filters:
		- retval!=0
```
