# Rules

Rules determine which events a policy should trace. 

## Events

An event can match all occurrences of events for a specific scope, or specific events depending on its filters.
Events support three types of filters: `context`, `arguments` and `return value`. 

### Type of Events

You can add events as either of the following:

**[A syscall](../events/builtin/syscalls/index.md)**

Example Scope Section referencing the `open` syscall:

```bash
spec:
	scope:
	    - global
	rules:
	    event: open
```

The name of the syscall is going to be the name of the event.

**[Network Events](../events/builtin/network.md)**

Network Events can be specified from the list of `Available network events`.

For example:

```bash
spec:
	scope:
	    - global
	rules:
	    event: net_packet_ipv4
```

**[A behavioural Signature](../events/builtin/signatures/index.md)**

To specify one of the behavioral signatures as an event, use the name of the signature from the table in the documentation as the event name:

```bash
spec:
	scope:
	    - global
	rules:
	    event: anti_debugging
```

**[Any of our extra events](../events/builtin/extra/bpf_attach.md)**

Any of the extra events listed in the Tracee documentation can be listed in the Tracee Policy.

For instance, to specify the [do_sigaction](../events/builtin/extra/do_sigaction.md) event, provide the name in the YAML manifest:

```bash
spec:
	scope:
	    - global
	rules:
	    event: do_sigaction
```

## Context filters

Context is data which is collected along the event. They can be filtered like:

```yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
	name: sample-context-filter
	annotations:
		description: sample context filter
spec:
	scope:
	    - global
	rules:
	    event: sched_process_exec
	    filters:
		- pid=1000
```

The context filters supported are:

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

#### hostParentProcessId

```yaml
event: sched_process_exec
filters:
    - hostParentProcessId=1
```

#### uid, userId

```yaml
event: sched_process_exec
filters:
    - uid=0
```

#### mntns, mountNamespace

```yaml
event: sched_process_exec
filters:
    - mntns=4026531840
```

#### pidns, pidNamespace

```yaml
event: sched_process_exec
filters:
    - pidns=4026531836
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

        
## Argument filter

Events have arguments, which can be filtered. 

```yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
	name: sample-argument-filter
	annotations:
		description: sample argument filter
spec:
	scope:
	    - global
	rules:
	    event: security_file_open
	    filters:
		- args.pathname=/tmp*
```

Arguments can be found on the respective event definition, in this case [security_file_open](https://github.com/aquasecurity/tracee/blob/main/pkg/events/events.goL5293-L529), or the user can test the event output in CLI before defining a policy, e.g:

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
