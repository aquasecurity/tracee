In this section you can find the reference documentation for Tracee's policies.

Policies are YAML manifests that allow you to define how Tracee should respond to different events. This is done through rules in the policy. A rule takes in one or several events. Additionally, events can be filtered to specific resources. If Tracee detects the event, it will respond with an action. 
The default action for Tracee is to log the detected events.

Lastly, policies require a scope. The scope details which resources the policy applies to. 

You can load multiple (up to 64) policies into Tracee using the --policy flag providing a path to the policy file.

Following is a sample policy:

```yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
	name: overview-policy
	annotations:
		description: sample overview policy
spec:
	scope:
	  - global
	rules:
	  - event: dropped_executable
	  - event: security_file_open
	    filters:
		- args.pathname=/tmp/*
	  - event: sched_process_exec
	    filters: 
		- uid=0
	  - event: close
	    filters:
		- retval!=0
```

This policy applies to any workload (global) and will log the dropped_executable, security_file_open, sched_process_exec and close events. Several filters are set to log only specific events:

1. An argument filter (args.pathname) is set on the security_file_open event to log only files which were opened from the /tmp directory

2. A context filter (uid) is set on the sched_process_exec event to log only processes executed by the root user (uid 0)

3. A return value filter (retval) is set on the close event to log only failed close syscalls

While specifying event filters is optional, policies must have the `name`, `description`, `scope` and `rules` fields.

!!! Note
    Note that currently only one rule can be defined per any event type in a policy

More information about defining a scope and the available filters can be found in the next sections.

## Video Content

 Tracking Kubernetes activity with eBPF and Tracee Policies 

 [![Watch the video](../../images/traceepolicies.png)](https://youtu.be/VneWxs9Jpu0?si=eAnRDJVZShhg_td0)
