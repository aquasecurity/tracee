# Policies

Policies allow you to specify which events in which workloads to trace. The policy `scope` defines which workloads this policy is limited to. The policy can define multiple `rules` that selects events to trace. 

Here is an example policy:

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
```

This policy applies to any workload (global) and will log the `dropped_executable`, and `security_file_open` events. An argument filter (`args.pathname``) is set on the `security_file_open`` event to log only files which were opened from the `/tmp` directory.

There are many ways to fine tune the scope and filters... 
send to [scopes]
send to [rules]

While specifying event filters is optional, policies must have the `name`, `description`, `scope` and `rules` fields.

!!! Note TODO
    Note that currently only one rule can be defined per any event type in a policy


You can load up to 64 policies into Tracee.

USAGE
 using the --policy flag providing a path to the policy file.

## Video Content USAGE

 Tracking Kubernetes activity with eBPF and Tracee Policies 

 [![Watch the video](../../images/traceepolicies.png)](https://youtu.be/VneWxs9Jpu0?si=eAnRDJVZShhg_td0)
