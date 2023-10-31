# Policies

Policies allow users to specify which [events](../events/index.md) to trace in which workloads. The policy `scope` defines which workloads this policy is limited to. The policy can define multiple `rules` that specify the events to trace. 

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

This policy applies to any workload (`global`) and will log the `dropped_executable`, and `security_file_open` events. An argument filter (`args.pathname`) is set on the `security_file_open` event to log only files which were opened from the `/tmp` directory.

There are many ways to fine tune the scope and filters. For further information on the details, have a look at the respective sections: 

* [scopes](./scopes.md)
* [rules](./rules.md)

While specifying event filters is optional, policies must have the `name`, `description`, `scope` and `rules` fields.
It is possible to load up to 64 policies into Tracee.

!!! Note TODO
    Note that currently each event type can only be defined once in a policy