# Policies

Policies allow users to specify which [events](../events/index.md) to trace in which workloads. The policy `scope` defines which workloads this policy is limited to. The policy can define multiple `rules` that specify the events to trace. Policies are used both for the [Tracee CLI](./usage/cli.md) and for the [Tracee Kubernetes](./usage/kubernetes.md) installation. This makes it easier to share policies across use cases and environments.

It is possible to load up to 64 policies into Tracee.

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

!!! Note TODO
    Note that currently each event type can only be defined once in a policy

There are many ways to fine tune the scope and filters. For further information on the details, have a look at the respective sections: 

* [Specify the Policy scope](./scopes.md)
* [Filter events in the rules section](./rules.md)

While specifying event filters is optional, policies must have the `name`, `description`, `scope` and `rules` fields.
