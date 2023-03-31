In this section you can find the reference documentation for Tracee's policies.

A policy is a yaml document where you can specify a scope and associate it with a set of rules. A scope defines the workloads to which the policy applies. A rule defines events to be matched and actions to take on them.

You can load multiple (up to 64) policies into Tracee using the --policy flag providing a path to the policy file.

Following is a sample policy:

```yaml
name: overview policy
description: sample overview policy
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

This policy applies to any workload (global) and will log the dropped_executable, security_file_open, sched_process_exec and close events. Several filters are set to log only specific events:

1. An argument filter (args.pathname) is set on the security_file_open event to log only files which were opened from the /tmp directory

2. A context filter (uid) is set on the sched_process_exec event to log only processes executed by the root user (uid 0)

3. A return value filter (retval) is set on the close event to log only failed close syscalls

While specifying event filters is optional, policies must have the `name`, `description`, `scope`, `defaultAction`, and `rules` fields.

!!! Note
    A current limitation is that only one rule can be defined per any event type in a policy

More information about defining a scope and the available filters can be found in the next sections.
