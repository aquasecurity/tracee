In this section you can find the reference documentation for Tracee's policies.

A sample policy with all its features:

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

Policies must have `name`, `description`, `scope`, `defaultAction`, and `rules`.