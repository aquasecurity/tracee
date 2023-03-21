# Actions

Policies support global actions and specific actions per event. The supported actions now are:

- log
- webhook

## Default Action

The default action is the action executed for every event in the policy:

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

## Event Action

```
name: rules events example
description: This policy shows multiple events tracing
scope:
  - global
defaultAction: log
rules:
  - event: dropped_executable
    action:
        - webhook:http://webhook:8080?timeout=5s
  - event: security_file_open
  - event: sched_process_exec
  - event: close
```