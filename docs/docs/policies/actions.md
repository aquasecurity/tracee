# Actions

Actions are taken when there is an event match. Currently the only action supported is `log`. 

```yaml
name: overview policy
description: sample overview policy
scope:
  - global
defaultAction: log
rules:
  - event: dropped_executable
```