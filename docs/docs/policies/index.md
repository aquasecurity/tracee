# Getting Started with Policies

Tracee's policies are how you describe what tracee should collect and what actions it should take.

For example, we would like to collect all `sched_process_exec` events from the whole host:

```
name: get started policy
description: This policy is a get started example
scope:
  - global
defaultAction: log
rules:
  - event: sched_process_exec
```

Here, we create a basic policy with the scope `global` (for the whole host) and the action of logging the events that match the policy.

We can execute the policy and see its result:
```
tracee -p get_started_policy.yaml
```

Once we execute, we notice we also want to collect the event `sched_process_exit`, so we can change the policy accordingly:

```
name: get started policy
description: This policy is a get started example
scope:
  - global
defaultAction: log
rules:
  - event: sched_process_exec
  - event: sched_process_exit
```

After testing, we see that for our usecase we only care about `sched_process_exit` when the user id is zero:

```
name: get started policy
description: This policy is a get started example
scope:
  - global
defaultAction: log
rules:
  - event: sched_process_exec
  - event: sched_process_exit
    filter:
        - uid=0 
```

And, the last change is that we don't care about the whole host, only new containers, so we change our scope from global
to `container=new`:

```
name: get started policy
description: This policy is a get started example
scope:
  - container=new
defaultAction: log
rules:
  - event: sched_process_exec
  - event: sched_process_exit
    filter:
        - uid=0 
```
