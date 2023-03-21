# Scopes

Scopes define the workload this policy cares about. For example,
we want to know all dns events executed by the tool `dig`:

Example 1:

```
name: dig
description: This policy traces dns events from the dig binary
scope:
  - binary=/usr/bin/dig
defaultAction: log
rules:
  - event: net_packet_dns
```

or 

Example 2: 

```
name: dig
description: This policy traces dns events from the dig binary
scope:
  - comm=dig
defaultAction: log
rules:
  - event: net_packet_dns
```

To track events in the whole host, use the `global` scope:

```
name: sched_process_exec
description: This policy traces all processes executed on the host
scope:
  - global
defaultAction: log
rules:
  - event: sched_process_exec
```

Or, if I want all `sched_process_exec` on the host, ignoring containers:

```
name: sched_process_exec
description: This policy traces all processes executed on the host
scope:
  - !container
defaultAction: log
rules:
  - event: sched_process_exec
```


   !!! Note
        The following is a list of available context fields:  
        1) "global"
        2) "uid"
		2) "pid"
		3) "mntNS"
		4) "pidns"
		5) "uts"
		6) "comm"
		7) "container"
		8) "!container"
		9) "tree"
		10) "binary"
		11) "bin"
		12) "follow"

