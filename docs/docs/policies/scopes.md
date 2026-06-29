# Scopes

`scope` allows you to select the scope for tracing events by defining filters. 

## FILTER EXPRESSION

Filter expressions can be defined to operate on scope options or process metadata. Only events that match all filter expressions will be traced.

Multiple flags are combined with AND logic, while multiple values within a single flag are combined with OR logic when using the equals operator '='. Multiple values can be specified using ','.

### NUMERICAL EXPRESSION OPERATORS

The following numerical fields support the operators '=', '!=', '<', '>', '<=', '>=':

- uid: Select events from specific user IDs.
- pid: Select events from specific process IDs.

The following numerical fields only support the operators '=' and '!=':

- mntns: Select events from specific mount namespace IDs.
- pidns: Select events from specific process namespace IDs.
- tree: Select events that descend from specific process IDs.

NOTE: Expressions containing '<' or '\>' tokens must be escaped!

### STRING EXPRESSION OPERATORS

'=', '!='

Available for the following string fields:

- uts: Select events based on UTS (Unix Timesharing System) names.
- comm: Select events based on process command names.
- container: Select events from specific container IDs.
- executable: Select events based on the executable path.



### BOOLEAN OPERATOR (PREPENDED)

'!'

Available for the following boolean field:

- container: Select events based on whether they originate from a container or not.

## Supported Scopes

### global

Events are collected from the whole host:
```yaml
scope:
    - global
```

### uid

Events are collected from the specific user id:

```yaml
scope:
    - uid=0
```

### pid

Events are collected from the specific pid:

```yaml
scope:
    - pid=1000
```

### mntns

Events are collected from the mount namespace:

```yaml
scope:
    - mntns=4026531840
```

### pidns

Events are collected from the pid namespace:

```yaml
scope:
    - pidns=4026531836
```

### uts

Events are collected from uts namespace:

```yaml
scope:
    - uts=ab356bc4dd554
```

### comm

Events are collected from process named `uname`:

```yaml
scope:
    - comm=uname
```

### container

Events are collected only from containers:

```yaml
scope:
    - container
```

You can also filter for containers based on their state:

- **container=new**: Events are collected only from newly created containers (during container initialization):

```yaml
scope:
    - container=new
```

- **container=started**: Events are collected only from containers that have completed initialization and started running (post-entrypoint execution):

```yaml
scope:
    - container=started
```

Note: The negation `container!=started` is not supported due to race conditions with early container event recognition.

### not-container

Events are collected from everything but containers:

```yaml
scope:
    - not-container
```

### tree

Collect events only from processes within the subtree(s) of one or more process IDs
(a process and all of its descendants). Use `=` to *include* a subtree and `!=` to
*exclude* one; multiple PIDs may be given comma-separated. The filter is recursive
(all descendants), dynamic (processes spawned later are included automatically), and
already-running descendants are covered at startup.

```yaml
scope:
    - tree=1000          # only PID 1000 and its descendants
```

```yaml
scope:
    - tree!=1000,2000    # everything except the subtrees of PIDs 1000 and 2000
```

### executable, exec

Events are collected from executable:

```yaml
scope:
    - executable=/usr/bin/dig
```

### follow

When a process matches the policy's scope, also collect events from its descendants even if
they would not match the scope on their own. The "followed" mark is inherited by children, so
an entire spawned subtree is traced once one of its ancestors matched.

```yaml
scope:
    - comm=bash
    - follow            # bash and everything it spawns (recursively)
```

## Scopes and network events

Process-context scopes (`uid`, `pid`, `comm`, `mntns`, `pidns`, `tree`, `executable`, etc.)
are evaluated for network packet and flow events (`net_packet_*`, `net_flow_*`) at the moment
the underlying socket is tracked — i.e. against the process that owned the socket then — and the
result is cached with the socket. They are **not** re-evaluated per packet against the task that
happens to send or receive each packet.

Two consequences follow:

- A long-lived socket keeps the scope match it had when it was first tracked, even if later
  packets are driven by a different task.
- Because sockets are tracked by kernel inode and inode numbers are reused, a packet from an
  unrelated process (for example background DNS from `systemd-resolved`) can occasionally be
  attributed to a scope that matched the original owner of that inode.

Note: this affects only the packet/flow network events listed above. Process-context network
events such as `net_tcp_connect` are evaluated against the acting task and scope normally.
If you need strict per-process attribution of network activity, prefer those process-context
events over `net_packet_*`/`net_flow_*`.
