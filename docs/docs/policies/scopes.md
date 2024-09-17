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

### not-container
Events are collected from everything but containers:

```yaml
scope:
    - not-container
```

### tree
Events are collected from process tree:

```yaml
scope:
    - tree=1000
```

### executable, exec
Events are collected from executable:

```yaml
scope:
    - executable=/usr/bin/dig
```

### follow

Events collected follow process children:

```yaml
scope:
    - follow
```
