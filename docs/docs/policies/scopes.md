# Scopes

Scope defines the workload a policy will be observing. 

The supported scopes are listed below.

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
