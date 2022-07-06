# Trace Options

Trace output can easily become unwieldy when tracing all of the events from all
of the system. Luckily, Tracee has a powerful mechanism to accurately trace
just the information that is relevant to you, using the `--trace` flag.

Using the `--trace` you define expressions that tells Tracee-eBPF what you are
interested in by means of event metadata, and process metadata. Only events
that match this criteria will be traced.

You can filter by most of the visible fields on a Tracee event. For example to
trace only events related to user ID 1000, use `--trace uid=1000`.

You can combine trace expressions into more complex criteria. For example, to
trace only events related to user ID 1000, which come from process ID 1234, use
`--trace uid=1000 --trace pid=1234`.

A special `pid` value is `new` which let's you trace all newly created
processes (that were created after Tracee started tracing).

Tracee-eBPF lets you easily trace events that originate in containers using
`--trace container` or only new containers (that were created after Tracee
started) using `--trace container=new`.

Event metadata can be used in trace expression as well. For example, to trace
only `openat` syscalls, use `--trace event:openat`. But you can also filter on
a specific argument of the event, e.g `--trace openat.pathname=/bin/ls` which
will show only `openat` syscalls that operate on the file `/bin/ls`.

A useful trace mode is the `--trace follow` which, if specified, will trace not
only processes that match the given trace expressions, but also their child
processes.

For example, the following will trace all the events that originate from zsh
shell, including all of the processes that it will spawn: `--trace comm=zsh
--trace follow`.

## CLI Options

Only events that match all trace expressions will be traced (trace flags are ANDed).
The following types of expressions are supported:

Numerical expressions which compare numbers and allow the following operators: '=', '!=', '<', '>'.
Available numerical expressions: uid, pid, mntns, pidns.

String expressions which compares text and allow the following operators: '=', '!='.
Available string expressions: event, set, uts, comm, container.

Boolean expressions that check if a boolean is true and allow the following operator: '!'.
Available boolean expressions: container.

Event arguments can be accessed using 'event_name.event_arg' and provide a way to filter an event by its arguments.
Event arguments allow the following operators: '=', '!='.
Strings can be compared as a prefix if ending with '*' or as suffix if starting with '*'.

Event return value can be accessed using 'event_name.retval' and provide a way to filter an event by its return value.
Event return value expression has the same syntax as a numerical expression.

Non-boolean expressions can compare a field to multiple values separated by ','.
Multiple values are ORed if used with equals operator '=', but are ANDed if used with any other operator.

The field 'container' and 'pid' also support the special value 'new' which selects new containers or pids, respectively.

The field 'set' selects a set of events to trace according to predefined sets, which can be listed by using the 'list' flag.

The special 'follow' expression declares that not only processes that match the criteria will be traced, but also their descendants.

Note: some of the above operators have special meanings in different shells. To 'escape' those operators, please use single quotes, e.g.: 'uid>0'

## Examples

only trace events from new processes

```
--trace pid=new
```

only trace events from pid 510 or pid 1709

```
--trace pid=510,1709
```

only trace events from pid 510 or pid 1709 (same as above)

```
--trace p=510 --trace p=1709
```

only trace events from newly created containers

```
--trace container=new
```

only trace events from container id ab356bc4dd554

```
--trace container=ab356bc4dd554
```

only trace events from containers

```
--trace container
```

only trace events from containers (same as above)

```
--trace c
```

only trace events from the host

```
--trace '!container'
```

only trace events from uid 0

```
--trace uid=0
```

only trace events from mntns id 4026531840

```
--trace mntns=4026531840
```
  
only trace events from pidns id not equal to 4026531840

```
--trace pidns!=4026531836
```

only trace events from uids greater than 0

```
--trace 'uid>0'
```

only trace events from pids between 0 and 1000

```
--trace 'pid>0' --trace 'pid<1000'
```
  
only trace events from uids greater than 0 but not 1000

```
--trace 'u>0' --trace u!=1000
```
  
only trace execve and open events

```
--trace event=execve,open
```

only trace events prefixed by "open"

```
--trace event=open*
```

don't trace events prefixed by "open" or "dup"

```
--trace event!=open*,dup*
```

trace all file-system related events
```
--trace set=fs
```

trace all file-system related events, but not open(at)

```
--trace s=fs --trace e!=open,openat
```

don't trace events from uts name ab356bc4dd554

```
--trace uts!=ab356bc4dd554
```

only trace events from ls command

```
--trace comm=ls
```

only trace 'close' events that have 'fd' equals 5

```
--trace close.fd=5
```

only trace 'openat' events that have 'pathname' prefixed by "/tmp"

```
--trace openat.pathname=/tmp*
```

don't trace 'openat' events that have 'pathname' equals /tmp/1 or /bin/ls

```
--trace openat.pathname!=/tmp/1,/bin/ls
```

trace all events that originated from bash or from one of the processes spawned by bash

```
--trace comm=bash --trace follow
```

trace the network events over a given interface name

```
-trace net=<iface>
```
