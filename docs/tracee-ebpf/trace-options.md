# Trace Options

Trace output can easily become unwieldy when tracing all of the events from all of the system. Luckily, Tracee has a powerful mechanism to accurately trace just the information that is relevant to you, using the `--trace` flag.
Using the `--trace` you define expressions that tells Tracee-eBPF what you are interested in by means of event metadata, and process metadata. Only events that match this criteria will be traced.

You can filter by most of the visible fields on a Tracee event. For example to trace only events related to user ID 1000, use `--trace uid=1000`.  
You can combine trace expressions into more complex criteria. For example, to trace only events related to user ID 1000, which come from process ID 1234, use `--trace uid=1000 --trace pid=1234`.  

A special `pid` value is `new` which let's you trace all newly created processes (that were created after Tracee started tracing).  
Tracee-eBPF lets you easily trace events that originate in containers using `--trace container` or only new containers (that were created after Tracee started) using `--trace container=new`.

Event metadata can be used in trace expression as well. For example, to trace only `openat` syscalls, use `--trace event:openat`. But you can also filter on a specific argument of the event, e.g `--trace openat.pathname=/bin/ls` which will show only `openat` syscalls that operate on the file `/bin/ls`.

A useful trace mode is the `--trace follow` which, if specified, will trace not only processes that match the given trace expressions, but also their child processes.
For example, the following will trace all the events that originate from zsh shell, including all of the processes that it will spawn: `--trace command=zsh --follow`.

For a complete list of trace options, run `--trace help`.
