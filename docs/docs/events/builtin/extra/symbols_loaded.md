# symbols_loaded

## Intro
symbols_loaded - a shared object which exports a watched symbol was loaded.

## Description
An event marking that a shared object, which export symbols configured to be watched,
was loaded to current process. This event can help in identifying some shared object
usage in the system, or inform on the occasion that a shared object tries to override
some symbol of another library.

### Configuring the event
The event is configured using arguments filtering.
For each argument, a filter can be used to configure the operation:
#### symbols
Configure the watched symbols by the event.
Specify the full name of the symbol for each symbol.
The use is only with the `=` operator, and wildcards aren't supported.
#### library_path
Whitelist for shared object paths prefixes.
The path can be absolute, or just a library name.
If only a name is given, then any shared object inside the known libraries directories which
starts with the prefix will be whitelisted.
The use is only with the `!=` operator, and wildcards aren't supported.

## Arguments
* `library_path`:`const char*`[K] - the path of the shared object file loaded.
* `symbols`:`const char*const*`[U,TOCTOU] - the watched symbols exported by the shared object.

## Dependency Events
### shared_object_loaded
The event of shared object loading triggers this event, and supplies the information on the
shared object necessary to examine its shared objects.

### sched_process_exec
Used by tracee to maintain mount NS cache, used in this event to get to processes file system

## Example Use Case
To catch SO which tries to override the `fopen` function of `libc`, we can use the event in
the following way:

```console
./dist/tracee -e symbols_loaded.args.symbols=fopen -e symbols_loaded.args.library_path!=libc
```

## Issues
Because the event is implemented in user-mode, it needs to open and read files.
This means that the event is not very performance efficient (although it uses some optimizations).
It also means that until the SO file is opened, it could be altered or removed.

## Related Events
shared_object_loaded, symbols_collision
