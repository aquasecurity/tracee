# symbols_collision

## Intro
symbols_collision - a shared object loaded to a process has collisions in exported symbols with another loaded shared object.

## Description
An event marking that a shared object loaded to current process, and have collisions of exported symbols
with other shared object already loaded to the process. This event can help in inform on the 
occasion that a shared object tries to override some symbol of another library.

### Configuring the event
The event is configured using arguments filtering.
#### symbols
Configure the watched symbols that upon collision will trigger the event.
Specify the full name of the symbol for each symbol.
Notice that only watched symbols will be outputed by the event, and the default is watching all symbols.
The use is only with the `=` or `!=` operators, and wildcards aren't supported.

## Arguments
* `loaded_path`:`const char*`[K] - the path of the file loaded.
* `collision_path`:`const char*`[K,TOCTOU] - the path of the file already loaded, which has collision with the new loaded one.
* `symbols`:`const char*const*`[U,TOCTOU] - list of symbols collided between the files.

## Dependency Events
### shared_object_loaded
The event of shared object loading triggers this event, and supplies the information on the
shared object necessary to examine its exported symbols.

### sched_process_exec
Used by tracee to maintain mount NS cache, used in this event to get to processes file system.
Also, used to maintain the cache used by the event for performance improvement.

## Example Use Case
Could be used for example to catch collision between a shared object and `libc.so`, overwriting libc symbols:

```console
./dist/tracee -e symbols_collision.args.loaded_path=/usr/lib/libc.so.6
```

Running this line will give a lot of spam symbols collision, for example collisions of `libc` with `libm`:

```text
TIME             UID    COMM             PID     TID     RET              EVENT                ARGS
14:41:48:296325  1000   xfce4-panel      6808    6808    0                symbols_collision    loaded_path: /usr/lib/libc.so.6, collision_path: /usr/lib/libm.so.6, symbols: [finitel __signbitf finite frexpl frexp scalbn __finite copysignl scalbnf __signbitl scalbnl copysign copysignf ldexpf modff modf ldexp ldexpl finitef frexpf __finitel modfl __finitef __signbit]
```

To reduce the spam collisions, we can configure the event to not print the collision using two ways:
1. Whitelist the collided symbols:

```console
./dist/tracee -e symbols_collision.args.loaded_path=/usr/lib/libc.so.6 -e symbols_collision.args.symbols!=finitel,__signbitf,finite,frexpl,frexp,scalbn,__finite,copysignl,scalbnf,__signbitl,scalbnl,copysign,copysignf,ldexpf,modff,modf,ldexp,ldexpl,finitef,frexpf,__finitel,modfl,__finitef,__signbit
```

2. Whitelist the library `libm`:

```console
./dist/tracee -e symbols_collision.args.loaded_path=/usr/lib/libc.so.6 -e symbols_collision.args.collision_path!=/usr/lib/libm.so.6
```

The first approach is recommended when dealing with common symbols like 'setup_', 'finish_' etc. because it will reduce
the overall noise and also reduce the event processing time, in contrast to the second filter which only works after processing the event.


## Issues
### User Mode Event
Because the event is implemented in user-mode, it needs to open and read files.
This means that the event is not very performance efficient (although it uses some optimizations).
It also means that until the SO file is opened, it could be altered or removed.

### Spam
Notice that there are symbols which unintentionally exported by shared objects regularly.
Moreover, there are times which the same ELF load multiple variations of the same shared object, or one shared object copies code from another (for example, `libm` and `libc`).
This cases will cause unintended spam events, so use wisely.

### Big Event Size
The event pass list of all collided symbols as an argument.
The list might be very large, which will result large memory event resulting performance reduction and excess memory usage.

## Related Events
shared_object_loaded, symbols_loaded
