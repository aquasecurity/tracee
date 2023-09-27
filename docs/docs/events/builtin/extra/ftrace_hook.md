# ftrace_hook

## Intro
ftrace_hook - an ftrace hook was detected.

## Description
An event marking that an ftrace hook was detected on your system.

## Arguments
* `symbol`:`const char*`[K] - the symbol that is being hooked. 
* `trampoline`:`const char*`[K] - the name/address of the ftrace trampoline.
* `callback`:`const char*`[K] - the callback name/address that will be called once the symbol is being executed.
* `callback_offset`:`off_t`[K] - the callback offset (inside the function).
* `callback_owner`:`const char*`[K] - the owner of the callback (kernel module name if applicable etc)
* `flags`:`const char*`[K] - the flags for ftrace. R: registers are passed to the callback; I: callback can change the RIP register value; D: direct call to the function; O: callsite-specific ops; M: the function had I or D.
* `count`:`unsigned long`[K] - the number of callbacks registered with the symbol.


## Hooks
Self-triggered hook.

## Example Use Case

```console
./tracee -e ftrace_hook
```

## Issues

## Related Events
