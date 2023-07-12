# hidden_kernel_module

## Intro
hidden_kernel_module - a linux kernel module that is hidden was detected.

## Description
An event marking that a loaded hidden kernel module was detected on your system.
This event helps in providing a strong indication that your system is compromised.
It periodically checks for a hidden module.

## Arguments
* `address`:`const char*`[K] - the memory address of the hidden kernel module. 
* `name`:`const char*`[K] - the name of the hidden kernel module.

## Hooks
Self-triggered hook by uprobing itself.

## Example Use Case

```console
./tracee -e hidden_kernel_module
```

## Issues

## Related Events
