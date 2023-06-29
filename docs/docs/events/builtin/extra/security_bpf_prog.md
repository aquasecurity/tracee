# security_bpf_prog

## Intro
security_bpf_prog - Do a check when the kernel generate and return a file descriptor for BPF programs.

## Description
This event marks the act of getting a file descriptor of a BPF program. It is triggered when the BPF program is being 
loaded, or when the user asks for it explicitly. This event is of type LSM hook.
The event contains data about the BPF program, and whether it is currently being loaded or not. 


## Arguments
* `type`:`int`[K] - the BPF program type.
* `name`:`const char*`[K] - the BPF program name (first 16 bytes only, as this is how it is saved in the kernel).
* `helpers`:`unsigned long[]`[K] - list of all BPF helpers being used by the BPF program.
* `id`:`u32`[K] - the BPF program ID as set by the kernel.
* `load`:`bool`[K] - whether this BPF program is currently being loaded.

## Hooks
### security_bpf_prog
#### Type
kprobe
#### Purpose
The LSM hook of getting a file descriptor of a BPF program. This hook triggers the event. 

### bpf_check
#### Type
kprobe
#### Purpose
Save data of whether this BPF program is currently being loaded.

### check_helper_call
#### Type
kprobe
#### Purpose
get information about which helper functions are used by the BPF program

### check_map_func_compatibility
#### Type
kprobe
#### Purpose
get information about which helper functions are used by the BPF program

## Example Use Case

```console
./tracee -e security_bpf_prog
```

## Issues

## Related Events
