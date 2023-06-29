# bpf_attach

## Intro
bpf_attach - a BPF program is attached to a probe (kprobe/uprobe/tracepoint/raw_tracepoint)

## Description
An event marking that a BPF program was attached to a probe in the system.
It occurs whenever a BPF program is attached to an instrumentation probe - either a 
raw_tracepoint or perf event of the types kprobe, uprobe or tracepoint.
The purpose of the event is to give the user information about the BPF program, 
as well as information about the probe itself.


## Arguments
* `prog_type`:`int`[K] - the BPF program type.
* `prog_name`:`const char*`[K] - the BPF program name (first 16 bytes only, as this is how it is saved in the kernel).
* `prog_id`:`u32`[K] - the BPF program ID as set by the kernel.
* `prog_helpers`:`unsigned long[]`[K] - list of all BPF helpers being used by the BPF program.
* `symbol_name`:`const char*`[K] - name/path of the symbol the BPF program is being attached to.
* `symbol_addr`:`u64`[K] - address/offset of the symbol the BPF program is being attached to.
* `attach_type`:`int`[K] - the probe's type.

## Hooks
### security_file_ioctl
#### Type
kprobe
#### Purpose
Catch the attachment of the BPF program to the perf event

### security_bpf
#### Type
kprobe
#### Purpose
Catch the attachment of the BPF program to the perf event

### security_bpf_prog
#### Type
kprobe
#### Purpose
save data of the BPF program for when we output the event

### tracepoint_probe_register_prio_may_exist
#### Type
kprobe
#### Purpose
Catch the attachment of the BPF program to a raw_tracepoint

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
./tracee -e bpf_attach
```

## Issues

## Related Events
