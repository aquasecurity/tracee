# bpf_attach

## Intro
bpf_attach - a BPF program is attached to a probe (kprobe/uprobe/tracepoint)

## Description
An event marking that a BPF program was attached to a probe in the system.
It occurs whenever a BPF program is attached to a perf event of the types: kprobe, uprobe or tracepoint.
The purpose of the event is to give the user information about the BPF program, 
as well as information about the probe itself.


## Arguments
* `prog_type`:`int`[K] - the BPF program type.
* `prog_name`:`const char*`[K] - the BPF program type (first 16 bytes only, as this is how it is saved in the kernel).
* `perf_symbol`:`const char*`[K] - name/path of the symbol the BPF program is being attached to.
* `perf_addr`:`u64`[K] - address/offset of the symbol the BPF program is being attached to.
* `prog_write_user`:`int`[K] - whether the BPF program uses the bpf_probe_write_user() helper function.
* `prog_override_return`:`int`[K] - whether the BPF program uses the bpf_override_return() helper function.
* `perf_type`:`int`[K] - the probe's type.

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

### check_helper_call
#### Type
kprobe
#### Purpose
check whether the BPF program uses helper functions of interest

### check_map_func_compatibility
#### Type
kprobe
#### Purpose
check whether the BPF program uses helper functions of interest

## Example Use Case
./tracee-ebpf -t e=bpf_attach

## Issues
the 'check_helper_call' and 'check_map_func_compatibility' serves the same purpose. 
in some kernels one of this symbols would not exist - therefore libbpf will output an error (execution will continue successfully due to the other hook).

## Related Events
