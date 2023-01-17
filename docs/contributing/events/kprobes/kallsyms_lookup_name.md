# kallsyms_lookup_name

## Intro
kallsyms_lookup_name - lookup the address for a symbol

## Description
This event is invoked when the 'kallsyms_lookup_name()' kernel function returns. 
It suggests a lookup of kernel symbol address.
This function is used mainly by external kernel extensions like kernel modules or BPF programs.
It might be interesting in cases where a sensitive kernel symbol is looked-up.

## Arguments
* `symbol_name`:`const char*`[K] - the symbol that is being looked-up.
* `symbol_address`:`void*`[K] - the address of the symbol returned by the function. 0 if not found.
* `syscall`:`int`[K] - the id of the syscall that invoked this lookup. If output option `parse-arguments` was chosen, the value will be transformed to the syscall name as a string type.

## Hooks
### kallsyms_lookup_name
#### Type
kprobe + kretprobe
#### Purpose
tracing the kallsyms_lookup_name event

## Example Use Case
`./dist/tracee-ebpf -t e=kallsyms_lookup_name`
