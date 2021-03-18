libbpfgo tries to make it natural for Go developers to use, by abstracting away C technicalities. For example, it will translate low level return codes into Go `error`, it will organize functionality around Go `struct`, and it will use `channel` as to let you consume events.

In a high level, this is a typical workflow for working with the library:

0. Compile your bpf program into an object file.
1. Initialize a `Module` struct - that is a unit of BPF functionality around your compiled object file.
2. Load bpf programs from the object file using the `BPFProg` struct.
3. Attach `BPFProg` to system facilities, for example to "raw tracepoints" or "kprobes" using the `BPFProg`'s associated functions.
4. Instantiate and manipulate BPF Maps via the `BPFMap` struct and it's associated methods.
5. Instantiate and manipulate Perf Buffer for communicating events from your BPF program to the driving userspace program, using the `PerfBuffer` struct and it's associated objects.
