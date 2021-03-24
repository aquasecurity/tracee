- Follow the [Tracee-eBPF](../../ebpf) guide to make sure you can run tracee-ebpf.

## Getting Tracee-Rules
Currently you need to build from source. `cd tracee-rules && make` will build the executable as well as all built-in signatures into the local `dist` directory.  

## Running with Tracee-eBPF

```bash
sudo tracee-ebpf -o format:gob | tracee-rules --input-tracee file:stdin --input-tracee format:gob
```

This will:

1. Start `tracee-ebpf` with the default tracing mode (see [Tracee-eBPF](../../ebpf)'s help for more filtering options).
2. Configure Tracee-eBPF to output events into stdout as [gob](https://golang.org/pkg/encoding/gob/) format, and add a terminating event to signal end of stream.
3. Start `tracee-rules` with all built-in rules enabled.
