# Tracee-Rules: Runtime Security Detection Engine

Tracee-Rules is a rule engine that helps you detect suspicious behavioral patterns in streams of events. It is primarily made to leverage events collected with Tracee-eBPF into a Runtime Security solution.  

There are 3 basic concepts for Tracee-Rules:

1. **Inputs** - Event sources to be processed. Currently only Tracee-eBPF is a supported event source.
2. **Rules (a.k.a Signatures)** - The particular behavioral pattern to detect in the input source. Signatures can be authored in Golang, or Rego (OPA).
3. **Outputs** - How to communicate detections. Print to stdout, post to a webhook, or integrate with external systems.

## Getting started

Tracee-Rules doesn't have any requirement, but in order to run with Tracee-eBPF, make sure you follow the [minimum requirements for running Tracee](TODO).

Getting Tracee-Rules:
Currently you need to build from source. `cd tracee-rules && make` will build the executable as well as all built-in signatures into the local `dist` directory.  

Running with Tracee-eBPF:

```bash
sudo tracee-ebpf -o format:gob | tracee-rules --input-tracee file:stdin --input-tracee format:gob
```

This will:
1. Start `tracee-ebpf` with the default tracing mode (see Tracee-eBPF's help for more info).
2. Configure Tracee-eBPF to output events into stdout as [gob](https://golang.org/pkg/encoding/gob/) format, and add a terminating event to signal end of stream.
3. Start `tracee-rules` with all built-in rules enabled.
