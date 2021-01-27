![Tracee Logo](../images/tracee.png)

# Tracee-Rules: Runtime Security Detection Engine

> Note: This is a new component for Tracee that is still under development

Tracee-Rules is a rule engine that helps you detect suspicious behavioral patterns in streams of events. It is primarily made to leverage events collected with Tracee-eBPF into a Runtime Security solution.  
There are 3 basic concepts for Tracee-Rules:
1. Inputs - Event sources to be processed. Currently only Tracee-eBPF is a supported event source.
3. Rules - (a.k.a Signatures) The particular behavioral pattern to detect in the input source. Signatures can be authored in Golang, or Rego (OPA).
2. Outputs - How to communicate detections. Print to stdout, post to a webhook, or integrate with external systems.

# Getting started

Prerequisites:
- Follow the [Tracee-eBPF](../tracee-ebpf/Readme.md#Getting-Started) guide to make sure you can run tracee-ebpf.

Getting Tracee-Rules:
Currently you need to build from source. `cd tracee-rules && make` will build the executable as well as all built-in signatures into the local `dist` directory.  

Running with Tracee-eBPF:

```bash
sudo tracee-ebpf -o format:gob -o option:eot | tracee-rules --tracee-file /dev/stdin
```

This will:
1. Start `tracee-ebpf` with the default tracing mode (see [Tracee-eBPF](../tracee-ebpf)'s help for more filtering options).
2. Configure Tracee-eBPF to output events into stdout as [gob](https://golang.org/pkg/encoding/gob/) format, and add a terminating event to signal end of stream.
3. Start `tracee-rules` with all built-in rules enabled.

# Integrations

When a detection is made by any of the signatures, it will be printed to stdout. Using the `--webhook` flag you can post detections into an HTTP endpoint that can further relay the detection.

# Rules
Rules are discovered from the local `rules` directory (unless changed by the `--rules-dir` flag). By default, all discovered rules will be loaded unless specific rules are selected using the `--rules` flag.

## Authoring Rules
Tracee-Rules supports authoring rules in Golang or in Rego (the language of Open Policy Agent).

### Rego Rules
Create a `.rego` file in the rules directory that has the following Rego Rules (in this context rules are Rego's language constructs):

1. `__rego_metadoc__`: A *document* rule that defines the rule's metadata (based on [WIP Rego convention](https://hackmd.io/@ZtQnh19kS26YiNlJLqKJnw/H1gAv5nB) for describing policy metadata).
2. `tracee_selected_events`: A *set* rule that defines the event selectors.
3. `tracee_match`: A *boolean* or a *document* rule that defines the logic of the signature. If bool is "returned", a true evaluation will generate a Finding with no data if document is "returned", any non-empty evaluation will generate a Finding with the returned document as the Finding's "Data".

See [example2.rego](/rules/rego/example2.rego) and [example1.rego](/rules/rego/example1.rego) for example Rego signatures.

### Go rules
Tracee-Rules exports a `Signature` interface that you can implement. We use [Go Plugins](https://golang.org/pkg/plugin/) to load Go signatures.  

1. Create a new Go project with a package `main`
2. Import `github.com/aquasecurity/tracee/tracee-rules/types` and implement the `types.Signature` interface.
3. Export a package level variable called `ExportedSignatures` of type `[]types.Signature` that declares the implemented signature (or more) that your package exports.
4. Compile using goplugins `go build -buildmode=plugin -o yourplugin.so yoursource.go`.
5. Place the resulting compiled file in the rules directory and it will be automatically discovered by Tracee-Rules.

See [example.go](/rules/golang/example.go) for example Go signatures.
