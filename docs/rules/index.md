![Tracee Logo](../images/tracee.png)

# Tracee-Rules: Runtime Security Detection Engine

> Note: This is a new component for Tracee that is still under development

Tracee-Rules is a rule engine that helps you detect suspicious behavioral patterns in streams of events. It is primarily made to leverage events collected with Tracee-eBPF into a Runtime Security solution.  

There are 3 basic concepts for Tracee-Rules:

1. **Inputs** - Event sources to be processed. Currently only Tracee-eBPF is a supported event source.
2. **Rules (a.k.a Signatures)** - The particular behavioral pattern to detect in the input source. Signatures can be authored in Golang, or Rego (OPA).
3. **Outputs** - How to communicate detections. Print to stdout, post to a webhook, or integrate with external systems.
