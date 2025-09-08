---
title: TRACEE-KPROBE-ATTACH
section: 1
header: Tracee Event Manual
---

## NAME

**kprobe_attach** - kernel probe attachment monitoring

## DESCRIPTION

Triggered when a new kernel probe (kprobe) is registered using the kernel's `register_kprobe` function. This event captures the dynamic instrumentation of kernel functions through kprobes, which are commonly used by debugging tools, monitoring systems, and potentially by rootkits for kernel hooking.

Kprobe registration is a powerful capability that allows dynamic kernel instrumentation and can be used for legitimate monitoring or malicious kernel modification and hiding techniques.

## EVENT SETS

**none**

## DATA FIELDS

**symbol_name** (*string*)
: The name of the kernel symbol being probed

**pre_handler_addr** (*trace.Pointer*)
: The address of the pre-handler function for the kprobe

**post_handler_addr** (*trace.Pointer*)
: The address of the post-handler function for the kprobe

## DEPENDENCIES

**Kernel Probe:**

- register_kprobe (kprobe + kretprobe, required): Kernel probe registration function

## USE CASES

- **Kernel debugging monitoring**: Track legitimate kernel instrumentation and debugging activities

- **Rootkit detection**: Identify unauthorized kernel probes that could indicate rootkit presence

- **Security monitoring**: Monitor kernel instrumentation for potential security threats

- **System analysis**: Track kernel probe usage for system analysis and debugging

- **Malware detection**: Detect malware using kprobes for kernel modification or hiding

## RELATED EVENTS

- **do_init_module**: Kernel module loading that may register probes
- **proc_create**: Procfs entry creation often used with kernel probes
- **Kernel module events**: Related kernel module and instrumentation monitoring
- **Security events**: Related kernel security and integrity monitoring
