---
title: TRACEE-HOOKED-SEQ-OPS
section: 1
header: Tracee Event Manual
---

## NAME

**hooked_seq_ops** - sequence operations hooking detection

## DESCRIPTION

Triggered when sequence operations (seq_ops) structures are detected to be hooked or modified from their original kernel implementations. This event identifies potential rootkit activity or kernel modifications that hook sequence operations to hide information or modify system behavior.

Sequence operations hooking is a common rootkit technique used to hide processes, network connections, or other system information by modifying the kernel's sequence operation structures.

## EVENT SETS

**none**

## DATA FIELDS

**hooked_seq_ops** (*map[string]trace.HookedSymbolData*)
: Map of hooked sequence operations with detailed hook information

## DEPENDENCIES

**Kernel Symbols:**

- _stext (required): Kernel text section start for address validation
- _etext (required): Kernel text section end for address validation

**Event Dependencies:**

- print_net_seq_ops (required): Network sequence operations information
- do_init_module (required): Kernel module information for analysis

**Capabilities:**

- SYSLOG (required): Required for reading /proc/kallsyms for symbol resolution

## USE CASES

- **Rootkit detection**: Identify kernel-level rootkits that modify sequence operations

- **Kernel security monitoring**: Monitor kernel data structure integrity for security threats

- **System integrity verification**: Verify that kernel operations and structures remain authentic

- **Security analysis**: Detect unauthorized kernel modifications and hooking attempts

- **Incident response**: Investigate potential kernel-level compromise and modifications

## RELATED EVENTS

- **print_net_seq_ops**: Network sequence operations that may be hooked
- **do_init_module**: Kernel module loading that may install hooks
- **Kernel integrity events**: Related kernel security and integrity monitoring
- **Rootkit detection events**: Related rootkit and malware detection
