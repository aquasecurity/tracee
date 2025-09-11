---
title: TRACEE-PRINT-MEM-DUMP
section: 1
header: Tracee Event Manual
---

## NAME

**print_mem_dump** - memory dump printing for analysis

## DESCRIPTION

Triggered during Tracee initialization when configured to dump memory content from a specific address. This event accepts a memory address and dumps the requested memory region for analysis and debugging purposes.

The event is configured via CLI parameters that specify the target memory address, dump length, and optionally symbol names. It uses a uprobe mechanism to capture and dump the memory content when Tracee starts up.

## EVENT SETS

**none**

## DATA FIELDS

**bytes** (*[]byte*)
: The raw memory content read from the specified address

**address** (*trace.Pointer*)
: The memory address from which content was dumped

**length** (*uint64*)
: The length of the memory region dumped in bytes

**caller_ctx_id** (*uint64*)
: The caller context identifier for tracking purposes

## DEPENDENCIES

**Uprobe:**

- uprobe_mem_dump_trigger (required): User-space probe attached to Tracee's triggerMemDumpCall function

## USE CASES

- **Kernel debugging**: Dump specific kernel memory regions during Tracee startup for analysis

- **Security research**: Examine memory content at specific addresses for vulnerability research

- **System diagnostics**: Capture memory state for troubleshooting system issues

- **Memory forensics**: Extract memory content from specific addresses for investigation

- **Development debugging**: Analyze memory content during Tracee development and testing

## CONFIGURATION

This event requires configuration via CLI parameters:

```bash
# Dump memory at specific address
-e print_mem_dump.data.address=0xffffffffc0000000

# Dump memory for specific symbol
-e print_mem_dump.data.symbol_name=system:security_file_open

# Specify dump length (optional, defaults to max allowed)
-e print_mem_dump.data.length=1024
```

## RELATED EVENTS

- **hooked_seq_ops**: Related memory integrity checking event
- **shared_object_loaded**: Symbol information for memory analysis
- **symbols_loaded**: Kernel symbol information for address resolution
