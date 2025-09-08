---
title: TRACEE-LOAD-ELF-PHDRS
section: 1
header: Tracee Event Manual
---

## NAME

**load_elf_phdrs** - ELF program header loading monitoring

## DESCRIPTION

Triggered when ELF (Executable and Linkable Format) program headers are loaded using the kernel's `load_elf_phdrs` function. This event captures the loading of ELF program headers during executable loading and dynamic linking operations, providing insight into binary loading and execution patterns.

ELF program header loading is part of the executable loading process and provides detailed information about how binaries are loaded and organized in memory.

## EVENT SETS

**proc**

## DATA FIELDS

**pathname** (*string*)
: The path of the ELF file whose program headers are being loaded

**dev** (*uint32*)
: The device identifier where the ELF file resides

**inode** (*uint64*)
: The inode number of the ELF file

## DEPENDENCIES

**Kernel Probe:**

- load_elf_phdrs (required): ELF program header loading function

## USE CASES

- **Executable monitoring**: Track ELF executable loading and program header processing

- **Dynamic linking analysis**: Monitor ELF loading during dynamic linking operations

- **Security monitoring**: Detect unusual ELF loading patterns indicating potential threats

- **Process debugging**: Debug ELF loading and binary execution issues

- **Binary analysis**: Analyze ELF loading patterns and binary characteristics

## RELATED EVENTS

- **execve**: Process execution events that trigger ELF loading
- **shared_object_loaded**: Shared library loading events
- **do_mmap**: Memory mapping operations for ELF loading
- **Process execution events**: Related process creation and execution monitoring
