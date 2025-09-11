---
title: TRACEE-SHARED-OBJECT-LOADED
section: 1
header: Tracee Event Manual
---

## NAME

**shared_object_loaded** - shared library loading detection

## DESCRIPTION

Triggered when a shared library (.so file) is loaded into a process memory space through memory mapping operations. This event captures shared library loading by monitoring memory mapping operations performed on executable shared objects, providing detailed information about library loading patterns and dependencies.

Shared library loading is fundamental to dynamic linking and process execution, but can also be used in injection attacks, library hijacking, or malware loading techniques.

## EVENT SETS

**lsm_hooks**, **fs**, **fs_file_ops**, **proc**, **proc_mem**

## DATA FIELDS

**pathname** (*string*)
: The path of the shared library being loaded

**flags** (*int32*)
: The flags used for the memory mapping operation

**dev** (*uint32*)
: The device identifier where the library file resides

**inode** (*uint64*)
: The inode number of the library file

**ctime** (*uint64*)
: The creation/change time of the library file

## DEPENDENCIES

**Kernel Probe:**

- security_mmap_file (required): Security check for file memory mapping operations

**Capabilities:**

- SYS_PTRACE (required): Required for loading shared object dynamic symbols

## USE CASES

- **Library dependency tracking**: Monitor shared library loading and application dependencies

- **Security monitoring**: Detect potential library hijacking or injection attacks

- **Application analysis**: Understand application library usage patterns and behavior

- **Malware detection**: Identify suspicious library loading patterns indicating malware

- **Performance analysis**: Track library loading overhead and optimization opportunities

## RELATED EVENTS

- **security_mmap_file**: Memory mapping security events
- **do_mmap**: Memory mapping operations
- **execve**: Process execution that triggers library loading
- **Dynamic linking events**: Related dynamic linking and library loading events
