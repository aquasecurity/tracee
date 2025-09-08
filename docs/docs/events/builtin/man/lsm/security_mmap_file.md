---
title: TRACEE-SECURITY-MMAP-FILE
section: 1
header: Tracee Event Manual
---

## NAME

**security_mmap_file** - LSM memory mapping operation monitoring

## DESCRIPTION

Triggered when the Linux Security Module (LSM) framework performs security checks on file memory mapping operations. Memory mapping allows files to be mapped directly into process memory space, which is commonly used for shared libraries, executables, and data files.

This event is crucial for security monitoring as memory mapping can be used for code injection, library loading, shared memory communication, and other security-relevant operations that affect process memory layout and execution.

## EVENT SETS

**lsm_hooks**, **fs**, **fs_file_ops**, **proc**, **proc_mem**

## DATA FIELDS

**pathname** (*string*)
: The path of the file being memory mapped

**flags** (*int32*)
: The flags used for the mapping operation

**dev** (*uint32*)
: The device number of the filesystem containing the file

**inode** (*uint64*)
: The inode number of the file

**ctime** (*uint64*)
: The creation/change time of the file

**prot** (*uint64*)
: The memory protection flags (read, write, execute)

**mmap_flags** (*uint64*)
: The memory mapping flags (shared, private, etc.)

## DEPENDENCIES

**Kernel Probe:**

- security_mmap_file (required): LSM hook for file memory mapping security checks

## USE CASES

- **Executable monitoring**: Track executable file mapping and dynamic library loading

- **Code injection detection**: Detect memory mapping patterns indicating code injection

- **Shared memory monitoring**: Monitor shared memory operations and inter-process communication

- **Process behavior analysis**: Understand application memory usage and loading patterns

- **Security analysis**: Detect unusual memory mapping patterns indicating attacks

## RELATED EVENTS

- **mmap, mmap2**: Memory mapping system calls
- **security_file_mprotect**: Memory protection change events
- **execve**: Process execution events
- **dlopen**: Dynamic library loading events
- **Process memory events**: Memory layout and usage events