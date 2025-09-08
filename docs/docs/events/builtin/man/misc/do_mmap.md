---
title: TRACEE-DO-MMAP
section: 1
header: Tracee Event Manual
---

## NAME

**do_mmap** - memory mapping operation monitoring

## DESCRIPTION

Triggered when memory mapping operations are performed using the kernel's `do_mmap` function. This event captures detailed information about memory mapping operations, including file mappings, anonymous mappings, and shared memory operations, providing comprehensive insight into process memory layout and usage patterns.

Memory mapping is fundamental to process execution, shared libraries, and inter-process communication, but can also be used in exploitation techniques and code injection attacks.

## EVENT SETS

**fs**, **fs_file_ops**, **proc**, **proc_mem**

## DATA FIELDS

**addr** (*trace.Pointer*)
: The memory address where the mapping is requested or created

**pathname** (*string*)
: The path of the file being mapped (for file mappings)

**flags** (*uint32*)
: The flags used for the memory mapping operation

**dev** (*uint32*)
: The device identifier where the mapped file resides

**inode** (*uint64*)
: The inode number of the mapped file

**ctime** (*uint64*)
: The creation/change time of the mapped file

**pgoff** (*uint64*)
: The page offset within the file for the mapping

**len** (*uint64*)
: The length of the memory mapping

**prot** (*uint64*)
: The memory protection flags (read, write, execute permissions)

**mmap_flags** (*uint64*)
: The memory mapping flags (shared, private, anonymous, etc.)

## DEPENDENCIES

**Kernel Probe:**

- do_mmap (kprobe + kretprobe, required): Kernel memory mapping function

## USE CASES

- **Memory security monitoring**: Track memory mapping operations for security analysis

- **Code injection detection**: Detect potential code injection through suspicious memory mappings

- **Performance analysis**: Monitor memory usage patterns and mapping efficiency

- **Process debugging**: Debug memory mapping and allocation issues

- **Shared memory monitoring**: Track shared memory operations and inter-process communication

## RELATED EVENTS

- **security_mmap_file**: LSM security checks for file memory mapping
- **shared_object_loaded**: Shared library loading through memory mapping
- **mmap, mmap2**: Memory mapping system calls
- **Memory management events**: Related memory allocation and management monitoring
