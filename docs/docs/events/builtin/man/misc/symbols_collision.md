---
title: TRACEE-SYMBOLS-COLLISION
section: 1
header: Tracee Event Manual
---

## NAME

**symbols_collision** - detect symbol collisions between shared objects

## DESCRIPTION

This event is triggered when a shared object is loaded into a process and has symbol collisions with another already-loaded shared object. A symbol collision occurs when two shared objects export the same symbol name, potentially leading to unexpected behavior or security issues.

The event helps identify cases where a shared object might override symbols from another library, which could be either legitimate (e.g., symbol versioning) or malicious (e.g., library hijacking).

## EVENT SETS

**lsm_hooks**, **fs**, **fs_file_ops**, **proc**, **proc_mem**

## DATA FIELDS

**loaded_path** (*string*)
: The path of the newly loaded shared object file

**collision_path** (*string*)
: The path of the already-loaded shared object that has symbol collisions

**symbols** (*[]string*)
: List of symbol names that collide between the two shared objects

## DEPENDENCIES

- `shared_object_loaded`: Provides information about loaded shared objects
- `sched_process_exec`: Used for mount namespace cache and performance optimization

## USE CASES

- **Library hijacking detection**: Identify attempts to override libc or other critical library functions

- **Dependency analysis**: Understand symbol conflicts in complex applications

- **Security auditing**: Monitor for unexpected symbol overrides

- **Debug symbol resolution**: Troubleshoot which library version is actually used

## CONFIGURATION

The event can be configured using data filtering:

- **symbols**: Specify which symbols to watch for collisions
  * Uses `=` or `!=` operators
  * No wildcard support
  * Default watches all symbols
  * Example: `symbols_collision.data.symbols=malloc,free`

- **loaded_path/collision_path**: Filter by specific libraries
  * Example: `symbols_collision.data.loaded_path=/usr/lib/libc.so.6`

## IMPLEMENTATION NOTES

- Implemented in user-mode for deep symbol analysis
- Uses caching to improve performance
- May have performance impact due to file operations
- Event size varies with number of collided symbols
- Race conditions possible between detection and file access

## COMMON PATTERNS

Common legitimate collision scenarios:

- Standard library variations (e.g., libc and libm)
- Symbol versioning in newer library versions
- Intentional symbol overriding for compatibility
- Debug/profiling library instrumentation

## SECURITY IMPLICATIONS

Symbol collisions can indicate:

- Library hijacking attempts
- Malicious symbol interposition
- Supply chain attacks
- Dynamic linker manipulation

## RELATED EVENTS

- **shared_object_loaded**: Track library loading
- **symbols_loaded**: Monitor symbol loading
- **file_modification**: Detect library file changes
- **process_vm_write**: Detect runtime symbol table modifications
