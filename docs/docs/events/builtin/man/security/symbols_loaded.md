---
title: TRACEE-SYMBOLS-LOADED
section: 1
header: Tracee Event Manual
---

## NAME

**symbols_loaded** - shared object with watched symbols loaded

## DESCRIPTION

Triggered when a shared object that exports watched symbols is loaded into the current process. This derived event helps identify shared object usage patterns and detect when shared objects attempt to override symbols from other libraries, which can indicate potential security threats or library hijacking attempts.

The event uses data filtering to configure which symbols to watch and which library paths to monitor, providing flexible control over symbol monitoring.

This event is useful for:

- **Library hijacking detection**: Identify attempts to override legitimate library symbols
- **Shared object monitoring**: Track loading of specific libraries and symbols
- **Security analysis**: Detect malicious library injection or symbol manipulation

## EVENT SETS

**derived**, **fs**, **security_alert**

## DATA FIELDS

**library_path** (*string*)
: The path of the shared object file that was loaded

**symbols** (*array*)
: The watched symbols exported by the shared object (subject to TOCTOU)

**sha256** (*string*)
: SHA256 hash of the loaded shared object file

## DEPENDENCIES

**Source Events:**

- shared_object_loaded (required): Provides information about loaded shared objects
- sched_process_exec (required): Used to maintain mount namespace cache for filesystem access

## CONFIGURATION

The event supports data filtering for fine-grained control:

### symbols Filter

Configure watched symbols using the `=` operator:
```bash
tracee -e symbols_loaded.data.symbols=fopen
```

### library_path Filter

Whitelist shared object path prefixes using the `!=` operator:
```bash
tracee -e symbols_loaded.data.library_path!=libc
```

## USE CASES

- **Library hijacking detection**: Detect attempts to override system library functions

- **Security monitoring**: Monitor loading of suspicious or unexpected shared objects

- **Malware analysis**: Identify malicious library injection techniques

- **System integrity**: Verify that only expected libraries are loading watched symbols

- **Forensic analysis**: Track library loading patterns during investigations

## EXAMPLE USAGE

Detect shared objects trying to override the `fopen` function from non-libc libraries:

```bash
tracee -e symbols_loaded.data.symbols=fopen -e symbols_loaded.data.library_path!=libc
```

## PERFORMANCE CONSIDERATIONS

The event is implemented in user-mode and requires file system access to examine shared objects. This introduces some performance overhead, especially with frequent library loading. The implementation includes optimizations, but consider monitoring scope in high-throughput environments.

## SECURITY CONSIDERATIONS

- **TOCTOU vulnerability**: Shared object files could be altered between detection and analysis
- **File access timing**: Until the shared object file is opened and read, it could be modified or removed

## RELATED EVENTS

- **shared_object_loaded**: Base event for shared object loading detection
- **symbols_collision**: Detection of symbol conflicts between libraries
- **security_file_open**: File access security monitoring