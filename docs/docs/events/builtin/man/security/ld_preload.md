---
title: TRACEE-LD-PRELOAD
section: 1
header: Tracee Event Manual
---

## NAME

**ld_preload** - detect library preload code injection attempts

## DESCRIPTION

This event detects potential code injection attempts using library preloading mechanisms. It monitors the use of `LD_PRELOAD` and `LD_LIBRARY_PATH` environment variables, as well as modifications to `/etc/ld.so.preload`. These mechanisms can be exploited to inject malicious code by forcing programs to load unauthorized libraries before their legitimate dependencies.

The event provides comprehensive monitoring of both environment-based and file-based preloading techniques, helping detect various code injection and function hooking attempts.

## SIGNATURE METADATA

- **ID**: TRC-107
- **Version**: 1
- **Severity**: 2
- **Category**: persistence
- **Technique**: Hijack Execution Flow
- **MITRE ID**: attack-pattern--aedfca76-3b30-4866-b2aa-0f1d7fd1e4b6
- **MITRE External ID**: T1574

## EVENT SETS

**signatures**, **default**

## DATA FIELDS

This signature event uses fields from multiple underlying events:

**env_vars** (*map[string]string*)
: Environment variables related to library loading

**pathname** (*string*)
: Path to preload configuration being accessed

**flags** (*string*)
: File access flags for preload operations

**old_path** (*string*)
: Original path in rename operations

**new_path** (*string*)
: New path in rename operations

## DEPENDENCIES

- `sched_process_exec`: Monitor process environment variables
- `security_file_open`: Track preload file access
- `security_inode_rename`: Monitor preload file renames

## USE CASES

- **Code injection detection**: Identify unauthorized library loading

- **Runtime integrity**: Monitor library load order tampering

- **Function hooking**: Detect API interception attempts

- **Persistence detection**: Identify malicious library persistence

## PRELOAD MECHANISMS

Common preload vectors:

- **LD_PRELOAD**: Environment variable for single library
- **LD_LIBRARY_PATH**: Search path manipulation
- **/etc/ld.so.preload**: System-wide preload configuration
- **RPATH/RUNPATH**: Binary-specific library paths

## ATTACK VECTORS

Common malicious uses include:

- **Function hooking**: Intercept library calls
- **Credential theft**: Hook authentication functions
- **Anti-debugging**: Intercept debugging APIs
- **Persistence**: System-wide library injection

## RISK ASSESSMENT

Risk factors to consider:

- **System-Wide Impact**: Affects all dynamic executables
- **Privilege Escalation**: Potential for elevated access
- **Stealth Capability**: Hard to detect once loaded
- **Persistence**: Survives process restarts

## LEGITIMATE USES

Valid preload scenarios:

- Debugging tools
- Profiling libraries
- API compatibility layers
- System monitoring tools

## MITIGATION

Recommended security controls:

- Restrict environment variables
- Monitor preload files
- Use static linking
- Implement library pinning
- Regular integrity checks

## RELATED EVENTS

- **security_bprm_check**: Binary execution security
- **shared_object_loaded**: Library loading events
- **symbols_loaded**: Symbol resolution tracking
- **dynamic_code_loading**: Runtime code execution
