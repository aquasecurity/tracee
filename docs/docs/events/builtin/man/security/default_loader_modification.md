---
title: TRACEE-DEFAULT-LOADER-MODIFICATION
section: 1
header: Tracee Event Manual
---

## NAME

**default_loader_mod** - detect modifications to system dynamic loader

## DESCRIPTION

This event detects unauthorized modifications to the default dynamic loader (ld.so) on Linux systems. The dynamic loader is a critical component responsible for loading shared libraries for dynamically linked applications. Due to its privileged position in program execution, modifications to the loader can affect nearly every application on the system.

Changes to the dynamic loader could indicate attempts to hijack execution flow, bypass security controls, or establish persistent system access. This event monitors both direct modifications and rename operations that might be used to replace the legitimate loader.

## SIGNATURE METADATA

- **ID**: TRC-1012
- **Version**: 1
- **Severity**: 3
- **Category**: defense-evasion
- **Technique**: Hijack Execution Flow
- **MITRE ID**: attack-pattern--aedfca76-3b30-4866-b2aa-0f1d7fd1e4b6
- **MITRE External ID**: T1574

## EVENT SETS

**signatures**, **default**

## DATA FIELDS

This signature event uses fields from the underlying security events:

**pathname** (*string*)
: Path to the dynamic loader file being accessed

**flags** (*string*)
: File access flags indicating the type of operation

**old_path** (*string*)
: Original path in case of rename operations

**new_path** (*string*)
: New path in case of rename operations

## DEPENDENCIES

- `security_file_open`: Monitor file access attempts
- `security_inode_rename`: Track file rename operations

## USE CASES

- **System integrity**: Monitor critical system component modifications

- **Defense evasion detection**: Identify attempts to bypass security controls

- **Persistence detection**: Detect loader-based persistence mechanisms

- **Supply chain security**: Monitor for unauthorized binary modifications

## LOADER SECURITY

Critical aspects of dynamic loader security:

- Loads shared libraries for all dynamic executables
- Runs before application code execution
- Has system-wide impact
- Can affect security mechanisms

## ATTACK VECTORS

Common malicious modifications include:

- **Library hijacking**: Forcing load of malicious libraries
- **Security bypass**: Disabling security features
- **Function hooking**: Intercepting library calls
- **Information theft**: Capturing sensitive data

## RISK ASSESSMENT

Risk factors to consider:

- **Critical Impact**: Affects all dynamic executables
- **System-Wide Scope**: Changes affect entire system
- **Privileged Access**: Loader runs with elevated privileges
- **Persistence**: Changes persist until loader is restored

## MITIGATION

Recommended security controls:

- File integrity monitoring
- Restricted write access to loader
- Regular checksum verification
- Secure boot mechanisms

## RELATED EVENTS

- **security_file_open**: File access monitoring
- **security_inode_rename**: File rename operations
- **shared_object_loaded**: Library loading events
- **symbols_loaded**: Symbol resolution tracking
