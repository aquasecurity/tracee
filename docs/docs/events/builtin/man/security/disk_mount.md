---
title: TRACEE-DISK-MOUNT
section: 1
header: Tracee Event Manual
---

## NAME

**disk_mount** - detect container mounting of host device filesystems

## DESCRIPTION

This event detects when a container attempts to mount a host device filesystem. While some containers legitimately need device access, mounting host devices can be a sign of container escape attempts or privilege escalation attacks.

The event specifically monitors mount operations within container contexts, focusing on attempts to mount devices from the host's `/dev/` directory. This helps identify potential security boundary violations between containers and the host system.

## SIGNATURE METADATA

- **ID**: TRC-1014
- **Version**: 1
- **Severity**: 3
- **Category**: privilege-escalation
- **Technique**: Escape to Host
- **MITRE ID**: attack-pattern--4a5b7ade-8bb5-4853-84ed-23f262002665
- **MITRE External ID**: T1611

## EVENT SETS

**signatures**, **default**

## DATA FIELDS

This signature event uses fields from the underlying security_sb_mount event:

**device** (*string*)
: The device being mounted

**mount_point** (*string*)
: The location where the device is being mounted

**filesystem_type** (*string*)
: The type of filesystem being mounted

**flags** (*string*)
: Mount operation flags

## DEPENDENCIES

- `security_sb_mount`: Monitor filesystem mount operations in containers

## USE CASES

- **Container security**: Detect potential container escape attempts

- **Device access monitoring**: Track container access to host devices

- **Privilege escalation detection**: Identify unauthorized device access

- **Compliance monitoring**: Ensure containers follow device access policies

## CONTAINER IMPLICATIONS

Device mounting affects container security:

- Breaks container isolation
- Provides host system access
- Bypasses container restrictions
- Enables privilege escalation

## ATTACK VECTORS

Common malicious uses include:

- **Host access**: Reading host filesystem data
- **Device control**: Manipulating host devices
- **Container escape**: Breaking container boundaries
- **Data exfiltration**: Accessing sensitive host data

## RISK ASSESSMENT

Risk factors to consider:

- **High Impact**: Direct host system access
- **Container Escape**: Potential isolation breach
- **Privilege Escalation**: Access to privileged devices
- **Data Exposure**: Host filesystem visibility

## LEGITIMATE USES

Valid device mount scenarios:

- Storage management containers
- Device management tools
- System monitoring tools
- Hardware access requirements

## RELATED EVENTS

- **security_sb_mount**: Filesystem mount operations
- **security_sb_umount**: Filesystem unmount events
- **container_create**: Container lifecycle events
- **security_bprm_check**: Binary execution security checks
